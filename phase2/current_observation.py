from __future__ import annotations

import base64
import binascii
import hashlib
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Any, Callable, Mapping, MutableMapping
from urllib.parse import quote

from .credentials import (
    create_app_jwt,
    require_state_repository_access,
    state_observation_profile,
    token_request,
    validate_token_response,
    verify_live_installation,
)
from .github_api import GitHubAPI, GitHubAPIError
from .operator_inventory import (
    CONTROL_REPOSITORY_ID,
    EXPECTED_REPOSITORY_IDS,
    INVENTORY_PERMISSIONS,
    STATE_REPOSITORY_ID,
    _list_complete_repository_ids,
    inventory_token_request,
    validate_inventory_token_response,
)
from .operator_manifest import SHA40, canonical_json, sha256_text
from .policy import load_policy


CONTROL_REPOSITORY = "8ft0-ai/gitstate-allocation-control"
CONTROL_OWNER = "8ft0-ai"
CONTROL_NAME = "gitstate-allocation-control"
ENVIRONMENT_NAME = "phase-2-allocator"
EXECUTION_VARIABLE = "PHASE2_WORKSTREAM_D_EXECUTION_ENABLED"
STATE_REPOSITORY = "8ft0-ai/gitstate-allocation-state"
STATE_REPOSITORY_REF = "refs/heads/main"
ENVIRONMENT_OBSERVATION_PERMISSIONS = {
    "environments": "read",
    "metadata": "read",
}
PERMISSION_PROFILE_SHA256 = (
    "e577e2ae1f3072a07de54b32c250e00cac492b4ae176ab485ff1d1157261942d"
)
RECIPIENT_CERTIFICATE_ENV = "INPUT_CURRENT_OBSERVATION_RECIPIENT_CERT_B64"
ENVELOPE_CONTRACT_VERSION = "gitstate-current-observation-envelope-v1"
MAX_RECIPIENT_CERTIFICATE_B64_CHARS = 16_384
MAX_RECIPIENT_CERTIFICATE_DER_BYTES = 12_288
MAX_PRIVATE_OBSERVATION_BYTES = 131_072
MAX_CIPHERTEXT_BYTES = 196_608
OPENSSL_TIMEOUT_SECONDS = 15


class CurrentObservationError(RuntimeError):
    pass


@dataclass(frozen=True)
class RecipientCertificate:
    der: bytes
    sha256: str

    def validate_binding(self) -> None:
        if (
            not self.der
            or len(self.der) > MAX_RECIPIENT_CERTIFICATE_DER_BYTES
            or hashlib.sha256(self.der).hexdigest() != self.sha256
        ):
            raise CurrentObservationError("RECIPIENT_CERTIFICATE_MISMATCH")


@dataclass(frozen=True)
class ObservationContext:
    repository: str
    ref: str
    trusted_sha: str
    run_id: int
    run_attempt: int
    operation: str

    def validate(self) -> None:
        if self.repository != CONTROL_REPOSITORY:
            raise CurrentObservationError("OBSERVATION_REPOSITORY_MISMATCH")
        if self.ref != "refs/heads/main":
            raise CurrentObservationError("OBSERVATION_PROTECTED_MAIN_REQUIRED")
        if SHA40.fullmatch(self.trusted_sha) is None:
            raise CurrentObservationError("OBSERVATION_TRUSTED_SHA_INVALID")
        if self.run_id <= 0 or self.run_attempt != 1:
            raise CurrentObservationError("OBSERVATION_RUN_IDENTITY_INVALID")
        if self.operation != "current_observation":
            raise CurrentObservationError("OBSERVATION_OPERATION_REQUIRED")


def _context(values: Mapping[str, str]) -> ObservationContext:
    try:
        result = ObservationContext(
            repository=values["GITHUB_REPOSITORY"],
            ref=values["GITHUB_REF"],
            trusted_sha=values["GITHUB_SHA"],
            run_id=int(values["GITHUB_RUN_ID"]),
            run_attempt=int(values["GITHUB_RUN_ATTEMPT"]),
            operation=values["INPUT_OPERATION"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CurrentObservationError("OBSERVATION_CONTEXT_INCOMPLETE") from exc
    result.validate()
    return result


def _required_positive_int(values: Mapping[str, str], name: str) -> int:
    try:
        value = int(values.get(name, ""))
    except (TypeError, ValueError) as exc:
        raise CurrentObservationError(f"{name}_INVALID") from exc
    if value <= 0:
        raise CurrentObservationError(f"{name}_INVALID")
    return value


def _run_openssl(
    arguments: list[str],
    *,
    stdin: bytes,
    failure_code: str,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            ["openssl", *arguments],
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=OPENSSL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CurrentObservationError(failure_code) from exc
    if result.returncode != 0:
        raise CurrentObservationError(failure_code)
    return result


def _load_recipient_certificate(values: Mapping[str, str]) -> RecipientCertificate:
    if values.get("GITHUB_ACTOR") != CONTROL_OWNER:
        raise CurrentObservationError("OBSERVATION_OWNER_ACTOR_REQUIRED")
    encoded = values.get(RECIPIENT_CERTIFICATE_ENV, "")
    if (
        not isinstance(encoded, str)
        or not encoded
        or len(encoded) > MAX_RECIPIENT_CERTIFICATE_B64_CHARS
        or not encoded.isascii()
    ):
        raise CurrentObservationError("RECIPIENT_CERTIFICATE_INVALID")
    try:
        certificate_der = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CurrentObservationError("RECIPIENT_CERTIFICATE_INVALID") from exc
    if (
        not certificate_der
        or len(certificate_der) > MAX_RECIPIENT_CERTIFICATE_DER_BYTES
    ):
        raise CurrentObservationError("RECIPIENT_CERTIFICATE_INVALID")

    parsed = _run_openssl(
        ["x509", "-inform", "DER", "-outform", "DER"],
        stdin=certificate_der,
        failure_code="RECIPIENT_CERTIFICATE_INVALID",
    )
    if parsed.stdout != certificate_der:
        raise CurrentObservationError("RECIPIENT_CERTIFICATE_INVALID")
    _run_openssl(
        ["x509", "-inform", "DER", "-noout", "-checkend", "0"],
        stdin=certificate_der,
        failure_code="RECIPIENT_CERTIFICATE_INVALID",
    )
    recipient = RecipientCertificate(
        der=certificate_der,
        sha256=hashlib.sha256(certificate_der).hexdigest(),
    )
    recipient.validate_binding()
    return recipient


def _list_counted_collection(
    api: GitHubAPI,
    path: str,
    *,
    key: str,
    per_page: int,
    max_pages: int = 100,
) -> list[Mapping[str, Any]]:
    if per_page <= 0 or max_pages <= 0:
        raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
    items: list[Mapping[str, Any]] = []
    expected_total: int | None = None
    for page in range(1, max_pages + 1):
        separator = "&" if "?" in path else "?"
        payload = api.get(f"{path}{separator}per_page={per_page}&page={page}")
        if not isinstance(payload, Mapping):
            raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
        total = payload.get("total_count")
        page_items = payload.get(key)
        if type(total) is not int or total < 0 or not isinstance(page_items, list):
            raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
        if expected_total is None:
            expected_total = total
            if expected_total > per_page * max_pages:
                raise CurrentObservationError("READ_EVIDENCE_TOO_LARGE")
        elif total != expected_total:
            raise CurrentObservationError("READ_EVIDENCE_MOVED")
        if any(not isinstance(item, Mapping) for item in page_items):
            raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
        items.extend(page_items)
        if len(items) > expected_total:
            raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
        if len(items) == expected_total:
            return items
        if not page_items:
            raise CurrentObservationError("READ_EVIDENCE_INCOMPLETE")
    raise CurrentObservationError("READ_EVIDENCE_INCOMPLETE")


def _normalise_standard_protection_rules(
    rules: object,
) -> list[dict[str, Any]]:
    if not isinstance(rules, list) or any(
        not isinstance(rule, Mapping) for rule in rules
    ):
        raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")

    normalised_rules: list[dict[str, Any]] = []
    for rule in rules:
        rule_type = rule.get("type")
        if rule_type == "wait_timer":
            timer = rule.get("wait_timer")
            if type(timer) is not int or timer < 0:
                raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
            normalised_rules.append({"type": "wait_timer", "wait_timer": timer})
            continue
        if rule_type == "required_reviewers":
            reviewers = rule.get("reviewers")
            prevent_self_review = rule.get("prevent_self_review")
            if not isinstance(reviewers, list) or type(prevent_self_review) is not bool:
                raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
            normalised_reviewers: list[dict[str, Any]] = []
            seen_reviewers: set[tuple[str, int]] = set()
            for entry in reviewers:
                if not isinstance(entry, Mapping):
                    raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
                reviewer = entry.get("reviewer")
                reviewer_type = entry.get("type")
                if not isinstance(reviewer, Mapping) or reviewer_type not in {
                    "User",
                    "Team",
                }:
                    raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
                reviewer_id = reviewer.get("id")
                if type(reviewer_id) is not int or reviewer_id <= 0:
                    raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
                identity = (reviewer_type, reviewer_id)
                if identity in seen_reviewers:
                    raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
                seen_reviewers.add(identity)
                normalised_reviewers.append(
                    {"id": reviewer_id, "type": reviewer_type}
                )
            normalised_reviewers.sort(key=lambda item: (item["type"], item["id"]))
            normalised_rules.append(
                {
                    "type": "required_reviewers",
                    "prevent_self_review": prevent_self_review,
                    "reviewers": normalised_reviewers,
                }
            )
            continue
        if rule_type == "branch_policy":
            normalised_rules.append({"type": "branch_policy"})
            continue
        raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
    normalised_rules.sort(key=canonical_json)
    return normalised_rules


def _normalise_branch_policies(
    values: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    seen_semantics: set[tuple[str, str]] = set()
    for value in values:
        policy_id = value.get("id")
        name = value.get("name")
        policy_type = value.get("type")
        if type(policy_id) is not int or policy_id <= 0:
            raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
        if not isinstance(name, str) or not name:
            raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
        if policy_type not in {"branch", "tag"}:
            raise CurrentObservationError("CUSTOM_BRANCH_POLICY_TYPE_UNAVAILABLE")
        semantic = (policy_type, name)
        if policy_id in seen_ids or semantic in seen_semantics:
            raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
        seen_ids.add(policy_id)
        seen_semantics.add(semantic)
        result.append({"id": policy_id, "name": name, "type": policy_type})
    result.sort(key=lambda item: (item["type"], item["name"], item["id"]))
    return result


def _normalise_custom_protection_rules(
    payload: object,
) -> list[dict[str, Any]]:
    if not isinstance(payload, Mapping):
        raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
    total = payload.get("total_count")
    rules = payload.get("custom_deployment_protection_rules")
    if type(total) is not int or total < 0 or not isinstance(rules, list):
        raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
    if total != len(rules):
        raise CurrentObservationError("READ_EVIDENCE_INCOMPLETE")

    result: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    seen_apps: set[tuple[int, str]] = set()
    for rule in rules:
        if not isinstance(rule, Mapping):
            raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
        rule_id = rule.get("id")
        enabled = rule.get("enabled")
        app = rule.get("app")
        if type(rule_id) is not int or rule_id <= 0 or enabled is not True:
            raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
        if not isinstance(app, Mapping):
            raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
        app_id = app.get("id")
        app_slug = app.get("slug")
        if type(app_id) is not int or app_id <= 0:
            raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
        if not isinstance(app_slug, str) or not app_slug:
            raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
        app_identity = (app_id, app_slug)
        if rule_id in seen_ids or app_identity in seen_apps:
            raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
        seen_ids.add(rule_id)
        seen_apps.add(app_identity)
        result.append(
            {
                "id": rule_id,
                "enabled": True,
                "app": {"id": app_id, "slug": app_slug},
            }
        )
    result.sort(key=lambda item: (item["app"]["slug"], item["app"]["id"], item["id"]))
    return result


def _environment_policy_material(
    payload: Mapping[str, Any],
    expected_name: str,
    *,
    branch_policies: list[Mapping[str, Any]] | None = None,
    custom_protection_rules: object | None = None,
) -> Mapping[str, Any]:
    if payload.get("name") != expected_name:
        raise CurrentObservationError("ENVIRONMENT_BOUNDARY_CHANGED")
    can_admins_bypass = payload.get("can_admins_bypass")
    if type(can_admins_bypass) is not bool:
        raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
    normalised_rules = _normalise_standard_protection_rules(
        payload.get("protection_rules")
    )

    branch_policy = payload.get("deployment_branch_policy")
    if branch_policy is None:
        normalised_branch_policy: Mapping[str, Any] | None = None
        custom_enabled = False
    elif isinstance(branch_policy, Mapping):
        protected = branch_policy.get("protected_branches")
        custom = branch_policy.get("custom_branch_policies")
        if type(protected) is not bool or type(custom) is not bool or protected == custom:
            raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
        normalised_branch_policy = {
            "custom_branch_policies": custom,
            "protected_branches": protected,
        }
        custom_enabled = custom
    else:
        raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")

    has_branch_rule = any(rule["type"] == "branch_policy" for rule in normalised_rules)
    if has_branch_rule != (normalised_branch_policy is not None):
        raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")

    supplied_branch_policies = [] if branch_policies is None else branch_policies
    if custom_enabled:
        normalised_custom_branch_policies = _normalise_branch_policies(
            supplied_branch_policies
        )
    else:
        if supplied_branch_policies:
            raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
        normalised_custom_branch_policies = []

    if custom_protection_rules is None:
        normalised_custom_protection_rules: list[dict[str, Any]] = []
    else:
        normalised_custom_protection_rules = _normalise_custom_protection_rules(
            custom_protection_rules
        )

    return {
        "can_admins_bypass": can_admins_bypass,
        "custom_deployment_protection_rules": normalised_custom_protection_rules,
        "deployment_branch_policy": normalised_branch_policy,
        "deployment_branch_policies": normalised_custom_branch_policies,
        "name": expected_name,
        "protection_rules": normalised_rules,
    }


def _environment_policy_sha256(
    payload: Mapping[str, Any],
    expected_name: str,
    *,
    branch_policies: list[Mapping[str, Any]] | None = None,
    custom_protection_rules: object | None = None,
) -> str:
    return sha256_text(
        canonical_json(
            _environment_policy_material(
                payload,
                expected_name,
                branch_policies=branch_policies,
                custom_protection_rules=custom_protection_rules,
            )
        )
    )


def _read_environment_policy_snapshot(api: GitHubAPI) -> Mapping[str, Any]:
    environment_path = (
        f"/repos/{CONTROL_REPOSITORY}/environments/{quote(ENVIRONMENT_NAME, safe='')}"
    )
    before = api.get(environment_path)
    if not isinstance(before, Mapping):
        raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")

    branch_policy = before.get("deployment_branch_policy")
    custom_enabled = (
        isinstance(branch_policy, Mapping)
        and branch_policy.get("custom_branch_policies") is True
    )
    if custom_enabled:
        branch_policies = _list_counted_collection(
            api,
            f"{environment_path}/deployment-branch-policies",
            key="branch_policies",
            per_page=100,
        )
    else:
        branch_policies = []

    custom_rules = api.get(f"{environment_path}/deployment_protection_rules")
    after = api.get(environment_path)
    if not isinstance(after, Mapping):
        raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")

    before_material = _environment_policy_material(
        before,
        ENVIRONMENT_NAME,
        branch_policies=branch_policies,
        custom_protection_rules=custom_rules,
    )
    after_material = _environment_policy_material(
        after,
        ENVIRONMENT_NAME,
        branch_policies=branch_policies,
        custom_protection_rules=custom_rules,
    )
    if canonical_json(before_material) != canonical_json(after_material):
        raise CurrentObservationError("ENVIRONMENT_POLICY_MOVED")
    return before_material


def _observe_environment_policy(api: GitHubAPI) -> tuple[Mapping[str, Any], str]:
    first = _read_environment_policy_snapshot(api)
    second = _read_environment_policy_snapshot(api)
    if canonical_json(first) != canonical_json(second):
        raise CurrentObservationError("ENVIRONMENT_POLICY_MOVED")
    return first, sha256_text(canonical_json(first))


def _state_observation_sha256(
    *, repository_id: int, ref: str, commit_sha: str, tree_sha: str
) -> str:
    if repository_id != STATE_REPOSITORY_ID:
        raise CurrentObservationError("STATE_REPOSITORY_ID_MISMATCH")
    if ref != STATE_REPOSITORY_REF:
        raise CurrentObservationError("STATE_BASELINE_CHANGED")
    if SHA40.fullmatch(commit_sha) is None or SHA40.fullmatch(tree_sha) is None:
        raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
    return sha256_text(
        canonical_json(
            {
                "commit_sha": commit_sha,
                "ref": ref,
                "repository_id": repository_id,
                "tree_sha": tree_sha,
            }
        )
    )


def _environment_observation_token_request() -> dict[str, object]:
    return {
        "repository_ids": [CONTROL_REPOSITORY_ID],
        "permissions": dict(ENVIRONMENT_OBSERVATION_PERMISSIONS),
    }


def _validate_environment_observation_token_response(
    response: Mapping[str, Any],
) -> str:
    token = response.get("token")
    permissions = response.get("permissions")
    repositories = response.get("repositories")
    if permissions != ENVIRONMENT_OBSERVATION_PERMISSIONS:
        raise CurrentObservationError("ENVIRONMENT_TOKEN_PERMISSION_MISMATCH")
    if not isinstance(repositories, list):
        raise CurrentObservationError("ENVIRONMENT_TOKEN_REPOSITORY_SCOPE_MISMATCH")
    ids = [
        repository.get("id") if isinstance(repository, Mapping) else None
        for repository in repositories
    ]
    if ids != [CONTROL_REPOSITORY_ID]:
        raise CurrentObservationError("ENVIRONMENT_TOKEN_REPOSITORY_SCOPE_MISMATCH")
    if not isinstance(token, str) or not token:
        raise CurrentObservationError("ENVIRONMENT_TOKEN_MISSING")
    return token


def _read_execution_variable_collection(
    api: GitHubAPI,
    collection_path: str,
) -> tuple[tuple[str, str], ...]:
    variables = _list_counted_collection(
        api,
        collection_path,
        key="variables",
        per_page=30,
    )
    canonical_variables: list[tuple[str, str]] = []
    seen_names: set[str] = set()
    for variable in variables:
        name = variable.get("name")
        value = variable.get("value")
        if not isinstance(name, str) or not name or not isinstance(value, str):
            raise CurrentObservationError("EXECUTION_VARIABLE_EVIDENCE_AMBIGUOUS")
        if name in seen_names:
            raise CurrentObservationError("EXECUTION_VARIABLE_EVIDENCE_AMBIGUOUS")
        seen_names.add(name)
        canonical_variables.append((name, value))
    return tuple(sorted(canonical_variables))


def _read_exact_execution_variable(
    api: GitHubAPI,
    exact_path: str,
) -> tuple[bool, str | None]:
    try:
        payload = api.get(exact_path)
    except GitHubAPIError as exc:
        if exc.status == 404:
            return False, None
        raise
    if not isinstance(payload, Mapping):
        raise CurrentObservationError("EXECUTION_VARIABLE_EVIDENCE_AMBIGUOUS")
    name = payload.get("name")
    value = payload.get("value")
    if name != EXECUTION_VARIABLE or not isinstance(value, str):
        raise CurrentObservationError("EXECUTION_VARIABLE_EVIDENCE_AMBIGUOUS")
    return True, value


def _observe_execution_variable(api: GitHubAPI) -> dict[str, object]:
    environment = quote(ENVIRONMENT_NAME, safe="")
    variable_name = quote(EXECUTION_VARIABLE, safe="")
    collection_path = (
        f"/repos/{CONTROL_REPOSITORY}/environments/{environment}/variables"
    )
    exact_path = f"{collection_path}/{variable_name}"

    first_exact = _read_exact_execution_variable(api, exact_path)
    first_collection = _read_execution_variable_collection(api, collection_path)
    second_collection = _read_execution_variable_collection(api, collection_path)
    if first_collection != second_collection:
        raise CurrentObservationError("EXECUTION_VARIABLE_EVIDENCE_MOVED")
    second_exact = _read_exact_execution_variable(api, exact_path)
    if first_exact != second_exact:
        raise CurrentObservationError("EXECUTION_VARIABLE_EVIDENCE_MOVED")

    collection_values = [
        value for name, value in first_collection if name == EXECUTION_VARIABLE
    ]
    selected_found, selected_value = first_exact
    if selected_found:
        if collection_values != [selected_value]:
            raise CurrentObservationError("EXECUTION_VARIABLE_EVIDENCE_AMBIGUOUS")
    elif collection_values:
        raise CurrentObservationError("EXECUTION_VARIABLE_EVIDENCE_AMBIGUOUS")

    if not selected_found:
        return {
            "name": EXECUTION_VARIABLE,
            "defined": False,
            "state": "not_defined",
        }
    return {
        "name": EXECUTION_VARIABLE,
        "defined": True,
        "state": "defined_empty" if selected_value == "" else "defined_non_empty",
    }


def _observe_installation_inventory(
    app_api: GitHubAPI,
    *,
    installation_id: int,
    api_url: str,
    api_factory: Callable[[str, str], GitHubAPI],
) -> tuple[int, ...]:
    request = inventory_token_request()
    if set(request) != {"permissions"} or request["permissions"] != INVENTORY_PERMISSIONS:
        raise CurrentObservationError("INVENTORY_TOKEN_REQUEST_WIDENED")

    response = app_api.post(
        f"/app/installations/{installation_id}/access_tokens",
        request,
    )
    if not isinstance(response, dict):
        raise CurrentObservationError("INVENTORY_TOKEN_RESPONSE_INVALID")
    token = response.get("token")
    if not isinstance(token, str) or not token:
        raise CurrentObservationError("INVENTORY_TOKEN_MISSING")

    primary_error: Exception | None = None
    inventory_api: GitHubAPI | None = None
    repository_ids: tuple[int, ...] | None = None
    try:
        validate_inventory_token_response(response)
        inventory_api = api_factory(token, api_url)
        repository_ids = _list_complete_repository_ids(inventory_api)
        if repository_ids != EXPECTED_REPOSITORY_IDS:
            raise CurrentObservationError("INVENTORY_EXACT_SET_MISMATCH")
    except Exception as exc:
        primary_error = exc

    try:
        revocation_api = (
            inventory_api if inventory_api is not None else api_factory(token, api_url)
        )
        _, _, status = revocation_api.request_with_status(
            "DELETE", "/installation/token"
        )
        if status != 204:
            raise CurrentObservationError("INVENTORY_TOKEN_REVOCATION_STATUS_INVALID")
    except Exception as revoke_exc:
        raise CurrentObservationError("INVENTORY_TOKEN_REVOCATION_FAILED") from (
            primary_error or revoke_exc
        )
    finally:
        token = ""

    if primary_error is not None:
        raise primary_error
    if repository_ids is None:
        raise CurrentObservationError("INVENTORY_EVIDENCE_MISSING")
    return repository_ids


def _with_environment_observation_token(
    app_api: GitHubAPI,
    *,
    installation_id: int,
    api_url: str,
    api_factory: Callable[[str, str], GitHubAPI],
    observe: Callable[[GitHubAPI], dict[str, object]],
) -> dict[str, object]:
    request = _environment_observation_token_request()
    if request != {
        "repository_ids": [CONTROL_REPOSITORY_ID],
        "permissions": {"environments": "read", "metadata": "read"},
    }:
        raise CurrentObservationError("ENVIRONMENT_TOKEN_REQUEST_WIDENED")

    response = app_api.post(
        f"/app/installations/{installation_id}/access_tokens",
        request,
    )
    if not isinstance(response, Mapping):
        raise CurrentObservationError("ENVIRONMENT_TOKEN_RESPONSE_INVALID")
    token = response.get("token")
    if not isinstance(token, str) or not token:
        raise CurrentObservationError("ENVIRONMENT_TOKEN_MISSING")

    primary_error: Exception | None = None
    environment_api: GitHubAPI | None = None
    result: dict[str, object] | None = None
    try:
        _validate_environment_observation_token_response(response)
        environment_api = api_factory(token, api_url)
        result = observe(environment_api)
    except Exception as exc:
        primary_error = exc

    try:
        revocation_api = (
            environment_api
            if environment_api is not None
            else api_factory(token, api_url)
        )
        _, _, status = revocation_api.request_with_status(
            "DELETE", "/installation/token"
        )
        if status != 204:
            raise CurrentObservationError(
                "ENVIRONMENT_TOKEN_REVOCATION_STATUS_INVALID"
            )
    except Exception as revoke_exc:
        raise CurrentObservationError("ENVIRONMENT_TOKEN_REVOCATION_FAILED") from (
            primary_error or revoke_exc
        )
    finally:
        token = ""

    if primary_error is not None:
        raise primary_error
    if result is None:
        raise CurrentObservationError("ENVIRONMENT_OBSERVATION_EVIDENCE_MISSING")
    return result


def _observe_state_baseline(
    app_api: GitHubAPI,
    *,
    installation_id: int,
    api_url: str,
    api_factory: Callable[[str, str], GitHubAPI],
) -> dict[str, object]:
    profile = state_observation_profile(STATE_REPOSITORY_ID)
    request = token_request(profile)
    if request != {
        "repository_ids": [STATE_REPOSITORY_ID],
        "permissions": {"contents": "read", "metadata": "read"},
    }:
        raise CurrentObservationError("STATE_OBSERVATION_TOKEN_REQUEST_WIDENED")

    response = app_api.post(
        f"/app/installations/{installation_id}/access_tokens",
        request,
    )
    if not isinstance(response, dict):
        raise CurrentObservationError("STATE_OBSERVATION_TOKEN_RESPONSE_INVALID")
    token = response.get("token")
    if not isinstance(token, str) or not token:
        raise CurrentObservationError("STATE_OBSERVATION_TOKEN_MISSING")

    primary_error: Exception | None = None
    state_api: GitHubAPI | None = None
    result: dict[str, object] | None = None
    try:
        validate_token_response(response, profile)
        state_api = api_factory(token, api_url)
        require_state_repository_access(
            token,
            "8ft0-ai",
            "gitstate-allocation-state",
            STATE_REPOSITORY_ID,
            api_url,
            api_factory=api_factory,
        )
        ref_payload = state_api.get(f"/repos/{STATE_REPOSITORY}/git/ref/heads/main")
        ref_object = ref_payload.get("object") if isinstance(ref_payload, Mapping) else None
        commit_sha = ref_object.get("sha") if isinstance(ref_object, Mapping) else None
        if not isinstance(commit_sha, str) or SHA40.fullmatch(commit_sha) is None:
            raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
        commit_payload = state_api.get(
            f"/repos/{STATE_REPOSITORY}/git/commits/{commit_sha}"
        )
        tree = commit_payload.get("tree") if isinstance(commit_payload, Mapping) else None
        tree_sha = tree.get("sha") if isinstance(tree, Mapping) else None
        if not isinstance(tree_sha, str) or SHA40.fullmatch(tree_sha) is None:
            raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
        result = {
            "repository_id": STATE_REPOSITORY_ID,
            "ref": STATE_REPOSITORY_REF,
            "commit_sha": commit_sha,
            "tree_sha": tree_sha,
            "digest_sha256": _state_observation_sha256(
                repository_id=STATE_REPOSITORY_ID,
                ref=STATE_REPOSITORY_REF,
                commit_sha=commit_sha,
                tree_sha=tree_sha,
            ),
        }
    except Exception as exc:
        primary_error = exc

    try:
        revocation_api = state_api if state_api is not None else api_factory(token, api_url)
        _, _, status = revocation_api.request_with_status(
            "DELETE", "/installation/token"
        )
        if status != 204:
            raise CurrentObservationError("STATE_OBSERVATION_TOKEN_REVOCATION_FAILED")
    except Exception as revoke_exc:
        raise CurrentObservationError("STATE_OBSERVATION_TOKEN_REVOCATION_FAILED") from (
            primary_error or revoke_exc
        )
    finally:
        token = ""

    if primary_error is not None:
        raise primary_error
    if result is None:
        raise CurrentObservationError("STATE_OBSERVATION_EVIDENCE_MISSING")
    return result


def run(
    values: MutableMapping[str, str] | None = None,
    *,
    api_factory: Callable[[str, str], GitHubAPI] = GitHubAPI,
    jwt_factory: Callable[[int, str], str] = create_app_jwt,
) -> dict[str, object]:
    env = os.environ if values is None else values
    context = _context(env)
    _load_recipient_certificate(env)
    api_url = env.get("GITHUB_API_URL", "https://api.github.com")

    policy = load_policy(env.get("PHASE2_POLICY", "policy/actors.json"))
    allocator = policy.get("allocator")
    if policy.get("control_repository") != CONTROL_REPOSITORY:
        raise CurrentObservationError("CONTROL_REPOSITORY_POLICY_MISMATCH")
    if not isinstance(allocator, Mapping):
        raise CurrentObservationError("ALLOCATOR_POLICY_INVALID")
    if allocator.get("owner") != CONTROL_OWNER:
        raise CurrentObservationError("ALLOCATOR_OWNER_POLICY_MISMATCH")
    if allocator.get("app_slug") != "gitstate-phase-2-allocator":
        raise CurrentObservationError("ALLOCATOR_APP_POLICY_MISMATCH")

    app_id_env = allocator.get("app_id_env")
    installation_id_env = allocator.get("installation_id_env")
    state_repository_id_env = policy.get("state_repository_id_env")
    if not all(
        isinstance(item, str) and item
        for item in (app_id_env, installation_id_env, state_repository_id_env)
    ):
        raise CurrentObservationError("ALLOCATOR_POLICY_INVALID")

    app_id = _required_positive_int(env, app_id_env)
    installation_id = _required_positive_int(env, installation_id_env)
    state_repository_id = _required_positive_int(env, state_repository_id_env)
    if state_repository_id != STATE_REPOSITORY_ID:
        raise CurrentObservationError("STATE_REPOSITORY_ID_MISMATCH")

    key_name = "PHASE2_ALLOCATOR_APP_PRIVATE_KEY"
    private_key = env.get(key_name, "")
    if not private_key:
        raise CurrentObservationError("ALLOCATOR_PRIVATE_KEY_MISSING")
    try:
        app_jwt = jwt_factory(app_id, private_key)
    finally:
        private_key = ""
        env.pop(key_name, None)
    if not isinstance(app_jwt, str) or not app_jwt:
        raise CurrentObservationError("ALLOCATOR_APP_JWT_MISSING")

    try:
        app_api = api_factory(app_jwt, api_url)
    finally:
        app_jwt = ""

    installation = verify_live_installation(
        app_api,
        CONTROL_OWNER,
        CONTROL_NAME,
        {
            "app_id": app_id,
            "installation_id": installation_id,
            "app_slug": allocator["app_slug"],
            "owner": allocator["owner"],
        },
    )
    repository_selection = installation.get("repository_selection")
    if repository_selection != "selected":
        raise CurrentObservationError("INVENTORY_INSTALLATION_NOT_SELECTED")

    def observe_interval(environment_api: GitHubAPI) -> dict[str, object]:
        environment_policy, policy_sha256 = _observe_environment_policy(
            environment_api
        )
        repository_ids = _observe_installation_inventory(
            app_api,
            installation_id=installation_id,
            api_url=api_url,
            api_factory=api_factory,
        )
        execution_variable = _observe_execution_variable(environment_api)
        state_baseline = _observe_state_baseline(
            app_api,
            installation_id=installation_id,
            api_url=api_url,
            api_factory=api_factory,
        )
        final_environment_policy, final_policy_sha256 = _observe_environment_policy(
            environment_api
        )
        if (
            final_policy_sha256 != policy_sha256
            or canonical_json(final_environment_policy)
            != canonical_json(environment_policy)
        ):
            raise CurrentObservationError("ENVIRONMENT_POLICY_MOVED")
        return {
            "environment_policy": environment_policy,
            "policy_sha256": policy_sha256,
            "repository_ids": list(repository_ids),
            "execution_variable": execution_variable,
            "state_baseline": state_baseline,
        }

    observed = _with_environment_observation_token(
        app_api,
        installation_id=installation_id,
        api_url=api_url,
        api_factory=api_factory,
        observe=observe_interval,
    )

    result = {
        "status": "GITSTATE_CURRENT_OBSERVATION_COMPLETE",
        "operation": context.operation,
        "run_id": context.run_id,
        "run_attempt": context.run_attempt,
        "trusted_sha": context.trusted_sha,
        "allocator_app": {
            "app_id": app_id,
            "installation_id": installation_id,
        },
        "installation_inventory": {
            "repository_selection": repository_selection,
            "selected_repository_ids": observed["repository_ids"],
        },
        "state_baseline": observed["state_baseline"],
        "permission_profile_sha256": PERMISSION_PROFILE_SHA256,
        "protected_environment": {
            "name": ENVIRONMENT_NAME,
            "policy": observed["environment_policy"],
            "policy_sha256": observed["policy_sha256"],
        },
        "execution_variable": observed["execution_variable"],
        "token_observation": {
            "inventory_token_permissions": dict(INVENTORY_PERMISSIONS),
            "environment_observation_token_permissions": dict(
                ENVIRONMENT_OBSERVATION_PERMISSIONS
            ),
            "state_observation_token_permissions": {
                "contents": "read",
                "metadata": "read",
            },
            "inventory_token_revoked": True,
            "environment_observation_token_revoked": True,
            "state_observation_token_revoked": True,
            "mutation_capable_tokens_minted": 0,
        },
        "authority_consumed": False,
        "canonical_state_mutated": False,
        "credential_material_emitted": False,
        "workstream_d_executed": False,
        "workstream_e_authorised": False,
    }
    try:
        canonical_json(result)
    except (TypeError, ValueError) as exc:
        raise CurrentObservationError("OBSERVATION_EVIDENCE_INVALID") from exc
    return result


def _seal_observation(
    payload: Mapping[str, object],
    recipient: RecipientCertificate,
) -> dict[str, object]:
    recipient.validate_binding()
    operation = payload.get("operation")
    run_id = payload.get("run_id")
    run_attempt = payload.get("run_attempt")
    trusted_sha = payload.get("trusted_sha")
    if (
        payload.get("status") != "GITSTATE_CURRENT_OBSERVATION_COMPLETE"
        or operation != "current_observation"
        or type(run_id) is not int
        or run_id <= 0
        or run_attempt != 1
        or not isinstance(trusted_sha, str)
        or SHA40.fullmatch(trusted_sha) is None
    ):
        raise CurrentObservationError("PRIVATE_OBSERVATION_IDENTITY_INVALID")
    recipient_pem = _run_openssl(
        ["x509", "-inform", "DER", "-outform", "PEM"],
        stdin=recipient.der,
        failure_code="RECIPIENT_CERTIFICATE_INVALID",
    ).stdout
    if not recipient_pem or len(recipient_pem) > MAX_RECIPIENT_CERTIFICATE_B64_CHARS:
        raise CurrentObservationError("RECIPIENT_CERTIFICATE_INVALID")
    plaintext = canonical_json(payload).encode("utf-8")
    if not plaintext or len(plaintext) > MAX_PRIVATE_OBSERVATION_BYTES:
        raise CurrentObservationError("PRIVATE_OBSERVATION_SIZE_INVALID")

    try:
        with tempfile.NamedTemporaryFile(
            mode="w+b", prefix="gitstate-recipient-", suffix=".pem"
        ) as certificate_file:
            certificate_file.write(recipient_pem)
            certificate_file.flush()
            encrypted = _run_openssl(
                [
                    "cms",
                    "-encrypt",
                    "-binary",
                    "-aes-256-gcm",
                    "-outform",
                    "DER",
                    "-recip",
                    certificate_file.name,
                ],
                stdin=plaintext,
                failure_code="OBSERVATION_ENCRYPTION_FAILED",
            )
    except OSError as exc:
        raise CurrentObservationError("OBSERVATION_ENCRYPTION_FAILED") from exc
    finally:
        plaintext = b""

    ciphertext = encrypted.stdout
    if not ciphertext or len(ciphertext) > MAX_CIPHERTEXT_BYTES:
        raise CurrentObservationError("OBSERVATION_CIPHERTEXT_SIZE_INVALID")
    ciphertext_b64 = base64.b64encode(ciphertext).decode("ascii")
    return {
        "status": "GITSTATE_CURRENT_OBSERVATION_ENVELOPE_COMPLETE",
        "contract_version": ENVELOPE_CONTRACT_VERSION,
        "operation": operation,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "trusted_sha": trusted_sha,
        "recipient_certificate_sha256": recipient.sha256,
        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
        "ciphertext_b64": ciphertext_b64,
        "authenticated_public_key_encryption": True,
        "one_use_recipient": True,
        "recipient_private_key_received": False,
        "private_observation_plaintext_emitted": False,
        "plaintext_temporary_file_created": False,
        "credential_material_emitted": False,
        "authority_consumed": False,
        "canonical_state_mutated": False,
        "workstream_d_executed": False,
        "workstream_e_authorised": False,
    }


def _blocked_payload(exc: Exception) -> dict[str, object]:
    payload: dict[str, object] = {
        "status": "BLOCKED",
        "reason_code": str(exc).split(":", 1)[0] or type(exc).__name__,
        "credential_material_emitted": False,
        "authority_consumed": False,
        "canonical_state_mutated": False,
        "workstream_d_executed": False,
        "workstream_e_authorised": False,
    }
    if isinstance(exc, GitHubAPIError):
        payload.update(exc.safe_diagnostic())
        payload["reason_code"] = (
            "READ_EVIDENCE_RATE_LIMITED"
            if exc.rate_limited
            else "READ_EVIDENCE_UNAVAILABLE"
        )
    return payload


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        print(
            canonical_json(
                _blocked_payload(CurrentObservationError("OBSERVATION_ARGUMENT_INVALID"))
            )
        )
        return 2
    try:
        recipient = _load_recipient_certificate(os.environ)
        payload = run()
        public_envelope = _seal_observation(payload, recipient)
    except Exception as exc:
        print(canonical_json(_blocked_payload(exc)))
        return 2
    print(canonical_json(public_envelope))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
