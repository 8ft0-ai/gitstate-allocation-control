from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Callable, Mapping, MutableMapping
from urllib.parse import quote

from . import workstream_d_live as live
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
    EXPECTED_REPOSITORY_IDS,
    INVENTORY_PERMISSIONS,
    InventoryProofError,
    STATE_REPOSITORY_ID,
    _list_complete_repository_ids,
    inventory_token_request,
    validate_inventory_token_response,
)
from .operator_manifest import SHA40, canonical_json
from .policy import load_policy
from .successor_runtime import (
    _environment_policy_material,
    environment_policy_sha256,
    state_observation_sha256,
)


CONTROL_REPOSITORY = "8ft0-ai/gitstate-allocation-control"
CONTROL_OWNER = "8ft0-ai"
CONTROL_NAME = "gitstate-allocation-control"
ENVIRONMENT_NAME = "phase-2-allocator"
EXECUTION_VARIABLE = "PHASE2_WORKSTREAM_D_EXECUTION_ENABLED"
STATE_REPOSITORY = live.STATE_REPOSITORY
STATE_REPOSITORY_REF = live.STATE_REPOSITORY_BASELINE_REF
MAX_VARIABLE_PAGES = 100
PERMISSION_PROFILE_SHA256 = (
    "e577e2ae1f3072a07de54b32c250e00cac492b4ae176ab485ff1d1157261942d"
)


class CurrentObservationError(RuntimeError):
    pass


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
        context = ObservationContext(
            repository=values["GITHUB_REPOSITORY"],
            ref=values["GITHUB_REF"],
            trusted_sha=values["GITHUB_SHA"],
            run_id=int(values["GITHUB_RUN_ID"]),
            run_attempt=int(values["GITHUB_RUN_ATTEMPT"]),
            operation=values["INPUT_OPERATION"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CurrentObservationError("OBSERVATION_CONTEXT_INCOMPLETE") from exc
    context.validate()
    return context


def _required_positive_int(values: Mapping[str, str], name: str) -> int:
    raw = values.get(name, "")
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise CurrentObservationError(f"{name}_INVALID") from exc
    if value <= 0:
        raise CurrentObservationError(f"{name}_INVALID")
    return value


def _control_api(
    values: Mapping[str, str],
    api_factory: Callable[[str, str], GitHubAPI],
) -> GitHubAPI:
    token = values.get("GITHUB_TOKEN", "")
    if not token:
        raise CurrentObservationError("READ_EVIDENCE_UNAVAILABLE")
    return api_factory(token, values.get("GITHUB_API_URL", "https://api.github.com"))


def _observe_environment_policy(api: GitHubAPI) -> tuple[Mapping[str, Any], str]:
    payload = api.get(
        f"/repos/{CONTROL_REPOSITORY}/environments/{quote(ENVIRONMENT_NAME, safe='')}"
    )
    if not isinstance(payload, Mapping):
        raise CurrentObservationError("READ_EVIDENCE_AMBIGUOUS")
    try:
        normalised = _environment_policy_material(payload, ENVIRONMENT_NAME)
        digest = environment_policy_sha256(payload, ENVIRONMENT_NAME)
    except Exception as exc:
        raise CurrentObservationError(str(exc).split(":", 1)[0]) from exc
    return normalised, digest


def _observe_execution_variable(api: GitHubAPI) -> dict[str, object]:
    expected_total: int | None = None
    observed_count = 0
    seen_names: set[str] = set()
    target_value: str | None = None
    target_seen = False

    for page in range(1, MAX_VARIABLE_PAGES + 1):
        payload = api.get(
            f"/repos/{CONTROL_REPOSITORY}/environments/"
            f"{quote(ENVIRONMENT_NAME, safe='')}/variables?per_page=100&page={page}"
        )
        if not isinstance(payload, Mapping):
            raise CurrentObservationError("EXECUTION_VARIABLE_EVIDENCE_AMBIGUOUS")
        total_count = payload.get("total_count")
        variables = payload.get("variables")
        if type(total_count) is not int or total_count < 0 or not isinstance(variables, list):
            raise CurrentObservationError("EXECUTION_VARIABLE_EVIDENCE_AMBIGUOUS")
        if expected_total is None:
            expected_total = total_count
        elif total_count != expected_total:
            raise CurrentObservationError("EXECUTION_VARIABLE_SET_CHANGED_DURING_PAGINATION")

        for item in variables:
            if not isinstance(item, Mapping):
                raise CurrentObservationError("EXECUTION_VARIABLE_EVIDENCE_AMBIGUOUS")
            name = item.get("name")
            value = item.get("value")
            if not isinstance(name, str) or not name or not isinstance(value, str):
                raise CurrentObservationError("EXECUTION_VARIABLE_EVIDENCE_AMBIGUOUS")
            if name in seen_names:
                raise CurrentObservationError("EXECUTION_VARIABLE_DUPLICATE_NAME")
            seen_names.add(name)
            observed_count += 1
            if name == EXECUTION_VARIABLE:
                target_seen = True
                target_value = value

        if observed_count > expected_total:
            raise CurrentObservationError("EXECUTION_VARIABLE_COUNT_MISMATCH")
        if observed_count == expected_total:
            break
        if len(variables) < 100:
            raise CurrentObservationError("EXECUTION_VARIABLE_PAGINATION_INCOMPLETE")
    else:
        raise CurrentObservationError("EXECUTION_VARIABLE_PAGINATION_EXCESSIVE")

    if expected_total is None or observed_count != expected_total:
        raise CurrentObservationError("EXECUTION_VARIABLE_PAGINATION_INCOMPLETE")
    if not target_seen:
        state = "not_defined"
    elif target_value == "":
        state = "defined_empty"
    else:
        state = "defined_non_empty"
    return {
        "name": EXECUTION_VARIABLE,
        "defined": target_seen,
        "state": state,
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
    inventory_api = api_factory(token, api_url)
    token = ""

    primary_error: Exception | None = None
    repository_ids: tuple[int, ...] | None = None
    try:
        validate_inventory_token_response(response)
        repository_ids = _list_complete_repository_ids(inventory_api)
        if repository_ids != EXPECTED_REPOSITORY_IDS:
            raise CurrentObservationError("INVENTORY_EXACT_SET_MISMATCH")
    except Exception as exc:
        primary_error = exc

    try:
        _, _, status = inventory_api.request_with_status(
            "DELETE", "/installation/token"
        )
        if status != 204:
            raise CurrentObservationError("INVENTORY_TOKEN_REVOCATION_STATUS_INVALID")
    except Exception as exc:
        raise CurrentObservationError("INVENTORY_TOKEN_REVOCATION_FAILED") from (
            primary_error or exc
        )

    if primary_error is not None:
        raise primary_error
    if repository_ids is None:
        raise CurrentObservationError("INVENTORY_EVIDENCE_MISSING")
    return repository_ids


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
    state_api = api_factory(token, api_url)
    token = ""

    primary_error: Exception | None = None
    result: dict[str, object] | None = None
    try:
        validate_token_response(response, profile)
        require_state_repository_access(
            state_api.token,
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
        digest = state_observation_sha256(
            repository_id=STATE_REPOSITORY_ID,
            ref=STATE_REPOSITORY_REF,
            commit_sha=commit_sha,
            tree_sha=tree_sha,
        )
        result = {
            "repository_id": STATE_REPOSITORY_ID,
            "ref": STATE_REPOSITORY_REF,
            "commit_sha": commit_sha,
            "tree_sha": tree_sha,
            "digest_sha256": digest,
        }
    except Exception as exc:
        primary_error = exc

    try:
        _, _, status = state_api.request_with_status("DELETE", "/installation/token")
        if status != 204:
            raise CurrentObservationError("STATE_OBSERVATION_TOKEN_REVOCATION_FAILED")
    except Exception as exc:
        raise CurrentObservationError("STATE_OBSERVATION_TOKEN_REVOCATION_FAILED") from (
            primary_error or exc
        )

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
    api_url = env.get("GITHUB_API_URL", "https://api.github.com")

    policy = load_policy(env.get("PHASE2_POLICY", "policy/actors.json"))
    if policy.get("control_repository") != CONTROL_REPOSITORY:
        raise CurrentObservationError("CONTROL_REPOSITORY_POLICY_MISMATCH")
    if policy.get("allocator", {}).get("owner") != CONTROL_OWNER:
        raise CurrentObservationError("ALLOCATOR_OWNER_POLICY_MISMATCH")
    if policy.get("allocator", {}).get("app_slug") != "gitstate-phase-2-allocator":
        raise CurrentObservationError("ALLOCATOR_APP_POLICY_MISMATCH")

    allocator = policy["allocator"]
    app_id = _required_positive_int(env, str(allocator["app_id_env"]))
    installation_id = _required_positive_int(env, str(allocator["installation_id_env"]))
    state_repository_id = _required_positive_int(env, str(policy["state_repository_id_env"]))
    if state_repository_id != STATE_REPOSITORY_ID:
        raise CurrentObservationError("STATE_REPOSITORY_ID_MISMATCH")

    control_api = _control_api(env, api_factory)
    environment_policy, policy_sha256 = _observe_environment_policy(control_api)
    execution_variable = _observe_execution_variable(control_api)

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

    app_api = api_factory(app_jwt, api_url)
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

    repository_ids = _observe_installation_inventory(
        app_api,
        installation_id=installation_id,
        api_url=api_url,
        api_factory=api_factory,
    )
    state_baseline = _observe_state_baseline(
        app_api,
        installation_id=installation_id,
        api_url=api_url,
        api_factory=api_factory,
    )
    app_jwt = ""

    return {
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
            "selected_repository_ids": list(repository_ids),
        },
        "state_baseline": state_baseline,
        "permission_profile_sha256": PERMISSION_PROFILE_SHA256,
        "protected_environment": {
            "name": ENVIRONMENT_NAME,
            "policy": environment_policy,
            "policy_sha256": policy_sha256,
        },
        "execution_variable": execution_variable,
        "token_observation": {
            "inventory_token_permissions": dict(INVENTORY_PERMISSIONS),
            "state_observation_token_permissions": {
                "contents": "read",
                "metadata": "read",
            },
            "inventory_token_revoked": True,
            "state_observation_token_revoked": True,
            "mutation_capable_tokens_minted": 0,
        },
        "authority_consumed": False,
        "canonical_state_mutated": False,
        "credential_material_emitted": False,
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
        print(canonical_json(_blocked_payload(CurrentObservationError("OBSERVATION_ARGUMENT_INVALID"))))
        return 2
    try:
        payload = run()
    except Exception as exc:
        print(canonical_json(_blocked_payload(exc)))
        return 2
    print(canonical_json(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
