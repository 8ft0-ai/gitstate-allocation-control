from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import quote

from .governance_state import (
    GovernanceHistory,
    GuardedExecutionManifest,
    build_governance_history,
    parse_guarded_execution_manifest,
)
from .github_api import GitHubAPI, GitHubAPIError
from .operator_guard import GuardObservation, GuardResult, OwnerObservation, evaluate_guards
from .operator_manifest import (
    GOVERNANCE_OWNER,
    SHA40,
    SHA256,
    HistoryBaseline,
    ModuleBlob,
    OperatorContractError,
    canonical_json,
    operator_history_baseline,
    parse_governance_comments,
    parse_v1_operator_history,
    sha256_text,
)


CONTROL_REPOSITORY = "8ft0-ai/gitstate-allocation-control"
PROJECTION_ISSUE_NUMBER = 28
OPERATOR_HISTORY_ISSUE_NUMBER = 17
WORKFLOW_FILENAME = "phase2-adversarial.yml"
WORKFLOW_PATH = ".github/workflows/phase2-adversarial.yml"
PROJECTION_OWNER = "8ft0-ai"
PROJECTION_CONTRACT = "gitstate-preflight-projection/v1"
PROJECTION_PREFIX = "/gitstate-preflight-projection-v1 "
INVALIDATION_CONTRACT = "gitstate-public-invalidation/v1"
INVALIDATION_PREFIX = "/gitstate-public-invalidation-v1 "
OPAQUE_ID = re.compile(r"^[0-9a-f]{32,64}$")

PROJECTION_FIELDS = frozenset(
    {
        "contract",
        "projection_id",
        "manifest_comment_id",
        "manifest_sha256",
        "manifest",
        "governance_sources",
        "observation",
        "execution_authorised",
        "workstream_e_authorised",
    }
)
GOVERNANCE_SOURCE_FIELDS = frozenset(
    {"comment_id", "body", "owner", "created_at", "updated_at"}
)
OBSERVATION_FIELDS = frozenset(
    {
        "protocol_sha",
        "state_commit_sha",
        "state_digest_sha256",
        "app_id",
        "installation_id",
        "repository_selection",
        "selected_repository_ids",
        "permission_profile_sha256",
        "owner_observation",
        "environment_name",
        "environment_policy_sha256",
        "execution_variable",
    }
)
COMMENT_BINDING_FIELDS = frozenset({"comment_id", "body_sha256"})
OPTIONAL_BINDING_DISABLED_FIELDS = frozenset({"required"})
OPTIONAL_BINDING_ENABLED_FIELDS = frozenset({"required", "comment_id", "body_sha256"})
INVALIDATION_FIELDS = frozenset(
    {
        "contract",
        "invalidation_id",
        "manifest_sha256",
        "projection",
        "authority",
        "manifest_approval",
        "reason",
        "execution_authorised",
        "workstream_e_authorised",
    }
)
OWNER_OBSERVATION_DISABLED_FIELDS = frozenset({"required"})
OWNER_OBSERVATION_ENABLED_FIELDS = frozenset(
    {"required", "observation_id", "observation_sha256", "valid"}
)


class PreflightProjectionError(RuntimeError):
    pass


def _duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PreflightProjectionError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_float(_: str) -> float:
    raise PreflightProjectionError("FLOAT_NOT_SUPPORTED")


def _reject_constant(_: str) -> float:
    raise PreflightProjectionError("NONFINITE_NUMBER_NOT_SUPPORTED")


def _require_supported_json(value: Any) -> None:
    if value is None or isinstance(value, float):
        raise PreflightProjectionError("UNSUPPORTED_JSON_VALUE")
    if isinstance(value, (str, bool)) or type(value) is int:
        return
    if isinstance(value, list):
        for item in value:
            _require_supported_json(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise PreflightProjectionError("UNSUPPORTED_JSON_VALUE")
            _require_supported_json(item)
        return
    raise PreflightProjectionError("UNSUPPORTED_JSON_VALUE")


def _strict_json(raw: str, reason: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_duplicate_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except PreflightProjectionError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise PreflightProjectionError(reason) from exc
    if not isinstance(value, dict):
        raise PreflightProjectionError(reason)
    _require_supported_json(value)
    if raw != canonical_json(value):
        raise PreflightProjectionError("NONCANONICAL_JSON")
    return value


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _require_exact_keys(value: Mapping[str, Any], expected: frozenset[str], reason: str) -> None:
    if frozenset(value) != expected:
        raise PreflightProjectionError(reason)


def _require_string(value: Any, reason: str) -> str:
    if not isinstance(value, str) or not value:
        raise PreflightProjectionError(reason)
    return value


def _require_int(value: Any, reason: str, *, minimum: int = 1) -> int:
    if type(value) is not int or value < minimum:
        raise PreflightProjectionError(reason)
    return value


def _require_hex(value: Any, pattern: re.Pattern[str], reason: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise PreflightProjectionError(reason)
    return value


def _require_false(value: Any, reason: str) -> None:
    if value is not False:
        raise PreflightProjectionError(reason)


def _parse_time(value: Any, reason: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PreflightProjectionError(reason)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PreflightProjectionError(reason) from exc
    if parsed.tzinfo is None:
        raise PreflightProjectionError(reason)
    return parsed.astimezone(timezone.utc)


def _comment_identity(comment: Mapping[str, Any], *, owner: str, reason: str) -> tuple[int, str, str]:
    comment_id = _require_int(comment.get("id"), reason)
    body = comment.get("body")
    if not isinstance(body, str):
        raise PreflightProjectionError(reason)
    user = comment.get("user")
    if not isinstance(user, Mapping) or user.get("login") != owner:
        raise PreflightProjectionError(f"{reason}_WRONG_OWNER")
    created = comment.get("created_at")
    updated = comment.get("updated_at")
    _parse_time(created, f"{reason}_TIME_INVALID")
    _parse_time(updated, f"{reason}_TIME_INVALID")
    if created != updated:
        raise PreflightProjectionError(f"{reason}_SOURCE_EDITED")
    return comment_id, body, sha256_text(body)


def _parse_owner_observation(value: Any) -> OwnerObservation | None:
    if not isinstance(value, dict) or "required" not in value:
        raise PreflightProjectionError("PREFLIGHT_OWNER_OBSERVATION_INVALID")
    if value.get("required") is False:
        _require_exact_keys(
            value,
            OWNER_OBSERVATION_DISABLED_FIELDS,
            "PREFLIGHT_OWNER_OBSERVATION_INVALID",
        )
        return None
    if value.get("required") is True:
        _require_exact_keys(
            value,
            OWNER_OBSERVATION_ENABLED_FIELDS,
            "PREFLIGHT_OWNER_OBSERVATION_INVALID",
        )
        observation_id = _require_string(
            value.get("observation_id"), "PREFLIGHT_OWNER_OBSERVATION_INVALID"
        )
        observation_sha256 = _require_hex(
            value.get("observation_sha256"),
            SHA256,
            "PREFLIGHT_OWNER_OBSERVATION_INVALID",
        )
        valid = value.get("valid")
        if type(valid) is not bool:
            raise PreflightProjectionError("PREFLIGHT_OWNER_OBSERVATION_INVALID")
        return OwnerObservation(observation_id, observation_sha256, valid)
    raise PreflightProjectionError("PREFLIGHT_OWNER_OBSERVATION_INVALID")


def _validate_bound_observation(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise PreflightProjectionError("PREFLIGHT_OBSERVATION_INVALID")
    _require_exact_keys(value, OBSERVATION_FIELDS, "PREFLIGHT_OBSERVATION_INVALID")
    for key in ("protocol_sha", "state_commit_sha"):
        _require_hex(value.get(key), SHA40, "PREFLIGHT_OBSERVATION_INVALID")
    for key in ("state_digest_sha256", "permission_profile_sha256", "environment_policy_sha256"):
        _require_hex(value.get(key), SHA256, "PREFLIGHT_OBSERVATION_INVALID")
    _require_int(value.get("app_id"), "PREFLIGHT_OBSERVATION_INVALID")
    _require_int(value.get("installation_id"), "PREFLIGHT_OBSERVATION_INVALID")
    if value.get("repository_selection") != "selected":
        raise PreflightProjectionError("PREFLIGHT_OBSERVATION_INVALID")
    repository_ids = value.get("selected_repository_ids")
    if (
        not isinstance(repository_ids, list)
        or not repository_ids
        or any(type(item) is not int or item <= 0 for item in repository_ids)
        or repository_ids != sorted(repository_ids)
        or len(repository_ids) != len(set(repository_ids))
    ):
        raise PreflightProjectionError("PREFLIGHT_OBSERVATION_INVALID")
    _parse_owner_observation(value.get("owner_observation"))
    _require_string(value.get("environment_name"), "PREFLIGHT_OBSERVATION_INVALID")
    _require_string(value.get("execution_variable"), "PREFLIGHT_OBSERVATION_INVALID")
    return _freeze(value)


def _source_comment(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PreflightProjectionError("PREFLIGHT_GOVERNANCE_SOURCE_INVALID")
    _require_exact_keys(
        value,
        GOVERNANCE_SOURCE_FIELDS,
        "PREFLIGHT_GOVERNANCE_SOURCE_INVALID",
    )
    comment_id = _require_int(value.get("comment_id"), "PREFLIGHT_GOVERNANCE_SOURCE_INVALID")
    body = _require_string(value.get("body"), "PREFLIGHT_GOVERNANCE_SOURCE_INVALID")
    owner = _require_string(value.get("owner"), "PREFLIGHT_GOVERNANCE_SOURCE_INVALID")
    created_at = _require_string(value.get("created_at"), "PREFLIGHT_GOVERNANCE_SOURCE_INVALID")
    updated_at = _require_string(value.get("updated_at"), "PREFLIGHT_GOVERNANCE_SOURCE_INVALID")
    return {
        "id": comment_id,
        "body": body,
        "user": {"login": owner},
        "created_at": created_at,
        "updated_at": updated_at,
    }


@dataclass(frozen=True)
class PreflightProjection:
    payload: Mapping[str, Any]
    comment_id: int
    body_sha256: str
    manifest: GuardedExecutionManifest
    governance_history: GovernanceHistory
    bound_observation: Mapping[str, Any]

    @property
    def projection_id(self) -> str:
        return str(self.payload["projection_id"])

    @property
    def manifest_sha256(self) -> str:
        return str(self.payload["manifest_sha256"])


@dataclass(frozen=True)
class PublicInvalidation:
    payload: Mapping[str, Any]
    comment_id: int
    body_sha256: str

    @property
    def invalidation_id(self) -> str:
        return str(self.payload["invalidation_id"])

    @property
    def manifest_sha256(self) -> str:
        return str(self.payload["manifest_sha256"])


def parse_projection_comment(
    comment: Mapping[str, Any],
    *,
    expected_body_sha256: str | None = None,
) -> PreflightProjection | None:
    body = comment.get("body")
    if not isinstance(body, str):
        raise PreflightProjectionError("PREFLIGHT_PROJECTION_COMMENT_INVALID")
    reserved_like = body.startswith("/gitstate-preflight-projection-v1")
    if not reserved_like:
        return None
    if not body.startswith(PROJECTION_PREFIX) or "\n" in body:
        raise PreflightProjectionError("PREFLIGHT_PROJECTION_RESERVED_RECORD_INVALID")

    comment_id, body, body_sha256 = _comment_identity(
        comment,
        owner=PROJECTION_OWNER,
        reason="PREFLIGHT_PROJECTION",
    )
    if expected_body_sha256 is not None:
        _require_hex(
            expected_body_sha256,
            SHA256,
            "PREFLIGHT_PROJECTION_EXPECTED_DIGEST_INVALID",
        )
        if body_sha256 != expected_body_sha256:
            raise PreflightProjectionError("PREFLIGHT_PROJECTION_BODY_DIGEST_MISMATCH")

    value = _strict_json(
        body[len(PROJECTION_PREFIX) :],
        "PREFLIGHT_PROJECTION_JSON_INVALID",
    )
    _require_exact_keys(value, PROJECTION_FIELDS, "PREFLIGHT_PROJECTION_SCHEMA_MISMATCH")
    if value.get("contract") != PROJECTION_CONTRACT:
        raise PreflightProjectionError("PREFLIGHT_PROJECTION_CONTRACT_MISMATCH")
    _require_hex(value.get("projection_id"), OPAQUE_ID, "PREFLIGHT_PROJECTION_ID_INVALID")
    _require_int(value.get("manifest_comment_id"), "PREFLIGHT_MANIFEST_COMMENT_INVALID")
    manifest_sha256 = _require_hex(
        value.get("manifest_sha256"), SHA256, "PREFLIGHT_MANIFEST_DIGEST_INVALID"
    )
    _require_false(value.get("execution_authorised"), "PREFLIGHT_EXECUTION_AUTHORITY_INVALID")
    _require_false(value.get("workstream_e_authorised"), "WORKSTREAM_E_NOT_AUTHORISED")

    manifest_value = value.get("manifest")
    if not isinstance(manifest_value, dict):
        raise PreflightProjectionError("PREFLIGHT_MANIFEST_INVALID")
    try:
        manifest = parse_guarded_execution_manifest(
            canonical_json(manifest_value),
            expected_sha256=manifest_sha256,
        )
    except OperatorContractError as exc:
        raise PreflightProjectionError(str(exc)) from exc

    source_values = value.get("governance_sources")
    if not isinstance(source_values, list) or not source_values:
        raise PreflightProjectionError("PREFLIGHT_GOVERNANCE_HISTORY_INVALID")
    source_comments = [_source_comment(item) for item in source_values]
    try:
        records = parse_governance_comments(
            source_comments,
            expected_owner=GOVERNANCE_OWNER,
            expected_issue=manifest.governing_issue,
        )
        governance_history = build_governance_history(manifest.sha256, records)
    except (OperatorContractError, RuntimeError, TypeError, ValueError, KeyError) as exc:
        raise PreflightProjectionError("PREFLIGHT_GOVERNANCE_HISTORY_INVALID") from exc

    bound_observation = _validate_bound_observation(value.get("observation"))
    return PreflightProjection(
        _freeze(value),
        comment_id,
        body_sha256,
        manifest,
        governance_history,
        bound_observation,
    )


def _parse_comment_binding(value: Any, reason: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise PreflightProjectionError(reason)
    _require_exact_keys(value, COMMENT_BINDING_FIELDS, reason)
    _require_int(value.get("comment_id"), reason)
    _require_hex(value.get("body_sha256"), SHA256, reason)
    return _freeze(value)


def _parse_optional_binding(value: Any, reason: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or "required" not in value:
        raise PreflightProjectionError(reason)
    if value.get("required") is False:
        _require_exact_keys(value, OPTIONAL_BINDING_DISABLED_FIELDS, reason)
        return _freeze(value)
    if value.get("required") is True:
        _require_exact_keys(value, OPTIONAL_BINDING_ENABLED_FIELDS, reason)
        _require_int(value.get("comment_id"), reason)
        _require_hex(value.get("body_sha256"), SHA256, reason)
        return _freeze(value)
    raise PreflightProjectionError(reason)


def parse_invalidation_comment(comment: Mapping[str, Any]) -> PublicInvalidation | None:
    body = comment.get("body")
    if not isinstance(body, str):
        raise PreflightProjectionError("PUBLIC_INVALIDATION_COMMENT_INVALID")
    reserved_like = body.startswith("/gitstate-public-invalidation-v1")
    if not reserved_like:
        return None
    if not body.startswith(INVALIDATION_PREFIX) or "\n" in body:
        raise PreflightProjectionError("PUBLIC_INVALIDATION_RESERVED_RECORD_INVALID")

    comment_id, body, body_sha256 = _comment_identity(
        comment,
        owner=PROJECTION_OWNER,
        reason="PUBLIC_INVALIDATION",
    )
    value = _strict_json(
        body[len(INVALIDATION_PREFIX) :],
        "PUBLIC_INVALIDATION_JSON_INVALID",
    )
    _require_exact_keys(value, INVALIDATION_FIELDS, "PUBLIC_INVALIDATION_SCHEMA_MISMATCH")
    if value.get("contract") != INVALIDATION_CONTRACT:
        raise PreflightProjectionError("PUBLIC_INVALIDATION_CONTRACT_MISMATCH")
    _require_hex(value.get("invalidation_id"), OPAQUE_ID, "PUBLIC_INVALIDATION_ID_INVALID")
    _require_hex(value.get("manifest_sha256"), SHA256, "PUBLIC_INVALIDATION_SUBJECT_INVALID")
    _parse_comment_binding(value.get("projection"), "PUBLIC_INVALIDATION_SUBJECT_INVALID")
    _parse_optional_binding(value.get("authority"), "PUBLIC_INVALIDATION_SUBJECT_INVALID")
    _parse_optional_binding(value.get("manifest_approval"), "PUBLIC_INVALIDATION_SUBJECT_INVALID")
    _require_string(value.get("reason"), "PUBLIC_INVALIDATION_REASON_INVALID")
    _require_false(value.get("execution_authorised"), "PUBLIC_INVALIDATION_AUTHORITY_INVALID")
    _require_false(value.get("workstream_e_authorised"), "WORKSTREAM_E_NOT_AUTHORISED")
    return PublicInvalidation(_freeze(value), comment_id, body_sha256)


def parse_projection_history(
    comments: Sequence[Mapping[str, Any]],
    *,
    expected_projection_comment_id: int,
    expected_projection_body_sha256: str,
) -> tuple[PreflightProjection, tuple[PublicInvalidation, ...]]:
    expected_projection_comment_id = _require_int(
        expected_projection_comment_id,
        "PREFLIGHT_PROJECTION_COMMENT_ID_INVALID",
    )
    _require_hex(
        expected_projection_body_sha256,
        SHA256,
        "PREFLIGHT_PROJECTION_EXPECTED_DIGEST_INVALID",
    )

    projection: PreflightProjection | None = None
    projection_ids: set[str] = set()
    manifest_projection_counts: dict[str, int] = {}
    invalidations: list[PublicInvalidation] = []
    invalidation_ids: set[str] = set()
    seen_comment_ids: set[int] = set()

    for comment in comments:
        comment_id = comment.get("id")
        if type(comment_id) is int:
            if comment_id in seen_comment_ids:
                raise PreflightProjectionError("PREFLIGHT_HISTORY_DUPLICATE_COMMENT")
            seen_comment_ids.add(comment_id)

        parsed_projection = parse_projection_comment(
            comment,
            expected_body_sha256=(
                expected_projection_body_sha256
                if comment_id == expected_projection_comment_id
                else None
            ),
        )
        if parsed_projection is not None:
            if parsed_projection.projection_id in projection_ids:
                raise PreflightProjectionError("PREFLIGHT_PROJECTION_AMBIGUOUS")
            projection_ids.add(parsed_projection.projection_id)
            manifest_projection_counts[parsed_projection.manifest_sha256] = (
                manifest_projection_counts.get(parsed_projection.manifest_sha256, 0) + 1
            )
            if parsed_projection.comment_id == expected_projection_comment_id:
                projection = parsed_projection
            continue

        invalidation = parse_invalidation_comment(comment)
        if invalidation is not None:
            if invalidation.invalidation_id in invalidation_ids:
                raise PreflightProjectionError("PUBLIC_INVALIDATION_AMBIGUOUS")
            invalidation_ids.add(invalidation.invalidation_id)
            invalidations.append(invalidation)

    if projection is None:
        raise PreflightProjectionError("PREFLIGHT_PROJECTION_NOT_FOUND")
    if manifest_projection_counts.get(projection.manifest_sha256, 0) != 1:
        raise PreflightProjectionError("PREFLIGHT_PROJECTION_AMBIGUOUS")

    return projection, tuple(sorted(invalidations, key=lambda item: item.comment_id))


def _matching_invalidation(
    projection: PreflightProjection,
    invalidations: Sequence[PublicInvalidation],
) -> PublicInvalidation | None:
    for invalidation in invalidations:
        subject = invalidation.payload["projection"]
        same_comment = int(subject["comment_id"]) == projection.comment_id
        same_body = str(subject["body_sha256"]) == projection.body_sha256
        same_manifest = invalidation.manifest_sha256 == projection.manifest_sha256
        if same_comment and (not same_body or not same_manifest):
            raise PreflightProjectionError("PUBLIC_INVALIDATION_SUBJECT_MISMATCH")
        if same_comment and same_body and same_manifest:
            return invalidation
    return None


def _list_issue_comments(api: GitHubAPI, issue_number: int) -> list[dict[str, Any]]:
    comments: list[dict[str, Any]] = []
    for page in range(1, 101):
        payload = api.get(
            f"/repos/{CONTROL_REPOSITORY}/issues/{issue_number}/comments"
            f"?per_page=100&page={page}"
        )
        if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
            raise PreflightProjectionError("READ_EVIDENCE_AMBIGUOUS")
        comments.extend(payload)
        if len(payload) < 100:
            return comments
    raise PreflightProjectionError("READ_EVIDENCE_AMBIGUOUS")


def _control_identity(
    api: GitHubAPI,
    manifest: GuardedExecutionManifest,
    *,
    trusted_sha: str,
) -> tuple[str, str, tuple[ModuleBlob, ...]]:
    commit = api.get(f"/repos/{CONTROL_REPOSITORY}/commits/{trusted_sha}")
    if not isinstance(commit, dict):
        raise PreflightProjectionError("READ_EVIDENCE_AMBIGUOUS")
    commit_value = commit.get("commit")
    tree = commit_value.get("tree") if isinstance(commit_value, dict) else None
    tree_sha = tree.get("sha") if isinstance(tree, dict) else None
    if not isinstance(tree_sha, str) or SHA40.fullmatch(tree_sha) is None:
        raise PreflightProjectionError("READ_EVIDENCE_AMBIGUOUS")

    workflow = api.get(
        f"/repos/{CONTROL_REPOSITORY}/contents/{quote(WORKFLOW_PATH, safe='/')}?ref={trusted_sha}"
    )
    workflow_sha = workflow.get("sha") if isinstance(workflow, dict) else None
    if not isinstance(workflow_sha, str) or SHA40.fullmatch(workflow_sha) is None:
        raise PreflightProjectionError("READ_EVIDENCE_AMBIGUOUS")

    module_blobs: list[ModuleBlob] = []
    for expected in manifest.module_blobs:
        value = api.get(
            f"/repos/{CONTROL_REPOSITORY}/contents/{quote(expected.path, safe='/')}?ref={trusted_sha}"
        )
        blob_sha = value.get("sha") if isinstance(value, dict) else None
        if not isinstance(blob_sha, str) or SHA40.fullmatch(blob_sha) is None:
            raise PreflightProjectionError("READ_EVIDENCE_AMBIGUOUS")
        module_blobs.append(ModuleBlob(expected.path, blob_sha))
    return tree_sha, workflow_sha, tuple(module_blobs)


def _operator_history(api: GitHubAPI) -> HistoryBaseline:
    comments = _list_issue_comments(api, OPERATOR_HISTORY_ISSUE_NUMBER)
    try:
        records = parse_v1_operator_history(comments)
        return operator_history_baseline(records)
    except OperatorContractError as exc:
        raise PreflightProjectionError("OPERATOR_HISTORY_CHANGED") from exc


def _list_workflow_runs(api: GitHubAPI) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for page in range(1, 101):
        payload = api.get(
            f"/repos/{CONTROL_REPOSITORY}/actions/workflows/{WORKFLOW_FILENAME}/runs"
            f"?event=workflow_dispatch&per_page=100&page={page}"
        )
        values = payload.get("workflow_runs") if isinstance(payload, dict) else None
        if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
            raise PreflightProjectionError("READ_EVIDENCE_AMBIGUOUS")
        runs.extend(values)
        if len(values) < 100:
            return runs
    raise PreflightProjectionError("READ_EVIDENCE_AMBIGUOUS")


def validate_preflight_workflow_suffix(
    api: GitHubAPI,
    baseline: HistoryBaseline,
    *,
    run_id: int,
    run_attempt: int,
    trusted_sha: str,
) -> None:
    if run_attempt != 1:
        raise PreflightProjectionError("OPERATOR_RERUN_FORBIDDEN")
    runs = _list_workflow_runs(api)
    suffix = [run for run in runs if type(run.get("id")) is int and int(run["id"]) > baseline.through_id]
    if len(suffix) != 1:
        raise PreflightProjectionError("WORKFLOW_HISTORY_CHANGED")
    current = suffix[0]
    if (
        current.get("id") != run_id
        or current.get("run_attempt") != 1
        or current.get("head_sha") != trusted_sha
        or current.get("event") != "workflow_dispatch"
    ):
        raise PreflightProjectionError("WORKFLOW_HISTORY_CHANGED")


def _guard_observation(
    projection: PreflightProjection,
    api: GitHubAPI,
    *,
    trusted_sha: str,
    evaluated_at: datetime,
    execution_variable_absent: bool,
) -> GuardObservation:
    tree_sha, workflow_sha, module_blobs = _control_identity(
        api,
        projection.manifest,
        trusted_sha=trusted_sha,
    )
    operator_history = _operator_history(api)
    bound = projection.bound_observation
    owner_observation = _parse_owner_observation(dict(bound["owner_observation"]))
    return GuardObservation(
        stage="preflight",
        read_status="complete",
        evaluated_at=evaluated_at,
        operation=projection.manifest.operation,
        control_repository=CONTROL_REPOSITORY,
        control_commit_sha=trusted_sha,
        control_tree_sha=tree_sha,
        workflow_blob_sha=workflow_sha,
        module_blobs=module_blobs,
        protocol_sha=str(bound["protocol_sha"]),
        state_commit_sha=str(bound["state_commit_sha"]),
        state_digest_sha256=str(bound["state_digest_sha256"]),
        operator_history=operator_history,
        workflow_history=projection.manifest.workflow_history,
        app_id=int(bound["app_id"]),
        installation_id=int(bound["installation_id"]),
        repository_selection=str(bound["repository_selection"]),
        selected_repository_ids=tuple(int(item) for item in bound["selected_repository_ids"]),
        permission_profile_sha256=str(bound["permission_profile_sha256"]),
        owner_observation=owner_observation,
        environment_name=str(bound["environment_name"]),
        environment_policy_sha256=str(bound["environment_policy_sha256"]),
        execution_variable=str(bound["execution_variable"]),
        execution_variable_absent=execution_variable_absent,
        governance_history=projection.governance_history,
    )


def _evidence(
    projection: PreflightProjection,
    result: GuardResult,
    *,
    run_id: int,
    run_attempt: int,
    trusted_sha: str,
) -> dict[str, object]:
    return {
        "status": "GITSTATE_PREFLIGHT_PASS" if result.passed else "GITSTATE_PREFLIGHT_BLOCKED",
        "run_id": run_id,
        "run_attempt": run_attempt,
        "trusted_sha": trusted_sha,
        "projection_comment_id": projection.comment_id,
        "projection_body_sha256": projection.body_sha256,
        "manifest_sha256": projection.manifest_sha256,
        "guard_passed": result.passed,
        "guard_code": result.code,
        "guard_category": result.category,
        "execution_authorised": False,
        "control_state_tokens_minted": 0,
        "canonical_state_mutated": False,
        "workstream_d_scenarios_executed": 0,
        "workstream_e_authorised": False,
    }


def run_preflight(
    values: Mapping[str, str] | None = None,
    *,
    api_factory: Callable[[str, str], GitHubAPI] = GitHubAPI,
    now: datetime | None = None,
) -> dict[str, object]:
    env = os.environ if values is None else values
    try:
        repository = env["GITHUB_REPOSITORY"]
        ref = env["GITHUB_REF"]
        trusted_sha = env["GITHUB_SHA"]
        run_id = int(env["GITHUB_RUN_ID"])
        run_attempt = int(env["GITHUB_RUN_ATTEMPT"])
        token = env["GITHUB_TOKEN"]
        projection_comment_id = int(env["PREFLIGHT_PROJECTION_COMMENT_ID"])
        expected_body_sha256 = env["PREFLIGHT_PROJECTION_BODY_SHA256"]
    except (KeyError, TypeError, ValueError) as exc:
        raise PreflightProjectionError("PREFLIGHT_CONTEXT_INCOMPLETE") from exc

    if repository != CONTROL_REPOSITORY:
        raise PreflightProjectionError("OPERATOR_REPOSITORY_MISMATCH")
    if ref != "refs/heads/main":
        raise PreflightProjectionError("OPERATOR_PROTECTED_MAIN_REQUIRED")
    _require_hex(trusted_sha, SHA40, "OPERATOR_TRUSTED_SHA_INVALID")
    _require_int(run_id, "OPERATOR_RUN_INVALID")
    _require_int(run_attempt, "OPERATOR_RUN_INVALID")
    _require_string(token, "READ_EVIDENCE_UNAVAILABLE")
    _require_int(projection_comment_id, "PREFLIGHT_PROJECTION_COMMENT_ID_INVALID")
    _require_hex(
        expected_body_sha256,
        SHA256,
        "PREFLIGHT_PROJECTION_EXPECTED_DIGEST_INVALID",
    )

    api = api_factory(token, env.get("GITHUB_API_URL", "https://api.github.com"))
    comments = _list_issue_comments(api, PROJECTION_ISSUE_NUMBER)
    projection, invalidations = parse_projection_history(
        comments,
        expected_projection_comment_id=projection_comment_id,
        expected_projection_body_sha256=expected_body_sha256,
    )

    if _matching_invalidation(projection, invalidations) is not None:
        result = GuardResult.failure("GOVERNANCE_SUPERSEDED")
        record = _evidence(
            projection,
            result,
            run_id=run_id,
            run_attempt=run_attempt,
            trusted_sha=trusted_sha,
        )
        print(json.dumps(record, sort_keys=True, separators=(",", ":")))
        return record

    validate_preflight_workflow_suffix(
        api,
        projection.manifest.workflow_history,
        run_id=run_id,
        run_attempt=run_attempt,
        trusted_sha=trusted_sha,
    )

    execution_variable = str(projection.bound_observation["execution_variable"])
    execution_variable_absent = env.get(execution_variable, "") == ""
    evaluated_at = now or datetime.now(timezone.utc)
    if evaluated_at.tzinfo is None:
        raise PreflightProjectionError("PREFLIGHT_TIME_INVALID")
    evaluated_at = evaluated_at.astimezone(timezone.utc)
    observation = _guard_observation(
        projection,
        api,
        trusted_sha=trusted_sha,
        evaluated_at=evaluated_at,
        execution_variable_absent=execution_variable_absent,
    )
    result = evaluate_guards(projection.manifest, observation)
    record = _evidence(
        projection,
        result,
        run_id=run_id,
        run_attempt=run_attempt,
        trusted_sha=trusted_sha,
    )
    print(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return record


def _blocked_payload(exc: Exception) -> dict[str, object]:
    if isinstance(exc, GitHubAPIError):
        reason = "READ_EVIDENCE_RATE_LIMITED" if exc.rate_limited else "READ_EVIDENCE_UNAVAILABLE"
        payload: dict[str, object] = {
            "status": "GITSTATE_PREFLIGHT_BLOCKED",
            "reason_code": reason,
            "execution_authorised": False,
            "credential_material_emitted": False,
            "control_state_tokens_minted": 0,
            "canonical_state_mutated": False,
            "workstream_d_scenarios_executed": 0,
            "workstream_e_authorised": False,
        }
        payload.update(exc.safe_diagnostic())
        return payload
    return {
        "status": "GITSTATE_PREFLIGHT_BLOCKED",
        "reason_code": str(exc).split(":", 1)[0] or type(exc).__name__,
        "execution_authorised": False,
        "credential_material_emitted": False,
        "control_state_tokens_minted": 0,
        "canonical_state_mutated": False,
        "workstream_d_scenarios_executed": 0,
        "workstream_e_authorised": False,
    }


def main() -> int:
    try:
        if len(sys.argv) != 2 or sys.argv[1] != "preflight":
            raise PreflightProjectionError("PREFLIGHT_COMMAND_REQUIRED")
        record = run_preflight()
        return 0 if record.get("guard_passed") is True else 1
    except Exception as exc:
        print(json.dumps(_blocked_payload(exc), sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
