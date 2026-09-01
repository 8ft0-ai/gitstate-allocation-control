from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Sequence


MANIFEST_CONTRACT = "gitstate-live-execution-manifest/v1"
GOVERNANCE_CONTRACT = "gitstate-execution-governance/v1"
GOVERNANCE_PREFIX = "/gitstate-governance-v1 "
V1_CAPSULE_CONTRACT = "gitstate-operator/v1"
V1_CONSUMPTION_CONTRACT = "gitstate-consumption/v1"
V1_GOVERNANCE_CONTRACT = "gitstate-private-governance/v1"
V1_CAPSULE_PREFIX = "/gitstate-operator-v1 "
V1_CONSUMPTION_PREFIX = "/gitstate-consumption-v1 "
V1_MAX_CAPSULE_LIFETIME = timedelta(hours=1)

GOVERNANCE_RECORD_TYPES = frozenset(
    {
        "proposal",
        "readiness",
        "authority",
        "manifest_approval",
        "supersession",
        "revocation",
        "consumption",
        "terminal",
    }
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
OPAQUE_ID = re.compile(r"^[0-9a-f]{32,64}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

MANIFEST_FIELDS = frozenset(
    {
        "contract",
        "operation",
        "governing_issue",
        "executor",
        "protocol_sha",
        "proposal",
        "readiness",
        "authority",
        "state_baseline",
        "operator_history",
        "workflow_history",
        "allocator_app",
        "environment",
        "single_use",
        "workstream_e_authorised",
    }
)
EXECUTOR_FIELDS = frozenset(
    {"repository", "commit_sha", "tree_sha", "workflow_blob_sha", "module_blobs"}
)
COMMENT_BINDING_FIELDS = frozenset({"comment_id", "body_sha256"})
STATE_BASELINE_FIELDS = frozenset({"commit_sha", "digest_sha256"})
HISTORY_BASELINE_FIELDS = frozenset({"through_id", "history_sha256"})
ALLOCATOR_APP_FIELDS = frozenset(
    {
        "app_id",
        "installation_id",
        "repository_selection",
        "selected_repository_ids",
        "permission_profile_sha256",
        "owner_observation",
    }
)
ENVIRONMENT_FIELDS = frozenset(
    {"name", "policy_sha256", "execution_variable", "execution_variable_expected_absent"}
)
MODULE_BLOB_FIELDS = frozenset({"path", "blob_sha"})
GOVERNANCE_FIELDS = frozenset(
    {
        "contract",
        "record_id",
        "record_type",
        "governing_issue",
        "operation",
        "subject",
        "details",
        "workstream_e_authorised",
    }
)
LINEAGE_SUBJECT_FIELDS = frozenset({"lineage_id", "record_ids", "comment_bindings"})
MANIFEST_SUBJECT_FIELDS = frozenset({"manifest_sha256", "record_ids", "comment_bindings"})

V1_CAPSULE_FIELDS = frozenset(
    {
        "contract",
        "capsule_id",
        "governance_contract",
        "governance_record_id",
        "review_record_id",
        "review_record_sha256",
        "authority_record_id",
        "authority_record_sha256",
        "operation",
        "expected_control_sha",
        "expected_protocol_sha",
        "expected_state_baseline",
        "created_at",
        "expires_at",
        "single_use",
        "workstream_e_authorised",
    }
)
V1_CONSUMPTION_FIELDS = frozenset(
    {
        "contract",
        "capsule_id",
        "capsule_comment_id",
        "capsule_body_sha256",
        "run_id",
        "run_attempt",
        "trusted_sha",
        "operation",
        "consumed_at",
        "workstream_e_authorised",
    }
)


class OperatorContractError(RuntimeError):
    pass


def _duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OperatorContractError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_float(_: str) -> float:
    raise OperatorContractError("FLOAT_NOT_SUPPORTED")


def _reject_constant(_: str) -> float:
    raise OperatorContractError("NONFINITE_NUMBER_NOT_SUPPORTED")


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_sha256(value: Mapping[str, Any]) -> str:
    return sha256_text(canonical_json(value))


def _strict_json(raw: str, reason: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_duplicate_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except OperatorContractError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise OperatorContractError(reason) from exc
    if not isinstance(value, dict):
        raise OperatorContractError(reason)
    _require_supported_json(value)
    if raw != canonical_json(value):
        raise OperatorContractError("NONCANONICAL_JSON")
    return value


def _require_supported_json(value: Any) -> None:
    if value is None or isinstance(value, float):
        raise OperatorContractError("UNSUPPORTED_JSON_VALUE")
    if isinstance(value, (str, bool)) or type(value) is int:
        return
    if isinstance(value, list):
        for item in value:
            _require_supported_json(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise OperatorContractError("UNSUPPORTED_JSON_VALUE")
            _require_supported_json(item)
        return
    raise OperatorContractError("UNSUPPORTED_JSON_VALUE")


def _require_exact_keys(value: Mapping[str, Any], expected: frozenset[str], reason: str) -> None:
    if frozenset(value) != expected:
        raise OperatorContractError(reason)


def _require_string(value: Any, reason: str) -> str:
    if not isinstance(value, str) or not value:
        raise OperatorContractError(reason)
    return value


def _require_int(value: Any, reason: str, *, minimum: int = 1) -> int:
    if type(value) is not int or value < minimum:
        raise OperatorContractError(reason)
    return value


def _require_hex(value: Any, pattern: re.Pattern[str], reason: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise OperatorContractError(reason)
    return value


def _require_bool(value: Any, expected: bool, reason: str) -> None:
    if value is not expected:
        raise OperatorContractError(reason)


def _parse_time(value: Any, reason: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise OperatorContractError(reason)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise OperatorContractError(reason) from exc
    if parsed.tzinfo is None:
        raise OperatorContractError(reason)
    return parsed.astimezone(timezone.utc)


def _require_comment_binding(value: Any, reason: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OperatorContractError(reason)
    _require_exact_keys(value, COMMENT_BINDING_FIELDS, reason)
    _require_int(value.get("comment_id"), reason)
    _require_hex(value.get("body_sha256"), SHA256, reason)
    return value


def _require_module_blobs(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise OperatorContractError("MANIFEST_MODULE_BLOBS_INVALID")
    paths: list[str] = []
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            raise OperatorContractError("MANIFEST_MODULE_BLOBS_INVALID")
        _require_exact_keys(item, MODULE_BLOB_FIELDS, "MANIFEST_MODULE_BLOBS_INVALID")
        path = _require_string(item.get("path"), "MANIFEST_MODULE_BLOBS_INVALID")
        if path.startswith("/") or ".." in path.split("/"):
            raise OperatorContractError("MANIFEST_MODULE_BLOBS_INVALID")
        _require_hex(item.get("blob_sha"), SHA40, "MANIFEST_MODULE_BLOBS_INVALID")
        paths.append(path)
        result.append(item)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise OperatorContractError("MANIFEST_MODULE_BLOBS_INVALID")
    return result


def _require_history_baseline(value: Any, reason: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OperatorContractError(reason)
    _require_exact_keys(value, HISTORY_BASELINE_FIELDS, reason)
    _require_int(value.get("through_id"), reason, minimum=0)
    _require_hex(value.get("history_sha256"), SHA256, reason)
    return value


def _require_owner_observation(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or "required" not in value:
        raise OperatorContractError("MANIFEST_OWNER_OBSERVATION_INVALID")
    if value.get("required") is False:
        _require_exact_keys(value, frozenset({"required"}), "MANIFEST_OWNER_OBSERVATION_INVALID")
        return value
    if value.get("required") is True:
        _require_exact_keys(
            value,
            frozenset({"required", "observation_id", "observation_sha256", "valid_through"}),
            "MANIFEST_OWNER_OBSERVATION_INVALID",
        )
        _require_string(value.get("observation_id"), "MANIFEST_OWNER_OBSERVATION_INVALID")
        _require_hex(value.get("observation_sha256"), SHA256, "MANIFEST_OWNER_OBSERVATION_INVALID")
        _parse_time(value.get("valid_through"), "MANIFEST_OWNER_OBSERVATION_INVALID")
        return value
    raise OperatorContractError("MANIFEST_OWNER_OBSERVATION_INVALID")


@dataclass(frozen=True)
class CommentBinding:
    comment_id: int
    body_sha256: str


@dataclass(frozen=True)
class HistoryBaseline:
    through_id: int
    history_sha256: str


@dataclass(frozen=True)
class ModuleBlob:
    path: str
    blob_sha: str


@dataclass(frozen=True)
class ExecutionManifest:
    payload: dict[str, Any]
    sha256: str

    @property
    def operation(self) -> str:
        return str(self.payload["operation"])

    @property
    def governing_issue(self) -> int:
        return int(self.payload["governing_issue"])

    @property
    def proposal(self) -> CommentBinding:
        value = self.payload["proposal"]
        return CommentBinding(int(value["comment_id"]), str(value["body_sha256"]))

    @property
    def readiness(self) -> CommentBinding:
        value = self.payload["readiness"]
        return CommentBinding(int(value["comment_id"]), str(value["body_sha256"]))

    @property
    def authority(self) -> CommentBinding:
        value = self.payload["authority"]
        return CommentBinding(int(value["comment_id"]), str(value["body_sha256"]))

    @property
    def operator_history(self) -> HistoryBaseline:
        value = self.payload["operator_history"]
        return HistoryBaseline(int(value["through_id"]), str(value["history_sha256"]))

    @property
    def workflow_history(self) -> HistoryBaseline:
        value = self.payload["workflow_history"]
        return HistoryBaseline(int(value["through_id"]), str(value["history_sha256"]))

    @property
    def module_blobs(self) -> tuple[ModuleBlob, ...]:
        return tuple(
            ModuleBlob(str(item["path"]), str(item["blob_sha"]))
            for item in self.payload["executor"]["module_blobs"]
        )


def parse_execution_manifest(raw: str, *, expected_sha256: str | None = None) -> ExecutionManifest:
    value = _strict_json(raw, "MANIFEST_JSON_INVALID")
    _require_exact_keys(value, MANIFEST_FIELDS, "MANIFEST_SCHEMA_MISMATCH")
    if value.get("contract") != MANIFEST_CONTRACT:
        raise OperatorContractError("MANIFEST_CONTRACT_MISMATCH")
    _require_string(value.get("operation"), "MANIFEST_OPERATION_INVALID")
    _require_int(value.get("governing_issue"), "MANIFEST_GOVERNING_ISSUE_INVALID")

    executor = value.get("executor")
    if not isinstance(executor, dict):
        raise OperatorContractError("MANIFEST_EXECUTOR_INVALID")
    _require_exact_keys(executor, EXECUTOR_FIELDS, "MANIFEST_EXECUTOR_INVALID")
    repository = _require_string(executor.get("repository"), "MANIFEST_EXECUTOR_INVALID")
    if REPOSITORY.fullmatch(repository) is None:
        raise OperatorContractError("MANIFEST_EXECUTOR_INVALID")
    for key in ("commit_sha", "tree_sha", "workflow_blob_sha"):
        _require_hex(executor.get(key), SHA40, "MANIFEST_EXECUTOR_INVALID")
    _require_module_blobs(executor.get("module_blobs"))

    _require_hex(value.get("protocol_sha"), SHA40, "MANIFEST_PROTOCOL_INVALID")
    for key in ("proposal", "readiness", "authority"):
        _require_comment_binding(value.get(key), f"MANIFEST_{key.upper()}_INVALID")

    state = value.get("state_baseline")
    if not isinstance(state, dict):
        raise OperatorContractError("MANIFEST_STATE_BASELINE_INVALID")
    _require_exact_keys(state, STATE_BASELINE_FIELDS, "MANIFEST_STATE_BASELINE_INVALID")
    _require_hex(state.get("commit_sha"), SHA40, "MANIFEST_STATE_BASELINE_INVALID")
    _require_hex(state.get("digest_sha256"), SHA256, "MANIFEST_STATE_BASELINE_INVALID")

    _require_history_baseline(value.get("operator_history"), "MANIFEST_OPERATOR_HISTORY_INVALID")
    _require_history_baseline(value.get("workflow_history"), "MANIFEST_WORKFLOW_HISTORY_INVALID")

    app = value.get("allocator_app")
    if not isinstance(app, dict):
        raise OperatorContractError("MANIFEST_APP_BOUNDARY_INVALID")
    _require_exact_keys(app, ALLOCATOR_APP_FIELDS, "MANIFEST_APP_BOUNDARY_INVALID")
    _require_int(app.get("app_id"), "MANIFEST_APP_BOUNDARY_INVALID")
    _require_int(app.get("installation_id"), "MANIFEST_APP_BOUNDARY_INVALID")
    if app.get("repository_selection") != "selected":
        raise OperatorContractError("MANIFEST_APP_BOUNDARY_INVALID")
    repository_ids = app.get("selected_repository_ids")
    if (
        not isinstance(repository_ids, list)
        or not repository_ids
        or any(type(item) is not int or item <= 0 for item in repository_ids)
        or repository_ids != sorted(repository_ids)
        or len(repository_ids) != len(set(repository_ids))
    ):
        raise OperatorContractError("MANIFEST_APP_BOUNDARY_INVALID")
    _require_hex(app.get("permission_profile_sha256"), SHA256, "MANIFEST_APP_BOUNDARY_INVALID")
    _require_owner_observation(app.get("owner_observation"))

    environment = value.get("environment")
    if not isinstance(environment, dict):
        raise OperatorContractError("MANIFEST_ENVIRONMENT_INVALID")
    _require_exact_keys(environment, ENVIRONMENT_FIELDS, "MANIFEST_ENVIRONMENT_INVALID")
    _require_string(environment.get("name"), "MANIFEST_ENVIRONMENT_INVALID")
    _require_hex(environment.get("policy_sha256"), SHA256, "MANIFEST_ENVIRONMENT_INVALID")
    _require_string(environment.get("execution_variable"), "MANIFEST_ENVIRONMENT_INVALID")
    _require_bool(
        environment.get("execution_variable_expected_absent"),
        True,
        "MANIFEST_ENVIRONMENT_INVALID",
    )

    _require_bool(value.get("single_use"), True, "MANIFEST_SINGLE_USE_REQUIRED")
    _require_bool(value.get("workstream_e_authorised"), False, "WORKSTREAM_E_NOT_AUTHORISED")

    digest = sha256_text(raw)
    if expected_sha256 is not None:
        _require_hex(expected_sha256, SHA256, "MANIFEST_EXPECTED_DIGEST_INVALID")
        if digest != expected_sha256:
            raise OperatorContractError("MANIFEST_IDENTITY_MISMATCH")
    return ExecutionManifest(dict(value), digest)


@dataclass(frozen=True)
class GovernanceRecord:
    payload: dict[str, Any]
    comment_id: int
    body_sha256: str

    @property
    def record_id(self) -> str:
        return str(self.payload["record_id"])

    @property
    def record_type(self) -> str:
        return str(self.payload["record_type"])

    @property
    def manifest_sha256(self) -> str | None:
        value = self.payload["subject"].get("manifest_sha256")
        return str(value) if isinstance(value, str) else None

    @property
    def lineage_id(self) -> str | None:
        value = self.payload["subject"].get("lineage_id")
        return str(value) if isinstance(value, str) else None

    @property
    def operation(self) -> str:
        return str(self.payload["operation"])

    @property
    def governing_issue(self) -> int:
        return int(self.payload["governing_issue"])

    @property
    def subject_record_ids(self) -> tuple[str, ...]:
        return tuple(str(value) for value in self.payload["subject"]["record_ids"])

    @property
    def comment_bindings(self) -> tuple[CommentBinding, ...]:
        return tuple(
            CommentBinding(int(value["comment_id"]), str(value["body_sha256"]))
            for value in self.payload["subject"]["comment_bindings"]
        )


def _require_subject(record_type: str, value: Any) -> None:
    if not isinstance(value, dict):
        raise OperatorContractError("GOVERNANCE_SUBJECT_INVALID")
    if record_type in {"proposal", "readiness", "authority"}:
        _require_exact_keys(value, LINEAGE_SUBJECT_FIELDS, "GOVERNANCE_SUBJECT_INVALID")
        _require_hex(value.get("lineage_id"), OPAQUE_ID, "GOVERNANCE_SUBJECT_INVALID")
    else:
        _require_exact_keys(value, MANIFEST_SUBJECT_FIELDS, "GOVERNANCE_SUBJECT_INVALID")
        _require_hex(value.get("manifest_sha256"), SHA256, "GOVERNANCE_SUBJECT_INVALID")

    record_ids = value.get("record_ids")
    if not isinstance(record_ids, list):
        raise OperatorContractError("GOVERNANCE_SUBJECT_INVALID")
    for record_id in record_ids:
        _require_hex(record_id, OPAQUE_ID, "GOVERNANCE_SUBJECT_INVALID")
    if record_ids != sorted(record_ids) or len(record_ids) != len(set(record_ids)):
        raise OperatorContractError("GOVERNANCE_SUBJECT_INVALID")

    bindings = value.get("comment_bindings")
    if not isinstance(bindings, list):
        raise OperatorContractError("GOVERNANCE_SUBJECT_INVALID")
    comment_ids: list[int] = []
    for binding in bindings:
        parsed = _require_comment_binding(binding, "GOVERNANCE_SUBJECT_INVALID")
        comment_ids.append(int(parsed["comment_id"]))
    if comment_ids != sorted(comment_ids) or len(comment_ids) != len(set(comment_ids)):
        raise OperatorContractError("GOVERNANCE_SUBJECT_INVALID")


def _require_public_invalidation(value: Any) -> None:
    if not isinstance(value, dict) or "required" not in value:
        raise OperatorContractError("GOVERNANCE_DETAILS_INVALID")
    if value.get("required") is False:
        _require_exact_keys(value, frozenset({"required"}), "GOVERNANCE_DETAILS_INVALID")
        return
    if value.get("required") is True:
        _require_exact_keys(
            value,
            frozenset({"required", "comment_id", "body_sha256"}),
            "GOVERNANCE_DETAILS_INVALID",
        )
        _require_int(value.get("comment_id"), "GOVERNANCE_DETAILS_INVALID")
        _require_hex(value.get("body_sha256"), SHA256, "GOVERNANCE_DETAILS_INVALID")
        return
    raise OperatorContractError("GOVERNANCE_DETAILS_INVALID")


def _require_governance_details(record_type: str, details: Any) -> None:
    if not isinstance(details, dict):
        raise OperatorContractError("GOVERNANCE_DETAILS_INVALID")
    if record_type == "proposal":
        _require_exact_keys(details, frozenset({"disposition"}), "GOVERNANCE_DETAILS_INVALID")
        if details.get("disposition") != "proposed":
            raise OperatorContractError("GOVERNANCE_DETAILS_INVALID")
    elif record_type == "readiness":
        _require_exact_keys(details, frozenset({"disposition"}), "GOVERNANCE_DETAILS_INVALID")
        if details.get("disposition") not in {"ready", "not_ready"}:
            raise OperatorContractError("GOVERNANCE_DETAILS_INVALID")
    elif record_type == "authority":
        _require_exact_keys(
            details,
            frozenset({"disposition", "execution_authorised", "single_use"}),
            "GOVERNANCE_DETAILS_INVALID",
        )
        if details.get("disposition") != "granted":
            raise OperatorContractError("GOVERNANCE_DETAILS_INVALID")
        _require_bool(details.get("execution_authorised"), True, "GOVERNANCE_DETAILS_INVALID")
        _require_bool(details.get("single_use"), True, "GOVERNANCE_DETAILS_INVALID")
    elif record_type == "manifest_approval":
        _require_exact_keys(details, frozenset({"disposition"}), "GOVERNANCE_DETAILS_INVALID")
        if details.get("disposition") not in {"approved", "rejected"}:
            raise OperatorContractError("GOVERNANCE_DETAILS_INVALID")
    elif record_type in {"supersession", "revocation"}:
        _require_exact_keys(
            details,
            frozenset({"reason", "public_invalidation"}),
            "GOVERNANCE_DETAILS_INVALID",
        )
        _require_string(details.get("reason"), "GOVERNANCE_DETAILS_INVALID")
        _require_public_invalidation(details.get("public_invalidation"))
    elif record_type == "consumption":
        _require_exact_keys(
            details,
            frozenset({"run_id", "run_attempt"}),
            "GOVERNANCE_DETAILS_INVALID",
        )
        _require_int(details.get("run_id"), "GOVERNANCE_DETAILS_INVALID")
        _require_int(details.get("run_attempt"), "GOVERNANCE_DETAILS_INVALID")
    elif record_type == "terminal":
        _require_exact_keys(
            details,
            frozenset({"conclusion", "run_id", "run_attempt"}),
            "GOVERNANCE_DETAILS_INVALID",
        )
        _require_string(details.get("conclusion"), "GOVERNANCE_DETAILS_INVALID")
        _require_int(details.get("run_id"), "GOVERNANCE_DETAILS_INVALID")
        _require_int(details.get("run_attempt"), "GOVERNANCE_DETAILS_INVALID")
    else:
        raise OperatorContractError("GOVERNANCE_RECORD_TYPE_INVALID")


def parse_governance_comment(
    comment: Mapping[str, Any],
    *,
    expected_owner: str,
    expected_issue: int,
    expected_body_sha256: str | None = None,
) -> GovernanceRecord | None:
    comment_id = comment.get("id")
    body = comment.get("body")
    if not isinstance(body, str):
        raise OperatorContractError("GOVERNANCE_COMMENT_INVALID")
    lines = body.splitlines()
    reserved_like = [line for line in lines if line.startswith("/gitstate-governance-v1")]
    machine_lines = [line for line in lines if line.startswith(GOVERNANCE_PREFIX)]
    if not reserved_like:
        return None
    if len(reserved_like) != 1 or len(machine_lines) != 1:
        raise OperatorContractError("GOVERNANCE_RESERVED_LINE_INVALID")
    _require_int(comment_id, "GOVERNANCE_COMMENT_INVALID")
    user = comment.get("user")
    if not isinstance(user, Mapping) or user.get("login") != expected_owner:
        raise OperatorContractError("GOVERNANCE_WRONG_OWNER")
    created = comment.get("created_at")
    updated = comment.get("updated_at")
    _parse_time(created, "GOVERNANCE_COMMENT_TIME_INVALID")
    if created != updated:
        raise OperatorContractError("GOVERNANCE_SOURCE_EDITED")

    body_digest = sha256_text(body)
    if expected_body_sha256 is not None:
        _require_hex(expected_body_sha256, SHA256, "GOVERNANCE_EXPECTED_DIGEST_INVALID")
        if body_digest != expected_body_sha256:
            raise OperatorContractError("GOVERNANCE_BODY_DIGEST_MISMATCH")

    value = _strict_json(machine_lines[0][len(GOVERNANCE_PREFIX) :], "GOVERNANCE_JSON_INVALID")
    _require_exact_keys(value, GOVERNANCE_FIELDS, "GOVERNANCE_SCHEMA_MISMATCH")
    if value.get("contract") != GOVERNANCE_CONTRACT:
        raise OperatorContractError("GOVERNANCE_CONTRACT_MISMATCH")
    _require_hex(value.get("record_id"), OPAQUE_ID, "GOVERNANCE_RECORD_ID_INVALID")
    record_type = value.get("record_type")
    if record_type not in GOVERNANCE_RECORD_TYPES:
        raise OperatorContractError("GOVERNANCE_RECORD_TYPE_INVALID")
    if value.get("governing_issue") != expected_issue:
        raise OperatorContractError("GOVERNANCE_ISSUE_MISMATCH")
    _require_string(value.get("operation"), "GOVERNANCE_OPERATION_INVALID")
    _require_subject(str(record_type), value.get("subject"))
    _require_governance_details(str(record_type), value.get("details"))
    _require_bool(value.get("workstream_e_authorised"), False, "WORKSTREAM_E_NOT_AUTHORISED")
    return GovernanceRecord(dict(value), int(comment_id), body_digest)


def parse_governance_comments(
    comments: Iterable[Mapping[str, Any]],
    *,
    expected_owner: str,
    expected_issue: int,
    expected_body_sha256_by_comment: Mapping[int, str] | None = None,
) -> tuple[GovernanceRecord, ...]:
    records: list[GovernanceRecord] = []
    record_ids: set[str] = set()
    comment_ids: set[int] = set()
    for comment in comments:
        comment_id = comment.get("id")
        expected_digest = None
        if type(comment_id) is int and expected_body_sha256_by_comment is not None:
            expected_digest = expected_body_sha256_by_comment.get(comment_id)
        record = parse_governance_comment(
            comment,
            expected_owner=expected_owner,
            expected_issue=expected_issue,
            expected_body_sha256=expected_digest,
        )
        if record is None:
            continue
        if record.comment_id in comment_ids:
            raise OperatorContractError("GOVERNANCE_DUPLICATE_COMMENT_ID")
        if record.record_id in record_ids:
            raise OperatorContractError("GOVERNANCE_DUPLICATE_RECORD_ID")
        comment_ids.add(record.comment_id)
        record_ids.add(record.record_id)
        records.append(record)
    records.sort(key=lambda record: record.comment_id)
    return tuple(records)


@dataclass(frozen=True)
class OperatorHistoryRecord:
    comment_id: int
    record_kind: str
    body_sha256: str
    capsule_id: str
    trusted_sha: str
    operation: str
    capsule_comment_id: int | None = None
    capsule_body_sha256: str | None = None
    run_id: int | None = None
    run_attempt: int | None = None


def _v1_comment_identity(comment: Mapping[str, Any]) -> tuple[int, str, str]:
    comment_id = _require_int(comment.get("id"), "OPERATOR_HISTORY_COMMENT_INVALID")
    created = comment.get("created_at")
    updated = comment.get("updated_at")
    _parse_time(created, "OPERATOR_HISTORY_COMMENT_TIME_INVALID")
    if created != updated:
        raise OperatorContractError("OPERATOR_HISTORY_SOURCE_EDITED")
    user = comment.get("user")
    if not isinstance(user, Mapping) or not isinstance(user.get("login"), str):
        raise OperatorContractError("OPERATOR_HISTORY_WRONG_OWNER")
    return comment_id, str(user["login"]), str(created)


def parse_v1_operator_history_comment(
    comment: Mapping[str, Any],
    *,
    capsule_owner: str = "8ft0-ai",
    consumption_owner: str = "github-actions[bot]",
) -> OperatorHistoryRecord | None:
    body = comment.get("body")
    if not isinstance(body, str):
        raise OperatorContractError("OPERATOR_HISTORY_COMMENT_INVALID")
    is_capsule = body.startswith(V1_CAPSULE_PREFIX)
    is_consumption = body.startswith(V1_CONSUMPTION_PREFIX)
    reserved_like = body.startswith("/gitstate-operator-v1") or body.startswith("/gitstate-consumption-v1")
    if not reserved_like:
        return None
    if not (is_capsule or is_consumption) or "\n" in body:
        raise OperatorContractError("OPERATOR_HISTORY_RESERVED_RECORD_INVALID")

    comment_id, login, comment_created = _v1_comment_identity(comment)
    prefix = V1_CAPSULE_PREFIX if is_capsule else V1_CONSUMPTION_PREFIX
    value = _strict_json(body[len(prefix) :], "OPERATOR_HISTORY_JSON_INVALID")

    if is_capsule:
        if login != capsule_owner:
            raise OperatorContractError("OPERATOR_HISTORY_WRONG_OWNER")
        _require_exact_keys(value, V1_CAPSULE_FIELDS, "OPERATOR_HISTORY_SCHEMA_MISMATCH")
        if value.get("contract") != V1_CAPSULE_CONTRACT:
            raise OperatorContractError("OPERATOR_HISTORY_CONTRACT_MISMATCH")
        if value.get("governance_contract") != V1_GOVERNANCE_CONTRACT:
            raise OperatorContractError("OPERATOR_HISTORY_GOVERNANCE_CONTRACT_MISMATCH")
        _require_hex(value.get("capsule_id"), OPAQUE_ID, "OPERATOR_HISTORY_CAPSULE_INVALID")
        for key in ("governance_record_id", "review_record_id", "authority_record_id"):
            _require_hex(value.get(key), OPAQUE_ID, "OPERATOR_HISTORY_PROVENANCE_INVALID")
        for key in ("review_record_sha256", "authority_record_sha256"):
            _require_hex(value.get(key), SHA256, "OPERATOR_HISTORY_PROVENANCE_INVALID")
        for key in ("expected_control_sha", "expected_protocol_sha", "expected_state_baseline"):
            _require_hex(value.get(key), SHA40, "OPERATOR_HISTORY_TRUSTED_SHA_INVALID")
        _require_string(value.get("operation"), "OPERATOR_HISTORY_OPERATION_INVALID")
        _require_bool(value.get("single_use"), True, "OPERATOR_HISTORY_SINGLE_USE_REQUIRED")
        _require_bool(value.get("workstream_e_authorised"), False, "WORKSTREAM_E_NOT_AUTHORISED")
        created = _parse_time(value.get("created_at"), "OPERATOR_HISTORY_CAPSULE_TIME_INVALID")
        expires = _parse_time(value.get("expires_at"), "OPERATOR_HISTORY_CAPSULE_TIME_INVALID")
        if expires <= created or expires - created > V1_MAX_CAPSULE_LIFETIME:
            raise OperatorContractError("OPERATOR_HISTORY_CAPSULE_TIME_INVALID")
        comment_time = _parse_time(comment_created, "OPERATOR_HISTORY_COMMENT_TIME_INVALID")
        if comment_time > expires:
            raise OperatorContractError("OPERATOR_HISTORY_CAPSULE_TIME_INVALID")
        return OperatorHistoryRecord(
            comment_id=comment_id,
            record_kind=V1_CAPSULE_CONTRACT,
            body_sha256=sha256_text(body),
            capsule_id=str(value["capsule_id"]),
            trusted_sha=str(value["expected_control_sha"]),
            operation=str(value["operation"]),
        )

    if login != consumption_owner:
        raise OperatorContractError("OPERATOR_HISTORY_WRONG_OWNER")
    _require_exact_keys(value, V1_CONSUMPTION_FIELDS, "OPERATOR_HISTORY_SCHEMA_MISMATCH")
    if value.get("contract") != V1_CONSUMPTION_CONTRACT:
        raise OperatorContractError("OPERATOR_HISTORY_CONTRACT_MISMATCH")
    _require_hex(value.get("capsule_id"), OPAQUE_ID, "OPERATOR_HISTORY_CAPSULE_INVALID")
    capsule_comment_id = _require_int(
        value.get("capsule_comment_id"), "OPERATOR_HISTORY_CAPSULE_COMMENT_INVALID"
    )
    capsule_body_sha256 = _require_hex(
        value.get("capsule_body_sha256"), SHA256, "OPERATOR_HISTORY_CAPSULE_DIGEST_INVALID"
    )
    run_id = _require_int(value.get("run_id"), "OPERATOR_HISTORY_RUN_INVALID")
    run_attempt = _require_int(value.get("run_attempt"), "OPERATOR_HISTORY_RUN_INVALID")
    _require_hex(value.get("trusted_sha"), SHA40, "OPERATOR_HISTORY_TRUSTED_SHA_INVALID")
    _require_string(value.get("operation"), "OPERATOR_HISTORY_OPERATION_INVALID")
    _parse_time(value.get("consumed_at"), "OPERATOR_HISTORY_CONSUMPTION_TIME_INVALID")
    _require_bool(value.get("workstream_e_authorised"), False, "WORKSTREAM_E_NOT_AUTHORISED")
    return OperatorHistoryRecord(
        comment_id=comment_id,
        record_kind=V1_CONSUMPTION_CONTRACT,
        body_sha256=sha256_text(body),
        capsule_id=str(value["capsule_id"]),
        trusted_sha=str(value["trusted_sha"]),
        operation=str(value["operation"]),
        capsule_comment_id=capsule_comment_id,
        capsule_body_sha256=capsule_body_sha256,
        run_id=run_id,
        run_attempt=run_attempt,
    )


def parse_v1_operator_history(
    comments: Iterable[Mapping[str, Any]],
) -> tuple[OperatorHistoryRecord, ...]:
    records = tuple(
        sorted(
            (
                record
                for comment in comments
                if (record := parse_v1_operator_history_comment(comment)) is not None
            ),
            key=lambda record: record.comment_id,
        )
    )
    validate_operator_history(records)
    return records


def _ordered_history(records: Sequence[OperatorHistoryRecord]) -> tuple[OperatorHistoryRecord, ...]:
    return tuple(sorted(records, key=lambda record: record.comment_id))


def validate_operator_history(records: Sequence[OperatorHistoryRecord]) -> None:
    comment_ids: set[int] = set()
    capsules: dict[str, OperatorHistoryRecord] = {}
    consumptions: set[str] = set()
    run_attempts: set[tuple[int, int]] = set()

    for record in _ordered_history(records):
        if record.comment_id in comment_ids:
            raise OperatorContractError("OPERATOR_HISTORY_DUPLICATE_COMMENT")
        comment_ids.add(record.comment_id)
        if record.record_kind == V1_CAPSULE_CONTRACT:
            if record.capsule_id in capsules:
                raise OperatorContractError("OPERATOR_HISTORY_DUPLICATE_CAPSULE")
            capsules[record.capsule_id] = record
            continue
        if record.record_kind != V1_CONSUMPTION_CONTRACT:
            raise OperatorContractError("OPERATOR_HISTORY_KIND_INVALID")
        capsule = capsules.get(record.capsule_id)
        if capsule is None:
            raise OperatorContractError("OPERATOR_HISTORY_ORPHAN_CONSUMPTION")
        if record.capsule_id in consumptions:
            raise OperatorContractError("OPERATOR_HISTORY_DUPLICATE_CONSUMPTION")
        if (
            record.capsule_comment_id != capsule.comment_id
            or record.capsule_body_sha256 != capsule.body_sha256
            or record.trusted_sha != capsule.trusted_sha
            or record.operation != capsule.operation
            or record.run_attempt != 1
            or record.run_id is None
        ):
            raise OperatorContractError("OPERATOR_HISTORY_CONSUMPTION_MISMATCH")
        run_key = (record.run_id, record.run_attempt)
        if run_key in run_attempts:
            raise OperatorContractError("OPERATOR_HISTORY_DUPLICATE_RUN_ATTEMPT")
        run_attempts.add(run_key)
        consumptions.add(record.capsule_id)

    unconsumed = set(capsules) - consumptions
    if unconsumed:
        raise OperatorContractError("OPERATOR_HISTORY_UNCONSUMED_CAPSULE")


def canonical_operator_history(
    records: Sequence[OperatorHistoryRecord],
    *,
    through_comment_id: int | None = None,
) -> str:
    selected = tuple(
        record
        for record in _ordered_history(records)
        if through_comment_id is None or record.comment_id <= through_comment_id
    )
    validate_operator_history(selected)
    return "".join(
        f"{record.comment_id}\t{record.record_kind}\t{record.body_sha256}\n"
        for record in selected
    )


def operator_history_baseline(
    records: Sequence[OperatorHistoryRecord],
    *,
    through_comment_id: int | None = None,
) -> HistoryBaseline:
    selected = tuple(
        record
        for record in _ordered_history(records)
        if through_comment_id is None or record.comment_id <= through_comment_id
    )
    canonical = canonical_operator_history(selected)
    through = max((record.comment_id for record in selected), default=0)
    return HistoryBaseline(through, sha256_text(canonical))


@dataclass(frozen=True)
class WorkflowHistoryRecord:
    run_id: int
    run_attempt: int
    trusted_sha: str
    operation: str
    conclusion: str = ""


def canonical_workflow_history(records: Sequence[WorkflowHistoryRecord]) -> str:
    ordered = sorted(records, key=lambda record: (record.run_id, record.run_attempt))
    seen: set[tuple[int, int]] = set()
    lines: list[str] = []
    for record in ordered:
        _require_int(record.run_id, "WORKFLOW_HISTORY_RUN_INVALID")
        _require_int(record.run_attempt, "WORKFLOW_HISTORY_RUN_INVALID")
        _require_hex(record.trusted_sha, SHA40, "WORKFLOW_HISTORY_TRUSTED_SHA_INVALID")
        _require_string(record.operation, "WORKFLOW_HISTORY_OPERATION_INVALID")
        key = (record.run_id, record.run_attempt)
        if key in seen:
            raise OperatorContractError("WORKFLOW_HISTORY_DUPLICATE_RUN_ATTEMPT")
        seen.add(key)
        # Terminal conclusion is intentionally not part of the B1 authority/history
        # identity. If it becomes decision-critical it must be modelled explicitly.
        lines.append(
            f"{record.run_id}\t{record.run_attempt}\t{record.trusted_sha}\t{record.operation}\n"
        )
    return "".join(lines)


def workflow_history_baseline(records: Sequence[WorkflowHistoryRecord]) -> HistoryBaseline:
    canonical = canonical_workflow_history(records)
    through = max((record.run_id for record in records), default=0)
    return HistoryBaseline(through, sha256_text(canonical))
