from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .governance_state import GovernanceHistory, GovernanceStateError, reduce_governance_history
from .operator_manifest import ExecutionManifest, HistoryBaseline, ModuleBlob


AUTHORITY_SECURITY = "authority_security"
MUTABLE_INVALIDATOR = "mutable_invalidator"
OBSERVATION_INCOMPLETE = "observation_incomplete"
IMPLEMENTATION_DEFECT = "implementation_defect"

FAILURE_CATEGORY = {
    "GOVERNANCE_HISTORY_CHANGED": AUTHORITY_SECURITY,
    "GOVERNANCE_RECORD_INVALID": AUTHORITY_SECURITY,
    "GOVERNANCE_AMBIGUOUS": AUTHORITY_SECURITY,
    "GOVERNANCE_SUPERSEDED": AUTHORITY_SECURITY,
    "AUTHORITY_NOT_GRANTED": AUTHORITY_SECURITY,
    "AUTHORITY_CONSUMED": AUTHORITY_SECURITY,
    "WORKSTREAM_E_NOT_AUTHORISED": AUTHORITY_SECURITY,
    "CONTROL_IDENTITY_CHANGED": MUTABLE_INVALIDATOR,
    "WORKFLOW_IDENTITY_CHANGED": MUTABLE_INVALIDATOR,
    "PROTOCOL_IDENTITY_CHANGED": MUTABLE_INVALIDATOR,
    "STATE_BASELINE_CHANGED": MUTABLE_INVALIDATOR,
    "OPERATOR_HISTORY_CHANGED": MUTABLE_INVALIDATOR,
    "WORKFLOW_HISTORY_CHANGED": MUTABLE_INVALIDATOR,
    "APP_BOUNDARY_CHANGED": MUTABLE_INVALIDATOR,
    "ENVIRONMENT_BOUNDARY_CHANGED": MUTABLE_INVALIDATOR,
    "EXECUTION_ENABLEMENT_CHANGED": MUTABLE_INVALIDATOR,
    "READ_EVIDENCE_UNAVAILABLE": OBSERVATION_INCOMPLETE,
    "READ_EVIDENCE_RATE_LIMITED": OBSERVATION_INCOMPLETE,
    "READ_EVIDENCE_AMBIGUOUS": OBSERVATION_INCOMPLETE,
    "MANIFEST_SCHEMA_UNSUPPORTED": IMPLEMENTATION_DEFECT,
    "OBSERVATION_SHAPE_UNSUPPORTED": IMPLEMENTATION_DEFECT,
    "GUARD_EVALUATOR_DEFECT": IMPLEMENTATION_DEFECT,
}

STAGES = frozenset({"preflight", "live_l1", "live_l2"})
READ_STATUSES = frozenset({"complete", "unavailable", "rate_limited", "ambiguous"})
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


@dataclass(frozen=True)
class OwnerObservation:
    observation_id: str
    observation_sha256: str
    valid: bool


@dataclass(frozen=True)
class GuardObservation:
    stage: str
    read_status: str
    evaluated_at: datetime
    operation: str
    control_repository: str
    control_commit_sha: str
    control_tree_sha: str
    workflow_blob_sha: str
    module_blobs: tuple[ModuleBlob, ...]
    protocol_sha: str
    state_commit_sha: str
    state_digest_sha256: str
    operator_history: HistoryBaseline
    workflow_history: HistoryBaseline
    app_id: int
    installation_id: int
    repository_selection: str
    selected_repository_ids: tuple[int, ...]
    permission_profile_sha256: str
    owner_observation: OwnerObservation | None
    environment_name: str
    environment_policy_sha256: str
    execution_variable: str
    execution_variable_absent: bool
    governance_history: GovernanceHistory


@dataclass(frozen=True)
class GuardResult:
    passed: bool
    code: str
    category: str

    @classmethod
    def pass_result(cls) -> "GuardResult":
        return cls(True, "PASS", "pass")

    @classmethod
    def failure(cls, code: str) -> "GuardResult":
        return cls(False, code, FAILURE_CATEGORY.get(code, IMPLEMENTATION_DEFECT))


def _valid_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _valid_positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def _valid_hex(value: object, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _valid_history(value: object) -> bool:
    return (
        isinstance(value, HistoryBaseline)
        and type(value.through_id) is int
        and value.through_id >= 0
        and _valid_hex(value.history_sha256, SHA256)
    )


def _valid_module_blobs(value: object) -> bool:
    if not isinstance(value, tuple) or not value:
        return False
    paths: list[str] = []
    for item in value:
        if not isinstance(item, ModuleBlob):
            return False
        if not _valid_string(item.path) or item.path.startswith("/") or ".." in item.path.split("/"):
            return False
        if not _valid_hex(item.blob_sha, SHA40):
            return False
        paths.append(item.path)
    return paths == sorted(paths) and len(paths) == len(set(paths))


def _valid_owner_observation(value: object) -> bool:
    if value is None:
        return True
    return (
        isinstance(value, OwnerObservation)
        and _valid_string(value.observation_id)
        and _valid_hex(value.observation_sha256, SHA256)
        and type(value.valid) is bool
    )


def _valid_utc_datetime(value: object) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() == timedelta(0)
    )


def _parse_manifest_utc_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _valid_complete_observation(observation: GuardObservation) -> bool:
    if not _valid_utc_datetime(observation.evaluated_at):
        return False
    if not _valid_string(observation.operation):
        return False
    if (
        not _valid_string(observation.control_repository)
        or REPOSITORY.fullmatch(observation.control_repository) is None
    ):
        return False
    for value in (
        observation.control_commit_sha,
        observation.control_tree_sha,
        observation.workflow_blob_sha,
        observation.protocol_sha,
        observation.state_commit_sha,
    ):
        if not _valid_hex(value, SHA40):
            return False
    if not _valid_hex(observation.state_digest_sha256, SHA256):
        return False
    if not _valid_module_blobs(observation.module_blobs):
        return False
    if not _valid_history(observation.operator_history) or not _valid_history(
        observation.workflow_history
    ):
        return False
    if not _valid_positive_int(observation.app_id) or not _valid_positive_int(
        observation.installation_id
    ):
        return False
    if observation.repository_selection != "selected":
        return False
    if (
        not isinstance(observation.selected_repository_ids, tuple)
        or not observation.selected_repository_ids
        or any(not _valid_positive_int(item) for item in observation.selected_repository_ids)
        or observation.selected_repository_ids != tuple(sorted(observation.selected_repository_ids))
        or len(observation.selected_repository_ids) != len(set(observation.selected_repository_ids))
    ):
        return False
    if not _valid_hex(observation.permission_profile_sha256, SHA256):
        return False
    if not _valid_owner_observation(observation.owner_observation):
        return False
    if not _valid_string(observation.environment_name):
        return False
    if not _valid_hex(observation.environment_policy_sha256, SHA256):
        return False
    if (
        not _valid_string(observation.execution_variable)
        or type(observation.execution_variable_absent) is not bool
    ):
        return False
    if not isinstance(observation.governance_history, GovernanceHistory):
        return False
    return True


def _evaluate_governance(
    manifest: ExecutionManifest,
    observation: GuardObservation,
) -> GuardResult | None:
    try:
        state = reduce_governance_history(manifest, observation.governance_history)
    except GovernanceStateError as exc:
        return GuardResult.failure(exc.code)

    if state.authority_status == "superseded":
        return GuardResult.failure("GOVERNANCE_SUPERSEDED")
    if state.authority_status == "consumed":
        return GuardResult.failure("AUTHORITY_CONSUMED")
    if state.authority_status != "active":
        return GuardResult.failure("AUTHORITY_NOT_GRANTED")

    if observation.stage != "preflight":
        if state.approval_status == "ambiguous":
            return GuardResult.failure("GOVERNANCE_AMBIGUOUS")
        if state.approval_status != "approved":
            return GuardResult.failure("AUTHORITY_NOT_GRANTED")
    return None


def _compare_control(
    manifest: ExecutionManifest,
    observation: GuardObservation,
) -> GuardResult | None:
    executor = manifest.payload["executor"]
    if observation.operation != manifest.operation:
        return GuardResult.failure("AUTHORITY_NOT_GRANTED")
    if observation.control_repository != executor["repository"]:
        return GuardResult.failure("CONTROL_IDENTITY_CHANGED")
    if (
        observation.control_commit_sha != executor["commit_sha"]
        or observation.control_tree_sha != executor["tree_sha"]
    ):
        return GuardResult.failure("CONTROL_IDENTITY_CHANGED")
    if observation.workflow_blob_sha != executor["workflow_blob_sha"]:
        return GuardResult.failure("WORKFLOW_IDENTITY_CHANGED")
    if observation.module_blobs != manifest.module_blobs:
        return GuardResult.failure("CONTROL_IDENTITY_CHANGED")
    return None


def _compare_app(
    manifest: ExecutionManifest,
    observation: GuardObservation,
) -> GuardResult | None:
    app = manifest.payload["allocator_app"]
    if (
        observation.app_id != app["app_id"]
        or observation.installation_id != app["installation_id"]
        or observation.repository_selection != app["repository_selection"]
        or observation.selected_repository_ids != tuple(app["selected_repository_ids"])
        or observation.permission_profile_sha256 != app["permission_profile_sha256"]
    ):
        return GuardResult.failure("APP_BOUNDARY_CHANGED")
    expected_owner = app["owner_observation"]
    if expected_owner["required"]:
        actual = observation.owner_observation
        if actual is None:
            return GuardResult.failure("READ_EVIDENCE_UNAVAILABLE")
        if not actual.valid:
            return GuardResult.failure("APP_BOUNDARY_CHANGED")
        if (
            actual.observation_id != expected_owner["observation_id"]
            or actual.observation_sha256 != expected_owner["observation_sha256"]
        ):
            return GuardResult.failure("APP_BOUNDARY_CHANGED")
        valid_through = _parse_manifest_utc_time(expected_owner["valid_through"])
        if valid_through is None:
            return GuardResult.failure("MANIFEST_SCHEMA_UNSUPPORTED")
        if observation.evaluated_at >= valid_through:
            return GuardResult.failure("APP_BOUNDARY_CHANGED")
    return None


def evaluate_guards(
    manifest: ExecutionManifest,
    observation: GuardObservation,
) -> GuardResult:
    if not isinstance(manifest, ExecutionManifest):
        return GuardResult.failure("MANIFEST_SCHEMA_UNSUPPORTED")
    if not isinstance(observation, GuardObservation):
        return GuardResult.failure("OBSERVATION_SHAPE_UNSUPPORTED")
    if observation.stage not in STAGES or observation.read_status not in READ_STATUSES:
        return GuardResult.failure("OBSERVATION_SHAPE_UNSUPPORTED")
    if observation.read_status == "unavailable":
        return GuardResult.failure("READ_EVIDENCE_UNAVAILABLE")
    if observation.read_status == "rate_limited":
        return GuardResult.failure("READ_EVIDENCE_RATE_LIMITED")
    if observation.read_status == "ambiguous":
        return GuardResult.failure("READ_EVIDENCE_AMBIGUOUS")
    if not _valid_complete_observation(observation):
        return GuardResult.failure("OBSERVATION_SHAPE_UNSUPPORTED")

    if manifest.payload.get("workstream_e_authorised") is not False:
        return GuardResult.failure("WORKSTREAM_E_NOT_AUTHORISED")

    governance = _evaluate_governance(manifest, observation)
    if governance is not None:
        return governance

    control = _compare_control(manifest, observation)
    if control is not None:
        return control
    if observation.protocol_sha != manifest.payload["protocol_sha"]:
        return GuardResult.failure("PROTOCOL_IDENTITY_CHANGED")

    state = manifest.payload["state_baseline"]
    if (
        observation.state_commit_sha != state["commit_sha"]
        or observation.state_digest_sha256 != state["digest_sha256"]
    ):
        return GuardResult.failure("STATE_BASELINE_CHANGED")

    if observation.operator_history != manifest.operator_history:
        return GuardResult.failure("OPERATOR_HISTORY_CHANGED")
    if observation.workflow_history != manifest.workflow_history:
        return GuardResult.failure("WORKFLOW_HISTORY_CHANGED")

    app = _compare_app(manifest, observation)
    if app is not None:
        return app

    environment = manifest.payload["environment"]
    if (
        observation.environment_name != environment["name"]
        or observation.environment_policy_sha256 != environment["policy_sha256"]
        or observation.execution_variable != environment["execution_variable"]
    ):
        return GuardResult.failure("ENVIRONMENT_BOUNDARY_CHANGED")
    if environment["execution_variable_expected_absent"] and not observation.execution_variable_absent:
        return GuardResult.failure("EXECUTION_ENABLEMENT_CHANGED")
    return GuardResult.pass_result()
