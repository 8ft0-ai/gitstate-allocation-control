from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Sequence

from .operator_manifest import (
    CommentBinding,
    ExecutionManifest,
    GovernanceRecord,
    HistoryBaseline,
    ModuleBlob,
)


AUTHORITY_SECURITY = "authority_security"
MUTABLE_INVALIDATOR = "mutable_invalidator"
OBSERVATION_INCOMPLETE = "observation_incomplete"
IMPLEMENTATION_DEFECT = "implementation_defect"

FAILURE_CATEGORY = {
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
    governance_records: tuple[GovernanceRecord, ...]
    manifest_approval: CommentBinding | None = None


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


def _valid_binding(value: object) -> bool:
    return (
        isinstance(value, CommentBinding)
        and _valid_positive_int(value.comment_id)
        and _valid_hex(value.body_sha256, SHA256)
    )


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
    if not _valid_string(observation.control_repository) or REPOSITORY.fullmatch(observation.control_repository) is None:
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
    if not _valid_history(observation.operator_history) or not _valid_history(observation.workflow_history):
        return False
    if not _valid_positive_int(observation.app_id) or not _valid_positive_int(observation.installation_id):
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
    if not _valid_string(observation.execution_variable) or type(observation.execution_variable_absent) is not bool:
        return False
    if not isinstance(observation.governance_records, tuple) or any(
        not isinstance(record, GovernanceRecord) for record in observation.governance_records
    ):
        return False
    if observation.manifest_approval is not None and not _valid_binding(observation.manifest_approval):
        return False
    return True


def _same_binding(record: GovernanceRecord, binding: CommentBinding) -> bool:
    return record.comment_id == binding.comment_id and record.body_sha256 == binding.body_sha256


def _contains_binding(record: GovernanceRecord, binding: CommentBinding) -> bool:
    return binding in record.comment_bindings


def _relevant_records(
    manifest: ExecutionManifest,
    records: Sequence[GovernanceRecord],
) -> tuple[GovernanceRecord, ...]:
    return tuple(
        record
        for record in records
        if record.governing_issue == manifest.governing_issue
        and record.operation == manifest.operation
        and (
            record.record_type in {"proposal", "readiness", "authority"}
            or record.manifest_sha256 == manifest.sha256
        )
    )


def _is_invalidated(record_id: str, records: Sequence[GovernanceRecord]) -> bool:
    return any(
        record.record_type in {"revocation", "supersession"}
        and record_id in record.subject_record_ids
        for record in records
    )


def _is_consumed(record_id: str, records: Sequence[GovernanceRecord]) -> bool:
    return any(
        record.record_type == "consumption" and record_id in record.subject_record_ids
        for record in records
    )


def _exact_record(
    records: Sequence[GovernanceRecord],
    *,
    record_type: str,
    binding: CommentBinding,
) -> GovernanceRecord | None:
    matches = [
        record
        for record in records
        if record.record_type == record_type and _same_binding(record, binding)
    ]
    if len(matches) != 1:
        return None
    return matches[0]


def _valid_lineage_authority(
    record: GovernanceRecord,
    *,
    proposal: GovernanceRecord,
    readiness: GovernanceRecord,
) -> bool:
    return (
        record.lineage_id == proposal.lineage_id
        and set(record.subject_record_ids) == {proposal.record_id, readiness.record_id}
        and set(record.comment_bindings) == {
            CommentBinding(proposal.comment_id, proposal.body_sha256),
            CommentBinding(readiness.comment_id, readiness.body_sha256),
        }
    )


def _validate_manifest_lifecycle_records(
    records: Sequence[GovernanceRecord],
    *,
    proposal: GovernanceRecord,
    readiness: GovernanceRecord,
    authority: GovernanceRecord,
) -> GuardResult | None:
    approvals = tuple(record for record in records if record.record_type == "manifest_approval")
    allowed_targets = {
        proposal.record_id: proposal,
        readiness.record_id: readiness,
        authority.record_id: authority,
        **{record.record_id: record for record in approvals},
    }
    authority_binding = CommentBinding(authority.comment_id, authority.body_sha256)
    consumptions = 0

    for record in records:
        if record.record_type == "manifest_approval":
            if (
                tuple(record.subject_record_ids) != (authority.record_id,)
                or set(record.comment_bindings) != {authority_binding}
            ):
                return GuardResult.failure("GOVERNANCE_RECORD_INVALID")
            continue

        if record.record_type in {"revocation", "supersession"}:
            if not record.subject_record_ids:
                return GuardResult.failure("GOVERNANCE_RECORD_INVALID")
            targets = []
            for record_id in record.subject_record_ids:
                target = allowed_targets.get(record_id)
                if target is None or target.comment_id >= record.comment_id:
                    return GuardResult.failure("GOVERNANCE_RECORD_INVALID")
                targets.append(target)
            target_bindings = {
                CommentBinding(target.comment_id, target.body_sha256) for target in targets
            }
            if any(binding not in target_bindings for binding in record.comment_bindings):
                return GuardResult.failure("GOVERNANCE_RECORD_INVALID")
            continue

        if record.record_type == "consumption":
            consumptions += 1
            if consumptions > 1:
                return GuardResult.failure("GOVERNANCE_RECORD_INVALID")
            if tuple(record.subject_record_ids) != (authority.record_id,):
                return GuardResult.failure("GOVERNANCE_RECORD_INVALID")
            if record.comment_id <= authority.comment_id:
                return GuardResult.failure("GOVERNANCE_RECORD_INVALID")
            if any(binding != authority_binding for binding in record.comment_bindings):
                return GuardResult.failure("GOVERNANCE_RECORD_INVALID")

    return None


def _evaluate_governance(
    manifest: ExecutionManifest,
    observation: GuardObservation,
) -> GuardResult | None:
    records = _relevant_records(manifest, observation.governance_records)

    proposal = _exact_record(records, record_type="proposal", binding=manifest.proposal)
    readiness = _exact_record(records, record_type="readiness", binding=manifest.readiness)
    authority = _exact_record(records, record_type="authority", binding=manifest.authority)
    if proposal is None or readiness is None or authority is None:
        return GuardResult.failure("GOVERNANCE_RECORD_INVALID")

    proposal_binding = CommentBinding(proposal.comment_id, proposal.body_sha256)
    readiness_binding = CommentBinding(readiness.comment_id, readiness.body_sha256)
    if (
        proposal.lineage_id is None
        or proposal.subject_record_ids
        or proposal.comment_bindings
        or readiness.lineage_id != proposal.lineage_id
        or set(readiness.subject_record_ids) != {proposal.record_id}
        or set(readiness.comment_bindings) != {proposal_binding}
        or not _valid_lineage_authority(authority, proposal=proposal, readiness=readiness)
    ):
        return GuardResult.failure("GOVERNANCE_RECORD_INVALID")

    lifecycle = _validate_manifest_lifecycle_records(
        records,
        proposal=proposal,
        readiness=readiness,
        authority=authority,
    )
    if lifecycle is not None:
        return lifecycle

    for record in (proposal, readiness, authority):
        if _is_invalidated(record.record_id, records):
            return GuardResult.failure("GOVERNANCE_SUPERSEDED")

    if readiness.payload["details"]["disposition"] != "ready":
        return GuardResult.failure("AUTHORITY_NOT_GRANTED")
    if authority.payload["details"]["disposition"] != "granted":
        return GuardResult.failure("AUTHORITY_NOT_GRANTED")

    active_authorities = [
        record
        for record in records
        if record.record_type == "authority"
        and record.lineage_id == authority.lineage_id
        and record.payload["details"].get("disposition") == "granted"
        and not _is_invalidated(record.record_id, records)
        and not _is_consumed(record.record_id, records)
    ]
    if any(
        not _valid_lineage_authority(record, proposal=proposal, readiness=readiness)
        for record in active_authorities
    ):
        return GuardResult.failure("GOVERNANCE_RECORD_INVALID")
    if len(active_authorities) > 1:
        return GuardResult.failure("GOVERNANCE_AMBIGUOUS")
    if _is_consumed(authority.record_id, records):
        return GuardResult.failure("AUTHORITY_CONSUMED")
    if not active_authorities or active_authorities[0].record_id != authority.record_id:
        return GuardResult.failure("AUTHORITY_NOT_GRANTED")

    if observation.stage != "preflight":
        if observation.manifest_approval is None:
            return GuardResult.failure("AUTHORITY_NOT_GRANTED")
        approval = _exact_record(
            records,
            record_type="manifest_approval",
            binding=observation.manifest_approval,
        )
        if approval is None:
            return GuardResult.failure("GOVERNANCE_RECORD_INVALID")
        if approval.payload["details"]["disposition"] != "approved":
            return GuardResult.failure("AUTHORITY_NOT_GRANTED")
        if authority.record_id not in approval.subject_record_ids or not _contains_binding(
            approval, CommentBinding(authority.comment_id, authority.body_sha256)
        ):
            return GuardResult.failure("GOVERNANCE_RECORD_INVALID")
        if _is_invalidated(approval.record_id, records):
            return GuardResult.failure("GOVERNANCE_SUPERSEDED")
    return None


def _compare_control(manifest: ExecutionManifest, observation: GuardObservation) -> GuardResult | None:
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
    expected_modules = tuple(
        ModuleBlob(str(item["path"]), str(item["blob_sha"]))
        for item in executor["module_blobs"]
    )
    if observation.module_blobs != expected_modules:
        return GuardResult.failure("CONTROL_IDENTITY_CHANGED")
    return None


def _compare_app(manifest: ExecutionManifest, observation: GuardObservation) -> GuardResult | None:
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
