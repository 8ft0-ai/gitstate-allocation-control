from __future__ import annotations

from dataclasses import dataclass
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


@dataclass(frozen=True)
class OwnerObservation:
    observation_id: str
    observation_sha256: str
    valid: bool


@dataclass(frozen=True)
class GuardObservation:
    stage: str
    read_status: str
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


def _same_binding(record: GovernanceRecord, binding: CommentBinding) -> bool:
    return record.comment_id == binding.comment_id and record.body_sha256 == binding.body_sha256


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
    if (
        proposal.lineage_id is None
        or readiness.lineage_id != proposal.lineage_id
        or authority.lineage_id != proposal.lineage_id
        or proposal.record_id not in readiness.subject_record_ids
        or proposal.record_id not in authority.subject_record_ids
        or readiness.record_id not in authority.subject_record_ids
    ):
        return GuardResult.failure("GOVERNANCE_RECORD_INVALID")
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
    if len(active_authorities) > 1:
        return GuardResult.failure("GOVERNANCE_AMBIGUOUS")
    if _is_invalidated(authority.record_id, records):
        return GuardResult.failure("GOVERNANCE_SUPERSEDED")
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
        if authority.record_id not in approval.subject_record_ids:
            return GuardResult.failure("GOVERNANCE_RECORD_INVALID")
        if _is_invalidated(approval.record_id, records):
            return GuardResult.failure("GOVERNANCE_SUPERSEDED")
    return None


def _compare_control(manifest: ExecutionManifest, observation: GuardObservation) -> GuardResult | None:
    executor = manifest.payload["executor"]
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
    return None


def evaluate_guards(
    manifest: ExecutionManifest,
    observation: GuardObservation,
) -> GuardResult:
    if observation.stage not in STAGES or observation.read_status not in READ_STATUSES:
        return GuardResult.failure("OBSERVATION_SHAPE_UNSUPPORTED")
    if observation.read_status == "unavailable":
        return GuardResult.failure("READ_EVIDENCE_UNAVAILABLE")
    if observation.read_status == "rate_limited":
        return GuardResult.failure("READ_EVIDENCE_RATE_LIMITED")
    if observation.read_status == "ambiguous":
        return GuardResult.failure("READ_EVIDENCE_AMBIGUOUS")

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
    ):
        return GuardResult.failure("ENVIRONMENT_BOUNDARY_CHANGED")
    if environment["execution_variable_expected_absent"] and not observation.execution_variable_absent:
        return GuardResult.failure("EXECUTION_ENABLEMENT_CHANGED")
    return GuardResult.pass_result()
