from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Sequence

from . import governance_state_v1 as _state_v1
from . import governance_state_v2 as _v2
from . import operator_manifest_v1 as _manifest_v1
from .operator_manifest_v3 import (
    MANIFEST_V3_FIELDS,
    ExecutionManifestV3,
    parse_execution_manifest_v3,
)
from .transition_witness import TransitionWitness


@dataclass(frozen=True)
class GuardedExecutionManifestV3(ExecutionManifestV3):
    governance_history: _manifest_v1.HistoryBaseline
    manifest_comment_id: int | None = None


@dataclass(frozen=True)
class GovernanceStateV3:
    proposal: _manifest_v1.GovernanceRecord
    approval_status: str
    active_approval: _manifest_v1.GovernanceRecord | None
    transition_status: str
    transition_witness: TransitionWitness | None
    readiness_status: str
    readiness: _manifest_v1.GovernanceRecord | None
    authority_status: str
    active_authority: _manifest_v1.GovernanceRecord | None
    consumption: _manifest_v1.GovernanceRecord | None


def attach_manifest_comment_id_v3(
    manifest: GuardedExecutionManifestV3, manifest_comment_id: int
) -> GuardedExecutionManifestV3:
    if type(manifest_comment_id) is not int or manifest_comment_id <= 0:
        raise _manifest_v1.OperatorContractError("MANIFEST_COMMENT_ID_INVALID")
    if manifest.manifest_comment_id not in (None, manifest_comment_id):
        raise _manifest_v1.OperatorContractError("MANIFEST_COMMENT_ID_MISMATCH")
    return replace(manifest, manifest_comment_id=manifest_comment_id)


def parse_guarded_execution_manifest_v3(
    raw: str,
    *,
    expected_sha256: str | None = None,
) -> GuardedExecutionManifestV3:
    value = _state_v1._strict_guarded_json(raw)
    expected_fields = MANIFEST_V3_FIELDS | frozenset({"governance_history"})
    if frozenset(value) != expected_fields:
        raise _manifest_v1.OperatorContractError("MANIFEST_SCHEMA_MISMATCH")

    history = value.get("governance_history")
    if (
        not isinstance(history, dict)
        or frozenset(history) != frozenset({"through_id", "history_sha256"})
        or type(history.get("through_id")) is not int
        or history["through_id"] < 0
        or not isinstance(history.get("history_sha256"), str)
        or _manifest_v1.SHA256.fullmatch(history["history_sha256"]) is None
    ):
        raise _manifest_v1.OperatorContractError("MANIFEST_GOVERNANCE_HISTORY_INVALID")

    core = dict(value)
    del core["governance_history"]
    parse_execution_manifest_v3(_manifest_v1.canonical_json(core))

    digest = _manifest_v1.sha256_text(raw)
    if expected_sha256 is not None:
        _manifest_v1._require_hex(
            expected_sha256,
            _manifest_v1.SHA256,
            "MANIFEST_EXPECTED_DIGEST_INVALID",
        )
        if digest != expected_sha256:
            raise _manifest_v1.OperatorContractError("MANIFEST_IDENTITY_MISMATCH")

    return GuardedExecutionManifestV3(
        _state_v1._freeze(value),
        digest,
        _manifest_v1.HistoryBaseline(
            int(history["through_id"]), str(history["history_sha256"])
        ),
        None,
    )


def validate_governance_history_v3(
    manifest: GuardedExecutionManifestV3,
    history: _state_v1.GovernanceHistory,
) -> tuple[_manifest_v1.GovernanceRecord, ...]:
    if not isinstance(manifest, GuardedExecutionManifestV3):
        raise _state_v1.GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    if not isinstance(history, _state_v1.GovernanceHistory):
        raise _state_v1.GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    if history.manifest_sha256 != manifest.sha256 or not isinstance(history.records, tuple):
        raise _state_v1.GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")

    records = _v2._records_from_sources_v2(manifest, history.records)
    if any(record.operation != manifest.operation for record in records):
        raise _state_v1.GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    actual = _state_v1.governance_history_baseline(records)
    if actual != history.baseline:
        raise _state_v1.GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")

    required = manifest.governance_history
    required_through = manifest.proposal.comment_id
    if required.through_id < required_through or history.baseline.through_id < required.through_id:
        raise _state_v1.GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    anchored = _state_v1.governance_history_baseline(
        records, through_comment_id=required.through_id
    )
    if anchored != required:
        raise _state_v1.GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    return records


def _record_binding(record: _manifest_v1.GovernanceRecord) -> _manifest_v1.CommentBinding:
    return _manifest_v1.CommentBinding(record.comment_id, record.body_sha256)


def _witness_binding(witness: TransitionWitness) -> _manifest_v1.CommentBinding:
    return _manifest_v1.CommentBinding(witness.comment_id, witness.body_sha256)


def _exact_manifest_subject(
    record: _manifest_v1.GovernanceRecord,
    manifest: GuardedExecutionManifestV3,
    manifest_comment_id: int,
) -> bool:
    return _v2._is_exact_manifest_subject(record, manifest, manifest_comment_id)


def _active_exact_approval(
    records: Sequence[_manifest_v1.GovernanceRecord],
    manifest: GuardedExecutionManifestV3,
    proposal: _manifest_v1.GovernanceRecord,
    manifest_comment_id: int,
    witness: TransitionWitness,
) -> _manifest_v1.GovernanceRecord:
    proposal_binding = _record_binding(proposal)
    preflight_binding = witness.preflight_evidence
    exact = [
        record
        for record in records
        if record.record_type == "manifest_approval"
        and _exact_manifest_subject(record, manifest, manifest_comment_id)
    ]
    valid: list[_manifest_v1.GovernanceRecord] = []
    for approval in exact:
        if (
            set(approval.subject_record_ids) != {proposal.record_id}
            or set(approval.comment_bindings) != {proposal_binding, preflight_binding}
            or approval.comment_id <= preflight_binding.comment_id
        ):
            raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")
        if not _v2._invalidated(approval, records, manifest, manifest_comment_id):
            valid.append(approval)
    if len(valid) > 1:
        raise _state_v1.GovernanceStateError("GOVERNANCE_AMBIGUOUS")
    if not valid or valid[0].details["disposition"] != "approved":
        raise _state_v1.GovernanceStateError("AUTHORITY_NOT_GRANTED")
    return valid[0]


def validate_transition_witness_v3(
    manifest: GuardedExecutionManifestV3,
    proposal: _manifest_v1.GovernanceRecord,
    approval: _manifest_v1.GovernanceRecord,
    witness: TransitionWitness,
    *,
    manifest_comment_id: int,
) -> None:
    if not isinstance(witness, TransitionWitness):
        raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")
    if (
        witness.payload.get("governing_issue") != manifest.governing_issue
        or witness.payload.get("operation") != manifest.operation
        or witness.proposal != _record_binding(proposal)
        or witness.manifest_comment_id != manifest_comment_id
        or witness.manifest_sha256 != manifest.sha256
        or witness.approval_record_id != approval.record_id
        or witness.approval != _record_binding(approval)
        or witness.payload.get("preflight_disposition") != "PASS"
        or witness.payload.get("run_attempt") != 1
        or witness.payload.get("capability_mode") != "capability-denied"
        or witness.payload["architecture_completion"].get("issue_number") != 40
        or witness.payload["architecture_completion"].get("disposition") != "COMPLETE"
        or witness.payload.get("workstream_e_authorised") is not False
    ):
        raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")

    completion = witness.architecture_completion
    if not (
        proposal.comment_id
        < manifest_comment_id
        < witness.preflight_evidence.comment_id
        < approval.comment_id
        < completion.comment_id
        < witness.comment_id
    ):
        raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")


def _active_readiness(
    records: Sequence[_manifest_v1.GovernanceRecord],
    manifest: GuardedExecutionManifestV3,
    proposal: _manifest_v1.GovernanceRecord,
    approval: _manifest_v1.GovernanceRecord,
    witness: TransitionWitness,
    manifest_comment_id: int,
) -> _manifest_v1.GovernanceRecord:
    expected_ids = {proposal.record_id, approval.record_id}
    expected_bindings = {
        _record_binding(proposal),
        _record_binding(approval),
        _witness_binding(witness),
    }
    candidates = [
        record
        for record in records
        if record.record_type == "readiness" and record.lineage_id == proposal.lineage_id
    ]
    valid: list[_manifest_v1.GovernanceRecord] = []
    for readiness in candidates:
        references_chain = bool(expected_ids.intersection(set(readiness.subject_record_ids)))
        if (
            set(readiness.subject_record_ids) != expected_ids
            or set(readiness.comment_bindings) != expected_bindings
            or readiness.comment_id <= witness.comment_id
        ):
            if references_chain:
                raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")
            continue
        if readiness.details["disposition"] != "ready":
            raise _state_v1.GovernanceStateError("AUTHORITY_NOT_GRANTED")
        if not _v2._invalidated(readiness, records, manifest, manifest_comment_id):
            valid.append(readiness)
    if len(valid) > 1:
        raise _state_v1.GovernanceStateError("GOVERNANCE_AMBIGUOUS")
    if not valid:
        raise _state_v1.GovernanceStateError("AUTHORITY_NOT_GRANTED")
    return valid[0]


def _active_authority(
    records: Sequence[_manifest_v1.GovernanceRecord],
    manifest: GuardedExecutionManifestV3,
    proposal: _manifest_v1.GovernanceRecord,
    approval: _manifest_v1.GovernanceRecord,
    witness: TransitionWitness,
    readiness: _manifest_v1.GovernanceRecord,
    manifest_comment_id: int,
) -> tuple[_manifest_v1.GovernanceRecord, _manifest_v1.GovernanceRecord | None]:
    expected_ids = {proposal.record_id, approval.record_id, readiness.record_id}
    expected_bindings = {
        _record_binding(proposal),
        _record_binding(approval),
        _witness_binding(witness),
        _record_binding(readiness),
    }
    active: list[_manifest_v1.GovernanceRecord] = []
    consumed: list[_manifest_v1.GovernanceRecord] = []
    invalid: list[_manifest_v1.GovernanceRecord] = []

    for authority in records:
        if authority.record_type != "authority":
            continue
        subject = authority.payload["subject"]
        if frozenset(subject) != _v2.V2_AUTHORITY_SUBJECT_FIELDS:
            continue
        if authority.lineage_id != proposal.lineage_id:
            continue
        if (
            subject.get("manifest_sha256") != manifest.sha256
            or subject.get("manifest_comment_id") != manifest_comment_id
        ):
            if expected_ids.intersection(set(authority.subject_record_ids)):
                raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")
            continue
        if (
            set(authority.subject_record_ids) != expected_ids
            or set(authority.comment_bindings) != expected_bindings
            or authority.comment_id <= readiness.comment_id
            or authority.details.get("execution_authorised") is not True
            or authority.details.get("single_use") is not True
        ):
            raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")
        if _v2._consumed(authority, records, manifest, manifest_comment_id):
            consumed.append(authority)
        elif _v2._invalidated(authority, records, manifest, manifest_comment_id):
            invalid.append(authority)
        else:
            active.append(authority)

    if len(active) > 1:
        raise _state_v1.GovernanceStateError("GOVERNANCE_AMBIGUOUS")
    if active:
        authority = active[0]
        consumptions = [
            record
            for record in records
            if record.record_type == "consumption"
            and authority.record_id in record.subject_record_ids
            and _exact_manifest_subject(record, manifest, manifest_comment_id)
        ]
        if len(consumptions) > 1:
            raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")
        return authority, consumptions[0] if consumptions else None
    if consumed:
        raise _state_v1.GovernanceStateError("AUTHORITY_CONSUMED")
    if invalid:
        raise _state_v1.GovernanceStateError("GOVERNANCE_SUPERSEDED")
    raise _state_v1.GovernanceStateError("AUTHORITY_NOT_GRANTED")


def reduce_governance_history_v3(
    manifest: GuardedExecutionManifestV3,
    history: _state_v1.GovernanceHistory,
    *,
    manifest_comment_id: int | None = None,
    transition_witness: TransitionWitness | None = None,
    stage: str = "preflight",
) -> GovernanceStateV3:
    if stage not in {"preflight", "pre_readiness", "live"}:
        raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")

    records = validate_governance_history_v3(manifest, history)
    proposal = _v2._exact_record(records, "proposal", manifest.proposal)
    if proposal is None:
        raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")
    if (
        proposal.lineage_id is None
        or proposal.subject_record_ids
        or proposal.comment_bindings
        or proposal.details["disposition"] != "proposed"
    ):
        raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")

    if stage == "preflight":
        return GovernanceStateV3(
            proposal, "absent", None, "not_required", None,
            "not_established", None, "not_granted", None, None,
        )

    manifest_id = manifest_comment_id or manifest.manifest_comment_id
    if type(manifest_id) is not int or manifest_id <= 0:
        raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")
    if not isinstance(transition_witness, TransitionWitness):
        raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")

    approval = _active_exact_approval(records, manifest, proposal, manifest_id, transition_witness)
    validate_transition_witness_v3(
        manifest,
        proposal,
        approval,
        transition_witness,
        manifest_comment_id=manifest_id,
    )

    if stage == "pre_readiness":
        return GovernanceStateV3(
            proposal, "approved", approval, "complete", transition_witness,
            "not_established", None, "not_granted", None, None,
        )

    readiness = _active_readiness(
        records, manifest, proposal, approval, transition_witness, manifest_id
    )
    authority, consumption = _active_authority(
        records,
        manifest,
        proposal,
        approval,
        transition_witness,
        readiness,
        manifest_id,
    )
    return GovernanceStateV3(
        proposal, "approved", approval, "complete", transition_witness,
        "ready", readiness, "active", authority, consumption,
    )
