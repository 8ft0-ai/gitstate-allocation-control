from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping, Sequence

from . import governance_state_v1 as _state_v1
from . import governance_state_v2 as _v2
from . import operator_manifest_v1 as _manifest_v1
from .operator_manifest_v3 import (
    MANIFEST_V3_FIELDS,
    ExecutionManifestV3,
    parse_execution_manifest_v3,
)
from .current_observation_readiness import (
    CONTROL_REPOSITORY as READINESS_CONTROL_REPOSITORY,
    READINESS_CONTRACT as CURRENT_OBSERVATION_READINESS_CONTRACT,
    READINESS_STATUS_READY,
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


EXTERNAL_PROPOSAL_FIELDS = frozenset(
    {
        "contract",
        "record_type",
        "proposal_contract",
        "governing_issue",
        "operation",
        "manifest_contract",
        "lineage_id",
        "implementation",
        "governance",
        "transport_preparation",
        "current_observation_execution",
        "external_readiness",
        "constraints",
    }
)
EXTERNAL_PROPOSAL_CONTRACT = "gitstate-v3-first-manifest-proposal/v4"
EXTERNAL_IMPLEMENTATION_FIELDS = frozenset(
    {
        "repository",
        "commit",
        "tree",
        "workflow",
        "module_blobs",
        "protocol_sha",
        "protected_tag",
        "relay_workflow",
        "relay_module",
        "policy_blob",
    }
)
EXTERNAL_READINESS_FIELDS = frozenset(
    {
        "repository",
        "pr",
        "comment_id",
        "contract",
        "body_sha256",
        "payload_sha256",
        "provenance_class",
        "subject_commit",
        "subject_tree",
        "protected_tag",
        "readiness_status",
        "matching_request_count_at_handoff",
        "matching_consumption_count_at_handoff",
        "matching_execution_count_at_handoff",
        "matching_rerun_count_at_handoff",
    }
)
EXTERNAL_LINEAGE = re.compile(
    r"^gitstate-lab#([1-9][0-9]*)/v3-first-manifest/([1-9][0-9]*)$"
)
EXTERNAL_RECORD_DOMAIN = "gitstate-external-proposal-record/v1"
EXTERNAL_LINEAGE_DOMAIN = "gitstate-external-proposal-lineage/v1"


def external_proposal_record_id(comment_id: int, body_sha256: str) -> str:
    if type(comment_id) is not int or comment_id <= 0:
        raise _manifest_v1.OperatorContractError("GOVERNANCE_COMMENT_INVALID")
    _manifest_v1._require_hex(
        body_sha256, _manifest_v1.SHA256, "GOVERNANCE_BODY_DIGEST_MISMATCH"
    )
    return _manifest_v1.sha256_text(
        f"{EXTERNAL_RECORD_DOMAIN}\n{comment_id}\n{body_sha256}"
    )


def external_proposal_lineage_id(lineage_id: str) -> str:
    if not isinstance(lineage_id, str) or EXTERNAL_LINEAGE.fullmatch(lineage_id) is None:
        raise _manifest_v1.OperatorContractError("GOVERNANCE_SUBJECT_INVALID")
    return _manifest_v1.sha256_text(f"{EXTERNAL_LINEAGE_DOMAIN}\n{lineage_id}")


def _external_proposal_source_v3(
    comment: Mapping[str, Any],
    manifest: ExecutionManifestV3,
    *,
    expected_owner: str,
) -> _manifest_v1.GovernanceRecord:
    comment_id = comment.get("id")
    body = comment.get("body")
    if type(comment_id) is not int or comment_id <= 0 or not isinstance(body, str):
        raise _manifest_v1.OperatorContractError("GOVERNANCE_COMMENT_INVALID")
    if comment_id != manifest.proposal.comment_id:
        raise _manifest_v1.OperatorContractError("GOVERNANCE_RECORD_INVALID")

    lines = body.splitlines()
    reserved_like = [line for line in lines if line.startswith("/gitstate-governance-v1")]
    machine_lines = [
        line for line in lines if line.startswith(_manifest_v1.GOVERNANCE_PREFIX)
    ]
    if len(reserved_like) != 1 or len(machine_lines) != 1:
        raise _manifest_v1.OperatorContractError("GOVERNANCE_RESERVED_LINE_INVALID")

    user = comment.get("user")
    if not isinstance(user, Mapping) or user.get("login") != expected_owner:
        raise _manifest_v1.OperatorContractError("GOVERNANCE_WRONG_OWNER")
    created = comment.get("created_at")
    updated = comment.get("updated_at")
    _manifest_v1._parse_time(created, "GOVERNANCE_COMMENT_TIME_INVALID")
    if created != updated:
        raise _manifest_v1.OperatorContractError("GOVERNANCE_SOURCE_EDITED")

    body_digest = _manifest_v1.sha256_text(body)
    if body_digest != manifest.proposal.body_sha256:
        raise _manifest_v1.OperatorContractError("GOVERNANCE_BODY_DIGEST_MISMATCH")

    value = _manifest_v1._strict_json(
        machine_lines[0][len(_manifest_v1.GOVERNANCE_PREFIX) :],
        "GOVERNANCE_JSON_INVALID",
    )
    _manifest_v1._require_exact_keys(
        value, EXTERNAL_PROPOSAL_FIELDS, "GOVERNANCE_SCHEMA_MISMATCH"
    )
    if value.get("contract") != _manifest_v1.GOVERNANCE_CONTRACT:
        raise _manifest_v1.OperatorContractError("GOVERNANCE_CONTRACT_MISMATCH")
    if value.get("record_type") != "proposal":
        raise _manifest_v1.OperatorContractError("GOVERNANCE_RECORD_TYPE_INVALID")
    proposal_contract = value.get("proposal_contract")
    if proposal_contract != EXTERNAL_PROPOSAL_CONTRACT:
        raise _manifest_v1.OperatorContractError("GOVERNANCE_EXTERNAL_PROPOSAL_CONTRACT_INVALID")
    if value.get("governing_issue") != manifest.governing_issue:
        raise _manifest_v1.OperatorContractError("GOVERNANCE_ISSUE_MISMATCH")
    if value.get("operation") != manifest.operation:
        raise _manifest_v1.OperatorContractError("GOVERNANCE_OPERATION_INVALID")
    if value.get("manifest_contract") != "gitstate-live-execution-manifest/v3":
        raise _manifest_v1.OperatorContractError("GOVERNANCE_EXTERNAL_MANIFEST_CONTRACT_INVALID")

    external_lineage = value.get("lineage_id")
    match = EXTERNAL_LINEAGE.fullmatch(external_lineage) if isinstance(external_lineage, str) else None
    if match is None or int(match.group(1)) != manifest.governing_issue:
        raise _manifest_v1.OperatorContractError("GOVERNANCE_SUBJECT_INVALID")

    for key in (
        "implementation",
        "governance",
        "transport_preparation",
        "current_observation_execution",
        "external_readiness",
        "constraints",
    ):
        if not isinstance(value.get(key), dict):
            raise _manifest_v1.OperatorContractError("GOVERNANCE_EXTERNAL_PROPOSAL_INVALID")

    implementation = value["implementation"]
    executor = manifest.payload["executor"]
    if frozenset(implementation) != EXTERNAL_IMPLEMENTATION_FIELDS:
        raise _manifest_v1.OperatorContractError("GOVERNANCE_EXTERNAL_IMPLEMENTATION_MISMATCH")
    if (
        implementation.get("repository") != executor["repository"]
        or implementation.get("commit") != executor["commit_sha"]
        or implementation.get("tree") != executor["tree_sha"]
        or implementation.get("protocol_sha") != manifest.payload["protocol_sha"]
        or implementation.get("protected_tag")
        != f"refs/tags/gitstate-current-observation/{executor['commit_sha']}"
    ):
        raise _manifest_v1.OperatorContractError("GOVERNANCE_EXTERNAL_IMPLEMENTATION_MISMATCH")

    readiness = value["external_readiness"]
    if frozenset(readiness) != EXTERNAL_READINESS_FIELDS:
        raise _manifest_v1.OperatorContractError("GOVERNANCE_EXTERNAL_READINESS_MISMATCH")
    if (
        readiness.get("repository") != READINESS_CONTROL_REPOSITORY
        or readiness.get("contract") != CURRENT_OBSERVATION_READINESS_CONTRACT
        or readiness.get("readiness_status") != READINESS_STATUS_READY
        or readiness.get("subject_commit") != executor["commit_sha"]
        or readiness.get("subject_tree") != executor["tree_sha"]
        or readiness.get("protected_tag")
        != f"refs/tags/gitstate-current-observation/{executor['commit_sha']}"
    ):
        raise _manifest_v1.OperatorContractError("GOVERNANCE_EXTERNAL_READINESS_MISMATCH")
    for key in ("body_sha256", "payload_sha256"):
        _manifest_v1._require_hex(
            readiness.get(key),
            _manifest_v1.SHA256,
            "GOVERNANCE_EXTERNAL_READINESS_MISMATCH",
        )
    for key in (
        "matching_request_count_at_handoff",
        "matching_consumption_count_at_handoff",
        "matching_execution_count_at_handoff",
        "matching_rerun_count_at_handoff",
    ):
        if type(readiness.get(key)) is not int or readiness.get(key) != 0:
            raise _manifest_v1.OperatorContractError("GOVERNANCE_EXTERNAL_READINESS_MISMATCH")

    record_id = external_proposal_record_id(comment_id, body_digest)
    lineage_id = external_proposal_lineage_id(str(external_lineage))
    synthetic = {
        "contract": _manifest_v1.GOVERNANCE_CONTRACT,
        "record_id": record_id,
        "record_type": "proposal",
        "governing_issue": manifest.governing_issue,
        "operation": manifest.operation,
        "subject": {
            "lineage_id": lineage_id,
            "record_ids": [],
            "comment_bindings": [],
        },
        "details": {"disposition": "proposed"},
        "workstream_e_authorised": False,
    }
    source = _manifest_v1.GovernanceSource(
        comment_id=comment_id,
        body=body,
        owner=str(user["login"]),
        created_at=str(created),
        updated_at=str(updated),
    )
    return _manifest_v1.GovernanceRecord(
        _state_v1._freeze(synthetic), comment_id, body_digest, source
    )


def parse_governance_comments_for_manifest_v3(
    manifest: ExecutionManifestV3,
    comments: Iterable[Mapping[str, Any]],
    *,
    expected_owner: str,
    expected_issue: int,
) -> tuple[_manifest_v1.GovernanceRecord, ...]:
    if not isinstance(manifest, ExecutionManifestV3):
        raise _manifest_v1.OperatorContractError("MANIFEST_CONTRACT_MISMATCH")
    if expected_issue != manifest.governing_issue:
        raise _manifest_v1.OperatorContractError("GOVERNANCE_ISSUE_MISMATCH")

    records: list[_manifest_v1.GovernanceRecord] = []
    seen_comments: set[int] = set()
    seen_records: set[str] = set()
    for comment in comments:
        comment_id = comment.get("id")
        if comment_id == manifest.proposal.comment_id:
            body = comment.get("body")
            if not isinstance(body, str):
                raise _manifest_v1.OperatorContractError("GOVERNANCE_COMMENT_INVALID")
            lines = body.splitlines()
            machine_lines = [
                line for line in lines if line.startswith(_manifest_v1.GOVERNANCE_PREFIX)
            ]
            if len(machine_lines) != 1:
                raise _manifest_v1.OperatorContractError("GOVERNANCE_RESERVED_LINE_INVALID")
            value = _manifest_v1._strict_json(
                machine_lines[0][len(_manifest_v1.GOVERNANCE_PREFIX) :],
                "GOVERNANCE_JSON_INVALID",
            )
            if frozenset(value) == _manifest_v1.GOVERNANCE_FIELDS:
                record = _v2.parse_governance_comment_v2(
                    comment,
                    expected_owner=expected_owner,
                    expected_issue=expected_issue,
                    expected_body_sha256=manifest.proposal.body_sha256,
                )
            elif frozenset(value) == EXTERNAL_PROPOSAL_FIELDS:
                record = _external_proposal_source_v3(
                    comment, manifest, expected_owner=expected_owner
                )
            else:
                raise _manifest_v1.OperatorContractError("GOVERNANCE_SCHEMA_MISMATCH")
        else:
            record = _v2.parse_governance_comment_v2(
                comment,
                expected_owner=expected_owner,
                expected_issue=expected_issue,
            )
        if record is None:
            continue
        if record.comment_id in seen_comments:
            raise _manifest_v1.OperatorContractError("GOVERNANCE_DUPLICATE_COMMENT_ID")
        if record.record_id in seen_records:
            raise _manifest_v1.OperatorContractError("GOVERNANCE_DUPLICATE_RECORD_ID")
        seen_comments.add(record.comment_id)
        seen_records.add(record.record_id)
        records.append(record)
    return tuple(sorted(records, key=lambda item: item.comment_id))


def _records_from_sources_v3(
    manifest: GuardedExecutionManifestV3,
    sources: tuple[_manifest_v1.GovernanceSource, ...],
) -> tuple[_manifest_v1.GovernanceRecord, ...]:
    comments: list[dict[str, Any]] = []
    previous = 0
    for source in sources:
        if not isinstance(source, _manifest_v1.GovernanceSource):
            raise _state_v1.GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
        if source.comment_id <= previous:
            raise _state_v1.GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
        previous = source.comment_id
        comments.append(
            {
                "id": source.comment_id,
                "body": source.body,
                "user": {"login": source.owner},
                "created_at": source.created_at,
                "updated_at": source.updated_at,
            }
        )
    try:
        return parse_governance_comments_for_manifest_v3(
            manifest,
            comments,
            expected_owner=_manifest_v1.GOVERNANCE_OWNER,
            expected_issue=manifest.governing_issue,
        )
    except (_manifest_v1.OperatorContractError, TypeError, ValueError, KeyError) as exc:
        raise _state_v1.GovernanceStateError("GOVERNANCE_HISTORY_CHANGED") from exc


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

    records = _records_from_sources_v3(manifest, history.records)
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
