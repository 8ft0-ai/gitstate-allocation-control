from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping, Sequence

from . import governance_state_v1 as _state_v1
from . import operator_manifest_v1 as _manifest_v1
from .operator_manifest_v2 import (
    MANIFEST_V2_CONTRACT,
    MANIFEST_V2_FIELDS,
    ExecutionManifestV2,
    parse_execution_manifest_v2,
)


V2_MANIFEST_SUBJECT_FIELDS = frozenset(
    {"manifest_sha256", "manifest_comment_id", "record_ids", "comment_bindings"}
)
V2_AUTHORITY_SUBJECT_FIELDS = frozenset(
    {
        "lineage_id",
        "manifest_sha256",
        "manifest_comment_id",
        "record_ids",
        "comment_bindings",
    }
)


@dataclass(frozen=True)
class GuardedExecutionManifestV2(ExecutionManifestV2):
    governance_history: _manifest_v1.HistoryBaseline
    manifest_comment_id: int | None = None


@dataclass(frozen=True)
class GovernanceStateV2:
    proposal: _manifest_v1.GovernanceRecord
    readiness: _manifest_v1.GovernanceRecord
    approval_status: str
    active_approval: _manifest_v1.GovernanceRecord | None
    authority_status: str
    active_authority: _manifest_v1.GovernanceRecord | None
    consumption: _manifest_v1.GovernanceRecord | None


def attach_manifest_comment_id(
    manifest: GuardedExecutionManifestV2, manifest_comment_id: int
) -> GuardedExecutionManifestV2:
    if type(manifest_comment_id) is not int or manifest_comment_id <= 0:
        raise _manifest_v1.OperatorContractError("MANIFEST_COMMENT_ID_INVALID")
    if manifest.manifest_comment_id not in (None, manifest_comment_id):
        raise _manifest_v1.OperatorContractError("MANIFEST_COMMENT_ID_MISMATCH")
    return replace(manifest, manifest_comment_id=manifest_comment_id)


def parse_guarded_execution_manifest_v2(
    raw: str,
    *,
    expected_sha256: str | None = None,
) -> GuardedExecutionManifestV2:
    value = _state_v1._strict_guarded_json(raw)
    expected_fields = MANIFEST_V2_FIELDS | frozenset({"governance_history"})
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
    parse_execution_manifest_v2(_manifest_v1.canonical_json(core))

    digest = _manifest_v1.sha256_text(raw)
    if expected_sha256 is not None:
        if (
            not isinstance(expected_sha256, str)
            or _manifest_v1.SHA256.fullmatch(expected_sha256) is None
        ):
            raise _manifest_v1.OperatorContractError(
                "MANIFEST_EXPECTED_DIGEST_INVALID"
            )
        if digest != expected_sha256:
            raise _manifest_v1.OperatorContractError("MANIFEST_IDENTITY_MISMATCH")

    return GuardedExecutionManifestV2(
        _state_v1._freeze(value),
        digest,
        _manifest_v1.HistoryBaseline(
            int(history["through_id"]), str(history["history_sha256"])
        ),
        None,
    )


def _require_record_lists(value: Mapping[str, Any]) -> None:
    record_ids = value.get("record_ids")
    if not isinstance(record_ids, list):
        raise _manifest_v1.OperatorContractError("GOVERNANCE_SUBJECT_INVALID")
    for record_id in record_ids:
        _manifest_v1._require_hex(
            record_id, _manifest_v1.OPAQUE_ID, "GOVERNANCE_SUBJECT_INVALID"
        )
    if record_ids != sorted(record_ids) or len(record_ids) != len(set(record_ids)):
        raise _manifest_v1.OperatorContractError("GOVERNANCE_SUBJECT_INVALID")

    bindings = value.get("comment_bindings")
    if not isinstance(bindings, list):
        raise _manifest_v1.OperatorContractError("GOVERNANCE_SUBJECT_INVALID")
    ids: list[int] = []
    for binding in bindings:
        parsed = _manifest_v1._require_comment_binding(
            binding, "GOVERNANCE_SUBJECT_INVALID"
        )
        ids.append(int(parsed["comment_id"]))
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise _manifest_v1.OperatorContractError("GOVERNANCE_SUBJECT_INVALID")


def _require_v2_subject(record_type: str, value: Any) -> None:
    if not isinstance(value, dict):
        raise _manifest_v1.OperatorContractError("GOVERNANCE_SUBJECT_INVALID")
    keys = frozenset(value)
    if record_type in {"proposal", "readiness"}:
        _manifest_v1._require_subject(record_type, value)
        return
    if record_type == "authority":
        if keys == _manifest_v1.LINEAGE_SUBJECT_FIELDS:
            _manifest_v1._require_subject(record_type, value)
            return
        _manifest_v1._require_exact_keys(
            value, V2_AUTHORITY_SUBJECT_FIELDS, "GOVERNANCE_SUBJECT_INVALID"
        )
        _manifest_v1._require_hex(
            value.get("lineage_id"),
            _manifest_v1.OPAQUE_ID,
            "GOVERNANCE_SUBJECT_INVALID",
        )
    else:
        if keys == _manifest_v1.MANIFEST_SUBJECT_FIELDS:
            _manifest_v1._require_subject(record_type, value)
            return
        _manifest_v1._require_exact_keys(
            value, V2_MANIFEST_SUBJECT_FIELDS, "GOVERNANCE_SUBJECT_INVALID"
        )
    if keys in {V2_AUTHORITY_SUBJECT_FIELDS, V2_MANIFEST_SUBJECT_FIELDS}:
        _manifest_v1._require_hex(
            value.get("manifest_sha256"),
            _manifest_v1.SHA256,
            "GOVERNANCE_SUBJECT_INVALID",
        )
        _manifest_v1._require_int(
            value.get("manifest_comment_id"), "GOVERNANCE_SUBJECT_INVALID"
        )
        _require_record_lists(value)


def parse_governance_comment_v2(
    comment: Mapping[str, Any],
    *,
    expected_owner: str,
    expected_issue: int,
    expected_body_sha256: str | None = None,
) -> _manifest_v1.GovernanceRecord | None:
    comment_id = comment.get("id")
    body = comment.get("body")
    if not isinstance(body, str):
        raise _manifest_v1.OperatorContractError("GOVERNANCE_COMMENT_INVALID")
    lines = body.splitlines()
    reserved_like = [
        line for line in lines if line.startswith("/gitstate-governance-v1")
    ]
    machine_lines = [
        line for line in lines if line.startswith(_manifest_v1.GOVERNANCE_PREFIX)
    ]
    if not reserved_like:
        return None
    if len(reserved_like) != 1 or len(machine_lines) != 1:
        raise _manifest_v1.OperatorContractError(
            "GOVERNANCE_RESERVED_LINE_INVALID"
        )
    _manifest_v1._require_int(comment_id, "GOVERNANCE_COMMENT_INVALID")
    user = comment.get("user")
    if not isinstance(user, Mapping) or user.get("login") != expected_owner:
        raise _manifest_v1.OperatorContractError("GOVERNANCE_WRONG_OWNER")
    created = comment.get("created_at")
    updated = comment.get("updated_at")
    _manifest_v1._parse_time(created, "GOVERNANCE_COMMENT_TIME_INVALID")
    if created != updated:
        raise _manifest_v1.OperatorContractError("GOVERNANCE_SOURCE_EDITED")

    body_digest = _manifest_v1.sha256_text(body)
    if expected_body_sha256 is not None:
        _manifest_v1._require_hex(
            expected_body_sha256,
            _manifest_v1.SHA256,
            "GOVERNANCE_EXPECTED_DIGEST_INVALID",
        )
        if body_digest != expected_body_sha256:
            raise _manifest_v1.OperatorContractError(
                "GOVERNANCE_BODY_DIGEST_MISMATCH"
            )

    value = _manifest_v1._strict_json(
        machine_lines[0][len(_manifest_v1.GOVERNANCE_PREFIX) :],
        "GOVERNANCE_JSON_INVALID",
    )
    _manifest_v1._require_exact_keys(
        value, _manifest_v1.GOVERNANCE_FIELDS, "GOVERNANCE_SCHEMA_MISMATCH"
    )
    if value.get("contract") != _manifest_v1.GOVERNANCE_CONTRACT:
        raise _manifest_v1.OperatorContractError("GOVERNANCE_CONTRACT_MISMATCH")
    _manifest_v1._require_hex(
        value.get("record_id"),
        _manifest_v1.OPAQUE_ID,
        "GOVERNANCE_RECORD_ID_INVALID",
    )
    record_type = value.get("record_type")
    if record_type not in _manifest_v1.GOVERNANCE_RECORD_TYPES:
        raise _manifest_v1.OperatorContractError(
            "GOVERNANCE_RECORD_TYPE_INVALID"
        )
    if value.get("governing_issue") != expected_issue:
        raise _manifest_v1.OperatorContractError("GOVERNANCE_ISSUE_MISMATCH")
    _manifest_v1._require_string(
        value.get("operation"), "GOVERNANCE_OPERATION_INVALID"
    )
    _require_v2_subject(str(record_type), value.get("subject"))
    _manifest_v1._require_governance_details(
        str(record_type), value.get("details")
    )
    _manifest_v1._require_bool(
        value.get("workstream_e_authorised"),
        False,
        "WORKSTREAM_E_NOT_AUTHORISED",
    )
    source = _manifest_v1.GovernanceSource(
        comment_id=int(comment_id),
        body=body,
        owner=str(user["login"]),
        created_at=str(created),
        updated_at=str(updated),
    )
    return _manifest_v1.GovernanceRecord(
        _manifest_v1._freeze(value), int(comment_id), body_digest, source
    )


def parse_governance_comments_v2(
    comments: Iterable[Mapping[str, Any]],
    *,
    expected_owner: str,
    expected_issue: int,
) -> tuple[_manifest_v1.GovernanceRecord, ...]:
    records: list[_manifest_v1.GovernanceRecord] = []
    seen_comments: set[int] = set()
    seen_records: set[str] = set()
    for comment in comments:
        record = parse_governance_comment_v2(
            comment, expected_owner=expected_owner, expected_issue=expected_issue
        )
        if record is None:
            continue
        if record.comment_id in seen_comments:
            raise _manifest_v1.OperatorContractError(
                "GOVERNANCE_DUPLICATE_COMMENT_ID"
            )
        if record.record_id in seen_records:
            raise _manifest_v1.OperatorContractError(
                "GOVERNANCE_DUPLICATE_RECORD_ID"
            )
        seen_comments.add(record.comment_id)
        seen_records.add(record.record_id)
        records.append(record)
    return tuple(sorted(records, key=lambda item: item.comment_id))


def _records_from_sources_v2(
    manifest: GuardedExecutionManifestV2,
    sources: tuple[_manifest_v1.GovernanceSource, ...],
) -> tuple[_manifest_v1.GovernanceRecord, ...]:
    comments = []
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
        return parse_governance_comments_v2(
            comments,
            expected_owner=_manifest_v1.GOVERNANCE_OWNER,
            expected_issue=manifest.governing_issue,
        )
    except (_manifest_v1.OperatorContractError, TypeError, ValueError, KeyError) as exc:
        raise _state_v1.GovernanceStateError(
            "GOVERNANCE_HISTORY_CHANGED"
        ) from exc


def validate_governance_history_v2(
    manifest: GuardedExecutionManifestV2,
    history: _state_v1.GovernanceHistory,
) -> tuple[_manifest_v1.GovernanceRecord, ...]:
    if not isinstance(manifest, GuardedExecutionManifestV2):
        raise _state_v1.GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    if not isinstance(history, _state_v1.GovernanceHistory):
        raise _state_v1.GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    if (
        history.manifest_sha256 != manifest.sha256
        or not isinstance(history.records, tuple)
    ):
        raise _state_v1.GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")

    records = _records_from_sources_v2(manifest, history.records)
    if any(record.operation != manifest.operation for record in records):
        raise _state_v1.GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    actual = _state_v1.governance_history_baseline(records)
    if actual != history.baseline:
        raise _state_v1.GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")

    required = manifest.governance_history
    required_through = max(
        manifest.proposal.comment_id, manifest.readiness.comment_id
    )
    if (
        required.through_id < required_through
        or history.baseline.through_id < required.through_id
    ):
        raise _state_v1.GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    anchored = _state_v1.governance_history_baseline(
        records, through_comment_id=required.through_id
    )
    if anchored != required:
        raise _state_v1.GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    return records


def _same_binding(
    record: _manifest_v1.GovernanceRecord,
    binding: _manifest_v1.CommentBinding,
) -> bool:
    return (
        record.comment_id == binding.comment_id
        and record.body_sha256 == binding.body_sha256
    )


def _exact_record(
    records: Sequence[_manifest_v1.GovernanceRecord],
    record_type: str,
    binding: _manifest_v1.CommentBinding,
):
    matches = [
        record
        for record in records
        if record.record_type == record_type and _same_binding(record, binding)
    ]
    return matches[0] if len(matches) == 1 else None


def _binding_set(records: Sequence[_manifest_v1.GovernanceRecord]):
    return {
        _manifest_v1.CommentBinding(record.comment_id, record.body_sha256)
        for record in records
    }


def _is_exact_manifest_subject(
    record: _manifest_v1.GovernanceRecord,
    manifest: GuardedExecutionManifestV2,
    manifest_comment_id: int,
) -> bool:
    subject = record.payload["subject"]
    return (
        frozenset(subject) in {V2_MANIFEST_SUBJECT_FIELDS, V2_AUTHORITY_SUBJECT_FIELDS}
        and subject.get("manifest_sha256") == manifest.sha256
        and subject.get("manifest_comment_id") == manifest_comment_id
    )


def _lifecycle_matches(
    candidate: _manifest_v1.GovernanceRecord,
    target: _manifest_v1.GovernanceRecord,
    manifest: GuardedExecutionManifestV2,
    manifest_comment_id: int,
) -> bool:
    if target.record_id not in candidate.subject_record_ids:
        return False
    if not _is_exact_manifest_subject(
        candidate, manifest, manifest_comment_id
    ):
        raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")
    target_binding = _manifest_v1.CommentBinding(
        target.comment_id, target.body_sha256
    )
    if (
        target_binding not in set(candidate.comment_bindings)
        or candidate.comment_id <= target.comment_id
    ):
        raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")
    return True


def _invalidated(
    record: _manifest_v1.GovernanceRecord,
    records: Sequence[_manifest_v1.GovernanceRecord],
    manifest: GuardedExecutionManifestV2,
    manifest_comment_id: int,
) -> bool:
    return any(
        candidate.record_type in {"revocation", "supersession"}
        and _lifecycle_matches(
            candidate, record, manifest, manifest_comment_id
        )
        for candidate in records
    )


def _consumed(
    record: _manifest_v1.GovernanceRecord,
    records: Sequence[_manifest_v1.GovernanceRecord],
    manifest: GuardedExecutionManifestV2,
    manifest_comment_id: int,
) -> bool:
    return any(
        candidate.record_type == "consumption"
        and _lifecycle_matches(
            candidate, record, manifest, manifest_comment_id
        )
        for candidate in records
    )


def reduce_governance_history_v2(
    manifest: GuardedExecutionManifestV2,
    history: _state_v1.GovernanceHistory,
    *,
    manifest_comment_id: int | None = None,
    require_live_authority: bool = False,
) -> GovernanceStateV2:
    records = validate_governance_history_v2(manifest, history)
    proposal = _exact_record(records, "proposal", manifest.proposal)
    readiness = _exact_record(records, "readiness", manifest.readiness)
    if proposal is None or readiness is None:
        raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")

    proposal_binding = _manifest_v1.CommentBinding(
        proposal.comment_id, proposal.body_sha256
    )
    if (
        proposal.lineage_id is None
        or proposal.subject_record_ids
        or proposal.comment_bindings
        or readiness.lineage_id != proposal.lineage_id
        or tuple(readiness.subject_record_ids) != (proposal.record_id,)
        or tuple(readiness.comment_bindings) != (proposal_binding,)
        or readiness.details["disposition"] != "ready"
    ):
        raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")

    if not require_live_authority:
        return GovernanceStateV2(
            proposal,
            readiness,
            "absent",
            None,
            "not_granted",
            None,
            None,
        )

    manifest_id = manifest_comment_id or manifest.manifest_comment_id
    if type(manifest_id) is not int or manifest_id <= 0:
        raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")

    exact_approvals = [
        record
        for record in records
        if record.record_type == "manifest_approval"
        and _is_exact_manifest_subject(record, manifest, manifest_id)
    ]
    wrong_exact_approvals = [
        record
        for record in records
        if record.record_type == "manifest_approval"
        and frozenset(record.payload["subject"]) == V2_MANIFEST_SUBJECT_FIELDS
        and (
            record.payload["subject"].get("manifest_sha256") != manifest.sha256
            or record.payload["subject"].get("manifest_comment_id") != manifest_id
        )
    ]
    for record in wrong_exact_approvals:
        if {proposal.record_id, readiness.record_id}.intersection(
            record.subject_record_ids
        ):
            raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")

    valid_approvals = []
    for approval in exact_approvals:
        if (
            set(approval.subject_record_ids)
            != {proposal.record_id, readiness.record_id}
            or set(approval.comment_bindings)
            != _binding_set((proposal, readiness))
            or approval.comment_id <= readiness.comment_id
        ):
            raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")
        if not _invalidated(approval, records, manifest, manifest_id):
            valid_approvals.append(approval)
    if len(valid_approvals) > 1:
        raise _state_v1.GovernanceStateError("GOVERNANCE_AMBIGUOUS")
    if not valid_approvals or valid_approvals[0].details["disposition"] != "approved":
        raise _state_v1.GovernanceStateError("AUTHORITY_NOT_GRANTED")
    approval = valid_approvals[0]

    exact_authorities = []
    for authority in records:
        if authority.record_type != "authority":
            continue
        subject = authority.payload["subject"]
        if frozenset(subject) != V2_AUTHORITY_SUBJECT_FIELDS:
            continue
        if authority.lineage_id != proposal.lineage_id:
            continue
        if (
            subject.get("manifest_sha256") != manifest.sha256
            or subject.get("manifest_comment_id") != manifest_id
        ):
            if {proposal.record_id, readiness.record_id}.issubset(
                set(authority.subject_record_ids)
            ):
                raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")
            continue
        if (
            set(authority.subject_record_ids)
            != {proposal.record_id, readiness.record_id, approval.record_id}
            or set(authority.comment_bindings)
            != _binding_set((proposal, readiness, approval))
            or authority.comment_id <= approval.comment_id
            or authority.details.get("execution_authorised") is not True
            or authority.details.get("single_use") is not True
        ):
            raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")
        if not _invalidated(authority, records, manifest, manifest_id) and not _consumed(authority, records, manifest, manifest_id):
            exact_authorities.append(authority)

    if len(exact_authorities) > 1:
        raise _state_v1.GovernanceStateError("GOVERNANCE_AMBIGUOUS")
    if not exact_authorities:
        consumed_exact = [
            record
            for record in records
            if record.record_type == "authority"
            and frozenset(record.payload["subject"]) == V2_AUTHORITY_SUBJECT_FIELDS
            and record.lineage_id == proposal.lineage_id
            and record.payload["subject"].get("manifest_sha256") == manifest.sha256
            and record.payload["subject"].get("manifest_comment_id") == manifest_id
            and _consumed(record, records, manifest, manifest_id)
        ]
        if consumed_exact:
            raise _state_v1.GovernanceStateError("AUTHORITY_CONSUMED")
        invalid_exact = [
            record
            for record in records
            if record.record_type == "authority"
            and frozenset(record.payload["subject"]) == V2_AUTHORITY_SUBJECT_FIELDS
            and record.lineage_id == proposal.lineage_id
            and record.payload["subject"].get("manifest_sha256") == manifest.sha256
            and record.payload["subject"].get("manifest_comment_id") == manifest_id
            and _invalidated(record, records, manifest, manifest_id)
        ]
        if invalid_exact:
            raise _state_v1.GovernanceStateError("GOVERNANCE_SUPERSEDED")
        raise _state_v1.GovernanceStateError("AUTHORITY_NOT_GRANTED")

    authority = exact_authorities[0]
    consumptions = [
        record
        for record in records
        if record.record_type == "consumption"
        and authority.record_id in record.subject_record_ids
        and _is_exact_manifest_subject(record, manifest, manifest_id)
    ]
    if len(consumptions) > 1:
        raise _state_v1.GovernanceStateError("GOVERNANCE_RECORD_INVALID")
    consumption = consumptions[0] if consumptions else None
    return GovernanceStateV2(
        proposal,
        readiness,
        "approved",
        approval,
        "active",
        authority,
        consumption,
    )
