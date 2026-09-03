from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

from .operator_manifest import (
    CommentBinding,
    ExecutionManifest,
    GovernanceRecord,
    HistoryBaseline,
    sha256_text,
)


SHA256 = re.compile(r"^[0-9a-f]{64}$")


class GovernanceStateError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class GovernanceHistory:
    """Manifest-bound snapshot supplied by a durable append-only history provider."""

    manifest_sha256: str
    baseline: HistoryBaseline
    records: tuple[GovernanceRecord, ...]


@dataclass(frozen=True)
class GovernanceState:
    proposal: GovernanceRecord
    readiness: GovernanceRecord
    authority: GovernanceRecord
    authority_status: str
    approval_status: str
    active_approval: GovernanceRecord | None
    consumption: GovernanceRecord | None
    terminal: GovernanceRecord | None


def canonical_governance_history(
    records: Sequence[GovernanceRecord],
    *,
    through_comment_id: int | None = None,
) -> str:
    ordered = tuple(sorted(records, key=lambda record: record.comment_id))
    seen_comments: set[int] = set()
    seen_records: set[str] = set()
    lines: list[str] = []
    for record in ordered:
        if not isinstance(record, GovernanceRecord):
            raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")
        if record.comment_id <= 0 or record.comment_id in seen_comments:
            raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")
        if record.record_id in seen_records:
            raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")
        if SHA256.fullmatch(record.body_sha256) is None:
            raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")
        seen_comments.add(record.comment_id)
        seen_records.add(record.record_id)
        if through_comment_id is None or record.comment_id <= through_comment_id:
            lines.append(
                f"{record.comment_id}\t{record.record_id}\t{record.record_type}\t{record.body_sha256}\n"
            )
    return "".join(lines)


def governance_history_baseline(
    records: Sequence[GovernanceRecord],
    *,
    through_comment_id: int | None = None,
) -> HistoryBaseline:
    selected = tuple(
        record
        for record in records
        if through_comment_id is None or record.comment_id <= through_comment_id
    )
    canonical = canonical_governance_history(records, through_comment_id=through_comment_id)
    through = max((record.comment_id for record in selected), default=0)
    return HistoryBaseline(through, sha256_text(canonical))


def build_governance_history(
    manifest_sha256: str,
    records: Sequence[GovernanceRecord],
) -> GovernanceHistory:
    ordered = tuple(sorted(records, key=lambda record: record.comment_id))
    return GovernanceHistory(
        manifest_sha256=manifest_sha256,
        baseline=governance_history_baseline(ordered),
        records=ordered,
    )


def validate_governance_history(
    manifest: ExecutionManifest,
    history: GovernanceHistory,
) -> None:
    if not isinstance(history, GovernanceHistory):
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    if SHA256.fullmatch(history.manifest_sha256) is None or history.manifest_sha256 != manifest.sha256:
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    if not isinstance(history.baseline, HistoryBaseline):
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    if not isinstance(history.records, tuple):
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    if tuple(sorted(history.records, key=lambda record: record.comment_id)) != history.records:
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    try:
        actual = governance_history_baseline(history.records)
    except GovernanceStateError:
        raise
    if actual != history.baseline:
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    required_through = max(
        manifest.proposal.comment_id,
        manifest.readiness.comment_id,
        manifest.authority.comment_id,
    )
    if history.baseline.through_id < required_through:
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")


def _same_binding(record: GovernanceRecord, binding: CommentBinding) -> bool:
    return record.comment_id == binding.comment_id and record.body_sha256 == binding.body_sha256


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


def _same_issue_operation(
    manifest: ExecutionManifest,
    records: Sequence[GovernanceRecord],
) -> tuple[GovernanceRecord, ...]:
    return tuple(
        record
        for record in records
        if record.governing_issue == manifest.governing_issue
        and record.operation == manifest.operation
    )


def _valid_lineage_authority(
    record: GovernanceRecord,
    *,
    proposal: GovernanceRecord,
    readiness: GovernanceRecord,
) -> bool:
    return (
        proposal.comment_id < readiness.comment_id < record.comment_id
        and record.lineage_id == proposal.lineage_id
        and set(record.subject_record_ids) == {proposal.record_id, readiness.record_id}
        and set(record.comment_bindings)
        == {
            CommentBinding(proposal.comment_id, proposal.body_sha256),
            CommentBinding(readiness.comment_id, readiness.body_sha256),
        }
    )


def _semantic_records(
    manifest: ExecutionManifest,
    records: Sequence[GovernanceRecord],
    *,
    lineage_record_ids: frozenset[str],
) -> tuple[GovernanceRecord, ...]:
    result: list[GovernanceRecord] = []
    for record in records:
        if record.record_type in {"proposal", "readiness", "authority"}:
            result.append(record)
            continue
        if record.manifest_sha256 == manifest.sha256:
            result.append(record)
            continue
        if (
            record.record_type in {"revocation", "supersession", "consumption"}
            and lineage_record_ids.intersection(record.subject_record_ids)
        ):
            result.append(record)
    return tuple(result)


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


def _validate_lifecycle(
    manifest: ExecutionManifest,
    records: Sequence[GovernanceRecord],
    *,
    proposal: GovernanceRecord,
    readiness: GovernanceRecord,
    authority: GovernanceRecord,
) -> tuple[tuple[GovernanceRecord, ...], GovernanceRecord | None, GovernanceRecord | None]:
    current_approvals = tuple(
        record
        for record in records
        if record.record_type == "manifest_approval" and record.manifest_sha256 == manifest.sha256
    )
    allowed_targets = {
        proposal.record_id: proposal,
        readiness.record_id: readiness,
        authority.record_id: authority,
        **{record.record_id: record for record in current_approvals},
    }
    authority_binding = CommentBinding(authority.comment_id, authority.body_sha256)
    consumptions: list[GovernanceRecord] = []
    current_consumptions: list[GovernanceRecord] = []
    current_terminals: list[GovernanceRecord] = []

    for record in records:
        if record.record_type == "manifest_approval":
            if record.manifest_sha256 != manifest.sha256:
                continue
            if (
                tuple(record.subject_record_ids) != (authority.record_id,)
                or tuple(record.comment_bindings) != (authority_binding,)
                or record.comment_id <= authority.comment_id
            ):
                raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")
            continue

        if record.record_type in {"revocation", "supersession"}:
            if not record.subject_record_ids:
                raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")
            targets: list[GovernanceRecord] = []
            for record_id in record.subject_record_ids:
                target = allowed_targets.get(record_id)
                if target is None or target.comment_id >= record.comment_id:
                    raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")
                targets.append(target)
            expected_bindings = {
                CommentBinding(target.comment_id, target.body_sha256) for target in targets
            }
            if set(record.comment_bindings) != expected_bindings:
                raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")
            continue

        if record.record_type == "consumption":
            consumptions.append(record)
            if (
                tuple(record.subject_record_ids) != (authority.record_id,)
                or tuple(record.comment_bindings) != (authority_binding,)
                or record.comment_id <= authority.comment_id
            ):
                raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")
            if record.manifest_sha256 == manifest.sha256:
                current_consumptions.append(record)
            continue

        if record.record_type == "terminal" and record.manifest_sha256 == manifest.sha256:
            current_terminals.append(record)

    if len(consumptions) > 1 or len(current_terminals) > 1:
        raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")

    current_consumption = current_consumptions[0] if current_consumptions else None
    terminal = current_terminals[0] if current_terminals else None
    if terminal is not None:
        if len(current_consumptions) != 1:
            raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")
        consumption_binding = CommentBinding(
            current_consumption.comment_id,
            current_consumption.body_sha256,
        )
        if (
            tuple(terminal.subject_record_ids) != (current_consumption.record_id,)
            or tuple(terminal.comment_bindings) != (consumption_binding,)
            or terminal.comment_id <= current_consumption.comment_id
            or terminal.details["run_id"] != current_consumption.details["run_id"]
            or terminal.details["run_attempt"] != current_consumption.details["run_attempt"]
        ):
            raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")

    return current_approvals, current_consumption, terminal


def reduce_governance_history(
    manifest: ExecutionManifest,
    history: GovernanceHistory,
) -> GovernanceState:
    validate_governance_history(manifest, history)
    all_records = _same_issue_operation(manifest, history.records)

    proposal = _exact_record(all_records, record_type="proposal", binding=manifest.proposal)
    readiness = _exact_record(all_records, record_type="readiness", binding=manifest.readiness)
    authority = _exact_record(all_records, record_type="authority", binding=manifest.authority)
    if proposal is None or readiness is None or authority is None:
        raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")

    proposal_binding = CommentBinding(proposal.comment_id, proposal.body_sha256)
    if (
        proposal.lineage_id is None
        or proposal.subject_record_ids
        or proposal.comment_bindings
        or readiness.lineage_id != proposal.lineage_id
        or tuple(readiness.subject_record_ids) != (proposal.record_id,)
        or tuple(readiness.comment_bindings) != (proposal_binding,)
        or not _valid_lineage_authority(authority, proposal=proposal, readiness=readiness)
    ):
        raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")

    lineage_ids = frozenset({proposal.record_id, readiness.record_id, authority.record_id})
    records = _semantic_records(manifest, all_records, lineage_record_ids=lineage_ids)
    approvals, current_consumption, terminal = _validate_lifecycle(
        manifest,
        records,
        proposal=proposal,
        readiness=readiness,
        authority=authority,
    )

    if any(_is_invalidated(record.record_id, records) for record in (proposal, readiness, authority)):
        authority_status = "superseded"
    elif readiness.details["disposition"] != "ready" or authority.details["disposition"] != "granted":
        authority_status = "not_granted"
    else:
        active_authorities = [
            record
            for record in records
            if record.record_type == "authority"
            and record.lineage_id == authority.lineage_id
            and record.details.get("disposition") == "granted"
            and not _is_invalidated(record.record_id, records)
            and not _is_consumed(record.record_id, records)
        ]
        if any(
            not _valid_lineage_authority(record, proposal=proposal, readiness=readiness)
            for record in active_authorities
        ):
            raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")
        if len(active_authorities) > 1:
            raise GovernanceStateError("GOVERNANCE_AMBIGUOUS")
        if _is_consumed(authority.record_id, records):
            authority_status = "consumed"
        elif not active_authorities or active_authorities[0].record_id != authority.record_id:
            authority_status = "not_granted"
        else:
            authority_status = "active"

    active_approvals = tuple(
        record for record in approvals if not _is_invalidated(record.record_id, records)
    )
    if len(active_approvals) > 1:
        approval_status = "ambiguous"
        active_approval = None
    elif not active_approvals:
        approval_status = "absent"
        active_approval = None
    else:
        active_approval = active_approvals[0]
        approval_status = str(active_approval.details["disposition"])

    return GovernanceState(
        proposal=proposal,
        readiness=readiness,
        authority=authority,
        authority_status=authority_status,
        approval_status=approval_status,
        active_approval=active_approval,
        consumption=current_consumption,
        terminal=terminal,
    )
