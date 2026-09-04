from __future__ import annotations

import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Sequence

from .operator_manifest import (
    GOVERNANCE_OWNER,
    MANIFEST_FIELDS,
    SHA256,
    CommentBinding,
    ExecutionManifest,
    GovernanceRecord,
    GovernanceSource,
    HistoryBaseline,
    OperatorContractError,
    canonical_json,
    parse_execution_manifest,
    parse_governance_comment,
    sha256_text,
)


class GovernanceStateError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class GuardedExecutionManifest(ExecutionManifest):
    governance_history: HistoryBaseline


@dataclass(frozen=True)
class GovernanceHistory:
    """Manifest-bound exact source evidence supplied by a durable history provider."""

    manifest_sha256: str
    baseline: HistoryBaseline
    records: tuple[GovernanceSource, ...]

    @property
    def sources(self) -> tuple[GovernanceSource, ...]:
        return self.records


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


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _strict_guarded_json(raw: str) -> dict[str, Any]:
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
        raise OperatorContractError("MANIFEST_JSON_INVALID") from exc
    if not isinstance(value, dict):
        raise OperatorContractError("MANIFEST_JSON_INVALID")
    _require_supported_json(value)
    if raw != canonical_json(value):
        raise OperatorContractError("NONCANONICAL_JSON")
    return value


def parse_guarded_execution_manifest(
    raw: str,
    *,
    expected_sha256: str | None = None,
) -> GuardedExecutionManifest:
    value = _strict_guarded_json(raw)
    expected_fields = MANIFEST_FIELDS | frozenset({"governance_history"})
    if frozenset(value) != expected_fields:
        raise OperatorContractError("MANIFEST_SCHEMA_MISMATCH")

    history = value.get("governance_history")
    if (
        not isinstance(history, dict)
        or frozenset(history) != frozenset({"through_id", "history_sha256"})
        or type(history.get("through_id")) is not int
        or history["through_id"] < 0
        or not isinstance(history.get("history_sha256"), str)
        or SHA256.fullmatch(history["history_sha256"]) is None
    ):
        raise OperatorContractError("MANIFEST_GOVERNANCE_HISTORY_INVALID")

    core = dict(value)
    del core["governance_history"]
    parse_execution_manifest(canonical_json(core))

    digest = sha256_text(raw)
    if expected_sha256 is not None:
        if not isinstance(expected_sha256, str) or SHA256.fullmatch(expected_sha256) is None:
            raise OperatorContractError("MANIFEST_EXPECTED_DIGEST_INVALID")
        if digest != expected_sha256:
            raise OperatorContractError("MANIFEST_IDENTITY_MISMATCH")

    return GuardedExecutionManifest(
        _freeze(value),
        digest,
        HistoryBaseline(int(history["through_id"]), str(history["history_sha256"])),
    )


def canonical_governance_history(
    records: Sequence[GovernanceRecord],
    *,
    through_comment_id: int | None = None,
) -> str:
    materialized = tuple(records)
    if any(not isinstance(record, GovernanceRecord) for record in materialized):
        raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")
    if any(type(record.comment_id) is not int for record in materialized):
        raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")
    ordered = tuple(sorted(materialized, key=lambda record: record.comment_id))
    seen_comments: set[int] = set()
    seen_records: set[str] = set()
    lines: list[str] = []
    for record in ordered:
        if record.comment_id <= 0 or record.comment_id in seen_comments:
            raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")
        if record.record_id in seen_records:
            raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")
        if not isinstance(record.body_sha256, str) or SHA256.fullmatch(record.body_sha256) is None:
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
    materialized = tuple(records)
    if any(not isinstance(record, GovernanceRecord) for record in materialized):
        raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")
    if any(type(record.comment_id) is not int for record in materialized):
        raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")
    selected = tuple(
        record
        for record in materialized
        if through_comment_id is None or record.comment_id <= through_comment_id
    )
    canonical = canonical_governance_history(materialized, through_comment_id=through_comment_id)
    through = max((record.comment_id for record in selected), default=0)
    return HistoryBaseline(through, sha256_text(canonical))


def build_governance_history(
    manifest_sha256: str,
    records: Sequence[GovernanceRecord],
) -> GovernanceHistory:
    if not isinstance(manifest_sha256, str) or SHA256.fullmatch(manifest_sha256) is None:
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    materialized = tuple(records)
    if any(not isinstance(record, GovernanceRecord) for record in materialized):
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    if any(type(record.comment_id) is not int for record in materialized):
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    ordered = tuple(sorted(materialized, key=lambda record: record.comment_id))
    sources: list[GovernanceSource] = []
    for record in ordered:
        source = record.source
        if not isinstance(source, GovernanceSource):
            raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
        if (
            source.comment_id != record.comment_id
            or not isinstance(source.body, str)
            or sha256_text(source.body) != record.body_sha256
        ):
            raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
        sources.append(source)
    return GovernanceHistory(
        manifest_sha256=manifest_sha256,
        baseline=governance_history_baseline(ordered),
        records=tuple(sources),
    )


def _source_comment(source: GovernanceSource) -> dict[str, Any]:
    if (
        type(source.comment_id) is not int
        or source.comment_id <= 0
        or not isinstance(source.body, str)
        or not isinstance(source.owner, str)
        or not source.owner
        or not isinstance(source.created_at, str)
        or not isinstance(source.updated_at, str)
    ):
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    return {
        "id": source.comment_id,
        "body": source.body,
        "user": {"login": source.owner},
        "created_at": source.created_at,
        "updated_at": source.updated_at,
    }


def _records_from_sources(
    manifest: GuardedExecutionManifest,
    sources: tuple[GovernanceSource, ...],
) -> tuple[GovernanceRecord, ...]:
    records: list[GovernanceRecord] = []
    seen_comments: set[int] = set()
    seen_records: set[str] = set()
    previous_comment_id = 0
    for source in sources:
        if not isinstance(source, GovernanceSource):
            raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
        source_comment = _source_comment(source)
        if source.comment_id <= previous_comment_id or source.comment_id in seen_comments:
            raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
        try:
            record = parse_governance_comment(
                source_comment,
                expected_owner=GOVERNANCE_OWNER,
                expected_issue=manifest.governing_issue,
            )
        except (OperatorContractError, TypeError, ValueError, KeyError, AttributeError) as exc:
            raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED") from exc
        if record is None or record.source != source:
            raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
        if record.record_id in seen_records:
            raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
        previous_comment_id = source.comment_id
        seen_comments.add(source.comment_id)
        seen_records.add(record.record_id)
        records.append(record)
    return tuple(records)


def validate_governance_history(
    manifest: ExecutionManifest,
    history: GovernanceHistory,
) -> tuple[GovernanceRecord, ...]:
    if not isinstance(manifest, GuardedExecutionManifest):
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    if not isinstance(history, GovernanceHistory):
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    if (
        not isinstance(history.manifest_sha256, str)
        or SHA256.fullmatch(history.manifest_sha256) is None
        or history.manifest_sha256 != manifest.sha256
    ):
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    if not isinstance(history.baseline, HistoryBaseline):
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    if (
        type(history.baseline.through_id) is not int
        or history.baseline.through_id < 0
        or not isinstance(history.baseline.history_sha256, str)
        or SHA256.fullmatch(history.baseline.history_sha256) is None
    ):
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    if not isinstance(history.records, tuple):
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")

    records = _records_from_sources(manifest, history.records)
    if any(record.operation != manifest.operation for record in records):
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")

    actual = governance_history_baseline(records)
    if actual != history.baseline:
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")

    required = manifest.governance_history
    required_through = max(
        manifest.proposal.comment_id,
        manifest.readiness.comment_id,
        manifest.authority.comment_id,
    )
    if required.through_id < required_through or history.baseline.through_id < required.through_id:
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    anchored_prefix = governance_history_baseline(
        records,
        through_comment_id=required.through_id,
    )
    if anchored_prefix != required:
        raise GovernanceStateError("GOVERNANCE_HISTORY_CHANGED")
    return records


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
    records = validate_governance_history(manifest, history)

    proposal = _exact_record(records, record_type="proposal", binding=manifest.proposal)
    readiness = _exact_record(records, record_type="readiness", binding=manifest.readiness)
    authority = _exact_record(records, record_type="authority", binding=manifest.authority)
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
    semantic_records = _semantic_records(manifest, records, lineage_record_ids=lineage_ids)
    approvals, current_consumption, terminal = _validate_lifecycle(
        manifest,
        semantic_records,
        proposal=proposal,
        readiness=readiness,
        authority=authority,
    )

    if any(
        _is_invalidated(record.record_id, semantic_records)
        for record in (proposal, readiness, authority)
    ):
        authority_status = "superseded"
    elif readiness.details["disposition"] != "ready" or authority.details["disposition"] != "granted":
        authority_status = "not_granted"
    else:
        active_authorities = [
            record
            for record in semantic_records
            if record.record_type == "authority"
            and record.lineage_id == authority.lineage_id
            and record.details.get("disposition") == "granted"
            and not _is_invalidated(record.record_id, semantic_records)
            and not _is_consumed(record.record_id, semantic_records)
        ]
        if any(
            not _valid_lineage_authority(record, proposal=proposal, readiness=readiness)
            for record in active_authorities
        ):
            raise GovernanceStateError("GOVERNANCE_RECORD_INVALID")
        if len(active_authorities) > 1:
            raise GovernanceStateError("GOVERNANCE_AMBIGUOUS")
        if _is_consumed(authority.record_id, semantic_records):
            authority_status = "consumed"
        elif not active_authorities or active_authorities[0].record_id != authority.record_id:
            authority_status = "not_granted"
        else:
            authority_status = "active"

    active_approvals = tuple(
        record for record in approvals if not _is_invalidated(record.record_id, semantic_records)
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
