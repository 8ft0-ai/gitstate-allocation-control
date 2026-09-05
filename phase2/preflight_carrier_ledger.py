from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import quote

from .github_api import GitHubAPIError
from .operator_manifest import SHA40, SHA256, canonical_json, sha256_text


CONTROL_REPOSITORY = "8ft0-ai/gitstate-allocation-control"
LEDGER_PATH = "policy/preflight-carrier-ledger.json"
LEDGER_CONTRACT = "gitstate-public-carrier-ledger/v1"
LEDGER_BASE_SHA = "2001449abb567deff097e76e228a5af9ebd0743d"
ZERO_SHA256 = "0" * 64
OPAQUE_ID = re.compile(r"^[0-9a-f]{32,64}$")

LEDGER_FIELDS = frozenset({"contract", "baseline_control_sha", "records"})
COMMON_RECORD_FIELDS = frozenset(
    {
        "sequence",
        "kind",
        "record_id",
        "comment_id",
        "body_sha256",
        "manifest_sha256",
        "previous_record_sha256",
        "record_sha256",
    }
)
PROJECTION_RECORD_FIELDS = COMMON_RECORD_FIELDS
INVALIDATION_RECORD_FIELDS = COMMON_RECORD_FIELDS | frozenset(
    {"projection_comment_id", "projection_body_sha256"}
)


class PublicCarrierLedgerError(RuntimeError):
    pass


@dataclass(frozen=True)
class CarrierLedger:
    records: tuple[Mapping[str, Any], ...]
    sha256: str


def _duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_float(_: str) -> float:
    raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_FLOAT_NOT_SUPPORTED")


def _reject_constant(_: str) -> float:
    raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_NONFINITE_NUMBER_NOT_SUPPORTED")


def _require_sha(value: object, pattern: re.Pattern[str], reason: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise PublicCarrierLedgerError(reason)
    return value


def _require_int(value: object, reason: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise PublicCarrierLedgerError(reason)
    return value


def _record_digest(record: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in record.items() if key != "record_sha256"}
    return sha256_text(canonical_json(unsigned))


def _parse_record(
    value: object,
    *,
    expected_sequence: int,
    previous_record_sha256: str,
) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_RECORD_INVALID")
    kind = value.get("kind")
    expected_fields = (
        PROJECTION_RECORD_FIELDS
        if kind == "projection"
        else INVALIDATION_RECORD_FIELDS
        if kind == "invalidation"
        else None
    )
    if expected_fields is None or frozenset(value) != expected_fields:
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_RECORD_INVALID")

    sequence = _require_int(
        value.get("sequence"),
        "PUBLIC_CARRIER_LEDGER_SEQUENCE_INVALID",
        minimum=1,
    )
    if sequence != expected_sequence:
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_SEQUENCE_INVALID")

    record_id = value.get("record_id")
    if not isinstance(record_id, str) or OPAQUE_ID.fullmatch(record_id) is None:
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_RECORD_ID_INVALID")

    comment_id = _require_int(
        value.get("comment_id"),
        "PUBLIC_CARRIER_LEDGER_COMMENT_ID_INVALID",
        minimum=0,
    )
    body_sha256 = _require_sha(
        value.get("body_sha256"),
        SHA256,
        "PUBLIC_CARRIER_LEDGER_BODY_DIGEST_INVALID",
    )
    _require_sha(
        value.get("manifest_sha256"),
        SHA256,
        "PUBLIC_CARRIER_LEDGER_MANIFEST_DIGEST_INVALID",
    )
    previous = _require_sha(
        value.get("previous_record_sha256"),
        SHA256,
        "PUBLIC_CARRIER_LEDGER_CHAIN_INVALID",
    )
    if previous != previous_record_sha256:
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_CHAIN_INVALID")

    record_sha256 = _require_sha(
        value.get("record_sha256"),
        SHA256,
        "PUBLIC_CARRIER_LEDGER_RECORD_DIGEST_INVALID",
    )
    if record_sha256 != _record_digest(value):
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_RECORD_DIGEST_INVALID")

    if kind == "projection":
        if comment_id <= 0:
            raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_COMMENT_ID_INVALID")
    else:
        _require_int(
            value.get("projection_comment_id"),
            "PUBLIC_CARRIER_LEDGER_SUBJECT_INVALID",
            minimum=1,
        )
        _require_sha(
            value.get("projection_body_sha256"),
            SHA256,
            "PUBLIC_CARRIER_LEDGER_SUBJECT_INVALID",
        )

    return dict(value)


def parse_carrier_ledger(raw: str) -> CarrierLedger:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_duplicate_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except PublicCarrierLedgerError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_JSON_INVALID") from exc

    if not isinstance(value, dict) or frozenset(value) != LEDGER_FIELDS:
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_SCHEMA_MISMATCH")
    if value.get("contract") != LEDGER_CONTRACT:
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_CONTRACT_MISMATCH")
    if value.get("baseline_control_sha") != LEDGER_BASE_SHA:
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_BASELINE_MISMATCH")

    records_value = value.get("records")
    if not isinstance(records_value, list):
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_SCHEMA_MISMATCH")

    canonical = canonical_json(value)
    if raw not in (canonical, canonical + "\n"):
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_NONCANONICAL")

    records: list[Mapping[str, Any]] = []
    previous = ZERO_SHA256
    seen_ids: set[tuple[str, str]] = set()
    for index, item in enumerate(records_value, start=1):
        record = _parse_record(
            item,
            expected_sequence=index,
            previous_record_sha256=previous,
        )
        identity = (str(record["kind"]), str(record["record_id"]))
        if identity in seen_ids:
            raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_RECORD_AMBIGUOUS")
        seen_ids.add(identity)
        previous = str(record["record_sha256"])
        records.append(record)

    return CarrierLedger(tuple(records), sha256_text(canonical))


def _ledger_contents_path(ref: str) -> str:
    return (
        f"/repos/{CONTROL_REPOSITORY}/contents/{quote(LEDGER_PATH, safe='/')}"
        f"?ref={quote(ref, safe='')}"
    )


def _read_ledger_at(api, ref: str) -> CarrierLedger | None:
    try:
        payload = api.get(_ledger_contents_path(ref))
    except GitHubAPIError as exc:
        if exc.status == 404:
            return None
        raise

    if not isinstance(payload, Mapping):
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_READ_AMBIGUOUS")
    if payload.get("encoding") != "base64":
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_READ_AMBIGUOUS")
    content = payload.get("content")
    blob_sha = payload.get("sha")
    if (
        not isinstance(content, str)
        or not isinstance(blob_sha, str)
        or SHA40.fullmatch(blob_sha) is None
    ):
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_READ_AMBIGUOUS")
    try:
        raw = base64.b64decode(content).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_READ_AMBIGUOUS") from exc
    return parse_carrier_ledger(raw)


def _commit_parent(api, commit_sha: str) -> str:
    payload = api.get(f"/repos/{CONTROL_REPOSITORY}/commits/{commit_sha}")
    if not isinstance(payload, Mapping) or payload.get("sha") != commit_sha:
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_HISTORY_AMBIGUOUS")
    parents = payload.get("parents")
    if not isinstance(parents, list) or not parents:
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_BASE_NOT_REACHED")
    parent = parents[0]
    parent_sha = parent.get("sha") if isinstance(parent, Mapping) else None
    if not isinstance(parent_sha, str) or SHA40.fullmatch(parent_sha) is None:
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_HISTORY_AMBIGUOUS")
    return parent_sha


def _require_current_protected_main(api, trusted_sha: str) -> None:
    payload = api.get(f"/repos/{CONTROL_REPOSITORY}/branches/main")
    if not isinstance(payload, Mapping):
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_MAIN_AMBIGUOUS")
    if payload.get("protected") is not True:
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_MAIN_NOT_PROTECTED")
    commit = payload.get("commit")
    current_sha = commit.get("sha") if isinstance(commit, Mapping) else None
    if current_sha != trusted_sha:
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_MAIN_MOVED")


def read_monotonic_carrier_ledger(api, *, trusted_sha: str) -> CarrierLedger:
    _require_sha(
        trusted_sha,
        SHA40,
        "PUBLIC_CARRIER_LEDGER_TRUSTED_SHA_INVALID",
    )
    _require_current_protected_main(api, trusted_sha)

    baseline_state = _read_ledger_at(api, LEDGER_BASE_SHA)
    if baseline_state is not None:
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_BASELINE_CONFLICT")

    chain: list[str] = []
    seen: set[str] = set()
    cursor = trusted_sha
    for _ in range(1000):
        if cursor == LEDGER_BASE_SHA:
            break
        if cursor in seen:
            raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_HISTORY_AMBIGUOUS")
        seen.add(cursor)
        chain.append(cursor)
        cursor = _commit_parent(api, cursor)
    else:
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_HISTORY_TOO_DEEP")

    if cursor != LEDGER_BASE_SHA:
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_BASE_NOT_REACHED")

    previous: CarrierLedger | None = None
    for commit_sha in reversed(chain):
        state = _read_ledger_at(api, commit_sha)
        if state is None:
            if previous is not None:
                raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_REWRITTEN")
            continue

        if previous is None:
            if state.records:
                raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_GENESIS_INVALID")
            previous = state
            continue

        if state.records == previous.records:
            previous = state
            continue

        if (
            len(state.records) == len(previous.records) + 1
            and state.records[:-1] == previous.records
        ):
            previous = state
            continue

        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_REWRITTEN")

    if previous is None:
        raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_MISSING")
    return previous


def validate_carrier_ledger(
    api,
    *,
    trusted_sha: str,
    projection_comment_id: int,
    projection_body_sha256: str,
    manifest_sha256: str,
) -> CarrierLedger:
    projection_comment_id = _require_int(
        projection_comment_id,
        "PUBLIC_CARRIER_LEDGER_SUBJECT_INVALID",
        minimum=1,
    )
    projection_body_sha256 = _require_sha(
        projection_body_sha256,
        SHA256,
        "PUBLIC_CARRIER_LEDGER_SUBJECT_INVALID",
    )
    manifest_sha256 = _require_sha(
        manifest_sha256,
        SHA256,
        "PUBLIC_CARRIER_LEDGER_SUBJECT_INVALID",
    )

    ledger = read_monotonic_carrier_ledger(api, trusted_sha=trusted_sha)

    matching_projection = [
        record
        for record in ledger.records
        if record["kind"] == "projection"
        and record["comment_id"] == projection_comment_id
        and record["body_sha256"] == projection_body_sha256
        and record["manifest_sha256"] == manifest_sha256
    ]
    if len(matching_projection) != 1:
        conflicting_projection = any(
            record["kind"] == "projection"
            and record["comment_id"] == projection_comment_id
            for record in ledger.records
        )
        raise PublicCarrierLedgerError(
            "PUBLIC_CARRIER_LEDGER_SUBJECT_MISMATCH"
            if conflicting_projection
            else "PUBLIC_CARRIER_LEDGER_PROJECTION_NOT_BOUND"
        )

    for record in ledger.records:
        if record["kind"] != "invalidation":
            continue
        same_comment = record["projection_comment_id"] == projection_comment_id
        same_body = record["projection_body_sha256"] == projection_body_sha256
        same_manifest = record["manifest_sha256"] == manifest_sha256
        if same_comment and (not same_body or not same_manifest):
            raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_SUBJECT_MISMATCH")
        if same_comment and same_body and same_manifest:
            raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_INVALIDATED")

    return ledger
