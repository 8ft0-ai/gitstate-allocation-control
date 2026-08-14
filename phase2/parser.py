from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

PREFIX = b"/beads-v0.2 "
PROTOCOL = "beads-allocation/v0.2"
MAX_BODY_BYTES = 4096
MAX_ARRAY_ITEMS = 20
ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
AGENT_RE = re.compile(
    r"^agent://(?:(?:github-app/[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?/\d+)|"
    r"(?:(?:human|operator)/[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?))/session/"
    r"[a-z0-9._-]{1,64}$"
)
TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
TASK_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")


class RequestError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


def _object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RequestError("DUPLICATE_KEY", key)
        result[key] = value
    return result


def _normalise(value: Any) -> Any:
    if isinstance(value, str):
        for char in value:
            codepoint = ord(char)
            if 0xD800 <= codepoint <= 0xDFFF:
                raise RequestError("INVALID_UNICODE", "surrogate code point")
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalise(item) for item in value]
    if isinstance(value, dict):
        return {_normalise(key): _normalise(item) for key, item in value.items()}
    return value


def _parse_json(raw: bytes) -> dict[str, Any]:
    if not raw.startswith(b"{") or not raw.endswith(b"}"):
        raise RequestError("INVALID_TRANSPORT")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise RequestError("INVALID_UTF8", str(exc)) from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_no_duplicates,
            parse_float=lambda _: (_ for _ in ()).throw(RequestError("NON_INTEGER_NUMBER")),
            parse_constant=lambda _: (_ for _ in ()).throw(RequestError("INVALID_NUMBER")),
        )
    except RequestError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise RequestError("INVALID_JSON", str(exc)) from exc
    if not isinstance(value, dict):
        raise RequestError("ROOT_NOT_OBJECT")
    return _normalise(value)


def _require_string(payload: dict[str, Any], key: str, pattern: re.Pattern[str]) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise RequestError("INVALID_FIELD", key)
    return value


def _optional_array(payload: dict[str, Any], key: str, *, required: bool) -> list[str]:
    if key not in payload:
        if required:
            raise RequestError("MISSING_FIELD", key)
        return []
    value = payload[key]
    if not isinstance(value, list) or len(value) > MAX_ARRAY_ITEMS:
        raise RequestError("INVALID_ARRAY", key)
    if any(not isinstance(item, str) or not TOKEN_RE.fullmatch(item) for item in value):
        raise RequestError("INVALID_ARRAY_ITEM", key)
    if value != sorted(set(value)):
        raise RequestError("ARRAY_NOT_SORTED_UNIQUE", key)
    return value


def _validate_keys(payload: dict[str, Any], required: set[str], optional: set[str]) -> None:
    keys = set(payload)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        raise RequestError("MISSING_FIELD", sorted(missing)[0])
    if unknown:
        raise RequestError("UNKNOWN_FIELD", sorted(unknown)[0])


def canonical_json(payload: dict[str, Any]) -> bytes:
    """RFC 8785-equivalent serialisation for this integer/string/array schema."""
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class ParsedRequest:
    payload: dict[str, Any]
    canonical_payload: bytes
    payload_hash: str


@dataclass(frozen=True)
class InvalidRequest:
    request_id: str
    reason_code: str
    payload_hash: str


def parse_request(body: bytes) -> ParsedRequest:
    if len(body) > MAX_BODY_BYTES:
        raise RequestError("BODY_TOO_LARGE")
    if b"\n" in body or b"\r" in body:
        raise RequestError("MULTILINE_BODY")
    if not body.startswith(PREFIX):
        raise RequestError("UNRELATED_COMMENT")
    payload = _parse_json(body[len(PREFIX) :])
    if payload.get("protocol") != PROTOCOL:
        raise RequestError("INVALID_PROTOCOL")
    request_type = payload.get("type")
    if request_type == "ALLOCATE_NEXT":
        required = {"protocol", "type", "request_id", "agent_id", "capabilities", "task_types"}
        optional = {"max_priority"}
    elif request_type == "ALLOCATE_TASK":
        required = {"protocol", "type", "request_id", "agent_id", "task_id"}
        optional = {"capabilities", "task_types"}
    elif request_type == "RELEASE":
        required = {"protocol", "type", "request_id", "agent_id", "allocation_id", "reason"}
        optional = set()
    else:
        raise RequestError("INVALID_REQUEST_TYPE")
    _validate_keys(payload, required, optional)
    _require_string(payload, "request_id", ULID_RE)
    _require_string(payload, "agent_id", AGENT_RE)
    if request_type == "ALLOCATE_NEXT":
        _optional_array(payload, "capabilities", required=True)
        _optional_array(payload, "task_types", required=True)
        if "max_priority" in payload:
            priority = payload["max_priority"]
            if isinstance(priority, bool) or not isinstance(priority, int) or not 0 <= priority <= 4:
                raise RequestError("INVALID_FIELD", "max_priority")
    elif request_type == "ALLOCATE_TASK":
        _require_string(payload, "task_id", TASK_RE)
        _optional_array(payload, "capabilities", required=False)
        _optional_array(payload, "task_types", required=False)
    else:
        _require_string(payload, "allocation_id", ULID_RE)
        reason = payload["reason"]
        if not isinstance(reason, str) or not 1 <= len(reason) <= 500:
            raise RequestError("INVALID_FIELD", "reason")
    canonical = canonical_json(payload)
    semantic = dict(payload)
    semantic.pop("request_id")
    payload_hash = hashlib.sha256(canonical_json(semantic)).hexdigest()
    return ParsedRequest(payload, canonical, payload_hash)


def malformed_descriptor(body: bytes, repository: str, comment_id: int, error: RequestError) -> InvalidRequest:
    if not body.startswith(PREFIX):
        raise RequestError("UNRELATED_COMMENT")
    return InvalidRequest(
        request_id=f"invalid:{repository}:{comment_id}",
        reason_code="INVALID_REQUEST",
        payload_hash=hashlib.sha256(body).hexdigest(),
    )
