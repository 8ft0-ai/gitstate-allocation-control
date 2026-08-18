from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from .github_api import GitHubAPI


CONTROL_REPOSITORY = "8ft0-ai/gitstate-allocation-control"
OPERATOR_ISSUE_NUMBER = 17
OPERATOR_OWNER = "8ft0-ai"
PROTOCOL_AUTHORITY_SHA = "edac1373644cfa09599a1ff930b493ccacd985d0"
STATE_BASELINE_SHA = "fb872aeb52863ce3597ff8337d545cae13292696"
CAPSULE_PREFIX = "/gitstate-operator-v1 "
CONSUMPTION_PREFIX = "/gitstate-consumption-v1 "
CAPSULE_CONTRACT = "gitstate-operator/v1"
GOVERNANCE_CONTRACT = "gitstate-private-governance/v1"
LIVE_PROFILE = "workstream-d-scenarios-1-14/v1"
PREFLIGHT_PROFILE = "operator-preflight/v1"
MAX_CAPSULE_LIFETIME = timedelta(hours=1)
CLOCK_SKEW = timedelta(minutes=1)
OPAQUE_ID = re.compile(r"^[0-9a-f]{32,64}$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")

CAPSULE_FIELDS = frozenset(
    {
        "contract",
        "capsule_id",
        "governance_contract",
        "governance_record_id",
        "review_record_id",
        "review_record_sha256",
        "authority_record_id",
        "authority_record_sha256",
        "operation",
        "expected_control_sha",
        "expected_protocol_sha",
        "expected_state_baseline",
        "created_at",
        "expires_at",
        "single_use",
        "workstream_e_authorised",
    }
)

CONSUMPTION_FIELDS = frozenset(
    {
        "contract",
        "capsule_id",
        "capsule_comment_id",
        "capsule_body_sha256",
        "run_id",
        "run_attempt",
        "trusted_sha",
        "operation",
        "consumed_at",
        "workstream_e_authorised",
    }
)


class OperatorCapsuleError(RuntimeError):
    pass


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise OperatorCapsuleError("DUPLICATE_JSON_KEY")
        value[key] = item
    return value


def _strict_json(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
    except OperatorCapsuleError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise OperatorCapsuleError("MALFORMED_CAPSULE_JSON") from exc
    if not isinstance(value, dict):
        raise OperatorCapsuleError("CAPSULE_JSON_OBJECT_REQUIRED")
    return value


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_sha256(value: Mapping[str, Any]) -> str:
    return sha256_text(canonical_json(value))


def _parse_time(value: Any, reason: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise OperatorCapsuleError(reason)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise OperatorCapsuleError(reason) from exc
    if parsed.tzinfo is None:
        raise OperatorCapsuleError(reason)
    return parsed.astimezone(timezone.utc)


def _require_exact_keys(value: Mapping[str, Any], expected: frozenset[str], reason: str) -> None:
    if frozenset(value) != expected:
        raise OperatorCapsuleError(reason)


def _require_hex(value: Any, pattern: re.Pattern[str], reason: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise OperatorCapsuleError(reason)
    return value


def profile_for_dispatch(operation: str) -> str:
    if operation == "live_scenario_suite":
        return LIVE_PROFILE
    if operation == "operator_preflight":
        return PREFLIGHT_PROFILE
    raise OperatorCapsuleError("OPERATOR_OPERATION_NOT_CAPSULE_BOUND")


@dataclass(frozen=True)
class Capsule:
    payload: dict[str, Any]
    body_sha256: str
    canonical_payload_sha256: str
    comment_id: int
    created_at: datetime

    @property
    def capsule_id(self) -> str:
        return str(self.payload["capsule_id"])

    @property
    def operation(self) -> str:
        return str(self.payload["operation"])

    @property
    def expected_control_sha(self) -> str:
        return str(self.payload["expected_control_sha"])

    @property
    def expected_protocol_sha(self) -> str:
        return str(self.payload["expected_protocol_sha"])

    @property
    def expected_state_baseline(self) -> str:
        return str(self.payload["expected_state_baseline"])

    def runtime_outputs(self, *, run_id: int, run_attempt: int) -> dict[str, str]:
        attempt_nonce = hashlib.sha256(
            f"{run_id}:{run_attempt}:{self.capsule_id}:{self.body_sha256}".encode("ascii")
        ).hexdigest()[:16]
        return {
            "capsule_id": self.capsule_id,
            "capsule_comment_id": str(self.comment_id),
            "capsule_body_sha256": self.body_sha256,
            "capsule_payload_sha256": self.canonical_payload_sha256,
            "expected_control_sha": self.expected_control_sha,
            "expected_protocol_sha": self.expected_protocol_sha,
            "expected_state_baseline": self.expected_state_baseline,
            "operation_profile": self.operation,
            "attempt_nonce": attempt_nonce,
        }


def parse_capsule_comment(
    comment: Mapping[str, Any],
    *,
    now: datetime,
    expected_control_sha: str,
    expected_profile: str,
) -> Capsule:
    if not isinstance(comment.get("id"), int):
        raise OperatorCapsuleError("CAPSULE_COMMENT_ID_INVALID")
    body = comment.get("body")
    if not isinstance(body, str) or "\n" in body or not body.startswith(CAPSULE_PREFIX):
        raise OperatorCapsuleError("CAPSULE_TRANSPORT_INVALID")
    user = comment.get("user")
    if not isinstance(user, Mapping) or user.get("login") != OPERATOR_OWNER:
        raise OperatorCapsuleError("CAPSULE_WRONG_OWNER")
    comment_created = _parse_time(comment.get("created_at"), "CAPSULE_COMMENT_TIME_INVALID")
    comment_updated = _parse_time(comment.get("updated_at"), "CAPSULE_COMMENT_TIME_INVALID")
    if comment_created != comment_updated:
        raise OperatorCapsuleError("CAPSULE_SOURCE_EDITED")

    payload = _strict_json(body[len(CAPSULE_PREFIX) :])
    _require_exact_keys(payload, CAPSULE_FIELDS, "CAPSULE_SCHEMA_MISMATCH")
    if payload.get("contract") != CAPSULE_CONTRACT:
        raise OperatorCapsuleError("CAPSULE_CONTRACT_MISMATCH")
    if payload.get("governance_contract") != GOVERNANCE_CONTRACT:
        raise OperatorCapsuleError("CAPSULE_GOVERNANCE_CONTRACT_MISMATCH")
    _require_hex(payload.get("capsule_id"), OPAQUE_ID, "CAPSULE_ID_INVALID")
    for key in ("governance_record_id", "review_record_id", "authority_record_id"):
        _require_hex(payload.get(key), OPAQUE_ID, "CAPSULE_PROVENANCE_ID_INVALID")
    for key in ("review_record_sha256", "authority_record_sha256"):
        _require_hex(payload.get(key), SHA256, "CAPSULE_RECORD_DIGEST_INVALID")
    _require_hex(payload.get("expected_control_sha"), SHA40, "CAPSULE_CONTROL_SHA_INVALID")
    _require_hex(payload.get("expected_protocol_sha"), SHA40, "CAPSULE_PROTOCOL_SHA_INVALID")
    _require_hex(payload.get("expected_state_baseline"), SHA40, "CAPSULE_STATE_BASELINE_INVALID")
    if payload.get("single_use") is not True:
        raise OperatorCapsuleError("CAPSULE_SINGLE_USE_REQUIRED")
    if payload.get("workstream_e_authorised") is not False:
        raise OperatorCapsuleError("WORKSTREAM_E_NOT_AUTHORISED")
    if payload.get("operation") != expected_profile:
        raise OperatorCapsuleError("CAPSULE_OPERATION_MISMATCH")
    if payload.get("expected_control_sha") != expected_control_sha:
        raise OperatorCapsuleError("CAPSULE_STALE_CONTROL_SHA")
    if payload.get("expected_protocol_sha") != PROTOCOL_AUTHORITY_SHA:
        raise OperatorCapsuleError("CAPSULE_STALE_PROTOCOL_SHA")
    if payload.get("expected_state_baseline") != STATE_BASELINE_SHA:
        raise OperatorCapsuleError("CAPSULE_STATE_BASELINE_MISMATCH")

    created = _parse_time(payload.get("created_at"), "CAPSULE_CREATED_AT_INVALID")
    expires = _parse_time(payload.get("expires_at"), "CAPSULE_EXPIRES_AT_INVALID")
    if expires <= created or expires - created > MAX_CAPSULE_LIFETIME:
        raise OperatorCapsuleError("CAPSULE_LIFETIME_INVALID")
    if comment_created + CLOCK_SKEW < created or comment_created > expires:
        raise OperatorCapsuleError("CAPSULE_PROJECTION_TIME_INVALID")
    now_utc = now.astimezone(timezone.utc)
    if now_utc + CLOCK_SKEW < created:
        raise OperatorCapsuleError("CAPSULE_NOT_YET_VALID")
    if now_utc >= expires:
        raise OperatorCapsuleError("CAPSULE_EXPIRED")

    canonical = canonical_json(payload)
    return Capsule(
        dict(payload),
        sha256_text(body),
        sha256_text(canonical),
        int(comment["id"]),
        comment_created,
    )


def _list_issue_comments(api: GitHubAPI) -> list[dict[str, Any]]:
    comments: list[dict[str, Any]] = []
    page = 1
    while True:
        payload = api.get(
            f"/repos/{CONTROL_REPOSITORY}/issues/{OPERATOR_ISSUE_NUMBER}/comments"
            f"?per_page=100&page={page}"
        )
        if not isinstance(payload, list):
            raise OperatorCapsuleError("OPERATOR_COMMENT_LIST_INVALID")
        for item in payload:
            if not isinstance(item, dict):
                raise OperatorCapsuleError("OPERATOR_COMMENT_LIST_INVALID")
            comments.append(item)
        if len(payload) < 100:
            return comments
        page += 1
        if page > 100:
            raise OperatorCapsuleError("OPERATOR_COMMENT_PAGINATION_EXCESSIVE")


def _valid_consumption_for(comment: Mapping[str, Any], capsule: Capsule) -> bool:
    body = comment.get("body")
    if not isinstance(body, str) or "\n" in body or not body.startswith(CONSUMPTION_PREFIX):
        return False
    user = comment.get("user")
    if not isinstance(user, Mapping) or user.get("login") != "github-actions[bot]":
        return False
    try:
        created = _parse_time(comment.get("created_at"), "CONSUMPTION_TIME_INVALID")
        updated = _parse_time(comment.get("updated_at"), "CONSUMPTION_TIME_INVALID")
        if created != updated:
            return False
        payload = _strict_json(body[len(CONSUMPTION_PREFIX) :])
        _require_exact_keys(payload, CONSUMPTION_FIELDS, "CONSUMPTION_SCHEMA_MISMATCH")
    except OperatorCapsuleError:
        return False
    return (
        payload.get("contract") == "gitstate-consumption/v1"
        and payload.get("capsule_id") == capsule.capsule_id
        and payload.get("capsule_comment_id") == capsule.comment_id
        and payload.get("capsule_body_sha256") == capsule.body_sha256
        and payload.get("operation") == capsule.operation
        and payload.get("workstream_e_authorised") is False
    )


def discover_capsule(
    api: GitHubAPI,
    *,
    expected_control_sha: str,
    expected_profile: str,
    run_attempt: int,
    now: datetime | None = None,
) -> Capsule:
    if run_attempt != 1:
        raise OperatorCapsuleError("OPERATOR_RERUN_FORBIDDEN")
    current = now or datetime.now(timezone.utc)
    comments = _list_issue_comments(api)
    candidates: list[Capsule] = []
    for comment in comments:
        body = comment.get("body")
        if not isinstance(body, str) or not body.startswith(CAPSULE_PREFIX):
            continue
        try:
            capsule = parse_capsule_comment(
                comment,
                now=current,
                expected_control_sha=expected_control_sha,
                expected_profile=expected_profile,
            )
        except OperatorCapsuleError:
            continue
        if any(_valid_consumption_for(item, capsule) for item in comments):
            continue
        candidates.append(capsule)
    if not candidates:
        raise OperatorCapsuleError("NO_ELIGIBLE_OPERATOR_CAPSULE")
    if len(candidates) != 1:
        raise OperatorCapsuleError("AMBIGUOUS_OPERATOR_CAPSULE")
    return candidates[0]


def consume_capsule(
    api: GitHubAPI,
    *,
    expected_control_sha: str,
    expected_profile: str,
    expected_capsule_id: str,
    expected_comment_id: int,
    expected_body_sha256: str,
    run_id: int,
    run_attempt: int,
    now: datetime | None = None,
) -> tuple[Capsule, dict[str, Any], str]:
    current = now or datetime.now(timezone.utc)
    capsule = discover_capsule(
        api,
        expected_control_sha=expected_control_sha,
        expected_profile=expected_profile,
        run_attempt=run_attempt,
        now=current,
    )
    if (
        capsule.capsule_id != expected_capsule_id
        or capsule.comment_id != expected_comment_id
        or capsule.body_sha256 != expected_body_sha256
    ):
        raise OperatorCapsuleError("CAPSULE_CHANGED_BEFORE_CONSUMPTION")
    payload: dict[str, Any] = {
        "contract": "gitstate-consumption/v1",
        "capsule_id": capsule.capsule_id,
        "capsule_comment_id": capsule.comment_id,
        "capsule_body_sha256": capsule.body_sha256,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "trusted_sha": expected_control_sha,
        "operation": expected_profile,
        "consumed_at": current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "workstream_e_authorised": False,
    }
    body = CONSUMPTION_PREFIX + canonical_json(payload)
    response = api.post(
        f"/repos/{CONTROL_REPOSITORY}/issues/{OPERATOR_ISSUE_NUMBER}/comments",
        {"body": body},
    )
    if not isinstance(response, dict) or not isinstance(response.get("id"), int):
        raise OperatorCapsuleError("CONSUMPTION_RECORD_CREATE_FAILED")
    return capsule, payload, canonical_sha256(payload)


def _require_workflow_identity(values: Mapping[str, str]) -> tuple[str, int, int, str]:
    if values.get("GITHUB_REPOSITORY") != CONTROL_REPOSITORY:
        raise OperatorCapsuleError("OPERATOR_REPOSITORY_MISMATCH")
    if values.get("GITHUB_REF") != "refs/heads/main":
        raise OperatorCapsuleError("OPERATOR_PROTECTED_MAIN_REQUIRED")
    sha = values.get("GITHUB_SHA", "")
    _require_hex(sha, SHA40, "OPERATOR_TRUSTED_SHA_INVALID")
    try:
        run_id = int(values["GITHUB_RUN_ID"])
        run_attempt = int(values["GITHUB_RUN_ATTEMPT"])
    except (KeyError, TypeError, ValueError) as exc:
        raise OperatorCapsuleError("OPERATOR_RUN_IDENTITY_INVALID") from exc
    if run_id <= 0 or run_attempt != 1:
        raise OperatorCapsuleError("OPERATOR_RERUN_FORBIDDEN")
    profile = profile_for_dispatch(values.get("INPUT_OPERATION", ""))
    return sha, run_id, run_attempt, profile


def _write_outputs(path: str, values: Mapping[str, str]) -> None:
    if not path:
        raise OperatorCapsuleError("GITHUB_OUTPUT_MISSING")
    with open(path, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            if "\n" in key or "\n" in value:
                raise OperatorCapsuleError("OPERATOR_OUTPUT_INVALID")
            handle.write(f"{key}={value}\n")


def _api_from_environment(values: Mapping[str, str]) -> GitHubAPI:
    token = values.get("GITHUB_TOKEN", "")
    if not token:
        raise OperatorCapsuleError("GITHUB_TOKEN_MISSING")
    return GitHubAPI(token, values.get("GITHUB_API_URL", "https://api.github.com"))


def command_discover(values: Mapping[str, str]) -> None:
    sha, run_id, run_attempt, profile = _require_workflow_identity(values)
    capsule = discover_capsule(
        _api_from_environment(values),
        expected_control_sha=sha,
        expected_profile=profile,
        run_attempt=run_attempt,
    )
    outputs = capsule.runtime_outputs(run_id=run_id, run_attempt=run_attempt)
    _write_outputs(values.get("GITHUB_OUTPUT", ""), outputs)
    print(
        json.dumps(
            {
                "status": "OPERATOR_CAPSULE_VALIDATED",
                "capsule_id": capsule.capsule_id,
                "capsule_body_sha256": capsule.body_sha256,
                "operation": capsule.operation,
                "run_id": run_id,
                "run_attempt": run_attempt,
                "trusted_sha": sha,
                "credential_accessed": False,
                "workstream_e_authorised": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def command_consume(values: Mapping[str, str]) -> None:
    sha, run_id, run_attempt, profile = _require_workflow_identity(values)
    try:
        comment_id = int(values["EXPECTED_CAPSULE_COMMENT_ID"])
    except (KeyError, TypeError, ValueError) as exc:
        raise OperatorCapsuleError("EXPECTED_CAPSULE_COMMENT_ID_INVALID") from exc
    capsule, _, digest = consume_capsule(
        _api_from_environment(values),
        expected_control_sha=sha,
        expected_profile=profile,
        expected_capsule_id=values.get("EXPECTED_CAPSULE_ID", ""),
        expected_comment_id=comment_id,
        expected_body_sha256=values.get("EXPECTED_CAPSULE_BODY_SHA256", ""),
        run_id=run_id,
        run_attempt=run_attempt,
    )
    outputs = capsule.runtime_outputs(run_id=run_id, run_attempt=run_attempt)
    outputs["consumption_record_sha256"] = digest
    _write_outputs(values.get("GITHUB_OUTPUT", ""), outputs)
    print(
        json.dumps(
            {
                "status": "OPERATOR_CAPSULE_CONSUMED",
                "capsule_id": capsule.capsule_id,
                "capsule_body_sha256": capsule.body_sha256,
                "consumption_record_sha256": digest,
                "operation": capsule.operation,
                "run_id": run_id,
                "run_attempt": run_attempt,
                "trusted_sha": sha,
                "credential_accessed": False,
                "workstream_e_authorised": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def main() -> int:
    try:
        if len(sys.argv) != 2:
            raise OperatorCapsuleError("OPERATOR_COMMAND_REQUIRED")
        if sys.argv[1] == "discover":
            command_discover(os.environ)
        elif sys.argv[1] == "consume":
            command_consume(os.environ)
        else:
            raise OperatorCapsuleError("OPERATOR_COMMAND_INVALID")
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "BLOCKED",
                    "reason_code": str(exc).split(":", 1)[0] or type(exc).__name__,
                    "credential_accessed": False,
                    "workstream_e_authorised": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
