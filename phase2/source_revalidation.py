from __future__ import annotations

import base64
import json
import os
import re
import sys
import urllib.parse
from typing import Any

from .control_surface import validate_control_surface
from .github_api import GitHubAPI, GitHubAPIError
from .parser import RequestError, parse_request
from .policy import AuthorisationError, authorise, load_policy

FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class SourceRevalidationError(RuntimeError):
    pass


def _encode(value: dict[str, Any]) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_candidate_set(value: str, trusted_sha: str) -> list[dict[str, Any]]:
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
        envelope = json.loads(decoded)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise SourceRevalidationError("INVALID_CANDIDATE_SET") from exc
    if (
        not isinstance(envelope, dict)
        or envelope.get("version") != 1
        or envelope.get("trusted_sha") != trusted_sha
        or not isinstance(envelope.get("candidates"), list)
        or not envelope["candidates"]
    ):
        raise SourceRevalidationError("INVALID_CANDIDATE_SET")

    candidates: list[dict[str, Any]] = []
    previous = -1
    required = {"comment_id", "payload_hash", "principal", "request_id"}
    for candidate in envelope["candidates"]:
        if not isinstance(candidate, dict) or set(candidate) != required:
            raise SourceRevalidationError("INVALID_CANDIDATE_SET")
        comment_id = candidate.get("comment_id")
        if not isinstance(comment_id, int) or comment_id <= previous:
            raise SourceRevalidationError("INVALID_CANDIDATE_ORDER")
        if not all(isinstance(candidate.get(key), str) and candidate[key] for key in ("payload_hash", "principal", "request_id")):
            raise SourceRevalidationError("INVALID_CANDIDATE_SET")
        previous = comment_id
        candidates.append(candidate)
    return candidates


def _candidate_set_payload(candidates: list[dict[str, Any]], trusted_sha: str) -> str:
    return _encode({"candidates": candidates, "trusted_sha": trusted_sha, "version": 1})


def _rejection_set_payload(rejections: list[dict[str, Any]], trusted_sha: str) -> str:
    return _encode({"rejections": rejections, "trusted_sha": trusted_sha, "version": 1})


def _comment_belongs_to_control_issue(comment: dict[str, Any], owner: str, repository: str, issue_number: int) -> bool:
    issue_url = comment.get("issue_url")
    if not isinstance(issue_url, str):
        return False
    path = urllib.parse.urlparse(issue_url).path.rstrip("/")
    return path.endswith(f"/repos/{owner}/{repository}/issues/{issue_number}")


def _rejection(comment_id: int, reason_code: str) -> dict[str, Any]:
    return {"reason_code": reason_code, "source_comment_id": comment_id}


def run(env: dict[str, str] | None = None) -> dict[str, Any]:
    values = os.environ if env is None else env
    policy = load_policy(values.get("PHASE2_POLICY", "policy/actors.json"))
    trusted_sha = values["PHASE2_TRUSTED_SHA"]
    if not FULL_SHA_RE.fullmatch(trusted_sha):
        raise SourceRevalidationError("INVALID_TRUSTED_SHA")
    candidates = _decode_candidate_set(values["PHASE2_CANDIDATE_SET"], trusted_sha)

    api_url = values.get("GITHUB_API_URL", "https://api.github.com")
    workflow_api = GitHubAPI(values["GITHUB_TOKEN"], api_url)
    owner, repo = policy["control_repository"].split("/", 1)
    validate_control_surface(workflow_api, owner, repo, policy)

    valid: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for candidate in candidates:
        comment_id = candidate["comment_id"]
        try:
            comment = workflow_api.get(f"/repos/{owner}/{repo}/issues/comments/{comment_id}")
        except GitHubAPIError as exc:
            if exc.status == 404:
                rejected.append(_rejection(comment_id, "SOURCE_COMMENT_DELETED_BEFORE_INGRESS"))
                continue
            raise
        if not isinstance(comment, dict) or comment.get("id") != comment_id:
            raise SourceRevalidationError("SOURCE_COMMENT_MISMATCH")
        if not _comment_belongs_to_control_issue(comment, owner, repo, policy["allocation_issue_number"]):
            raise SourceRevalidationError("SOURCE_COMMENT_MISMATCH")

        try:
            body = comment.get("body")
            if not isinstance(body, str):
                raise RequestError("INVALID_REQUEST")
            parsed = parse_request(body.encode("utf-8"))
            principal = authorise(comment, parsed, policy)
            if (
                parsed.payload_hash != candidate.get("payload_hash")
                or parsed.payload["request_id"] != candidate.get("request_id")
                or principal.encode() != candidate.get("principal")
            ):
                raise AuthorisationError("AGENT_NOT_AUTHORISED", "candidate changed")
            if comment.get("updated_at") != comment.get("created_at"):
                raise AuthorisationError("SOURCE_COMMENT_EDITED_BEFORE_INGRESS")
        except (RequestError, AuthorisationError) as exc:
            rejected.append(_rejection(comment_id, getattr(exc, "code", "INVALID_REQUEST")))
            continue
        valid.append(candidate)

    result: dict[str, Any] = {
        "candidate_count": len(valid),
        "rejection_count": len(rejected),
        "report_issue_number": policy["allocation_issue_number"],
    }
    if rejected:
        result["rejection_set"] = _rejection_set_payload(rejected, trusted_sha)

    if valid:
        result.update(
            {
                "action": "live_check",
                "candidate_set": _candidate_set_payload(valid, trusted_sha),
                "source_comment_id": valid[0]["comment_id"],
            }
        )
        return result

    result.update(
        {
            "action": "rejected",
            "reason_code": rejected[0]["reason_code"],
            "source_comment_id": rejected[0]["source_comment_id"],
        }
    )
    return result


def _write_outputs(result: dict[str, Any], path: str | None) -> None:
    if not path:
        return
    keys = (
        "action",
        "candidate_count",
        "candidate_set",
        "reason_code",
        "rejection_count",
        "rejection_set",
        "report_issue_number",
        "source_comment_id",
    )
    with open(path, "a", encoding="utf-8") as handle:
        for key in keys:
            if key in result and result[key] is not None:
                handle.write(f"{key}={result[key]}\n")


def main() -> int:
    try:
        result = run()
        _write_outputs(result, os.environ.get("GITHUB_OUTPUT"))
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as exc:
        result = {"action": "blocked", "reason_code": type(exc).__name__}
        _write_outputs(result, os.environ.get("GITHUB_OUTPUT"))
        print(json.dumps(result, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
