from __future__ import annotations

import base64
import json
import os
import re
import sys
import urllib.parse
from typing import Any

from .control_surface import validate_control_surface
from .github_api import GitHubAPI
from .parser import RequestError, parse_request
from .policy import AuthorisationError, authorise, load_policy

FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class SourceRevalidationError(RuntimeError):
    pass


def _decode_candidate(value: str) -> dict[str, Any]:
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
        candidate = json.loads(decoded)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise SourceRevalidationError("INVALID_CANDIDATE") from exc
    if not isinstance(candidate, dict):
        raise SourceRevalidationError("INVALID_CANDIDATE")
    return candidate


def _comment_belongs_to_control_issue(comment: dict[str, Any], owner: str, repository: str, issue_number: int) -> bool:
    issue_url = comment.get("issue_url")
    if not isinstance(issue_url, str):
        return False
    path = urllib.parse.urlparse(issue_url).path.rstrip("/")
    return path.endswith(f"/repos/{owner}/{repository}/issues/{issue_number}")


def run(env: dict[str, str] | None = None) -> dict[str, Any]:
    values = os.environ if env is None else env
    policy = load_policy(values.get("PHASE2_POLICY", "policy/actors.json"))
    trusted_sha = values["PHASE2_TRUSTED_SHA"]
    if not FULL_SHA_RE.fullmatch(trusted_sha):
        raise SourceRevalidationError("INVALID_TRUSTED_SHA")
    candidate = _decode_candidate(values["PHASE2_CANDIDATE"])
    if candidate.get("trusted_sha") != trusted_sha:
        raise SourceRevalidationError("CANDIDATE_SHA_MISMATCH")
    comment_id = candidate.get("comment_id")
    if not isinstance(comment_id, int):
        raise SourceRevalidationError("INVALID_COMMENT_ID")

    api_url = values.get("GITHUB_API_URL", "https://api.github.com")
    workflow_api = GitHubAPI(values["GITHUB_TOKEN"], api_url)
    owner, repo = policy["control_repository"].split("/", 1)
    validate_control_surface(workflow_api, owner, repo, policy)
    comment = workflow_api.get(f"/repos/{owner}/{repo}/issues/comments/{comment_id}")
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
        return {
            "action": "rejected",
            "reason_code": getattr(exc, "code", "INVALID_REQUEST"),
            "report_issue_number": policy["allocation_issue_number"],
            "source_comment_id": comment_id,
        }

    return {
        "action": "live_check",
        "report_issue_number": policy["allocation_issue_number"],
        "source_comment_id": comment_id,
    }


def _write_outputs(result: dict[str, Any], path: str | None) -> None:
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        for key in ("action", "reason_code", "report_issue_number", "source_comment_id"):
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
