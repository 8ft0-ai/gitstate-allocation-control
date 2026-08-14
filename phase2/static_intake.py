from __future__ import annotations

import base64
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from .control_surface import ControlSurfaceError, validate_control_surface
from .discovery import Candidate, DiscoveryError, discover_candidates, paginate_comments
from .github_api import GitHubAPI
from .parser import PREFIX
from .policy import load_policy

FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MANUAL_OPERATIONS = {"reconcile", "scope_probe"}


def _result(action: str, **values: Any) -> dict[str, Any]:
    return {"action": action, **values}


def _encode(value: dict[str, Any]) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _candidate_record(candidate: Candidate) -> dict[str, Any]:
    return {
        "comment_id": candidate.comment_id,
        "payload_hash": candidate.payload_hash,
        "principal": candidate.principal,
        "request_id": candidate.request_id,
    }


def _candidate_set_payload(candidates: list[Candidate], trusted_sha: str) -> str:
    return _encode(
        {
            "candidates": [_candidate_record(candidate) for candidate in candidates],
            "trusted_sha": trusted_sha,
            "version": 1,
        }
    )


def _rejection_set_payload(candidates: list[Candidate], trusted_sha: str) -> str:
    return _encode(
        {
            "rejections": [
                {"reason_code": candidate.reason_code, "source_comment_id": candidate.comment_id}
                for candidate in candidates
            ],
            "trusted_sha": trusted_sha,
            "version": 1,
        }
    )


def _single_rejection_set_payload(reason_code: str, source_comment_id: int, trusted_sha: str) -> str:
    return _encode(
        {
            "rejections": [
                {"reason_code": reason_code, "source_comment_id": source_comment_id}
            ],
            "trusted_sha": trusted_sha,
            "version": 1,
        }
    )


def run(env: dict[str, str] | None = None) -> dict[str, Any]:
    values = os.environ if env is None else env
    policy = load_policy(values.get("PHASE2_POLICY", "policy/actors.json"))
    event_name = values["GITHUB_EVENT_NAME"]
    if event_name not in {"issue_comment", "schedule", "workflow_dispatch"}:
        return _result("blocked", reason_code="UNAPPROVED_EVENT")
    trusted_sha = values["PHASE2_TRUSTED_SHA"]
    if not FULL_SHA_RE.fullmatch(trusted_sha):
        return _result("blocked", reason_code="INVALID_TRUSTED_SHA")

    with Path(values["GITHUB_EVENT_PATH"]).open(encoding="utf-8") as handle:
        event = json.load(handle)

    repository = event.get("repository") or {}
    if repository.get("full_name") != policy["control_repository"] or repository.get("id") != policy["control_repository_id"]:
        return _result("rejected", reason_code="WRONG_CONTROL_REPOSITORY")

    manual_operation: str | None = None
    if event_name == "workflow_dispatch":
        actor = values.get("GITHUB_ACTOR", "")
        sender = (event.get("sender") or {}).get("login")
        if actor not in policy.get("operators", []) or sender != actor:
            return _result("blocked", reason_code="OPERATOR_NOT_AUTHORISED")
        inputs = event.get("inputs") or {}
        manual_operation = inputs.get("operation", "reconcile")
        if manual_operation not in MANUAL_OPERATIONS:
            return _result("blocked", reason_code="UNAPPROVED_MANUAL_OPERATION")

    if event_name == "issue_comment":
        issue = event.get("issue") or {}
        comment = event.get("comment") or {}
        body = comment.get("body") or ""
        is_pull_request = isinstance(issue.get("pull_request"), dict)
        if issue.get("number") != policy["allocation_issue_number"] or is_pull_request:
            if isinstance(body, str) and body.encode("utf-8").startswith(PREFIX):
                report_issue_number = issue.get("number")
                source_comment_id = comment.get("id")
                if not isinstance(report_issue_number, int) or not isinstance(source_comment_id, int):
                    return _result("blocked", reason_code="INVALID_EVENT_IDENTITY")
                return _result(
                    "rejected",
                    reason_code="NON_CONTROL_SURFACE",
                    rejection_count=1,
                    rejection_set=_single_rejection_set_payload(
                        "NON_CONTROL_SURFACE", source_comment_id, trusted_sha
                    ),
                    report_issue_number=report_issue_number,
                    source_comment_id=source_comment_id,
                    trusted_sha=trusted_sha,
                )
            return _result("noop")

    api = GitHubAPI(values["GITHUB_TOKEN"], values.get("GITHUB_API_URL", "https://api.github.com"))
    owner, repo = policy["control_repository"].split("/", 1)
    try:
        validate_control_surface(api, owner, repo, policy)
    except ControlSurfaceError as exc:
        return _result("blocked", reason_code=str(exc))

    if event_name == "workflow_dispatch" and manual_operation == "scope_probe":
        return _result("scope_probe", trusted_sha=trusted_sha)

    def fetch_page(page: int, per_page: int) -> tuple[list[dict[str, Any]], bool]:
        path = f"/repos/{owner}/{repo}/issues/{policy['allocation_issue_number']}/comments?per_page={per_page}&page={page}&sort=created&direction=asc"
        payload, headers = api.request("GET", path)
        link = headers.get("link", "")
        return payload, 'rel="next"' in link

    try:
        candidates = discover_candidates(
            paginate_comments(fetch_page),
            policy["control_repository"],
            policy,
            set(),
        )
    except DiscoveryError as exc:
        return _result("blocked", reason_code=str(exc))

    if not candidates:
        return _result("noop")

    ready = [candidate for candidate in candidates if candidate.disposition == "READY_FOR_LIVE_CHECK"]
    rejected = [candidate for candidate in candidates if candidate.disposition == "REJECTED"]
    common: dict[str, Any] = {
        "candidate_count": len(ready),
        "rejection_count": len(rejected),
        "report_issue_number": policy["allocation_issue_number"],
        "trusted_sha": trusted_sha,
    }
    if rejected:
        common["rejection_set"] = _rejection_set_payload(rejected, trusted_sha)

    if ready:
        return _result(
            "live_check",
            **common,
            candidate_set=_candidate_set_payload(ready, trusted_sha),
            source_comment_id=ready[0].comment_id,
        )

    first = rejected[0]
    return _result(
        "rejected",
        **common,
        reason_code=first.reason_code,
        source_comment_id=first.comment_id,
    )


def main() -> int:
    try:
        print(json.dumps(run(), sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as exc:
        print(json.dumps({"action": "blocked", "reason_code": type(exc).__name__}, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
