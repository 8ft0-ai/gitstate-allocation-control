"""Canonical-derived Workstream C projection envelopes.

This module is deliberately credential-free.  It accepts only already-canonical
records and produces the complete GitHub-visible result envelope defined by the
Phase 2 protocol.  A projection is visibility, never ownership authority.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

PROTOCOL = "beads-allocation/v0.2"
CANONICAL_REF = "refs/dolt/data"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
TERMINAL_RESULTS = frozenset({"ALLOCATED", "REJECTED", "RELEASED"})


class ProjectionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CanonicalProjection:
    """Immutable canonical facts from which one result projection is rendered."""

    request_id: str
    result_status: str
    reason_code: str
    source_repository: str
    source_issue_number: int
    source_comment_id: int
    canonical_git_ref_sha: str
    canonical_dolt_commit: str
    agent_id: str | None = None
    allocation_id: str | None = None
    task_id: str | None = None
    task_summary: str | None = None
    grant_timestamp: str | None = None
    ownership_valid: bool = True

    def validate(self) -> None:
        if self.result_status not in TERMINAL_RESULTS:
            raise ProjectionError("NON_TERMINAL_CANONICAL_RESULT")
        if not self.request_id:
            raise ProjectionError("MISSING_REQUEST_ID")
        if not self.reason_code:
            raise ProjectionError("MISSING_REASON_CODE")
        if not self.source_repository or self.source_issue_number <= 0 or self.source_comment_id <= 0:
            raise ProjectionError("INVALID_SOURCE_IDENTITY")
        if not FULL_SHA.fullmatch(self.canonical_git_ref_sha):
            raise ProjectionError("INVALID_CANONICAL_GIT_SHA")
        if not self.canonical_dolt_commit or any(ch.isspace() for ch in self.canonical_dolt_commit):
            raise ProjectionError("INVALID_CANONICAL_DOLT_COMMIT")
        if self.result_status == "ALLOCATED":
            if not self.ownership_valid:
                raise ProjectionError("CANONICAL_OWNERSHIP_MISMATCH")
            if not all((self.agent_id, self.allocation_id, self.task_id, self.task_summary, self.grant_timestamp)):
                raise ProjectionError("INCOMPLETE_ALLOCATED_RESULT")
        if self.result_status == "RELEASED" and not self.allocation_id:
            raise ProjectionError("INCOMPLETE_RELEASED_RESULT")

    def envelope(self) -> dict[str, Any]:
        self.validate()
        payload: dict[str, Any] = {
            "canonical_dolt_commit": self.canonical_dolt_commit,
            "canonical_git_ref": CANONICAL_REF,
            "canonical_git_ref_sha": self.canonical_git_ref_sha,
            "execution_may_begin": self.result_status == "ALLOCATED",
            "protocol": PROTOCOL,
            "reason_code": self.reason_code,
            "request_id": self.request_id,
            "result_status": self.result_status,
            "source_comment_id": self.source_comment_id,
            "source_issue_number": self.source_issue_number,
            "source_repository": self.source_repository,
        }
        if self.agent_id is not None:
            payload["agent_id"] = self.agent_id
        if self.allocation_id is not None:
            payload["allocation_id"] = self.allocation_id
        if self.task_id is not None:
            payload["task_id"] = self.task_id
        if self.result_status == "ALLOCATED":
            payload["task_summary"] = self.task_summary
            payload["grant_timestamp"] = self.grant_timestamp
            payload["release_instruction"] = (
                "Post a new /beads-v0.2 RELEASE request referencing this allocation_id."
            )
        return payload


def render_projection(projection: CanonicalProjection | Mapping[str, Any]) -> str:
    """Render exactly one machine-readable JSON object for an issue comment."""
    payload = projection.envelope() if isinstance(projection, CanonicalProjection) else dict(projection)
    _validate_envelope(payload)
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def parse_projection(body: str) -> dict[str, Any] | None:
    """Parse only the bare JSON projection format emitted by this implementation.

    Intake comments, prose comments and fenced diagnostic JSON are intentionally
    not treated as projections.  This keeps reconciliation from deriving
    authority from unrelated GitHub content.
    """
    text = body.strip()
    if not text.startswith("{") or not text.endswith("}"):
        return None
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(value, dict) or value.get("protocol") != PROTOCOL:
        return None
    try:
        _validate_envelope(value)
    except ProjectionError:
        return None
    return value


def _validate_envelope(payload: Mapping[str, Any]) -> None:
    required = {
        "canonical_dolt_commit",
        "canonical_git_ref",
        "canonical_git_ref_sha",
        "execution_may_begin",
        "protocol",
        "reason_code",
        "request_id",
        "result_status",
        "source_comment_id",
        "source_issue_number",
        "source_repository",
    }
    if not required.issubset(payload):
        raise ProjectionError("INCOMPLETE_PROJECTION")
    if payload["protocol"] != PROTOCOL or payload["canonical_git_ref"] != CANONICAL_REF:
        raise ProjectionError("INVALID_PROJECTION_PROTOCOL")
    if payload["result_status"] not in TERMINAL_RESULTS:
        raise ProjectionError("NON_TERMINAL_CANONICAL_RESULT")
    sha = payload["canonical_git_ref_sha"]
    if not isinstance(sha, str) or not FULL_SHA.fullmatch(sha):
        raise ProjectionError("INVALID_CANONICAL_GIT_SHA")
    dolt = payload["canonical_dolt_commit"]
    if not isinstance(dolt, str) or not dolt or any(ch.isspace() for ch in dolt):
        raise ProjectionError("INVALID_CANONICAL_DOLT_COMMIT")
    if not isinstance(payload["source_issue_number"], int) or payload["source_issue_number"] <= 0:
        raise ProjectionError("INVALID_SOURCE_IDENTITY")
    if not isinstance(payload["source_comment_id"], int) or payload["source_comment_id"] <= 0:
        raise ProjectionError("INVALID_SOURCE_IDENTITY")
    may_begin = payload["execution_may_begin"]
    if not isinstance(may_begin, bool):
        raise ProjectionError("INVALID_EXECUTION_FLAG")
    if may_begin != (payload["result_status"] == "ALLOCATED"):
        raise ProjectionError("INVALID_EXECUTION_FLAG")
    if payload["result_status"] == "ALLOCATED":
        allocated = {
            "agent_id",
            "allocation_id",
            "task_id",
            "task_summary",
            "grant_timestamp",
            "release_instruction",
        }
        if not allocated.issubset(payload):
            raise ProjectionError("INCOMPLETE_ALLOCATED_RESULT")


def projection_identity(payload: Mapping[str, Any]) -> tuple[object, ...]:
    """Stable identity used to correlate durable visibility with canonical facts."""
    _validate_envelope(payload)
    return (
        payload["request_id"],
        payload["source_comment_id"],
        payload["result_status"],
        payload["reason_code"],
        payload["canonical_git_ref_sha"],
        payload["canonical_dolt_commit"],
    )


def projection_matches(payload: Mapping[str, Any], expected: CanonicalProjection) -> bool:
    """Return true only when the visible projection exactly matches canonical facts."""
    try:
        return dict(payload) == expected.envelope()
    except ProjectionError:
        return False
