"""Domain values for deterministic Workstream B allocation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from .parser import ParsedRequest

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def stable_ulid(namespace: str) -> str:
    """Generate a stable, valid 128-bit Crockford identifier for retry safety."""
    value = int.from_bytes(hashlib.sha256(namespace.encode("utf-8")).digest()[:16], "big")
    output = ["0"] * 26
    for index in range(25, -1, -1):
        output[index] = CROCKFORD[value & 31]
        value >>= 5
    return "".join(output)


@dataclass(frozen=True)
class AllocationCommand:
    request_id: str
    request_type: str
    payload_hash: str
    agent_id: str
    capabilities: tuple[str, ...] = ()
    task_types: tuple[str, ...] = ()
    max_priority: int | None = None
    task_id: str | None = None
    allocation_id: str | None = None
    reason: str | None = None

    @classmethod
    def from_parsed(cls, request: ParsedRequest) -> "AllocationCommand":
        payload = request.payload
        return cls(
            request_id=payload["request_id"],
            request_type=payload["type"],
            payload_hash=request.payload_hash,
            agent_id=payload["agent_id"],
            capabilities=tuple(payload.get("capabilities", ())),
            task_types=tuple(payload.get("task_types", ())),
            max_priority=payload.get("max_priority"),
            task_id=payload.get("task_id"),
            allocation_id=payload.get("allocation_id"),
            reason=payload.get("reason"),
        )


@dataclass(frozen=True)
class RequestContext:
    source_repository: str
    source_issue_number: int
    source_comment_id: int
    requested_by: str
    authorised_agent_id: str
    is_operator: bool = False


@dataclass(frozen=True)
class AllocationResult:
    request_id: str
    status: str
    reason_code: str
    allocation_id: str | None = None
    task_id: str | None = None
    canonical_git_ref_sha: str | None = None
    canonical_dolt_commit: str | None = None
    ref_advanced: bool = False
    retry_count: int = 0


@dataclass(frozen=True)
class Task:
    task_id: str
    task_type: str
    status: str
    assignee: str | None
    priority: int
    created_at: str
    ready: bool
    blocked: bool
    labels: tuple[str, ...] = ()

    @property
    def required_capabilities(self) -> set[str]:
        return {label.removeprefix("capability:") for label in self.labels if label.startswith("capability:")}


def allocation_digest(allocation: dict[str, Any]) -> str:
    import json

    canonical = json.dumps(allocation, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
