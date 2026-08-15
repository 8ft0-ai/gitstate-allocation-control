"""Narrow Workstream B command path from trusted intake to canonical mutation.

This module deliberately accepts an already-authorised context and an injected
canonical repository. It has no credential minting, GitHub projection, workflow
dispatch, or default live-state adapter.
"""

from __future__ import annotations

from .allocation_engine import AllocationService
from .allocation_types import AllocationCommand, AllocationResult, RequestContext
from .canonical import CanonicalRepository
from .parser import ParsedRequest


def process_authorised_request(
    repository: CanonicalRepository,
    request: ParsedRequest,
    context: RequestContext,
    *,
    max_stale_retries: int = 3,
) -> AllocationResult:
    """Process one statically authorised request through the bounded CAS path."""
    command = AllocationCommand.from_parsed(request)
    return AllocationService(
        repository, max_stale_retries=max_stale_retries
    ).process(command, context)
