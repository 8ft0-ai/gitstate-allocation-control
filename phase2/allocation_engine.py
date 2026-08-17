"""Deterministic claim/release engine for Workstream B."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from typing import Callable, Iterable

from .allocation_store import (
    AllocationStore,
    CanonicalOwnershipMismatch,
)
from .allocation_types import AllocationCommand, AllocationResult, RequestContext, Task
from .canonical import (
    CanonicalIdentity,
    CanonicalPushFailed,
    CanonicalRepository,
    StaleCanonicalBase,
    verify_canonical_identity,
)

SUPPORTED_TASK_TYPES = frozenset({"bug", "feature", "task"})


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _store(repository: CanonicalRepository, snapshot: object) -> AllocationStore:
    """Open the repository-specific store without weakening local isolation."""
    factory = getattr(repository, "store", None)
    if callable(factory):
        return factory(snapshot)
    return AllocationStore(snapshot.connection)  # type: ignore[attr-defined]


def _with_publish(
    result: AllocationResult,
    identity: CanonicalIdentity,
    *,
    advanced: bool,
    retries: int,
) -> AllocationResult:
    return replace(
        result,
        canonical_git_ref_sha=result.canonical_git_ref_sha or identity.git_ref_sha,
        canonical_dolt_commit=result.canonical_dolt_commit or identity.dolt_commit,
        ref_advanced=advanced,
        retry_count=retries,
    )


class AllocationService:
    """Serialisable mutation service with bounded stale-base retries."""

    def __init__(
        self,
        repository: CanonicalRepository,
        *,
        clock: Callable[[], str] = utc_now,
        max_stale_retries: int = 3,
        supported_task_types: frozenset[str] = SUPPORTED_TASK_TYPES,
    ) -> None:
        if max_stale_retries < 0:
            raise ValueError("max_stale_retries must be non-negative")
        self.repository = repository
        self.clock = clock
        self.max_stale_retries = max_stale_retries
        self.supported_task_types = supported_task_types

    def _consume_stale_retry(self, stale_retries: int) -> int | None:
        """Return the next retry count, or ``None`` when the bounded budget is spent."""
        if stale_retries >= self.max_stale_retries:
            return None
        return stale_retries + 1

    def process(self, command: AllocationCommand, context: RequestContext) -> AllocationResult:
        stale_retries = 0
        while True:
            try:
                snapshot = self.repository.bootstrap()
            except StaleCanonicalBase:
                next_retry = self._consume_stale_retry(stale_retries)
                if next_retry is None:
                    return AllocationResult(
                        command.request_id,
                        "REJECTED",
                        "STALE_ALLOCATOR_RETRY_EXHAUSTED",
                        retry_count=stale_retries,
                    )
                stale_retries = next_retry
                continue

            verify_canonical_identity(snapshot.identity)
            store = _store(self.repository, snapshot)
            source = store.get_request_by_source(context)
            if source is not None and source["request_id"] != command.request_id:
                try:
                    return AllocationResult(
                        command.request_id,
                        "REJECTED",
                        "SOURCE_COMMENT_EDITED",
                        canonical_git_ref_sha=(
                            source["canonical_git_ref_sha"] or snapshot.identity.git_ref_sha
                        ),
                        canonical_dolt_commit=(
                            source["canonical_dolt_commit"] or snapshot.identity.dolt_commit
                        ),
                        retry_count=stale_retries,
                    )
                finally:
                    snapshot.close()
            existing = store.get_request(command.request_id)
            if existing is not None:
                try:
                    if existing["payload_sha256"] == command.payload_hash:
                        return _with_publish(
                            store.result_from_request(existing),
                            snapshot.identity,
                            advanced=False,
                            retries=stale_retries,
                        )
                    return AllocationResult(
                        command.request_id,
                        "REJECTED",
                        "REQUEST_ID_PAYLOAD_MISMATCH",
                        canonical_git_ref_sha=(
                            existing["canonical_git_ref_sha"] or snapshot.identity.git_ref_sha
                        ),
                        canonical_dolt_commit=(
                            existing["canonical_dolt_commit"] or snapshot.identity.dolt_commit
                        ),
                        retry_count=stale_retries,
                    )
                finally:
                    snapshot.close()

            try:
                store.begin()
                result = self._apply(store, command, context, self.clock())
                store.commit()
            except Exception:
                store.rollback()
                snapshot.close()
                raise

            expected = snapshot.identity.git_ref_sha
            try:
                accepted = self.repository.publish(expected, snapshot)
            except StaleCanonicalBase:
                snapshot.close()
                next_retry = self._consume_stale_retry(stale_retries)
                if next_retry is None:
                    return AllocationResult(
                        command.request_id,
                        "REJECTED",
                        "STALE_ALLOCATOR_RETRY_EXHAUSTED",
                        retry_count=stale_retries,
                    )
                stale_retries = next_retry
                continue
            except CanonicalPushFailed:
                snapshot.close()
                return AllocationResult(
                    command.request_id,
                    "REJECTED",
                    "CANONICAL_PUSH_FAILED",
                    retry_count=stale_retries,
                )
            snapshot.close()
            return _with_publish(result, accepted, advanced=True, retries=stale_retries)

    def _apply(
        self,
        store: AllocationStore,
        command: AllocationCommand,
        context: RequestContext,
        processed_at: str,
    ) -> AllocationResult:
        if context.authorised_agent_id != command.agent_id and not context.is_operator:
            return store.reject(command, context, "AGENT_NOT_AUTHORISED", processed_at)
        if command.request_type == "RELEASE":
            return store.release(command, context, processed_at)
        if command.request_type not in {"ALLOCATE_NEXT", "ALLOCATE_TASK"}:
            return store.reject(command, context, "INVALID_REQUEST", processed_at)

        if command.request_type == "ALLOCATE_TASK":
            task = store.task(command.task_id or "")
            if task is None:
                return store.reject(command, context, "TASK_NOT_FOUND", processed_at)
            try:
                store.assert_ownership_invariant(task)
            except CanonicalOwnershipMismatch as exc:
                return store.reject(
                    command,
                    context,
                    "CANONICAL_OWNERSHIP_MISMATCH",
                    processed_at,
                    mismatch_task_id=exc.task_id,
                )
            reason = self._ineligible_reason(task, command)
            if reason is not None:
                return store.reject(command, context, reason, processed_at)
            return store.grant(command, context, task, processed_at)

        tasks = store.tasks()
        for task in tasks:
            try:
                store.assert_ownership_invariant(task)
            except CanonicalOwnershipMismatch as exc:
                return store.reject(
                    command,
                    context,
                    "CANONICAL_OWNERSHIP_MISMATCH",
                    processed_at,
                    mismatch_task_id=exc.task_id,
                )
        eligible = [task for task in tasks if self._ineligible_reason(task, command) is None]
        if not eligible:
            return store.reject(command, context, "NO_ELIGIBLE_TASK", processed_at)
        eligible.sort(key=lambda task: (task.priority, task.created_at, task.task_id.encode("utf-8")))
        return store.grant(command, context, eligible[0], processed_at)

    def _ineligible_reason(self, task: Task, command: AllocationCommand) -> str | None:
        if task.task_type not in self.supported_task_types:
            return "TASK_TYPE_NOT_SUPPORTED"
        if command.task_types and task.task_type not in command.task_types:
            return "TASK_TYPE_NOT_SUPPORTED"
        if task.status != "open":
            return "TASK_ALREADY_ALLOCATED"
        if not task.ready or task.blocked:
            return "TASK_NOT_READY"
        if command.max_priority is not None and task.priority > command.max_priority:
            return "TASK_NOT_READY"
        if not task.required_capabilities.issubset(command.capabilities):
            return "CAPABILITY_MISMATCH"
        return None

    def record_anchor(
        self,
        request_id: str,
        first_git_ref_sha: str,
        first_dolt_commit: str,
    ) -> AllocationResult:
        stale_retries = 0
        verify_canonical_identity(
            CanonicalIdentity("refs/dolt/data", first_git_ref_sha, first_dolt_commit)
        )
        while True:
            try:
                snapshot = self.repository.bootstrap()
            except StaleCanonicalBase:
                next_retry = self._consume_stale_retry(stale_retries)
                if next_retry is None:
                    return AllocationResult(
                        request_id,
                        "REJECTED",
                        "STALE_ALLOCATOR_RETRY_EXHAUSTED",
                        retry_count=stale_retries,
                    )
                stale_retries = next_retry
                continue

            store = _store(self.repository, snapshot)
            try:
                store.begin()
                changed = store.record_anchor(
                    request_id, first_git_ref_sha, first_dolt_commit, self.clock()
                )
                store.commit()
            except Exception:
                store.rollback()
                snapshot.close()
                raise
            if not changed:
                row = store.get_request(request_id)
                result = store.result_from_request(row)  # type: ignore[arg-type]
                identity = snapshot.identity
                snapshot.close()
                return _with_publish(result, identity, advanced=False, retries=stale_retries)
            try:
                accepted = self.repository.publish(snapshot.identity.git_ref_sha, snapshot)
            except StaleCanonicalBase:
                snapshot.close()
                next_retry = self._consume_stale_retry(stale_retries)
                if next_retry is None:
                    return AllocationResult(
                        request_id,
                        "REJECTED",
                        "STALE_ALLOCATOR_RETRY_EXHAUSTED",
                        retry_count=stale_retries,
                    )
                stale_retries = next_retry
                continue
            except CanonicalPushFailed:
                snapshot.close()
                return AllocationResult(request_id, "REJECTED", "CANONICAL_PUSH_FAILED")
            row = store.get_request(request_id)
            result = store.result_from_request(row)  # type: ignore[arg-type]
            snapshot.close()
            return _with_publish(result, accepted, advanced=True, retries=stale_retries)

    @staticmethod
    def unsupported_mutation(store: AllocationStore, mutation: str) -> None:
        store.unsupported_mutation(mutation)


def seed_local_fixture(repository: CanonicalRepository, tasks: Iterable[Task]) -> CanonicalIdentity:
    """Create synthetic Beads fixtures in an isolated repository only."""
    snapshot = repository.bootstrap()
    store = _store(repository, snapshot)
    store.begin()
    try:
        for task in tasks:
            store.seed_task(task)
        store.commit()
        return repository.publish(snapshot.identity.git_ref_sha, snapshot)
    except Exception:
        store.rollback()
        raise
    finally:
        snapshot.close()
