"""Workstream C projection, reconciliation and operator-recovery logic.

All GitHub I/O and allocation-state persistence are injected. The reconciler
never treats comments as ownership authority: canonical allocation rows and the
Beads ownership mirror are checked before an ALLOCATED projection can be
rendered. Metadata repairs use the same canonical repository CAS boundary as
Workstream B.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Protocol, Sequence

from .allocation_engine import AllocationService
from .allocation_store import AllocationStore, CanonicalOwnershipMismatch
from .allocation_types import AllocationCommand, AllocationResult, RequestContext
from .canonical import (
    CanonicalIdentity,
    CanonicalPushFailed,
    CanonicalRepository,
    StaleCanonicalBase,
    verify_canonical_identity,
)
from .parser import RequestError, parse_request
from .projection import (
    CanonicalProjection,
    ProjectionError,
    parse_projection,
    projection_matches,
    render_projection,
)

CONTROL_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class ProjectionDeliveryError(RuntimeError):
    pass


class ReconciliationError(RuntimeError):
    pass


@dataclass(frozen=True)
class DurableComment:
    comment_id: int
    body: str
    html_url: str


@dataclass(frozen=True)
class PostedComment:
    comment_id: int
    html_url: str


@dataclass(frozen=True)
class CanonicalHistoryRevision:
    """One accepted first-parent canonical revision reconstructed from Git/Dolt.

    ``request_ids`` is the complete set of canonical request IDs visible in that
    accepted revision. A production history reader must obtain these facts from
    durable ``refs/dolt/data`` history, never from runner memory or a remembered
    result tuple.
    """

    identity: CanonicalIdentity
    request_ids: frozenset[str]


class CanonicalHistoryReader(Protocol):
    """Complete accepted first-parent history for ``refs/dolt/data``."""

    @property
    def complete(self) -> bool: ...

    def accepted_revisions(self) -> Sequence[CanonicalHistoryRevision]: ...


class ReconciliationGateway(Protocol):
    """Complete durable control-issue view plus bounded issue-write operations."""

    def list_comments(self, issue_number: int) -> Sequence[DurableComment]: ...

    def post_projection(self, issue_number: int, body: str) -> PostedComment: ...

    def invalidate_projection(
        self, issue_number: int, comment: DurableComment, reason_code: str
    ) -> PostedComment: ...

    def post_summary(self, issue_number: int, body: str) -> PostedComment: ...


@dataclass
class ReconciliationSummary:
    run_id: str
    projections_posted: list[int] = field(default_factory=list)
    projections_repaired: list[int] = field(default_factory=list)
    orphan_projections_invalidated: list[int] = field(default_factory=list)
    ownership_mismatches: list[str] = field(default_factory=list)
    source_mutations: list[str] = field(default_factory=list)
    unprocessed_comments: list[int] = field(default_factory=list)
    pending_anchors: list[str] = field(default_factory=list)
    stale_allocations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def payload(self) -> dict[str, object]:
        return {
            "errors": sorted(set(self.errors)),
            "orphan_projections_invalidated": sorted(set(self.orphan_projections_invalidated)),
            "ownership_mismatches": sorted(set(self.ownership_mismatches)),
            "pending_anchors": sorted(set(self.pending_anchors)),
            "projections_posted": sorted(set(self.projections_posted)),
            "projections_repaired": sorted(set(self.projections_repaired)),
            "protocol": "beads-allocation/v0.2",
            "run_id": self.run_id,
            "source_mutations": sorted(set(self.source_mutations)),
            "stale_allocations": sorted(set(self.stale_allocations)),
            "type": "RECONCILIATION_SUMMARY",
            "unprocessed_comments": sorted(set(self.unprocessed_comments)),
        }

    def render(self) -> str:
        return json.dumps(self.payload(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class ReconciliationService:
    """Recover GitHub visibility from canonical state without inferring ownership."""

    def __init__(
        self,
        repository: CanonicalRepository,
        gateway: ReconciliationGateway,
        *,
        control_repository: str,
        issue_number: int,
        task_summary_lookup: Callable[[str], str],
        canonical_history: CanonicalHistoryReader,
        unprocessed_handler: Callable[[DurableComment], None] | None = None,
        clock: Callable[[], str] = utc_now,
        stale_after_seconds: int = 24 * 60 * 60,
        max_stale_retries: int = 3,
    ) -> None:
        if not CONTROL_REPOSITORY_RE.fullmatch(control_repository):
            raise ValueError("invalid control_repository")
        if issue_number <= 0:
            raise ValueError("issue_number must be positive")
        if stale_after_seconds <= 0:
            raise ValueError("stale_after_seconds must be positive")
        if max_stale_retries < 0:
            raise ValueError("max_stale_retries must be non-negative")
        self.repository = repository
        self.gateway = gateway
        self.control_repository = control_repository
        self.issue_number = issue_number
        self.task_summary_lookup = task_summary_lookup
        self.canonical_history = canonical_history
        self.unprocessed_handler = unprocessed_handler
        self.clock = clock
        self.stale_after_seconds = stale_after_seconds
        self.max_stale_retries = max_stale_retries

    def _store(self, snapshot: object) -> AllocationStore:
        factory = getattr(self.repository, "store", None)
        if callable(factory):
            return factory(snapshot)
        return AllocationStore(snapshot.connection)  # type: ignore[attr-defined]

    def _requests(self) -> list[dict[str, object]]:
        snapshot = self.repository.bootstrap()
        try:
            store = self._store(snapshot)
            return [
                dict(row)
                for row in store.connection.execute(
                    "SELECT * FROM allocation_requests ORDER BY processed_at, request_id"
                ).fetchall()
            ]
        finally:
            snapshot.close()

    def _request(self, request_id: str) -> dict[str, object] | None:
        snapshot = self.repository.bootstrap()
        try:
            store = self._store(snapshot)
            row = store.get_request(request_id)
            return None if row is None else dict(row)
        finally:
            snapshot.close()

    def _mutate(self, mutation: Callable[[AllocationStore], bool]) -> None:
        stale_retries = 0
        while True:
            snapshot = self.repository.bootstrap()
            store = self._store(snapshot)
            try:
                store.begin()
                changed = mutation(store)
                if not changed:
                    store.rollback()
                    snapshot.close()
                    return
                store.commit()
            except Exception:
                store.rollback()
                snapshot.close()
                raise
            try:
                self.repository.publish(snapshot.identity.git_ref_sha, snapshot)
            except StaleCanonicalBase:
                snapshot.close()
                if stale_retries >= self.max_stale_retries:
                    raise ReconciliationError("STALE_ALLOCATOR_RETRY_EXHAUSTED")
                stale_retries += 1
                continue
            except CanonicalPushFailed as exc:
                snapshot.close()
                raise ReconciliationError("CANONICAL_PUSH_FAILED") from exc
            snapshot.close()
            return

    def _canonical_projection(
        self,
        request_id: str,
        *,
        source_comment_id: int | None = None,
        override_status: str | None = None,
        override_reason: str | None = None,
        override_agent: str | None = None,
    ) -> CanonicalProjection:
        snapshot = self.repository.bootstrap()
        try:
            store = self._store(snapshot)
            row = store.get_request(request_id)
            if row is None:
                raise ProjectionError("CANONICAL_REQUEST_NOT_FOUND")
            if row["anchor_status"] != "RECORDED":
                raise ProjectionError("CANONICAL_ANCHOR_PENDING")
            git_sha = row["canonical_git_ref_sha"]
            dolt_commit = row["canonical_dolt_commit"]
            status = override_status or row["status"]
            reason = override_reason or row["result_code"]
            allocation_id = row["allocation_id"] or row["release_allocation_id"]
            task_id = None
            task_summary = None
            grant_timestamp = None
            if status in {"ALLOCATED", "RELEASED"} and allocation_id is not None:
                allocation = store.connection.execute(
                    "SELECT * FROM allocations WHERE allocation_id = ?", (allocation_id,)
                ).fetchone()
                if allocation is None:
                    raise ProjectionError("CANONICAL_ALLOCATION_NOT_FOUND")
                task_id = allocation["task_id"]
                task = store.task(task_id)
                if task is None:
                    raise ProjectionError("CANONICAL_TASK_NOT_FOUND")
                try:
                    store.assert_ownership_invariant(task)
                except CanonicalOwnershipMismatch as exc:
                    raise ProjectionError("CANONICAL_OWNERSHIP_MISMATCH") from exc
                if status == "ALLOCATED" and allocation["state"] != "ACTIVE":
                    raise ProjectionError("CANONICAL_OWNERSHIP_MISMATCH")
                if status == "RELEASED" and allocation["state"] != "RELEASED":
                    raise ProjectionError("CANONICAL_OWNERSHIP_MISMATCH")
                if status == "ALLOCATED":
                    task_summary = self.task_summary_lookup(task_id)
                    grant_timestamp = allocation["granted_at"]
            return CanonicalProjection(
                request_id=request_id,
                result_status=status,
                reason_code=reason,
                agent_id=override_agent if override_agent is not None else row["agent_id"],
                source_repository=row["source_repository"],
                source_issue_number=row["source_issue_number"],
                source_comment_id=source_comment_id or row["source_comment_id"],
                canonical_git_ref_sha=git_sha,
                canonical_dolt_commit=dolt_commit,
                allocation_id=allocation_id if status in {"ALLOCATED", "RELEASED"} else None,
                task_id=task_id if status in {"ALLOCATED", "RELEASED"} else None,
                task_summary=task_summary,
                grant_timestamp=grant_timestamp,
                ownership_valid=True,
            )
        finally:
            snapshot.close()

    def _record_projection_missing(self, request_id: str) -> None:
        def mutation(store: AllocationStore) -> bool:
            row = store.get_request(request_id)
            if row is None:
                return False
            if row["projection_status"] == "MISSING" and row["reconciliation_status"] == "REQUIRED":
                return False
            store.connection.execute(
                """UPDATE allocation_requests
                   SET projection_status = 'MISSING', reconciliation_status = 'REQUIRED'
                   WHERE request_id = ?""",
                (request_id,),
            )
            existing = store.connection.execute(
                """SELECT event_id FROM allocation_events
                   WHERE request_id = ? AND event_type = 'AUDIT_FINDING'
                   AND reason_code = 'PROJECTION_RECONCILIATION_REQUIRED' LIMIT 1""",
                (request_id,),
            ).fetchone()
            if existing is None:
                store.insert_event(
                    request_id=request_id,
                    allocation_id=row["allocation_id"] or row["release_allocation_id"],
                    event_type="AUDIT_FINDING",
                    actor="allocator://phase2/v0.2",
                    event_at=self.clock(),
                    reason_code="PROJECTION_RECONCILIATION_REQUIRED",
                    details={"projection_status": "MISSING", "version": 1},
                    discriminator="projection-missing",
                )
            return True

        self._mutate(mutation)

    def _record_projection_posted(self, request_id: str, posted: PostedComment) -> bool:
        repaired = False

        def mutation(store: AllocationStore) -> bool:
            nonlocal repaired
            row = store.get_request(request_id)
            if row is None:
                return False
            if row["projection_status"] == "POSTED":
                return False
            repaired = row["projection_status"] == "MISSING" or row["reconciliation_status"] == "REQUIRED"
            store.connection.execute(
                """UPDATE allocation_requests SET projection_status = 'POSTED',
                   reconciliation_status = ? WHERE request_id = ?""",
                ("REPAIRED" if repaired else "NONE", request_id),
            )
            store.insert_event(
                request_id=request_id,
                allocation_id=row["allocation_id"] or row["release_allocation_id"],
                event_type="PROJECTION_REPAIRED" if repaired else "PROJECTION_POSTED",
                actor="allocator://phase2/v0.2",
                event_at=self.clock(),
                reason_code=row["result_code"],
                canonical_git_ref_sha=row["canonical_git_ref_sha"],
                canonical_dolt_commit=row["canonical_dolt_commit"],
                details={
                    "comment_id": posted.comment_id,
                    "projection_url": posted.html_url,
                    "version": 1,
                },
                discriminator=str(posted.comment_id),
            )
            return True

        self._mutate(mutation)
        return repaired

    def _orphan_subject(self, comment: DurableComment) -> str:
        return (
            f"{self.control_repository}:issue:{self.issue_number}:"
            f"projection_comment:{comment.comment_id}"
        )

    def _ensure_orphan_audit(self, comment: DurableComment, reason_code: str) -> None:
        subject = self._orphan_subject(comment)

        def mutation(store: AllocationStore) -> bool:
            existing = store.connection.execute(
                """SELECT event_id FROM allocation_events WHERE event_type = 'AUDIT_FINDING'
                   AND request_id IS NULL AND audit_subject_type = 'PROJECTION_COMMENT'
                   AND audit_subject_id = ? AND reason_code = ? LIMIT 1""",
                (subject, reason_code),
            ).fetchone()
            if existing is not None:
                return False
            store.insert_event(
                request_id=None,
                allocation_id=None,
                event_type="AUDIT_FINDING",
                actor="allocator://phase2/v0.2",
                event_at=self.clock(),
                reason_code=reason_code,
                audit_subject_type="PROJECTION_COMMENT",
                audit_subject_id=subject,
                details={
                    "comment_id": comment.comment_id,
                    "comment_url": comment.html_url,
                    "control_repository": self.control_repository,
                    "issue_number": self.issue_number,
                    "version": 1,
                },
                discriminator=f"orphan:{subject}",
            )
            return True

        self._mutate(mutation)

    def _orphan_invalidation_recorded(self, comment: DurableComment) -> bool:
        subject = self._orphan_subject(comment)
        snapshot = self.repository.bootstrap()
        try:
            store = self._store(snapshot)
            row = store.connection.execute(
                """SELECT event_id FROM allocation_events WHERE event_type = 'AUDIT_FINDING'
                   AND request_id IS NULL AND audit_subject_type = 'PROJECTION_COMMENT'
                   AND audit_subject_id = ?
                   AND reason_code = 'ORPHAN_PROJECTION_INVALIDATED' LIMIT 1""",
                (subject,),
            ).fetchone()
            return row is not None
        finally:
            snapshot.close()

    def _record_orphan_invalidation(
        self, comment: DurableComment, posted: PostedComment
    ) -> None:
        subject = self._orphan_subject(comment)

        def mutation(store: AllocationStore) -> bool:
            existing = store.connection.execute(
                """SELECT event_id FROM allocation_events WHERE event_type = 'AUDIT_FINDING'
                   AND request_id IS NULL AND audit_subject_type = 'PROJECTION_COMMENT'
                   AND audit_subject_id = ?
                   AND reason_code = 'ORPHAN_PROJECTION_INVALIDATED' LIMIT 1""",
                (subject,),
            ).fetchone()
            if existing is not None:
                return False
            store.insert_event(
                request_id=None,
                allocation_id=None,
                event_type="AUDIT_FINDING",
                actor="allocator://phase2/v0.2",
                event_at=self.clock(),
                reason_code="ORPHAN_PROJECTION_INVALIDATED",
                audit_subject_type="PROJECTION_COMMENT",
                audit_subject_id=subject,
                details={
                    "invalidation_comment_id": posted.comment_id,
                    "invalidation_url": posted.html_url,
                    "projection_comment_id": comment.comment_id,
                    "projection_url": comment.html_url,
                    "version": 1,
                },
                discriminator=f"invalidation:{subject}",
            )
            return True

        self._mutate(mutation)

    def _invalidate_orphan(
        self, comment: DurableComment, summary: ReconciliationSummary
    ) -> None:
        try:
            self._ensure_orphan_audit(comment, "ORPHAN_PROJECTION")
        except ReconciliationError as exc:
            summary.errors.append(f"ORPHAN:{comment.comment_id}:AUDIT:{exc}")
            return
        if self._orphan_invalidation_recorded(comment):
            return
        try:
            posted = self.gateway.invalidate_projection(
                self.issue_number, comment, "ORPHAN_PROJECTION"
            )
        except Exception as exc:
            summary.errors.append(
                f"ORPHAN:{comment.comment_id}:INVALIDATION_POST_FAILED:{type(exc).__name__}"
            )
            return
        try:
            self._record_orphan_invalidation(comment, posted)
        except ReconciliationError as exc:
            summary.errors.append(f"ORPHAN:{comment.comment_id}:INVALIDATION_AUDIT:{exc}")
            return
        summary.orphan_projections_invalidated.append(comment.comment_id)

    def _record_request_audit(self, request_id: str, reason_code: str) -> None:
        def mutation(store: AllocationStore) -> bool:
            row = store.get_request(request_id)
            if row is None:
                return False
            existing = store.connection.execute(
                """SELECT event_id FROM allocation_events WHERE request_id = ?
                   AND event_type = 'AUDIT_FINDING' AND reason_code = ? LIMIT 1""",
                (request_id, reason_code),
            ).fetchone()
            if existing is not None:
                return False
            store.insert_event(
                request_id=request_id,
                allocation_id=row["allocation_id"] or row["release_allocation_id"],
                event_type="AUDIT_FINDING",
                actor="allocator://phase2/v0.2",
                event_at=self.clock(),
                reason_code=reason_code,
                details={"version": 1},
                discriminator=reason_code,
            )
            if reason_code == "CANONICAL_OWNERSHIP_MISMATCH":
                store.connection.execute(
                    """UPDATE allocation_requests SET projection_status = 'INVALID',
                       reconciliation_status = 'ESCALATED' WHERE request_id = ?""",
                    (request_id,),
                )
            return True

        self._mutate(mutation)

    def _allocation_creation_anchor(self, request_id: str) -> CanonicalIdentity | None:
        if not self.canonical_history.complete:
            raise ReconciliationError("CANONICAL_HISTORY_INCOMPLETE")
        revisions = tuple(self.canonical_history.accepted_revisions())
        if not revisions:
            raise ReconciliationError("CANONICAL_HISTORY_EMPTY")

        first: CanonicalIdentity | None = None
        seen_request = False
        seen_git_shas: set[str] = set()
        for revision in revisions:
            try:
                verify_canonical_identity(revision.identity)
            except Exception as exc:
                raise ReconciliationError("CANONICAL_HISTORY_IDENTITY_INVALID") from exc
            if revision.identity.git_ref_sha in seen_git_shas:
                raise ReconciliationError("CANONICAL_HISTORY_DUPLICATE_REVISION")
            seen_git_shas.add(revision.identity.git_ref_sha)
            contains = request_id in revision.request_ids
            if contains and not seen_request:
                first = revision.identity
                seen_request = True
            elif seen_request and not contains:
                raise ReconciliationError("CANONICAL_HISTORY_REQUEST_REGRESSION")
        return first

    def _repair_anchor(self, request_id: str) -> bool:
        identity = self._allocation_creation_anchor(request_id)
        if identity is None:
            return False
        result = AllocationService(
            self.repository, clock=self.clock, max_stale_retries=self.max_stale_retries
        ).record_anchor(request_id, identity.git_ref_sha, identity.dolt_commit)
        if result.reason_code in {"CANONICAL_PUSH_FAILED", "STALE_ALLOCATOR_RETRY_EXHAUSTED"}:
            raise ReconciliationError(result.reason_code)
        return True

    def _stale_allocations(self) -> list[str]:
        snapshot = self.repository.bootstrap()
        try:
            store = self._store(snapshot)
            now = _parse_time(self.clock())
            rows = store.connection.execute(
                "SELECT allocation_id, granted_at FROM allocations WHERE state = 'ACTIVE'"
            ).fetchall()
            stale: list[str] = []
            for row in rows:
                age = (now - _parse_time(str(row["granted_at"]))).total_seconds()
                if age >= self.stale_after_seconds:
                    stale.append(str(row["allocation_id"]))
            return sorted(stale)
        finally:
            snapshot.close()

    def reconcile(self, run_id: str) -> ReconciliationSummary:
        summary = ReconciliationSummary(run_id)
        comments = list(self.gateway.list_comments(self.issue_number))
        by_id = {comment.comment_id: comment for comment in comments}
        parsed_projections: list[tuple[DurableComment, dict[str, object]]] = []
        for comment in comments:
            projection = parse_projection(comment.body)
            if projection is not None:
                parsed_projections.append((comment, projection))

        canonical_rows = self._requests()
        canonical_ids = {str(row["request_id"]) for row in canonical_rows}
        canonical_source_ids = {int(row["source_comment_id"]) for row in canonical_rows}
        handled_projection_ids: set[int] = set()

        for original in canonical_rows:
            request_id = str(original["request_id"])
            source_comment_id = int(original["source_comment_id"])
            source = by_id.get(source_comment_id)
            if source is None:
                self._record_request_audit(request_id, "SOURCE_COMMENT_DELETED")
                summary.source_mutations.append(f"{request_id}:SOURCE_COMMENT_DELETED")
            else:
                try:
                    current = parse_request(source.body.encode("utf-8"))
                    if current.payload_hash != original["payload_sha256"]:
                        raise RequestError("SOURCE_COMMENT_EDITED")
                except RequestError:
                    self._record_request_audit(request_id, "SOURCE_COMMENT_EDITED")
                    summary.source_mutations.append(f"{request_id}:SOURCE_COMMENT_EDITED")

            current_row = self._request(request_id)
            if current_row is None:
                continue
            if current_row["anchor_status"] != "RECORDED":
                try:
                    repaired = self._repair_anchor(request_id)
                except ReconciliationError as exc:
                    summary.errors.append(f"{request_id}:{exc}")
                    continue
                if not repaired:
                    summary.pending_anchors.append(request_id)
                    continue
                current_row = self._request(request_id)
                if current_row is None or current_row["anchor_status"] != "RECORDED":
                    summary.pending_anchors.append(request_id)
                    continue

            try:
                expected = self._canonical_projection(request_id)
            except ProjectionError as exc:
                if exc.code == "CANONICAL_OWNERSHIP_MISMATCH":
                    self._record_request_audit(request_id, exc.code)
                    summary.ownership_mismatches.append(request_id)
                else:
                    summary.errors.append(f"{request_id}:{exc.code}")
                continue

            exact: DurableComment | None = None
            for comment, payload in parsed_projections:
                if payload.get("request_id") != request_id:
                    continue
                if payload.get("source_comment_id") != source_comment_id:
                    continue
                if projection_matches(payload, expected):
                    exact = comment
                    handled_projection_ids.add(comment.comment_id)
                    break
                handled_projection_ids.add(comment.comment_id)
                self._invalidate_orphan(comment, summary)

            if exact is not None:
                repaired = self._record_projection_posted(
                    request_id, PostedComment(exact.comment_id, exact.html_url)
                )
                if repaired:
                    summary.projections_repaired.append(exact.comment_id)
                continue

            try:
                posted = self.gateway.post_projection(self.issue_number, render_projection(expected))
            except Exception as exc:
                try:
                    self._record_projection_missing(request_id)
                except ReconciliationError as metadata_exc:
                    summary.errors.append(f"{request_id}:{metadata_exc}")
                summary.errors.append(f"{request_id}:PROJECTION_POST_FAILED:{type(exc).__name__}")
                continue
            repaired = self._record_projection_posted(request_id, posted)
            summary.projections_posted.append(posted.comment_id)
            if repaired:
                summary.projections_repaired.append(posted.comment_id)

        # Reconcile protocol comments that are not the canonical source comment.
        # They may be unprocessed intake, same-payload duplicate delivery or a
        # payload-mismatch reuse of an existing request ID. None can create
        # ownership from GitHub visibility.
        for comment in comments:
            if comment.comment_id in canonical_source_ids:
                continue
            try:
                parsed = parse_request(comment.body.encode("utf-8"))
            except RequestError:
                continue
            request_id = parsed.payload["request_id"]
            if request_id not in canonical_ids:
                summary.unprocessed_comments.append(comment.comment_id)
                if self.unprocessed_handler is not None:
                    self.unprocessed_handler(comment)
                continue
            row = self._request(request_id)
            if row is None or row["anchor_status"] != "RECORDED":
                continue
            try:
                if parsed.payload_hash == row["payload_sha256"]:
                    delivery = self._canonical_projection(
                        request_id,
                        source_comment_id=comment.comment_id,
                    )
                else:
                    delivery = self._canonical_projection(
                        request_id,
                        source_comment_id=comment.comment_id,
                        override_status="REJECTED",
                        override_reason="REQUEST_ID_PAYLOAD_MISMATCH",
                        override_agent=parsed.payload.get("agent_id"),
                    )
            except ProjectionError:
                continue
            already = any(
                payload.get("source_comment_id") == comment.comment_id
                and projection_matches(payload, delivery)
                for _, payload in parsed_projections
            )
            if not already:
                try:
                    posted = self.gateway.post_projection(self.issue_number, render_projection(delivery))
                    summary.projections_posted.append(posted.comment_id)
                except Exception as exc:
                    summary.errors.append(
                        f"{request_id}:DELIVERY_PROJECTION_FAILED:{type(exc).__name__}"
                    )

        # Anything projection-shaped that was not correlated above must not be
        # allowed to stand as apparent authority.
        for comment, payload in parsed_projections:
            if comment.comment_id in handled_projection_ids:
                continue
            request_id = str(payload.get("request_id", ""))
            if request_id not in canonical_ids:
                self._invalidate_orphan(comment, summary)
                continue
            try:
                expected = self._canonical_projection(
                    request_id, source_comment_id=int(payload["source_comment_id"])
                )
            except (ProjectionError, TypeError, ValueError, KeyError):
                expected = None
            if expected is None or not projection_matches(payload, expected):
                self._invalidate_orphan(comment, summary)

        summary.stale_allocations.extend(self._stale_allocations())
        try:
            self.gateway.post_summary(self.issue_number, summary.render())
        except Exception as exc:
            summary.errors.append(f"SUMMARY_POST_FAILED:{type(exc).__name__}")
        return summary


class OperatorRecovery:
    """Narrow operator release path; no expiry or inferred abandonment exists."""

    def __init__(
        self,
        repository: CanonicalRepository,
        *,
        clock: Callable[[], str] = utc_now,
        max_stale_retries: int = 3,
    ) -> None:
        self.service = AllocationService(
            repository, clock=clock, max_stale_retries=max_stale_retries
        )

    def release(
        self, command: AllocationCommand, context: RequestContext
    ) -> AllocationResult:
        if command.request_type != "RELEASE" or not context.is_operator:
            return AllocationResult(command.request_id, "REJECTED", "RELEASE_NOT_AUTHORISED")
        if command.reason is None or not command.reason.strip():
            return AllocationResult(command.request_id, "REJECTED", "INVALID_REQUEST")
        # Workstream B records command.reason in the canonical RELEASED event;
        # this wrapper supplies the explicit operator-authority gate only.
        return self.service.process(command, context)
