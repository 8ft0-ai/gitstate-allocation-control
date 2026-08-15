"""Transactional SQL store for canonical allocation state."""

from __future__ import annotations

import json
import sqlite3

from .allocation_types import (
    AllocationCommand,
    AllocationResult,
    RequestContext,
    Task,
    allocation_digest,
    stable_ulid,
)

PROTOCOL = "beads-allocation/v0.2"
ALLOCATOR_ACTOR = "allocator://phase2/v0.2"


class CanonicalOwnershipMismatch(RuntimeError):
    def __init__(self, task_id: str) -> None:
        super().__init__("CANONICAL_OWNERSHIP_MISMATCH")
        self.task_id = task_id


class UnsupportedMutation(RuntimeError):
    pass


class AllocationStore:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def begin(self) -> None:
        self.connection.execute("BEGIN IMMEDIATE")

    def commit(self) -> None:
        self.connection.commit()

    def rollback(self) -> None:
        self.connection.rollback()

    def seed_task(self, task: Task) -> None:
        """Operator-only local fixture seed; not an ordinary mutation API."""
        self.connection.execute(
            """INSERT INTO beads_tasks
               (task_id, task_type, status, assignee, priority, created_at, ready, blocked, labels_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                task.task_id,
                task.task_type,
                task.status,
                task.assignee,
                task.priority,
                task.created_at,
                int(task.ready),
                int(task.blocked),
                json.dumps(list(task.labels), sort_keys=True, separators=(",", ":")),
            ),
        )

    def unsupported_mutation(self, mutation: str) -> None:
        frozen = {
            "CREATE_TASK",
            "CLOSE_TASK",
            "CHANGE_STATUS",
            "CHANGE_DEPENDENCY",
            "CHANGE_PRIORITY",
            "CHANGE_TYPE",
            "CHANGE_BLOCKER",
            "CHANGE_READINESS_METADATA",
        }
        if mutation in frozen:
            raise UnsupportedMutation("UNSUPPORTED_READINESS_MUTATION")
        raise UnsupportedMutation("UNKNOWN_MUTATION")

    def get_request(self, request_id: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM allocation_requests WHERE request_id = ?", (request_id,)
        ).fetchone()

    def get_request_by_source(self, context: RequestContext) -> sqlite3.Row | None:
        return self.connection.execute(
            """SELECT * FROM allocation_requests WHERE source_repository = ?
               AND source_issue_number = ? AND source_comment_id = ?""",
            (
                context.source_repository,
                context.source_issue_number,
                context.source_comment_id,
            ),
        ).fetchone()

    def result_from_request(self, row: sqlite3.Row) -> AllocationResult:
        task_id = None
        if row["allocation_id"] is not None:
            allocation = self.connection.execute(
                "SELECT task_id FROM allocations WHERE allocation_id = ?", (row["allocation_id"],)
            ).fetchone()
            if allocation is not None:
                task_id = allocation["task_id"]
        elif row["release_allocation_id"] is not None:
            allocation = self.connection.execute(
                "SELECT task_id FROM allocations WHERE allocation_id = ?",
                (row["release_allocation_id"],),
            ).fetchone()
            if allocation is not None:
                task_id = allocation["task_id"]
        return AllocationResult(
            request_id=row["request_id"],
            status=row["status"],
            reason_code=row["result_code"],
            allocation_id=row["allocation_id"] or row["release_allocation_id"],
            task_id=task_id,
            canonical_git_ref_sha=row["canonical_git_ref_sha"],
            canonical_dolt_commit=row["canonical_dolt_commit"],
            ref_advanced=False,
        )

    def tasks(self) -> list[Task]:
        rows = self.connection.execute(
            "SELECT * FROM beads_tasks ORDER BY priority, created_at, task_id COLLATE BINARY"
        ).fetchall()
        return [self._task(row) for row in rows]

    def task(self, task_id: str) -> Task | None:
        row = self.connection.execute("SELECT * FROM beads_tasks WHERE task_id = ?", (task_id,)).fetchone()
        return None if row is None else self._task(row)

    @staticmethod
    def _task(row: sqlite3.Row) -> Task:
        return Task(
            task_id=row["task_id"],
            task_type=row["task_type"],
            status=row["status"],
            assignee=row["assignee"],
            priority=row["priority"],
            created_at=row["created_at"],
            ready=bool(row["ready"]),
            blocked=bool(row["blocked"]),
            labels=tuple(json.loads(row["labels_json"])),
        )

    def assert_ownership_invariant(self, task: Task) -> None:
        allocations = self.connection.execute(
            "SELECT * FROM allocations WHERE task_id = ? AND state = 'ACTIVE'", (task.task_id,)
        ).fetchall()
        active = self.connection.execute(
            "SELECT * FROM active_task_allocations WHERE task_id = ?", (task.task_id,)
        ).fetchall()
        if task.status == "open" and task.assignee is None:
            valid = len(allocations) == 0 and len(active) == 0
        elif task.status == "assigned" and task.assignee is not None:
            valid = (
                len(allocations) == 1
                and len(active) == 1
                and active[0]["allocation_id"] == allocations[0]["allocation_id"]
                and allocations[0]["agent_id"] == task.assignee
            )
        else:
            valid = False
        if not valid:
            raise CanonicalOwnershipMismatch(task.task_id)

    def insert_request(
        self,
        command: AllocationCommand,
        context: RequestContext,
        *,
        status: str,
        result_code: str,
        processed_at: str,
        allocation_id: str | None = None,
    ) -> None:
        self.connection.execute(
            """INSERT INTO allocation_requests (
                 request_id, protocol_version, request_type, payload_sha256,
                 source_repository, source_issue_number, source_comment_id, requested_by,
                 agent_id, nominated_task_id, release_allocation_id, status, result_code,
                 terminal_reason_code, allocation_id, processed_at, anchor_status,
                 projection_status, reconciliation_status
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', 'PENDING', 'NONE')""",
            (
                command.request_id,
                PROTOCOL,
                command.request_type,
                command.payload_hash,
                context.source_repository,
                context.source_issue_number,
                context.source_comment_id,
                context.requested_by,
                command.agent_id,
                command.task_id,
                command.allocation_id,
                status,
                result_code,
                None if status == "ALLOCATED" else result_code,
                allocation_id,
                processed_at,
            ),
        )

    def insert_event(
        self,
        *,
        request_id: str | None,
        allocation_id: str | None,
        event_type: str,
        actor: str,
        event_at: str,
        reason_code: str | None,
        details: dict[str, object],
        audit_subject_type: str | None = None,
        audit_subject_id: str | None = None,
        canonical_git_ref_sha: str | None = None,
        canonical_dolt_commit: str | None = None,
        discriminator: str = "",
    ) -> str:
        event_id = stable_ulid(
            f"event:{event_type}:{request_id}:{allocation_id}:{audit_subject_id}:{discriminator}"
        )
        self.connection.execute(
            """INSERT INTO allocation_events (
                 event_id, allocation_id, request_id, event_type, audit_subject_type,
                 audit_subject_id, actor, event_at, reason_code, canonical_git_ref_sha,
                 canonical_dolt_commit, details_json
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id,
                allocation_id,
                request_id,
                event_type,
                audit_subject_type,
                audit_subject_id,
                actor,
                event_at,
                reason_code,
                canonical_git_ref_sha,
                canonical_dolt_commit,
                json.dumps(details, sort_keys=True, separators=(",", ":")),
            ),
        )
        return event_id

    def reject(
        self,
        command: AllocationCommand,
        context: RequestContext,
        reason_code: str,
        processed_at: str,
        *,
        mismatch_task_id: str | None = None,
    ) -> AllocationResult:
        self.insert_request(
            command, context, status="REJECTED", result_code=reason_code, processed_at=processed_at
        )
        self.insert_event(
            request_id=command.request_id,
            allocation_id=None,
            event_type="REQUEST_TERMINAL",
            actor=ALLOCATOR_ACTOR,
            event_at=processed_at,
            reason_code=reason_code,
            details={"result": "REJECTED", "version": 1},
        )
        if mismatch_task_id is not None:
            self.insert_event(
                request_id=command.request_id,
                allocation_id=None,
                event_type="AUDIT_FINDING",
                actor=ALLOCATOR_ACTOR,
                event_at=processed_at,
                reason_code="CANONICAL_OWNERSHIP_MISMATCH",
                details={"task_id": mismatch_task_id, "version": 1},
            )
        return AllocationResult(command.request_id, "REJECTED", reason_code)

    def grant(
        self,
        command: AllocationCommand,
        context: RequestContext,
        task: Task,
        processed_at: str,
    ) -> AllocationResult:
        allocation_id = stable_ulid(f"allocation:{command.request_id}")
        # Insert the request before its allocation so the allocation FK is
        # satisfiable on MySQL/Dolt. The intermediate shape is transaction-local.
        self.insert_request(
            command,
            context,
            status="REJECTED",
            result_code="ALLOCATED_PENDING",
            processed_at=processed_at,
        )
        digest = allocation_digest(
            {
                "agent_id": command.agent_id,
                "allocation_id": allocation_id,
                "granted_at": processed_at,
                "request_id": command.request_id,
                "state": "ACTIVE",
                "task_id": task.task_id,
            }
        )
        self.connection.execute(
            """INSERT INTO allocations
               (allocation_id, request_id, agent_id, task_id, state, granted_at, allocation_state_digest)
               VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?)""",
            (allocation_id, command.request_id, command.agent_id, task.task_id, processed_at, digest),
        )
        self.connection.execute(
            """UPDATE allocation_requests SET status = 'ALLOCATED', result_code = 'ALLOCATED',
               terminal_reason_code = NULL, allocation_id = ? WHERE request_id = ?""",
            (allocation_id, command.request_id),
        )
        self.connection.execute(
            "INSERT INTO active_task_allocations (task_id, allocation_id) VALUES (?, ?)",
            (task.task_id, allocation_id),
        )
        self.connection.execute(
            "UPDATE beads_tasks SET status = 'assigned', assignee = ? WHERE task_id = ?",
            (command.agent_id, task.task_id),
        )
        self.insert_event(
            request_id=command.request_id,
            allocation_id=allocation_id,
            event_type="ALLOCATED",
            actor=ALLOCATOR_ACTOR,
            event_at=processed_at,
            reason_code="ALLOCATED",
            details={"task_id": task.task_id, "agent_id": command.agent_id, "version": 1},
        )
        self.insert_event(
            request_id=command.request_id,
            allocation_id=allocation_id,
            event_type="REQUEST_TERMINAL",
            actor=ALLOCATOR_ACTOR,
            event_at=processed_at,
            reason_code="ALLOCATED",
            details={"result": "ALLOCATED", "version": 1},
        )
        self.assert_ownership_invariant(self.task(task.task_id))  # type: ignore[arg-type]
        return AllocationResult(
            command.request_id, "ALLOCATED", "ALLOCATED", allocation_id, task.task_id
        )

    def release(
        self,
        command: AllocationCommand,
        context: RequestContext,
        processed_at: str,
    ) -> AllocationResult:
        allocation = self.connection.execute(
            """SELECT a.*, r.requested_by AS grant_requested_by
               FROM allocations a JOIN allocation_requests r ON r.request_id = a.request_id
               WHERE a.allocation_id = ?""",
            (command.allocation_id,),
        ).fetchone()
        if allocation is None or allocation["state"] != "ACTIVE":
            return self.reject(command, context, "ALLOCATION_NOT_ACTIVE", processed_at)
        task = self.task(allocation["task_id"])
        assert task is not None
        try:
            self.assert_ownership_invariant(task)
        except CanonicalOwnershipMismatch as exc:
            return self.reject(
                command,
                context,
                "CANONICAL_OWNERSHIP_MISMATCH",
                processed_at,
                mismatch_task_id=exc.task_id,
            )
        authorised = (
            context.is_operator
            or context.requested_by == allocation["grant_requested_by"]
            or (
                command.agent_id == allocation["agent_id"]
                and context.authorised_agent_id == allocation["agent_id"]
            )
        )
        if not authorised:
            return self.reject(command, context, "RELEASE_NOT_AUTHORISED", processed_at)
        self.insert_request(
            command, context, status="RELEASED", result_code="RELEASED", processed_at=processed_at
        )
        self.connection.execute(
            "DELETE FROM active_task_allocations WHERE task_id = ? AND allocation_id = ?",
            (allocation["task_id"], allocation["allocation_id"]),
        )
        self.connection.execute(
            "UPDATE beads_tasks SET status = 'open', assignee = NULL WHERE task_id = ?",
            (allocation["task_id"],),
        )
        released = {
            "agent_id": allocation["agent_id"],
            "allocation_id": allocation["allocation_id"],
            "granted_at": allocation["granted_at"],
            "released_at": processed_at,
            "release_actor": context.requested_by,
            "release_request_id": command.request_id,
            "request_id": allocation["request_id"],
            "state": "RELEASED",
            "task_id": allocation["task_id"],
        }
        self.connection.execute(
            """UPDATE allocations SET state = 'RELEASED', released_at = ?, release_actor = ?,
               release_request_id = ?, allocation_state_digest = ? WHERE allocation_id = ?""",
            (
                processed_at,
                context.requested_by,
                command.request_id,
                allocation_digest(released),
                allocation["allocation_id"],
            ),
        )
        self.insert_event(
            request_id=command.request_id,
            allocation_id=allocation["allocation_id"],
            event_type="RELEASED",
            actor=context.requested_by,
            event_at=processed_at,
            reason_code="RELEASED",
            details={
                "reason": command.reason or "",
                "task_id": allocation["task_id"],
                "version": 1,
            },
        )
        self.insert_event(
            request_id=command.request_id,
            allocation_id=allocation["allocation_id"],
            event_type="REQUEST_TERMINAL",
            actor=ALLOCATOR_ACTOR,
            event_at=processed_at,
            reason_code="RELEASED",
            details={"result": "RELEASED", "version": 1},
        )
        self.assert_ownership_invariant(self.task(allocation["task_id"]))  # type: ignore[arg-type]
        return AllocationResult(
            command.request_id,
            "RELEASED",
            "RELEASED",
            allocation["allocation_id"],
            allocation["task_id"],
        )

    def record_anchor(
        self,
        request_id: str,
        canonical_git_ref_sha: str,
        canonical_dolt_commit: str,
        event_at: str,
    ) -> bool:
        row = self.get_request(request_id)
        if row is None:
            raise KeyError(request_id)
        if row["anchor_status"] == "RECORDED":
            if (
                row["canonical_git_ref_sha"] != canonical_git_ref_sha
                or row["canonical_dolt_commit"] != canonical_dolt_commit
            ):
                raise ValueError("CANONICAL_ANCHOR_MISMATCH")
            return False
        self.connection.execute(
            """UPDATE allocation_requests SET anchor_status = 'RECORDED',
               canonical_git_ref_sha = ?, canonical_dolt_commit = ? WHERE request_id = ?""",
            (canonical_git_ref_sha, canonical_dolt_commit, request_id),
        )
        anchored = self.connection.execute(
            """SELECT event_id FROM allocation_events WHERE request_id = ?
               AND event_type IN ('ALLOCATED', 'RELEASED', 'REQUEST_TERMINAL')
               ORDER BY CASE event_type
                 WHEN 'ALLOCATED' THEN 0 WHEN 'RELEASED' THEN 0 ELSE 1 END, event_id
               LIMIT 1""",
            (request_id,),
        ).fetchone()
        if anchored is None:
            raise ValueError("CANONICAL_ANCHOR_EVENT_MISSING")
        self.insert_event(
            request_id=request_id,
            allocation_id=row["allocation_id"] or row["release_allocation_id"],
            event_type="ANCHOR_RECORDED",
            actor=ALLOCATOR_ACTOR,
            event_at=event_at,
            reason_code=None,
            canonical_git_ref_sha=canonical_git_ref_sha,
            canonical_dolt_commit=canonical_dolt_commit,
            details={
                "anchored_event_id": anchored["event_id"],
                "metadata_only": True,
                "request_id": request_id,
                "version": 1,
            },
        )
        return True

    def reconstruct(self) -> dict[str, list[dict[str, object]]]:
        def rows(table: str, order: str) -> list[dict[str, object]]:
            return [dict(row) for row in self.connection.execute(f"SELECT * FROM {table} ORDER BY {order}")]

        return {
            "requests": rows("allocation_requests", "processed_at, request_id"),
            "allocations": rows("allocations", "granted_at, allocation_id"),
            "active_ownership": rows("active_task_allocations", "task_id"),
            "tasks": rows("beads_tasks", "task_id"),
            "events": rows("allocation_events", "event_at, event_id"),
        }
