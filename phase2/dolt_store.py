"""Dolt/MySQL allocation store bound to the pinned Beads SQL schema.

The fast unit suite uses :mod:`phase2.allocation_store` with SQLite.  Runtime
canonical mutation must instead operate on the Beads tables in the same Dolt
database.  This adapter deliberately implements the same store surface while
using PEP-249 MySQL parameter semantics and Beads' ``issues``, ``dependencies``
and ``labels`` tables.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .allocation_store import AllocationStore, CanonicalOwnershipMismatch
from .allocation_types import Task


@dataclass
class _Result:
    rows: list[dict[str, Any]]
    rowcount: int = 0

    def fetchone(self) -> dict[str, Any] | None:
        return None if not self.rows else self.rows[0]

    def fetchall(self) -> list[dict[str, Any]]:
        return list(self.rows)


def _qmark_to_format(sql: str) -> str:
    """Translate the store's qmark placeholders to MySQL ``%s`` placeholders."""
    return sql.replace("?", "%s")


class _MySQLConnectionAdapter:
    """Small execute-compatible facade over a PEP-249 MySQL connection."""

    def __init__(self, connection: Any) -> None:
        self.raw = connection

    @staticmethod
    def _beads_sql(sql: str) -> str:
        compact = " ".join(sql.split())
        if compact == "UPDATE beads_tasks SET status = 'assigned', assignee = ? WHERE task_id = ?":
            return (
                "UPDATE issues SET status = 'in_progress', assignee = %s "
                "WHERE id = %s AND status = 'open' AND (assignee IS NULL OR assignee = '')"
            )
        if compact == "UPDATE beads_tasks SET status = 'open', assignee = NULL WHERE task_id = ?":
            return (
                "UPDATE issues SET status = 'open', assignee = NULL "
                "WHERE id = %s AND status = 'in_progress'"
            )
        return _qmark_to_format(sql)

    def execute(self, sql: str, params: Iterable[Any] = ()) -> _Result:
        cursor = self.raw.cursor()
        try:
            cursor.execute(self._beads_sql(sql), tuple(params))
            if cursor.description is None:
                return _Result([], getattr(cursor, "rowcount", 0) or 0)
            names = [column[0] for column in cursor.description]
            raw_rows = cursor.fetchall()
            rows: list[dict[str, Any]] = []
            for row in raw_rows:
                if isinstance(row, dict):
                    rows.append(dict(row))
                else:
                    rows.append(dict(zip(names, row)))
            return _Result(rows, getattr(cursor, "rowcount", len(rows)) or len(rows))
        finally:
            cursor.close()

    def commit(self) -> None:
        self.raw.commit()

    def rollback(self) -> None:
        self.raw.rollback()


class DoltAllocationStore(AllocationStore):
    """Allocation store for the pinned Beads schema inside Dolt.

    The canonical allocation rows and the Beads issue status/assignee mirror are
    mutated through one database connection and therefore one Dolt SQL
    transaction.  Beads ``in_progress`` is the protocol's assigned/non-open
    materialisation; release restores ``open`` with no assignee.
    """

    def __init__(self, connection: Any) -> None:
        self.raw_connection = connection
        super().__init__(_MySQLConnectionAdapter(connection))  # type: ignore[arg-type]

    def begin(self) -> None:
        self.connection.execute("START TRANSACTION")

    def seed_task(self, task: Task) -> None:
        """Seed only an isolated Beads-compatible fixture; never a live runtime task."""
        status = "in_progress" if task.status == "assigned" else task.status
        assignee = task.assignee or ""
        self.connection.execute(
            """INSERT INTO issues
               (id, title, description, design, acceptance_criteria, notes, status,
                priority, issue_type, assignee, created_at, created_by)
               VALUES (?, ?, '', '', '', '', ?, ?, ?, ?, ?, 'phase2-fixture')""",
            (task.task_id, task.task_id, status, task.priority, task.task_type, assignee, task.created_at),
        )
        for label in task.labels:
            self.connection.execute(
                "INSERT INTO labels (issue_id, label) VALUES (?, ?)", (task.task_id, label)
            )

    def _blocked(self, task_id: str) -> bool:
        row = self.connection.execute(
            """SELECT COUNT(*) AS blocker_count
               FROM dependencies d
               JOIN issues prerequisite ON prerequisite.id = d.depends_on_id
               WHERE d.issue_id = ? AND d.type = 'blocks' AND prerequisite.status <> 'closed'""",
            (task_id,),
        ).fetchone()
        return bool(row and int(row["blocker_count"]) > 0)

    def _labels(self, task_id: str) -> tuple[str, ...]:
        rows = self.connection.execute(
            "SELECT label FROM labels WHERE issue_id = ? ORDER BY label", (task_id,)
        ).fetchall()
        return tuple(str(row["label"]) for row in rows)

    def _beads_task(self, row: dict[str, Any]) -> Task:
        assignee = row.get("assignee") or None
        blocked = self._blocked(str(row["id"]))
        status = str(row["status"])
        ready = status == "open" and assignee is None and not blocked
        created = row["created_at"]
        created_at = created.isoformat() if hasattr(created, "isoformat") else str(created)
        return Task(
            task_id=str(row["id"]),
            task_type=str(row["issue_type"]),
            status=status,
            assignee=assignee,
            priority=int(row["priority"]),
            created_at=created_at,
            ready=ready,
            blocked=blocked,
            labels=self._labels(str(row["id"])),
        )

    def tasks(self) -> list[Task]:
        rows = self.connection.execute(
            """SELECT id, issue_type, status, assignee, priority, created_at
               FROM issues ORDER BY priority, created_at, BINARY id"""
        ).fetchall()
        return [self._beads_task(row) for row in rows]

    def task(self, task_id: str) -> Task | None:
        row = self.connection.execute(
            """SELECT id, issue_type, status, assignee, priority, created_at
               FROM issues WHERE id = ?""",
            (task_id,),
        ).fetchone()
        return None if row is None else self._beads_task(row)

    def assert_ownership_invariant(self, task: Task) -> None:
        allocations = self.connection.execute(
            "SELECT * FROM allocations WHERE task_id = ? AND state = 'ACTIVE'", (task.task_id,)
        ).fetchall()
        active = self.connection.execute(
            "SELECT * FROM active_task_allocations WHERE task_id = ?", (task.task_id,)
        ).fetchall()

        if len(allocations) == 0 and len(active) == 0:
            valid = task.status != "in_progress" and task.assignee is None
        else:
            valid = (
                task.status == "in_progress"
                and task.assignee is not None
                and len(allocations) == 1
                and len(active) == 1
                and active[0]["allocation_id"] == allocations[0]["allocation_id"]
                and allocations[0]["agent_id"] == task.assignee
            )
        if not valid:
            raise CanonicalOwnershipMismatch(task.task_id)

    def reconstruct(self) -> dict[str, list[dict[str, object]]]:
        def rows(table: str, order: str) -> list[dict[str, object]]:
            return [dict(row) for row in self.connection.execute(f"SELECT * FROM {table} ORDER BY {order}").fetchall()]

        return {
            "requests": rows("allocation_requests", "processed_at, request_id"),
            "allocations": rows("allocations", "granted_at, allocation_id"),
            "active_ownership": rows("active_task_allocations", "task_id"),
            "tasks": rows("issues", "id"),
            "events": rows("allocation_events", "event_at, event_id"),
        }
