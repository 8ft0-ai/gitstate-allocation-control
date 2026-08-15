import json
import sqlite3
import unittest

from phase2.allocation_schema import dolt_schema, initialise_sqlite_fixture
from phase2.allocation_types import stable_ulid


def valid_request(connection, request_id="01ARZ3NDEKTSV4RRFFQ69G5FAV", comment_id=1):
    connection.execute(
        """INSERT INTO allocation_requests (
             request_id, protocol_version, request_type, payload_sha256, source_repository,
             source_issue_number, source_comment_id, requested_by, agent_id, status,
             result_code, terminal_reason_code, processed_at
           ) VALUES (?, 'beads-allocation/v0.2', 'ALLOCATE_NEXT', ?, 'example/control',
             1, ?, 'user:1', 'agent://human/example/session/1', 'REJECTED',
             'NO_ELIGIBLE_TASK', 'NO_ELIGIBLE_TASK', '2026-01-01T00:00:00Z')""",
        (request_id, "a" * 64, comment_id),
    )


class AllocationSchemaTests(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        initialise_sqlite_fixture(self.connection)

    def tearDown(self):
        self.connection.close()

    def test_authoritative_dolt_schema_contains_required_database_guards(self):
        ddl = dolt_schema()
        for fragment in (
            "CREATE TABLE allocation_requests",
            "CREATE TABLE allocations",
            "CREATE TABLE active_task_allocations",
            "CREATE TABLE allocation_events",
            "fk_active_task_allocation_pair",
            "allocation_events_no_update",
            "allocation_events_no_delete",
            "REGEXP '^[0-9a-f]{64}$'",
        ):
            self.assertIn(fragment, ddl)

    def test_request_source_uniqueness_and_foreign_keys(self):
        valid_request(self.connection)
        with self.assertRaises(sqlite3.IntegrityError):
            valid_request(self.connection, request_id="01ARZ3NDEKTSV4RRFFQ69G5FAW", comment_id=1)
        self.connection.execute(
            """INSERT INTO beads_tasks VALUES
               ('task-1', 'task', 'open', NULL, 1, '2026-01-01T00:00:00Z', 1, 0, '[]')"""
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """INSERT INTO allocations VALUES
                   (?, 'missing-request', 'agent://human/example/session/1', 'task-1',
                    'ACTIVE', '2026-01-01T00:00:00Z', NULL, NULL, NULL, ?)""",
                (stable_ulid("missing"), "b" * 64),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "UPDATE allocation_requests SET allocation_id = ? WHERE request_id = ?",
                (stable_ulid("missing-allocation"), "01ARZ3NDEKTSV4RRFFQ69G5FAV"),
            )
        self.connection.execute("PRAGMA foreign_key_check")
        self.assertEqual(self.connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_audit_event_orphan_constraints_and_append_only_history(self):
        valid_request(self.connection)
        ordinary = (
            stable_ulid("ordinary"),
            None,
            None,
            "REQUEST_TERMINAL",
            None,
            None,
            "allocator",
            "2026-01-01T00:00:00Z",
            "NO_ELIGIBLE_TASK",
            None,
            None,
            json.dumps({"version": 1}),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "INSERT INTO allocation_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", ordinary
            )
        orphan = (
            stable_ulid("orphan"),
            None,
            None,
            "AUDIT_FINDING",
            "PROJECTION_COMMENT",
            "example/control:1:99",
            "allocator",
            "2026-01-01T00:00:00Z",
            "ORPHAN_PROJECTION",
            None,
            None,
            json.dumps({"version": 1}),
        )
        self.connection.execute(
            "INSERT INTO allocation_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", orphan
        )
        unidentified = list(orphan)
        unidentified[0] = stable_ulid("unidentified")
        unidentified[4] = None
        unidentified[5] = None
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "INSERT INTO allocation_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                unidentified,
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "ALLOCATION_EVENTS_APPEND_ONLY"):
            self.connection.execute(
                "UPDATE allocation_events SET reason_code = 'CHANGED' WHERE event_id = ?", (orphan[0],)
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "ALLOCATION_EVENTS_APPEND_ONLY"):
            self.connection.execute("DELETE FROM allocation_events WHERE event_id = ?", (orphan[0],))


if __name__ == "__main__":
    unittest.main()
