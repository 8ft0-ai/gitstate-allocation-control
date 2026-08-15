import hashlib
import sqlite3
import subprocess
import unittest

from phase2.allocation_schema import initialise_sqlite_fixture
from phase2.allocation_types import AllocationCommand, RequestContext, stable_ulid
from phase2.canonical import CanonicalIdentityMismatch
from phase2.dolt_repository import DoltCanonicalRepository, _normalise_dolt_remote
from phase2.dolt_store import DoltAllocationStore

NOW = "2026-08-15T00:00:00Z"
AGENT = "agent://human/alice/session/a"


class SQLiteMySQLCursor:
    def __init__(self, connection):
        self.connection = connection
        self.cursor = None
        self.description = None
        self.rowcount = 0

    def execute(self, sql, params=()):
        translated = sql.replace("%s", "?")
        if translated.strip().upper() == "START TRANSACTION":
            translated = "BEGIN IMMEDIATE"
        self.cursor = self.connection.execute(translated, tuple(params))
        self.description = self.cursor.description
        self.rowcount = self.cursor.rowcount
        return self

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()

    def close(self):
        pass


class SQLiteMySQLConnection:
    def __init__(self, connection):
        self.connection = connection

    def cursor(self):
        return SQLiteMySQLCursor(self.connection)

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()


class FakeDoltCursor:
    def __init__(self, connection):
        self.connection = connection
        self.row = None
        self.description = (("value",),)

    def execute(self, sql, params=()):
        self.connection.statements.append(sql)
        if "DOLT_HASHOF" in sql:
            self.row = (self.connection.dolt_head,)
        elif "ACTIVE_BRANCH" in sql:
            self.row = (self.connection.active_branch,)
        elif "DOLT_COMMIT" in sql:
            self.connection.dolt_head = "dolt-2"
            self.row = None
        else:
            self.row = None
        return self

    def fetchone(self):
        return self.row

    def close(self):
        pass


class FakeDoltConnection:
    def __init__(self):
        self.dolt_head = "dolt-1"
        self.active_branch = "main"
        self.statements = []
        self.commits = 0
        self.closed = False

    def cursor(self):
        return FakeDoltCursor(self)

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True


class DoltStoreTests(unittest.TestCase):
    def setUp(self):
        inner = sqlite3.connect(":memory:", isolation_level=None)
        inner.execute("PRAGMA foreign_keys = ON")
        initialise_sqlite_fixture(inner)
        inner.executescript(
            """
            CREATE TABLE issues (
              id TEXT PRIMARY KEY,
              title TEXT NOT NULL,
              description TEXT NOT NULL,
              design TEXT NOT NULL,
              acceptance_criteria TEXT NOT NULL,
              notes TEXT NOT NULL,
              status TEXT NOT NULL,
              priority INTEGER NOT NULL,
              issue_type TEXT NOT NULL,
              assignee TEXT,
              created_at TEXT NOT NULL,
              created_by TEXT NOT NULL
            );
            CREATE TABLE dependencies (
              issue_id TEXT NOT NULL,
              depends_on_id TEXT NOT NULL,
              type TEXT NOT NULL DEFAULT 'blocks',
              PRIMARY KEY (issue_id, depends_on_id)
            );
            CREATE TABLE labels (
              issue_id TEXT NOT NULL,
              label TEXT NOT NULL,
              PRIMARY KEY (issue_id, label)
            );
            """
        )
        # The fast SQLite conformance schema predates the real-Beads adapter and
        # keeps its fixture-only task FK. Seed that compatibility row as well as
        # the actual Beads issue used by DoltAllocationStore.
        inner.execute(
            """INSERT INTO beads_tasks VALUES
               ('task-1', 'task', 'open', NULL, 1, ?, 1, 0, '[]')""",
            (NOW,),
        )
        self.inner = inner
        self.connection = SQLiteMySQLConnection(inner)
        self.store = DoltAllocationStore(self.connection)
        self.store.seed_task(
            __import__("phase2.allocation_types", fromlist=["Task"]).Task(
                "task-1", "task", "open", None, 1, NOW, True, False, ("capability:linux",)
            )
        )

    def tearDown(self):
        self.inner.close()

    @staticmethod
    def command(kind, name, *, allocation_id=None):
        return AllocationCommand(
            request_id=stable_ulid(f"request:{name}"),
            request_type=kind,
            payload_hash=hashlib.sha256(name.encode()).hexdigest(),
            agent_id=AGENT,
            capabilities=("linux",),
            task_types=("task",),
            allocation_id=allocation_id,
        )

    @staticmethod
    def context(name):
        return RequestContext("example/control", 1, abs(hash(name)) + 1, "user:alice", AGENT)

    def test_grant_and_release_mutate_real_beads_issue_in_same_transaction(self):
        grant_command = self.command("ALLOCATE_NEXT", "grant")
        self.store.begin()
        task = self.store.task("task-1")
        self.assertTrue(task.ready)
        grant = self.store.grant(grant_command, self.context("grant"), task, NOW)
        self.store.commit()
        status, assignee = self.inner.execute(
            "SELECT status, assignee FROM issues WHERE id = 'task-1'"
        ).fetchone()
        self.assertEqual((status, assignee), ("in_progress", AGENT))
        self.assertEqual(
            self.inner.execute("SELECT allocation_id FROM active_task_allocations").fetchone()[0],
            grant.allocation_id,
        )

        release_command = self.command("RELEASE", "release", allocation_id=grant.allocation_id)
        self.store.begin()
        release = self.store.release(release_command, self.context("release"), NOW)
        self.store.commit()
        self.assertEqual(release.reason_code, "RELEASED")
        status, assignee = self.inner.execute(
            "SELECT status, assignee FROM issues WHERE id = 'task-1'"
        ).fetchone()
        self.assertEqual((status, assignee), ("open", None))
        self.assertEqual(self.inner.execute("SELECT COUNT(*) FROM active_task_allocations").fetchone()[0], 0)

    def test_beads_dependencies_and_capability_labels_drive_readiness(self):
        self.inner.execute(
            """INSERT INTO issues VALUES
               ('blocker', 'blocker', '', '', '', '', 'open', 0, 'task', NULL, ?, 'fixture')""",
            (NOW,),
        )
        self.inner.execute(
            "INSERT INTO dependencies (issue_id, depends_on_id, type) VALUES ('task-1', 'blocker', 'blocks')"
        )
        task = self.store.task("task-1")
        self.assertTrue(task.blocked)
        self.assertFalse(task.ready)
        self.assertEqual(task.required_capabilities, {"linux"})


class DoltRepositoryTests(unittest.TestCase):
    def test_git_remote_urls_are_normalised_like_pinned_beads(self):
        self.assertEqual(
            _normalise_dolt_remote("https://example.invalid/state.git"),
            "git+https://example.invalid/state.git",
        )
        self.assertEqual(
            _normalise_dolt_remote("git@example.invalid:org/state.git"),
            "git+ssh://git@example.invalid/org/state.git",
        )
        self.assertEqual(
            _normalise_dolt_remote("file:///tmp/state.git"),
            "file:///tmp/state.git",
        )

    def test_publication_clones_and_pushes_through_dolt_without_force(self):
        commands = []
        old_sha = "a" * 40
        new_sha = "b" * 40
        remote_sha = [old_sha]
        connection = FakeDoltConnection()
        factory_paths = []

        def factory(database):
            factory_paths.append(database)
            return connection

        def runner(command, cwd):
            command = tuple(command)
            commands.append(command)
            if command[:2] == ("git", "ls-remote"):
                stdout = f"{remote_sha[0]}\trefs/dolt/data\n"
            elif command[:2] == ("dolt", "sql"):
                stdout = f"commit_hash\n{connection.dolt_head}\n"
            elif command[:2] == ("dolt", "push"):
                remote_sha[0] = new_sha
                stdout = ""
            else:
                stdout = ""
            return subprocess.CompletedProcess(command, 0, stdout, "")

        repository = DoltCanonicalRepository(
            "https://example.invalid/state.git",
            factory,
            run_command=runner,
        )
        snapshot = repository.bootstrap()
        accepted = repository.publish(old_sha, snapshot)

        self.assertEqual(factory_paths, [snapshot.database])
        self.assertEqual(snapshot.database.name, "canonical")
        self.assertEqual(accepted.git_ref_sha, new_sha)
        self.assertEqual(accepted.dolt_commit, "dolt-2")

        clone = next(command for command in commands if command[:2] == ("dolt", "clone"))
        self.assertEqual(clone[2], "git+https://example.invalid/state.git")
        self.assertEqual(clone[3], "canonical")
        push = next(command for command in commands if command[:2] == ("dolt", "push"))
        self.assertEqual(push, ("dolt", "push", "origin", "main"))
        self.assertFalse(any("--force" in part or part == "-f" for command in commands for part in command))
        self.assertFalse(
            any(
                command[:2]
                in {
                    ("git", "init"),
                    ("git", "fetch"),
                    ("git", "checkout"),
                    ("git", "add"),
                    ("git", "commit"),
                    ("git", "push"),
                }
                for command in commands
            )
        )
        snapshot.close()

    def test_bootstrap_rejects_connection_not_bound_to_cloned_dolt_head(self):
        old_sha = "a" * 40
        connection = FakeDoltConnection()

        def runner(command, cwd):
            command = tuple(command)
            if command[:2] == ("git", "ls-remote"):
                return subprocess.CompletedProcess(command, 0, f"{old_sha}\trefs/dolt/data\n", "")
            if command[:2] == ("dolt", "sql"):
                return subprocess.CompletedProcess(command, 0, "commit_hash\ndifferent-head\n", "")
            return subprocess.CompletedProcess(command, 0, "", "")

        repository = DoltCanonicalRepository(
            "https://example.invalid/state.git",
            lambda database: connection,
            run_command=runner,
        )
        with self.assertRaisesRegex(CanonicalIdentityMismatch, "CANONICAL_DOLT_CONNECTION_MISMATCH"):
            repository.bootstrap()
        self.assertTrue(connection.closed)


if __name__ == "__main__":
    unittest.main()
