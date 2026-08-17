import hashlib
import subprocess
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from phase2.adversarial import (
    AttemptNamespace,
    CONTROL_REPOSITORY_ID,
    STATE_REPOSITORY_ID,
)
from phase2.allocation_engine import AllocationService, seed_local_fixture
from phase2.allocation_store import AllocationStore
from phase2.allocation_types import (
    AllocationCommand,
    RequestContext,
    Task,
    stable_ulid,
)
from phase2.canonical import LocalCanonicalRepository, StaleCanonicalBase
from phase2.dolt_repository import DoltCanonicalRepository
from phase2.inventory import InventoryAttestation
from phase2.workstream_d_live import (
    LiveFixtureBackend,
    PROTOCOL_AUTHORITY,
    ValidatedInventory,
    _run_close_timed_calls,
)

NOW = "2026-08-17T00:00:00Z"
AGENT = "agent://human/bootstrap-stale/session/test"


def task(task_id: str, created_at: str = "2026-01-01T00:00:00Z") -> Task:
    return Task(task_id, "task", "open", None, 1, created_at, True, False)


def command(name: str) -> AllocationCommand:
    return AllocationCommand(
        request_id=stable_ulid(f"bootstrap-stale:{name}"),
        request_type="ALLOCATE_NEXT",
        payload_hash=hashlib.sha256(f"bootstrap-stale:{name}".encode()).hexdigest(),
        agent_id=AGENT,
        task_types=("task",),
    )


def context(source_comment_id: int) -> RequestContext:
    return RequestContext(
        "example/control",
        1,
        source_comment_id,
        "fixture:bootstrap-stale",
        AGENT,
    )


def rows(repository: LocalCanonicalRepository, table: str) -> list[dict[str, object]]:
    connection = repository.inspect()
    try:
        return [dict(row) for row in connection.execute(f"SELECT * FROM {table}")]
    finally:
        connection.close()


class BootstrapStaleRepository:
    """Credential-free wrapper that injects stale failure before a snapshot exists."""

    def __init__(self, inner: LocalCanonicalRepository, failures: int) -> None:
        self.inner = inner
        self.remaining = failures
        self.bootstrap_attempts = 0

    def bootstrap(self):
        self.bootstrap_attempts += 1
        if self.remaining:
            self.remaining -= 1
            raise StaleCanonicalBase("STALE_EXPECTED_OLD_SHA")
        return self.inner.bootstrap()

    @staticmethod
    def store(snapshot):
        return AllocationStore(snapshot.connection)

    def publish(self, expected_old_sha, snapshot):
        return self.inner.publish(expected_old_sha, snapshot)


class ProbeCursor:
    def __init__(self) -> None:
        self.row = None

    def execute(self, sql, params=()):
        if "DOLT_HASHOF" in sql:
            self.row = ("probe-head",)
        elif "ACTIVE_BRANCH" in sql:
            self.row = ("main",)
        else:
            raise AssertionError(f"unexpected probe SQL: {sql}")
        return self

    def fetchone(self):
        return self.row

    def close(self):
        pass


class ProbeConnection:
    def cursor(self):
        return ProbeCursor()

    def close(self):
        pass


class CloseTimedBootstrapStaleRepository:
    """Reproduce real bootstrap CAS movement twice for the first close-timed worker."""

    def __init__(self, inner: LocalCanonicalRepository, root: Path) -> None:
        self.inner = inner
        self.root = root
        self.remote = root / "canonical.git"
        self.lock = threading.Lock()
        self.victim: int | None = None
        self.bootstrap_stales = 0
        self.ref_moves = 0
        self._next_ref_shas = self._initialise_probe_remote()

    @staticmethod
    def _run_git(command: list[str], *, cwd: Path) -> str:
        completed = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if completed.returncode != 0:
            raise AssertionError(
                f"git command failed ({completed.returncode}): {' '.join(command)}\n"
                f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
            )
        return completed.stdout.strip()

    def _initialise_probe_remote(self) -> tuple[str, str]:
        source = self.root / "source"
        source.mkdir()
        self._run_git(["git", "init", "--initial-branch=main"], cwd=source)
        self._run_git(["git", "config", "user.name", "Bootstrap Stale Test"], cwd=source)
        self._run_git(
            ["git", "config", "user.email", "bootstrap-stale@example.invalid"], cwd=source
        )

        commits = []
        for index in range(3):
            (source / "state.txt").write_text(f"state-{index}\n", encoding="utf-8")
            self._run_git(["git", "add", "state.txt"], cwd=source)
            self._run_git(["git", "commit", "-m", f"state {index}"], cwd=source)
            commits.append(self._run_git(["git", "rev-parse", "HEAD"], cwd=source))

        self._run_git(["git", "init", "--bare", str(self.remote)], cwd=self.root)
        self._run_git(
            ["git", "push", str(self.remote), f"{commits[0]}:refs/dolt/data"], cwd=source
        )
        # Transfer both future commits without advancing the canonical ref yet.
        self._run_git(
            [
                "git",
                "push",
                str(self.remote),
                f"{commits[2]}:refs/heads/bootstrap-stale-next",
            ],
            cwd=source,
        )
        return commits[1], commits[2]

    def _probe_bootstrap(self, *, move_ref: bool) -> None:
        next_sha = self._next_ref_shas[self.ref_moves] if move_ref else None

        def runner(command, cwd):
            command = tuple(command)
            if command[:2] == ("git", "ls-remote"):
                return subprocess.run(
                    list(command),
                    cwd=cwd,
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            if command[:2] == ("dolt", "clone"):
                (cwd / command[3]).mkdir(exist_ok=True)
                if next_sha is not None:
                    self._run_git(
                        [
                            "git",
                            "--git-dir",
                            str(self.remote),
                            "update-ref",
                            "refs/dolt/data",
                            next_sha,
                        ],
                        cwd=self.root,
                    )
                    self.ref_moves += 1
                return subprocess.CompletedProcess(command, 0, "", "")
            if command[:2] == ("dolt", "sql"):
                return subprocess.CompletedProcess(command, 0, "commit_hash\nprobe-head\n", "")
            raise AssertionError(f"unexpected probe command: {command}")

        repository = DoltCanonicalRepository(
            "git+file://" + str(self.remote),
            lambda _: ProbeConnection(),
            run_command=runner,
            workspace_root=self.root,
        )
        snapshot = repository.bootstrap()
        snapshot.close()

    def bootstrap(self):
        worker = threading.get_ident()
        with self.lock:
            if self.victim is None:
                self.victim = worker
            move_ref = worker == self.victim and self.ref_moves < len(self._next_ref_shas)
            try:
                self._probe_bootstrap(move_ref=move_ref)
            except StaleCanonicalBase:
                self.bootstrap_stales += 1
                raise
        return self.inner.bootstrap()

    @staticmethod
    def store(snapshot):
        return AllocationStore(snapshot.connection)

    def publish(self, expected_old_sha, snapshot):
        return self.inner.publish(expected_old_sha, snapshot)


class BootstrapStaleRetryTests(unittest.TestCase):
    def repository(self, *tasks: Task) -> LocalCanonicalRepository:
        repository = LocalCanonicalRepository()
        seed_local_fixture(repository, tasks)
        return repository

    def test_process_retries_bootstrap_stale_from_fresh_snapshot(self):
        inner = self.repository(task("task-1"))
        repository = BootstrapStaleRepository(inner, failures=1)

        result = AllocationService(repository, clock=lambda: NOW).process(
            command("process-once"), context(101)
        )

        self.assertEqual(result.reason_code, "ALLOCATED")
        self.assertEqual(result.retry_count, 1)
        self.assertEqual(repository.bootstrap_attempts, 2)
        self.assertEqual(len(rows(inner, "allocation_requests")), 1)
        self.assertEqual(len(rows(inner, "allocations")), 1)

    def test_process_bootstrap_stale_exhaustion_is_terminal_without_mutation(self):
        inner = self.repository(task("task-1"))
        repository = BootstrapStaleRepository(inner, failures=3)

        result = AllocationService(
            repository, clock=lambda: NOW, max_stale_retries=2
        ).process(command("process-exhaust"), context(102))

        self.assertEqual(result.reason_code, "STALE_ALLOCATOR_RETRY_EXHAUSTED")
        self.assertEqual(result.retry_count, 2)
        self.assertEqual(repository.bootstrap_attempts, 3)
        self.assertEqual(rows(inner, "allocation_requests"), [])
        self.assertEqual(rows(inner, "allocations"), [])
        self.assertEqual(rows(inner, "beads_tasks")[0]["status"], "open")

    def test_record_anchor_retries_bootstrap_stale_and_preserves_creation_identity(self):
        inner = self.repository(task("task-1"))
        granted = AllocationService(inner, clock=lambda: NOW).process(
            command("anchor-success"), context(103)
        )
        creation_git_sha = granted.canonical_git_ref_sha
        creation_dolt_commit = granted.canonical_dolt_commit
        self.assertIsNotNone(creation_git_sha)
        self.assertIsNotNone(creation_dolt_commit)

        repository = BootstrapStaleRepository(inner, failures=1)
        anchored = AllocationService(repository, clock=lambda: NOW).record_anchor(
            granted.request_id,
            creation_git_sha or "",
            creation_dolt_commit or "",
        )

        self.assertEqual(anchored.reason_code, "ALLOCATED")
        self.assertEqual(anchored.retry_count, 1)
        self.assertTrue(anchored.ref_advanced)
        request_row = rows(inner, "allocation_requests")[0]
        self.assertEqual(request_row["anchor_status"], "RECORDED")
        self.assertEqual(request_row["canonical_git_ref_sha"], creation_git_sha)
        self.assertEqual(request_row["canonical_dolt_commit"], creation_dolt_commit)
        self.assertEqual(len(rows(inner, "allocations")), 1)

    def test_record_anchor_bootstrap_stale_exhaustion_leaves_pending_anchor_and_owner(self):
        inner = self.repository(task("task-1"))
        granted = AllocationService(inner, clock=lambda: NOW).process(
            command("anchor-exhaust"), context(104)
        )
        creation_git_sha = granted.canonical_git_ref_sha
        creation_dolt_commit = granted.canonical_dolt_commit
        self.assertIsNotNone(creation_git_sha)
        self.assertIsNotNone(creation_dolt_commit)

        repository = BootstrapStaleRepository(inner, failures=3)
        anchored = AllocationService(
            repository, clock=lambda: NOW, max_stale_retries=2
        ).record_anchor(
            granted.request_id,
            creation_git_sha or "",
            creation_dolt_commit or "",
        )

        self.assertEqual(anchored.reason_code, "STALE_ALLOCATOR_RETRY_EXHAUSTED")
        self.assertEqual(anchored.retry_count, 2)
        request_row = rows(inner, "allocation_requests")[0]
        self.assertEqual(request_row["anchor_status"], "PENDING")
        self.assertIsNone(request_row["canonical_git_ref_sha"])
        self.assertIsNone(request_row["canonical_dolt_commit"])
        allocations = rows(inner, "allocations")
        self.assertEqual(len(allocations), 1)
        self.assertEqual(allocations[0]["allocation_id"], granted.allocation_id)
        self.assertEqual(allocations[0]["state"], "ACTIVE")

    def test_close_timed_workstream_d_adapter_retries_real_bootstrap_ref_movement(self):
        inner = self.repository(
            task("task-a", "2026-01-01T00:00:00Z"),
            task("task-b", "2026-01-01T00:00:01Z"),
        )
        with tempfile.TemporaryDirectory(prefix="bootstrap-stale-ref-move-") as directory:
            repository = CloseTimedBootstrapStaleRepository(inner, Path(directory))
            namespace = AttemptNamespace.parse("wd-1-1-abc123", run_id=1, run_attempt=1)
            inventory = ValidatedInventory(
                InventoryAttestation(
                    app_id=1,
                    installation_id=2,
                    repository_selection="selected",
                    repository_ids=(CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID),
                    audited_at=datetime.now(timezone.utc),
                ),
                "fixture-inventory",
            )
            backend = LiveFixtureBackend(
                repository,
                object(),
                1,
                "a" * 40,
                PROTOCOL_AUTHORITY,
                (),
                inventory,
                namespace,
            )
            workers = (backend._fresh_backend(), backend._fresh_backend())

            values, start_spread = _run_close_timed_calls(
                (
                    lambda: workers[0]._process(
                        1,
                        1,
                        request_type="ALLOCATE_NEXT",
                        project=False,
                        source_override=(201, "https://example.invalid/source/201"),
                    ),
                    lambda: workers[1]._process(
                        1,
                        2,
                        request_type="ALLOCATE_NEXT",
                        project=False,
                        source_override=(202, "https://example.invalid/source/202"),
                    ),
                )
            )

            self.assertLessEqual(start_spread, 30.0)
            self.assertEqual(repository.ref_moves, 2)
            self.assertEqual(repository.bootstrap_stales, 2)
            self.assertEqual({record.reason for record in values}, {"ALLOCATED"})
            self.assertEqual({record.task_id for record in values}, {"task-a", "task-b"})
            self.assertEqual(len(rows(inner, "allocations")), 2)
            self.assertEqual(
                {row["anchor_status"] for row in rows(inner, "allocation_requests")},
                {"RECORDED"},
            )


if __name__ == "__main__":
    unittest.main()
