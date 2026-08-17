"""Credential-free real-runtime validation for Workstream B.

This script is intentionally excluded from dependency-free unittest discovery.
CI supplies cryptographically pinned Beads v1.1.0 and Dolt v2.1.4 binaries and
PyMySQL. Everything runs against temporary local repositories and databases;
no live canonical state or repository credential is accepted.
"""

from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import pymysql

from phase2 import workstream_d_anchor_repair as anchor_repair
from phase2 import workstream_d_live as live
from phase2.allocation_engine import AllocationService
from phase2.allocation_schema import dolt_schema
from phase2.allocation_types import AllocationCommand, RequestContext, Task, stable_ulid
from phase2.canonical import StaleCanonicalBase
from phase2.dolt_repository import DoltCanonicalRepository

NOW = "2026-08-15T00:00:00Z"
AGENT = "agent://human/runtime/session/1"


def run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed.stdout.strip()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


class ManagedDoltConnection:
    """PEP-249 connection whose close also stops its isolated Dolt server."""

    def __init__(self, database: Path, dolt_bin: str) -> None:
        self.database = database
        self.port = free_port()
        self.log_path = database.parent / "sql-server.log"
        self.log = self.log_path.open("w+")
        self.process = subprocess.Popen(
            [
                dolt_bin,
                "sql-server",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--loglevel",
                "warning",
            ],
            cwd=database,
            text=True,
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        self.inner = self._connect()

    def _connect(self):
        deadline = time.monotonic() + 15.0
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            try:
                return pymysql.connect(
                    host="127.0.0.1",
                    port=self.port,
                    user="root",
                    password="",
                    database=self.database.name,
                    autocommit=False,
                    connect_timeout=1,
                )
            except pymysql.MySQLError as exc:
                last_error = exc
                time.sleep(0.1)
        self.log.flush()
        self.log.seek(0)
        output = self.log.read()
        self._stop()
        raise AssertionError(f"Dolt SQL server did not become ready: {last_error}\n{output}")

    def cursor(self):
        return self.inner.cursor()

    def commit(self) -> None:
        self.inner.commit()

    def rollback(self) -> None:
        self.inner.rollback()

    def close(self) -> None:
        try:
            self.inner.close()
        finally:
            self._stop()

    def _stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if not self.log.closed:
            self.log.close()


def execute_ddl(connection, ddl: str) -> None:
    """Execute MySQL DDL while respecting DELIMITER blocks for triggers."""
    delimiter = ";"
    buffered: list[str] = []
    cursor = connection.cursor()
    try:
        for line in ddl.splitlines():
            stripped = line.strip()
            if not buffered and (not stripped or stripped.startswith("--")):
                continue
            if stripped.upper().startswith("DELIMITER "):
                if "\n".join(buffered).strip():
                    raise AssertionError("unexpected buffered SQL before DELIMITER")
                delimiter = stripped.split(None, 1)[1]
                continue
            buffered.append(line)
            statement = "\n".join(buffered).rstrip()
            if not statement.endswith(delimiter):
                continue
            statement = statement[: -len(delimiter)].strip()
            buffered.clear()
            if statement:
                cursor.execute(statement)
        if "\n".join(buffered).strip():
            raise AssertionError("unterminated DDL statement")
        connection.commit()
    finally:
        cursor.close()


def fetch_one(connection, sql: str, params=()):
    cursor = connection.cursor()
    try:
        cursor.execute(sql, params)
        return cursor.fetchone()
    finally:
        cursor.close()


def assert_real_database_guards(repository: DoltCanonicalRepository) -> None:
    snapshot = repository.bootstrap()
    try:
        cursor = snapshot.connection.cursor()
        request_id = stable_ulid("runtime:fk-request")
        allocation_id = stable_ulid("runtime:fk-allocation")
        try:
            cursor.execute("START TRANSACTION")
            cursor.execute(
                """INSERT INTO allocation_requests (
                     request_id, protocol_version, request_type, payload_sha256,
                     source_repository, source_issue_number, source_comment_id,
                     requested_by, agent_id, status, result_code,
                     terminal_reason_code, processed_at
                   ) VALUES (%s, 'beads-allocation/v0.2', 'ALLOCATE_NEXT', %s,
                     'runtime/control', 1, 9001, 'user:runtime', %s,
                     'REJECTED', 'FIXTURE', 'FIXTURE', %s)""",
                (request_id, "a" * 64, AGENT, NOW),
            )
            try:
                cursor.execute(
                    """INSERT INTO allocations (
                         allocation_id, request_id, agent_id, task_id, state,
                         granted_at, allocation_state_digest
                       ) VALUES (%s, %s, %s, 'missing-task', 'ACTIVE', %s, %s)""",
                    (allocation_id, request_id, AGENT, NOW, "b" * 64),
                )
            except pymysql.MySQLError:
                pass
            else:
                raise AssertionError("real Dolt did not enforce allocations.task_id FK")
        finally:
            snapshot.connection.rollback()
            cursor.close()
    finally:
        snapshot.close()


def assert_append_only_trigger(repository: DoltCanonicalRepository) -> None:
    snapshot = repository.bootstrap()
    try:
        cursor = snapshot.connection.cursor()
        try:
            cursor.execute("START TRANSACTION")
            try:
                cursor.execute(
                    "UPDATE allocation_events SET reason_code = 'MUTATED' "
                    "WHERE event_type = 'ALLOCATED' LIMIT 1"
                )
            except pymysql.MySQLError as exc:
                if "ALLOCATION_EVENTS_APPEND_ONLY" not in str(exc):
                    raise AssertionError(f"unexpected append-only failure: {exc}") from exc
            else:
                raise AssertionError("real Dolt allowed allocation_events update")
        finally:
            snapshot.connection.rollback()
            cursor.close()
    finally:
        snapshot.close()


def initialise_pinned_beads_remote(root: Path, bd_bin: str) -> tuple[Path, str]:
    source = root / "beads-source"
    remote = root / "canonical.git"
    source.mkdir()
    run(["git", "init", "--initial-branch=main"], cwd=source)
    run(["git", "config", "user.name", "Workstream B Runtime"], cwd=source)
    run(["git", "config", "user.email", "runtime@example.invalid"], cwd=source)
    (source / "README.md").write_text("isolated Workstream B runtime fixture\n")
    run(["git", "add", "README.md"], cwd=source)
    run(["git", "commit", "-m", "initial fixture"], cwd=source)

    env = dict(os.environ)
    env.update({"BD_NON_INTERACTIVE": "1", "CI": "true"})
    run(
        [
            bd_bin,
            "init",
            "--prefix",
            "wb",
            "--quiet",
            "--skip-hooks",
            "--skip-agents",
            "--non-interactive",
        ],
        cwd=source,
        env=env,
    )

    run(["git", "init", "--bare", str(remote)], cwd=root)
    git_remote = "file://" + str(remote)
    run(["git", "remote", "add", "canonical-fixture", git_remote], cwd=source)
    run(["git", "push", "canonical-fixture", "main:main"], cwd=source)

    dolt_remote = "git+file://" + str(remote)
    run([bd_bin, "dolt", "remote", "add", "origin", dolt_remote], cwd=source, env=env)
    run([bd_bin, "dolt", "commit", "-m", "pinned Beads v1.1.0 baseline"], cwd=source, env=env)
    run([bd_bin, "dolt", "push"], cwd=source, env=env)

    ref = run(["git", "ls-remote", "--refs", git_remote, "refs/dolt/data"], cwd=root)
    fields = ref.split()
    if len(fields) != 2 or fields[1] != "refs/dolt/data" or len(fields[0]) != 40:
        raise AssertionError(f"pinned Beads did not publish refs/dolt/data: {ref!r}")
    return remote, fields[0]


def assert_durable_anchor_history_repair(
    repository: DoltCanonicalRepository,
    remote: Path,
    dolt_bin: str,
    granted,
) -> None:
    """Exercise the production first-parent history reader through anchor repair."""
    creation_git_sha = granted.canonical_git_ref_sha
    creation_dolt_commit = granted.canonical_dolt_commit
    if not creation_git_sha or not creation_dolt_commit:
        raise AssertionError("grant did not expose allocation-creation identity")

    snapshot = repository.bootstrap()
    try:
        row = repository.store(snapshot).get_request(granted.request_id)
        if row is None or row["anchor_status"] != "PENDING":
            raise AssertionError(f"grant was not pending anchor before repair: {row}")
    finally:
        snapshot.close()

    # Advance canonical state after the allocation but before repair. This makes
    # the current head deliberately different from the allocation-creation
    # identity, so a repair that substitutes current runner state cannot pass.
    snapshot = repository.bootstrap()
    try:
        store = repository.store(snapshot)
        store.begin()
        store.seed_task(
            Task(
                "task-anchor-history-later",
                "task",
                "open",
                None,
                4,
                NOW,
                True,
                False,
            )
        )
        store.commit()
        intervening = repository.publish(snapshot.identity.git_ref_sha, snapshot)
    finally:
        snapshot.close()
    if intervening.git_ref_sha == creation_git_sha:
        raise AssertionError("intervening canonical mutation did not advance Git history")
    if intervening.dolt_commit == creation_dolt_commit:
        raise AssertionError("intervening canonical mutation did not advance Dolt history")

    def read_only_remote_factory(root: Path) -> tuple[Path, str]:
        mirror = root / "state-read-only.git"
        env = live._credential_free_git_env()
        run(
            ["git", "clone", "--mirror", "--no-hardlinks", str(remote), str(mirror)],
            cwd=root,
            env=env,
        )
        source_sha = run(
            ["git", "--git-dir", str(mirror), "rev-parse", "refs/dolt/data"],
            cwd=root,
            env=env,
        )
        live._set_tree_read_only(mirror, read_only=True)
        return mirror, source_sha

    history = anchor_repair.DurableAcceptedHistory(
        read_only_remote_factory,
        dolt_bin=dolt_bin,
    )
    repaired = anchor_repair.repair_pending_anchor(
        repository,
        granted.request_id,
        history,
        control_repository="runtime/control",
        issue_number=1,
        clock=lambda: NOW,
    )
    if repaired["anchor_status"] != "RECORDED":
        raise AssertionError(f"anchor repair did not record metadata: {repaired}")
    if repaired["canonical_git_ref_sha"] != creation_git_sha:
        raise AssertionError(
            "durable history repair did not retain allocation-creation Git SHA"
        )
    if repaired["canonical_dolt_commit"] != creation_dolt_commit:
        raise AssertionError(
            "durable history repair did not retain allocation-creation Dolt commit"
        )

    snapshot = repository.bootstrap()
    try:
        current = snapshot.identity
        row = repository.store(snapshot).get_request(granted.request_id)
        if row is None:
            raise AssertionError("repaired request disappeared")
        if row["canonical_git_ref_sha"] != creation_git_sha:
            raise AssertionError("canonical row drifted from original Git identity")
        if row["canonical_dolt_commit"] != creation_dolt_commit:
            raise AssertionError("canonical row drifted from original Dolt identity")
        if current.git_ref_sha in {creation_git_sha, intervening.git_ref_sha}:
            raise AssertionError("metadata-only anchor repair did not create a later Git commit")
        if current.dolt_commit in {creation_dolt_commit, intervening.dolt_commit}:
            raise AssertionError("metadata-only anchor repair did not create a later Dolt commit")
    finally:
        snapshot.close()


def main() -> None:
    bd_bin = os.environ.get("BD_BIN")
    dolt_bin = os.environ.get("DOLT_BIN")
    if not bd_bin or not dolt_bin:
        raise SystemExit("BD_BIN and DOLT_BIN are required")

    with tempfile.TemporaryDirectory(prefix="workstream-b-real-runtime-") as directory:
        root = Path(directory)
        home = root / "home"
        home.mkdir()
        os.environ["HOME"] = str(home)
        os.environ["GIT_CONFIG_NOSYSTEM"] = "1"

        bd_version = run([bd_bin, "--version"], cwd=root)
        dolt_version = run([dolt_bin, "version"], cwd=root)
        if "1.1.0" not in bd_version:
            raise AssertionError(f"unexpected Beads version: {bd_version}")
        if "2.1.4" not in dolt_version:
            raise AssertionError(f"unexpected Dolt version: {dolt_version}")

        remote, initial_git_sha = initialise_pinned_beads_remote(root, bd_bin)
        remote_url = "git+file://" + str(remote)
        repository = DoltCanonicalRepository(
            remote_url,
            lambda database: ManagedDoltConnection(database, dolt_bin),
            dolt_bin=dolt_bin,
            workspace_root=root,
        )

        # Fresh clone proves the real pinned Beads schema exists before the
        # Workstream B migration is applied.
        snapshot = repository.bootstrap()
        try:
            columns = fetch_one(
                snapshot.connection,
                "SELECT COUNT(*) FROM information_schema.columns "
                "WHERE table_schema = DATABASE() AND table_name = 'issues' "
                "AND column_name IN ('id','status','assignee','issue_type')",
            )
            if int(columns[0]) != 4:
                raise AssertionError("pinned Beads issues schema is not present")
            execute_ddl(snapshot.connection, dolt_schema())
            ddl_identity = repository.publish(snapshot.identity.git_ref_sha, snapshot)
        finally:
            snapshot.close()
        if ddl_identity.git_ref_sha == initial_git_sha:
            raise AssertionError("DDL publication did not advance refs/dolt/data")

        assert_real_database_guards(repository)

        # Seed one genuine Beads issue through the concrete Dolt store and make
        # the seed canonical before exercising the allocation service.
        snapshot = repository.bootstrap()
        try:
            store = repository.store(snapshot)
            store.begin()
            store.seed_task(
                Task(
                    "task-runtime-1",
                    "task",
                    "open",
                    None,
                    1,
                    NOW,
                    True,
                    False,
                    ("capability:linux",),
                )
            )
            store.commit()
            repository.publish(snapshot.identity.git_ref_sha, snapshot)
        finally:
            snapshot.close()

        service = AllocationService(repository, clock=lambda: NOW, max_stale_retries=1)
        grant = AllocationCommand(
            request_id=stable_ulid("runtime:grant"),
            request_type="ALLOCATE_NEXT",
            payload_hash=hashlib.sha256(b"runtime:grant").hexdigest(),
            agent_id=AGENT,
            capabilities=("linux",),
            task_types=("task",),
        )
        grant_context = RequestContext("runtime/control", 1, 1001, "user:runtime", AGENT)
        granted = service.process(grant, grant_context)
        if granted.status != "ALLOCATED" or not granted.ref_advanced or not granted.allocation_id:
            raise AssertionError(f"real runtime grant failed: {granted}")

        snapshot = repository.bootstrap()
        try:
            issue = fetch_one(
                snapshot.connection,
                "SELECT status, assignee FROM issues WHERE id = %s",
                ("task-runtime-1",),
            )
            if issue != ("in_progress", AGENT):
                raise AssertionError(f"Beads ownership mirror mismatch after grant: {issue}")
            active = fetch_one(
                snapshot.connection,
                "SELECT allocation_id FROM active_task_allocations WHERE task_id = %s",
                ("task-runtime-1",),
            )
            if active != (granted.allocation_id,):
                raise AssertionError(f"active uniqueness mismatch after grant: {active}")
            allocation = fetch_one(
                snapshot.connection,
                "SELECT state, agent_id FROM allocations WHERE allocation_id = %s",
                (granted.allocation_id,),
            )
            if allocation != ("ACTIVE", AGENT):
                raise AssertionError(f"allocation authority mismatch after grant: {allocation}")
        finally:
            snapshot.close()

        assert_durable_anchor_history_repair(repository, remote, dolt_bin, granted)
        assert_append_only_trigger(repository)

        release = AllocationCommand(
            request_id=stable_ulid("runtime:release"),
            request_type="RELEASE",
            payload_hash=hashlib.sha256(b"runtime:release").hexdigest(),
            agent_id=AGENT,
            allocation_id=granted.allocation_id,
            reason="runtime integration release",
        )
        release_context = RequestContext("runtime/control", 1, 1002, "user:runtime", AGENT)
        released = service.process(release, release_context)
        if released.status != "RELEASED" or not released.ref_advanced:
            raise AssertionError(f"real runtime release failed: {released}")

        snapshot = repository.bootstrap()
        try:
            issue = fetch_one(
                snapshot.connection,
                "SELECT status, assignee FROM issues WHERE id = %s",
                ("task-runtime-1",),
            )
            if issue != ("open", None):
                raise AssertionError(f"Beads ownership mirror mismatch after release: {issue}")
            allocation = fetch_one(
                snapshot.connection,
                "SELECT state, release_request_id FROM allocations WHERE allocation_id = %s",
                (granted.allocation_id,),
            )
            if allocation != ("RELEASED", release.request_id):
                raise AssertionError(f"release history mismatch: {allocation}")
            active_count = fetch_one(
                snapshot.connection,
                "SELECT COUNT(*) FROM active_task_allocations WHERE task_id = %s",
                ("task-runtime-1",),
            )
            if int(active_count[0]) != 0:
                raise AssertionError("release did not remove active uniqueness row")
        finally:
            snapshot.close()

        # Two fresh writers share the same expected old Git ref. The first
        # advances canonical state; the second must fail closed without force.
        writer_a = repository.bootstrap()
        writer_b = repository.bootstrap()
        try:
            if writer_a.identity.git_ref_sha != writer_b.identity.git_ref_sha:
                raise AssertionError("CAS writers did not start from the same base")
            store_a = repository.store(writer_a)
            store_b = repository.store(writer_b)
            store_a.begin()
            store_a.seed_task(Task("task-cas-a", "task", "open", None, 2, NOW, True, False))
            store_a.commit()
            store_b.begin()
            store_b.seed_task(Task("task-cas-b", "task", "open", None, 2, NOW, True, False))
            store_b.commit()
            repository.publish(writer_a.identity.git_ref_sha, writer_a)
            try:
                repository.publish(writer_b.identity.git_ref_sha, writer_b)
            except StaleCanonicalBase:
                pass
            else:
                raise AssertionError("stale writer overwrote canonical state")
        finally:
            writer_a.close()
            writer_b.close()

        snapshot = repository.bootstrap()
        try:
            task_a = fetch_one(
                snapshot.connection,
                "SELECT COUNT(*) FROM issues WHERE id = 'task-cas-a'",
            )
            task_b = fetch_one(
                snapshot.connection,
                "SELECT COUNT(*) FROM issues WHERE id = 'task-cas-b'",
            )
            if int(task_a[0]) != 1 or int(task_b[0]) != 0:
                raise AssertionError(f"stale CAS leaked losing writer: a={task_a} b={task_b}")
        finally:
            snapshot.close()

        print("WORKSTREAM_B_REAL_RUNTIME_PASSED")
        print("beads_version=1.1.0")
        print("dolt_version=2.1.4")
        print("ddl_applied=true")
        print("grant_release_atomic=true")
        print("durable_anchor_history_repair=true")
        print("append_only_trigger=true")
        print("stale_expected_old_sha_rejected=true")
        print("force_push_used=false")


if __name__ == "__main__":
    main()