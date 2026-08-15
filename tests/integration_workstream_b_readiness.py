"""Real pinned-Beads readiness regression for Workstream B.

Runs only against an isolated local Git-backed Dolt remote. It proves the
allocator consumes Beads' maintained ``issues.is_blocked`` value rather than
reimplementing only a subset of dependency semantics.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

from phase2.allocation_engine import AllocationService
from phase2.allocation_schema import dolt_schema
from phase2.allocation_types import AllocationCommand, RequestContext, Task, stable_ulid
from phase2.dolt_repository import DoltCanonicalRepository
from tests.integration_workstream_b_runtime import (
    AGENT,
    NOW,
    ManagedDoltConnection,
    execute_ddl,
    fetch_one,
    initialise_pinned_beads_remote,
    run,
)


def main() -> None:
    bd_bin = os.environ.get("BD_BIN")
    dolt_bin = os.environ.get("DOLT_BIN")
    if not bd_bin or not dolt_bin:
        raise SystemExit("BD_BIN and DOLT_BIN are required")

    with tempfile.TemporaryDirectory(prefix="workstream-b-readiness-") as directory:
        root = Path(directory)
        home = root / "home"
        home.mkdir()
        os.environ["HOME"] = str(home)
        os.environ["GIT_CONFIG_NOSYSTEM"] = "1"

        if "1.1.0" not in run([bd_bin, "--version"], cwd=root):
            raise AssertionError("unexpected Beads version")
        if "2.1.4" not in run([dolt_bin, "version"], cwd=root):
            raise AssertionError("unexpected Dolt version")

        remote, _ = initialise_pinned_beads_remote(root, bd_bin)
        repository = DoltCanonicalRepository(
            "git+file://" + str(remote),
            lambda database: ManagedDoltConnection(database, dolt_bin),
            dolt_bin=dolt_bin,
            workspace_root=root,
        )

        snapshot = repository.bootstrap()
        try:
            columns = fetch_one(
                snapshot.connection,
                "SELECT COUNT(*) FROM information_schema.columns "
                "WHERE table_schema = DATABASE() AND table_name = 'issues' "
                "AND column_name IN ('id','status','assignee','issue_type','is_blocked')",
            )
            if int(columns[0]) != 5:
                raise AssertionError("pinned Beads canonical readiness column is absent")
            execute_ddl(snapshot.connection, dolt_schema())
            repository.publish(snapshot.identity.git_ref_sha, snapshot)
        finally:
            snapshot.close()

        snapshot = repository.bootstrap()
        try:
            store = repository.store(snapshot)
            store.begin()
            # This task sorts first by priority but Beads canonically marks it
            # blocked. It must never be selected by ALLOCATE_NEXT.
            store.seed_task(
                Task(
                    "task-runtime-blocked",
                    "task",
                    "open",
                    None,
                    0,
                    NOW,
                    False,
                    True,
                    ("capability:linux",),
                )
            )
            store.seed_task(
                Task(
                    "task-runtime-ready",
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
        command = AllocationCommand(
            request_id=stable_ulid("runtime:canonical-readiness"),
            request_type="ALLOCATE_NEXT",
            payload_hash=hashlib.sha256(b"runtime:canonical-readiness").hexdigest(),
            agent_id=AGENT,
            capabilities=("linux",),
            task_types=("task",),
        )
        context = RequestContext("runtime/control", 1, 2001, "user:runtime", AGENT)
        result = service.process(command, context)
        if result.status != "ALLOCATED" or result.task_id != "task-runtime-ready":
            raise AssertionError(f"canonical Beads readiness was not respected: {result}")

        snapshot = repository.bootstrap()
        try:
            blocked = fetch_one(
                snapshot.connection,
                "SELECT status, assignee, is_blocked FROM issues WHERE id = %s",
                ("task-runtime-blocked",),
            )
            if blocked != ("open", "", 1) and blocked != ("open", None, 1):
                raise AssertionError(f"blocked task was mutated: {blocked}")
            count = fetch_one(
                snapshot.connection,
                "SELECT COUNT(*) FROM active_task_allocations WHERE task_id = %s",
                ("task-runtime-blocked",),
            )
            if int(count[0]) != 0:
                raise AssertionError("blocked task acquired canonical ownership")
        finally:
            snapshot.close()

        print("WORKSTREAM_B_CANONICAL_READINESS_PASSED")
        print("beads_is_blocked_consumed=true")
        print("higher_priority_blocked_task_skipped=true")


if __name__ == "__main__":
    main()
