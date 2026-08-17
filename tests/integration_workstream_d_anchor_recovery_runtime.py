"""Credential-free real-runtime regression for Workstream D anchor recovery.

CI supplies the same cryptographically pinned Beads, Dolt and PyMySQL runtime as
Workstream B.  Everything runs against temporary local file:// Git/Dolt remotes;
no GitHub credential or live canonical state is accepted.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace

from integration_workstream_b_runtime import (
    ManagedDoltConnection,
    execute_ddl,
    initialise_pinned_beads_remote,
    run,
)

from phase2 import workstream_d_live as live
from phase2 import workstream_d_revocation as remediation
from phase2.allocation_engine import AllocationService
from phase2.allocation_schema import dolt_schema
from phase2.allocation_types import AllocationCommand, RequestContext, Task, stable_ulid
from phase2.dolt_repository import DoltCanonicalRepository

NOW = "2026-08-17T00:00:00Z"
AGENT = "agent://operator/8ft0-ai/session/anchor-runtime"


def main() -> None:
    bd_bin = os.environ.get("BD_BIN")
    dolt_bin = os.environ.get("DOLT_BIN")
    if not bd_bin or not dolt_bin:
        raise SystemExit("BD_BIN and DOLT_BIN are required")

    with tempfile.TemporaryDirectory(prefix="workstream-d-anchor-runtime-") as directory:
        root = Path(directory)
        home = root / "home"
        home.mkdir()
        os.environ["HOME"] = str(home)
        os.environ["GIT_CONFIG_NOSYSTEM"] = "1"

        remote, _ = initialise_pinned_beads_remote(root, bd_bin)
        repository = DoltCanonicalRepository(
            "git+file://" + str(remote),
            lambda database: ManagedDoltConnection(database, dolt_bin),
            dolt_bin=dolt_bin,
            workspace_root=root,
        )

        snapshot = repository.bootstrap()
        try:
            execute_ddl(snapshot.connection, dolt_schema())
            repository.publish(snapshot.identity.git_ref_sha, snapshot)
        finally:
            snapshot.close()

        snapshot = repository.bootstrap()
        try:
            store = repository.store(snapshot)
            store.begin()
            store.seed_task(
                Task(
                    "task-anchor-runtime",
                    "task",
                    "open",
                    None,
                    1,
                    NOW,
                    True,
                    False,
                )
            )
            store.commit()
            repository.publish(snapshot.identity.git_ref_sha, snapshot)
        finally:
            snapshot.close()

        request_id = stable_ulid("anchor-runtime-request")
        command = AllocationCommand(
            request_id=request_id,
            request_type="ALLOCATE_TASK",
            payload_hash=hashlib.sha256(b"anchor-runtime-request").hexdigest(),
            agent_id=AGENT,
            task_id="task-anchor-runtime",
        )
        context = RequestContext(
            "runtime/control",
            1,
            4001,
            "8ft0-ai",
            AGENT,
        )
        result = AllocationService(
            repository,
            clock=lambda: NOW,
            max_stale_retries=3,
        ).process(command, context)
        if (
            result.status != "ALLOCATED"
            or not result.ref_advanced
            or not result.canonical_git_ref_sha
            or not result.canonical_dolt_commit
            or not result.allocation_id
        ):
            raise AssertionError(f"real runtime allocation failed: {result}")

        snapshot = repository.bootstrap()
        try:
            store = repository.store(snapshot)
            request_before = dict(store.get_request(request_id))
            allocation_before = dict(
                store.connection.execute(
                    "SELECT * FROM allocations WHERE allocation_id = %s",
                    (result.allocation_id,),
                ).fetchone()
            )
        finally:
            snapshot.close()
        if request_before["anchor_status"] != "PENDING":
            raise AssertionError("fixture request was unexpectedly pre-anchored")
        if allocation_before["state"] != "ACTIVE":
            raise AssertionError("fixture ownership was not canonical before anchor repair")

        def read_only_remote_factory(target_root: Path):
            mirror = target_root / "state-read-only.git"
            run(["git", "clone", "--mirror", str(remote), str(mirror)], cwd=target_root)
            current = run(
                ["git", "--git-dir", str(mirror), "rev-parse", "refs/dolt/data"],
                cwd=target_root,
            )
            live._set_tree_read_only(mirror, read_only=True)
            return mirror, current

        backend = SimpleNamespace(
            repository=repository,
            gateway=object(),
            issue_number=1,
            read_only_remote_factory=read_only_remote_factory,
        )

        identity = remediation._verified_creation_identity(
            backend,
            request_id,
            result.canonical_git_ref_sha,
            result.canonical_dolt_commit,
        )
        if (
            identity.git_ref_sha != result.canonical_git_ref_sha
            or identity.dolt_commit != result.canonical_dolt_commit
        ):
            raise AssertionError("history verifier did not return the creation identity")

        reconciler = remediation._TargetedAnchorReconciler(
            backend,
            request_id,
            result.canonical_git_ref_sha,
            result.canonical_dolt_commit,
        )
        if not reconciler._repair_anchor(request_id):
            raise AssertionError("accepted reconciliation path did not repair the anchor")

        snapshot = repository.bootstrap()
        try:
            store = repository.store(snapshot)
            request_after = dict(store.get_request(request_id))
            allocation_after = dict(
                store.connection.execute(
                    "SELECT * FROM allocations WHERE allocation_id = %s",
                    (result.allocation_id,),
                ).fetchone()
            )
        finally:
            snapshot.close()

        if request_after["anchor_status"] != "RECORDED":
            raise AssertionError("anchor repair did not become canonical")
        if request_after["canonical_git_ref_sha"] != result.canonical_git_ref_sha:
            raise AssertionError("anchor repair changed the allocation-creation Git identity")
        if request_after["canonical_dolt_commit"] != result.canonical_dolt_commit:
            raise AssertionError("anchor repair changed the allocation-creation Dolt identity")
        if allocation_after != allocation_before:
            raise AssertionError("metadata-only anchor repair changed canonical ownership")


if __name__ == "__main__":
    main()
