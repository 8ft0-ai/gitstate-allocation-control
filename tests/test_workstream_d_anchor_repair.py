import inspect
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

import phase2.workstream_d_anchor_repair as remediation
import phase2.workstream_d_live as live
import phase2.workstream_d_revocation as revocation
from phase2.allocation_engine import AllocationService, seed_local_fixture
from phase2.allocation_types import AllocationCommand, RequestContext, Task, stable_ulid
from phase2.canonical import LocalCanonicalRepository
from phase2.reconciliation import CanonicalHistoryRevision


NOW = "2026-08-17T00:00:00Z"
AGENT = "agent://operator/8ft0-ai/session/wd-anchor-test"


class RecordedContentionRepository:
    """Local canonical authority that records revisions and gates anchor CAS."""

    def __init__(self):
        self.inner = LocalCanonicalRepository()
        self.history = [
            CanonicalHistoryRevision(self.inner.identity, frozenset())
        ]
        self.anchor_barrier = None
        self._history_lock = threading.Lock()

    @property
    def identity(self):
        return self.inner.identity

    def bootstrap(self):
        return self.inner.bootstrap()

    def inspect(self):
        return self.inner.inspect()

    @staticmethod
    def _recorded_count(connection):
        row = connection.execute(
            "SELECT COUNT(*) AS n FROM allocation_requests "
            "WHERE anchor_status = 'RECORDED'"
        ).fetchone()
        return int(row["n"])

    def _is_anchor_candidate(self, snapshot):
        candidate = self._recorded_count(snapshot.connection)
        current = self.inner.inspect()
        try:
            accepted = self._recorded_count(current)
        finally:
            current.close()
        return candidate > accepted

    def _request_ids(self):
        connection = self.inner.inspect()
        try:
            return frozenset(
                str(row["request_id"])
                for row in connection.execute(
                    "SELECT request_id FROM allocation_requests ORDER BY request_id"
                ).fetchall()
            )
        finally:
            connection.close()

    def publish(self, expected_old_sha, snapshot):
        if self.anchor_barrier is not None and self._is_anchor_candidate(snapshot):
            self.anchor_barrier.wait(timeout=10)
        identity = self.inner.publish(expected_old_sha, snapshot)
        with self._history_lock:
            self.history.append(
                CanonicalHistoryRevision(identity, self._request_ids())
            )
        return identity


class RecordedHistory:
    def __init__(self, repository):
        self.repository = repository

    @property
    def complete(self):
        return True

    def accepted_revisions(self):
        with self.repository._history_lock:
            return tuple(self.repository.history)


def command(name, task_id):
    return AllocationCommand(
        request_id=stable_ulid(f"wd27:{name}"),
        request_type="ALLOCATE_TASK",
        payload_hash=("a" if name == "a" else "b") * 64,
        agent_id=AGENT,
        task_id=task_id,
    )


def context(index):
    return RequestContext(
        live.CONTROL_REPOSITORY,
        1,
        7000 + index,
        "fixture:gitstate-phase-2-allocator",
        AGENT,
    )


class WorkstreamDAnchorRepairTests(unittest.TestCase):
    def test_concurrent_anchor_cas_failure_preserves_ownership_and_reconciliation_repairs_original_identity(self):
        repository = RecordedContentionRepository()
        seed_local_fixture(
            repository,
            [
                Task("task-a", "task", "open", None, 1, NOW, True, False),
                Task("task-b", "task", "open", None, 1, NOW, True, False),
            ],
        )

        inputs = (
            (command("a", "task-a"), context(1)),
            (command("b", "task-b"), context(2)),
        )
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(
                    AllocationService(repository, clock=lambda: NOW).process,
                    item[0],
                    item[1],
                )
                for item in inputs
            ]
            results = tuple(future.result(timeout=30) for future in futures)

        self.assertEqual({result.status for result in results}, {"ALLOCATED"})
        self.assertTrue(all(result.ref_advanced for result in results))

        # Named fault injection: force both metadata-only anchor CAS candidates to
        # publish from the same base and give the loser no local stale retry.
        # This deterministically reproduces the recoverable condition exposed by
        # the live run without changing accepted production retry semantics.
        repository.anchor_barrier = threading.Barrier(2)

        def record(result):
            return AllocationService(
                repository, clock=lambda: NOW, max_stale_retries=0
            ).record_anchor(
                result.request_id,
                result.canonical_git_ref_sha,
                result.canonical_dolt_commit,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            anchor_results = tuple(
                future.result(timeout=30)
                for future in [pool.submit(record, result) for result in results]
            )
        repository.anchor_barrier = None

        failures = [
            (result, anchor)
            for result, anchor in zip(results, anchor_results)
            if anchor.reason_code == "STALE_ALLOCATOR_RETRY_EXHAUSTED"
        ]
        self.assertEqual(len(failures), 1)
        loser, _ = failures[0]

        before = repository.inspect()
        try:
            self.assertEqual(
                before.execute(
                    "SELECT COUNT(*) AS n FROM allocations WHERE state = 'ACTIVE'"
                ).fetchone()["n"],
                2,
            )
            self.assertEqual(
                before.execute(
                    "SELECT anchor_status FROM allocation_requests WHERE request_id = ?",
                    (loser.request_id,),
                ).fetchone()["anchor_status"],
                "PENDING",
            )
        finally:
            before.close()

        repaired = remediation.repair_pending_anchor(
            repository,
            loser.request_id,
            RecordedHistory(repository),
            clock=lambda: NOW,
        )
        self.assertEqual(repaired["anchor_status"], "RECORDED")
        self.assertEqual(
            repaired["canonical_git_ref_sha"], loser.canonical_git_ref_sha
        )
        self.assertEqual(
            repaired["canonical_dolt_commit"], loser.canonical_dolt_commit
        )

        after = repository.inspect()
        try:
            self.assertEqual(
                after.execute(
                    "SELECT COUNT(*) AS n FROM allocations WHERE state = 'ACTIVE'"
                ).fetchone()["n"],
                2,
            )
            self.assertEqual(
                after.execute(
                    "SELECT COUNT(*) AS n FROM active_task_allocations"
                ).fetchone()["n"],
                2,
            )
        finally:
            after.close()

    def test_live_backend_restores_default_retry_and_uses_reconciliation_before_projection(self):
        source = inspect.getsource(remediation.AnchorRepairLiveFixtureBackend._process)
        self.assertIn(
            "service = live.AllocationService(self.repository, clock=lambda: live.NOW)",
            source,
        )
        self.assertNotRegex(
            source, r"AllocationService\([^)]*max_stale_retries\s*=\s*1"
        )
        self.assertIn("self._repair_request_anchor", source)
        self.assertIn("_canonical_projection", source)
        self.assertLess(
            source.index("self._repair_request_anchor"),
            source.index("_canonical_projection"),
        )

    def test_durable_history_is_first_parent_credential_free_and_local_only_after_broker(self):
        source = inspect.getsource(remediation.DurableAcceptedHistory)
        self.assertIn('"rev-list"', source)
        self.assertIn('"--first-parent"', source)
        self.assertIn('"--reverse"', source)
        self.assertIn('"git+file://"', source)
        self.assertIn("_credential_free_git_env", source)
        self.assertIn("CANONICAL_HISTORY_REMOTE_WRITE_FORBIDDEN", source)
        self.assertNotIn("PHASE2_STATE_TOKEN", source)

    def test_anchor_repair_module_is_bound_into_executable_identity(self):
        original = live.LIVE_EXECUTABLE_PATHS
        try:
            live.LIVE_EXECUTABLE_PATHS = (".github/workflows/phase2-adversarial.yml",)
            remediation._bind_executable_identity()
            self.assertIn(
                remediation.REMEDIATION_EXECUTABLE_PATH,
                live.LIVE_EXECUTABLE_PATHS,
            )
        finally:
            live.LIVE_EXECUTABLE_PATHS = original

    def test_revocation_wrapper_delegates_through_anchor_repair_layer(self):
        source = inspect.getsource(revocation.execute_live_suite)
        self.assertIn("anchor_repair.execute_live_suite", source)
        self.assertNotIn("result = live.execute_live_suite", source)

    def test_anchor_repair_does_not_authorise_workstream_e_or_change_token_profiles(self):
        module_source = inspect.getsource(remediation)
        self.assertNotIn("scenario 15", module_source.lower())
        self.assertNotIn("workstream_e_authorised = True", module_source)
        self.assertNotIn("control_profile(", module_source)
        self.assertNotIn("state_profile(", module_source)


if __name__ == "__main__":
    unittest.main()
