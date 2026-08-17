import hashlib
import inspect
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from phase2 import workstream_d_live as live
from phase2 import workstream_d_revocation as remediation
from phase2.allocation_engine import AllocationService, seed_local_fixture
from phase2.allocation_types import AllocationCommand, AllocationResult, RequestContext, Task, stable_ulid
from phase2.canonical import LocalCanonicalRepository
from phase2.projection import ProjectionError
from phase2.reconciliation import CanonicalHistoryRevision, ReconciliationService

NOW = "2026-08-17T00:00:00Z"
AGENT = "agent://operator/8ft0-ai/session/anchor-regression"
CONTROL_REPOSITORY = "example/control"
ISSUE = 1


def task(task_id):
    return Task(
        task_id=task_id,
        task_type="task",
        status="open",
        assignee=None,
        priority=1,
        created_at="2026-01-01T00:00:00Z",
        ready=True,
        blocked=False,
    )


def command(name, task_id):
    return AllocationCommand(
        request_id=stable_ulid(f"request:{name}"),
        request_type="ALLOCATE_TASK",
        payload_hash=hashlib.sha256(f"payload:{name}".encode()).hexdigest(),
        agent_id=AGENT,
        task_id=task_id,
    )


def context(name):
    return RequestContext(
        CONTROL_REPOSITORY,
        ISSUE,
        int.from_bytes(hashlib.sha256(name.encode()).digest()[:4], "big") + 1,
        "8ft0-ai",
        AGENT,
    )


class FirstBootstrapBarrier:
    """Force the first two snapshots to share one canonical base."""

    def __init__(self, inner):
        self.inner = inner
        self.barrier = threading.Barrier(2)
        self.lock = threading.Lock()
        self.calls = 0

    def bootstrap(self):
        snapshot = self.inner.bootstrap()
        with self.lock:
            self.calls += 1
            wait = self.calls <= 2
        if wait:
            self.barrier.wait(timeout=10)
        return snapshot

    def publish(self, expected_old_sha, snapshot):
        return self.inner.publish(expected_old_sha, snapshot)


class FakeHistory:
    def __init__(self, revisions):
        self._revisions = tuple(revisions)

    @property
    def complete(self):
        return True

    def accepted_revisions(self):
        return self._revisions


class AnchorRecoveryRegressionTests(unittest.TestCase):
    def test_concurrent_process_anchor_contention_preserves_ownership_and_reconciles(self):
        repository = LocalCanonicalRepository()
        seed_local_fixture(repository, [task("task-a"), task("task-b")])
        base = repository.identity

        process_repository = FirstBootstrapBarrier(repository)
        anchor_repository = FirstBootstrapBarrier(repository)
        processing_complete = threading.Barrier(2)
        results = []
        anchors = []
        failures = []
        lock = threading.Lock()

        def worker(name, task_id):
            try:
                result = AllocationService(
                    process_repository,
                    clock=lambda: NOW,
                    max_stale_retries=3,
                ).process(command(name, task_id), context(name))
                processing_complete.wait(timeout=10)
                anchor = AllocationService(
                    anchor_repository,
                    clock=lambda: NOW,
                    max_stale_retries=0,
                ).record_anchor(
                    result.request_id,
                    result.canonical_git_ref_sha,
                    result.canonical_dolt_commit,
                )
                with lock:
                    results.append(result)
                    anchors.append((result, anchor))
            except Exception as exc:  # pragma: no cover - asserted below
                with lock:
                    failures.append(exc)

        threads = [
            threading.Thread(target=worker, args=("left", "task-a")),
            threading.Thread(target=worker, args=("right", "task-b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        self.assertEqual(failures, [])
        self.assertEqual(len(results), 2)
        self.assertEqual({result.reason_code for result in results}, {"ALLOCATED"})
        self.assertEqual({result.retry_count for result in results}, {0, 1})

        failed = [
            pair
            for pair in anchors
            if pair[1].reason_code == "STALE_ALLOCATOR_RETRY_EXHAUSTED"
        ]
        succeeded = [
            pair
            for pair in anchors
            if pair[1].reason_code != "STALE_ALLOCATOR_RETRY_EXHAUSTED"
        ]
        self.assertEqual(len(failed), 1)
        self.assertEqual(len(succeeded), 1)

        failed_result = failed[0][0]
        successful_result = succeeded[0][0]

        connection = repository.inspect()
        try:
            failed_request = dict(
                connection.execute(
                    "SELECT * FROM allocation_requests WHERE request_id = ?",
                    (failed_result.request_id,),
                ).fetchone()
            )
            failed_allocation = dict(
                connection.execute(
                    "SELECT * FROM allocations WHERE allocation_id = ?",
                    (failed_result.allocation_id,),
                ).fetchone()
            )
        finally:
            connection.close()

        self.assertEqual(failed_request["anchor_status"], "PENDING")
        self.assertEqual(failed_allocation["state"], "ACTIVE")

        ordered = sorted(results, key=lambda result: result.retry_count)
        first, second = ordered
        first_identity = type(base)(
            "refs/dolt/data",
            first.canonical_git_ref_sha,
            first.canonical_dolt_commit,
        )
        second_identity = type(base)(
            "refs/dolt/data",
            second.canonical_git_ref_sha,
            second.canonical_dolt_commit,
        )
        current = repository.identity
        history = FakeHistory(
            (
                CanonicalHistoryRevision(base, frozenset()),
                CanonicalHistoryRevision(
                    first_identity,
                    frozenset({first.request_id}),
                ),
                CanonicalHistoryRevision(
                    second_identity,
                    frozenset({first.request_id, second.request_id}),
                ),
                CanonicalHistoryRevision(
                    current,
                    frozenset({first.request_id, second.request_id}),
                ),
            )
        )
        reconciler = ReconciliationService(
            repository,
            object(),
            control_repository=CONTROL_REPOSITORY,
            issue_number=ISSUE,
            task_summary_lookup=lambda task_id: task_id,
            canonical_history=history,
            clock=lambda: NOW,
            max_stale_retries=3,
        )

        with self.assertRaisesRegex(ProjectionError, "CANONICAL_ANCHOR_PENDING"):
            reconciler._canonical_projection(failed_result.request_id)

        self.assertTrue(reconciler._repair_anchor(failed_result.request_id))

        connection = repository.inspect()
        try:
            repaired_request = dict(
                connection.execute(
                    "SELECT * FROM allocation_requests WHERE request_id = ?",
                    (failed_result.request_id,),
                ).fetchone()
            )
            repaired_allocation = dict(
                connection.execute(
                    "SELECT * FROM allocations WHERE allocation_id = ?",
                    (failed_result.allocation_id,),
                ).fetchone()
            )
        finally:
            connection.close()

        self.assertEqual(repaired_request["anchor_status"], "RECORDED")
        self.assertEqual(
            repaired_request["canonical_git_ref_sha"],
            failed_result.canonical_git_ref_sha,
        )
        self.assertEqual(
            repaired_request["canonical_dolt_commit"],
            failed_result.canonical_dolt_commit,
        )
        self.assertEqual(repaired_allocation, failed_allocation)

        projection = reconciler._canonical_projection(failed_result.request_id)
        self.assertEqual(
            projection.canonical_git_ref_sha,
            failed_result.canonical_git_ref_sha,
        )
        self.assertEqual(
            projection.canonical_dolt_commit,
            failed_result.canonical_dolt_commit,
        )

        # The other request remains anchored and ownership survives throughout.
        self.assertTrue(successful_result.allocation_id)

    def test_live_adapter_uses_accepted_retry_budget_and_recovery_path(self):
        source = inspect.getsource(remediation._process_with_anchor_recovery)
        self.assertIn("max_stale_retries=ANCHOR_MAX_STALE_RETRIES", source)
        self.assertNotIn("max_stale_retries=1", source)
        self.assertIn("_repair_pending_anchor", source)
        self.assertEqual(remediation.ANCHOR_MAX_STALE_RETRIES, 3)

    def test_live_adapter_invokes_reconciliation_only_after_anchor_failure(self):
        creation_git = "a" * 40
        creation_dolt = "dolt-creation"
        request_id = stable_ulid("anchor-live-adapter")
        repair_calls = []

        class FakeService:
            def process(self, command, request_context):
                return AllocationResult(
                    request_id,
                    "ALLOCATED",
                    "ALLOCATED",
                    stable_ulid("allocation-live-adapter"),
                    "task-a",
                    creation_git,
                    creation_dolt,
                    True,
                    0,
                )

            def record_anchor(self, *args):
                return AllocationResult(
                    request_id,
                    "REJECTED",
                    "STALE_ALLOCATOR_RETRY_EXHAUSTED",
                )

        class FakeReconciler:
            def _canonical_projection(self, *args, **kwargs):
                raise AssertionError("projection must not be reached in this test")

        backend = SimpleNamespace(
            namespace=SimpleNamespace(value="wd-test"),
            agent_id=AGENT,
            issue_number=1,
            repository=object(),
            reconciler=FakeReconciler(),
            gateway=object(),
            memory={},
            _post_body=lambda body: (123, "https://example.invalid/comment/123"),
            _request_row_identity=lambda rid: "row-digest",
            _request_row=lambda rid: {
                "anchor_status": "RECORDED",
                "canonical_git_ref_sha": creation_git,
                "canonical_dolt_commit": creation_dolt,
            },
        )

        def fake_repair(target, rid, git_sha, dolt_commit):
            repair_calls.append((target, rid, git_sha, dolt_commit))

        with (
            patch.object(live, "AllocationService", return_value=FakeService()),
            patch.object(
                remediation,
                "_repair_pending_anchor",
                side_effect=fake_repair,
            ),
        ):
            record = remediation._process_with_anchor_recovery(
                backend,
                2,
                1,
                request_type="ALLOCATE_TASK",
                task_id="task-a",
                request_id=request_id,
                project=False,
            )

        self.assertEqual(len(repair_calls), 1)
        self.assertEqual(repair_calls[0][1:], (request_id, creation_git, creation_dolt))
        self.assertEqual(record.accepted_ref, creation_git)
        self.assertEqual(record.dolt_commit, creation_dolt)


if __name__ == "__main__":
    unittest.main()
