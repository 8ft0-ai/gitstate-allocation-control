from __future__ import annotations

import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from phase2.allocation_engine import AllocationService, seed_local_fixture
from phase2.allocation_types import AllocationCommand, RequestContext, Task, stable_ulid
from phase2.canonical import LocalCanonicalRepository, StaleCanonicalBase
from phase2.parser import parse_request
from phase2.reconciliation import PostedComment, ReconciliationError, ReconciliationService

NOW = "2026-08-16T00:00:00Z"
CONTROL_REPOSITORY = "example/control"
ISSUE = 1
AGENT = "agent://operator/8ft0-ai/session/reconciliation-bootstrap-stale"


class EmptyHistory:
    complete = True

    def accepted_revisions(self):
        return ()


class NoopGateway:
    def list_comments(self, issue_number):
        raise AssertionError("gateway should not be used by focused metadata tests")

    def post_projection(self, issue_number, body):
        raise AssertionError("gateway should not be used by focused metadata tests")

    def invalidate_projection(self, issue_number, comment, reason_code):
        raise AssertionError("gateway should not be used by focused metadata tests")

    def post_summary(self, issue_number, body):
        raise AssertionError("gateway should not be used by focused metadata tests")


class BootstrapStaleRepository:
    """Inject bootstrap-stage canonical staleness before delegating to local state."""

    def __init__(self, delegate: LocalCanonicalRepository, failures: int):
        self.delegate = delegate
        self.remaining_failures = failures
        self.bootstrap_calls = 0
        self._lock = threading.Lock()

    def bootstrap(self):
        with self._lock:
            self.bootstrap_calls += 1
            if self.remaining_failures:
                self.remaining_failures -= 1
                raise StaleCanonicalBase("STALE_EXPECTED_OLD_SHA")
        return self.delegate.bootstrap()

    def publish(self, expected_old_sha, snapshot):
        return self.delegate.publish(expected_old_sha, snapshot)


def task(task_id: str, created_second: int) -> Task:
    return Task(
        task_id=task_id,
        task_type="task",
        status="open",
        assignee=None,
        priority=1,
        created_at=f"2026-08-16T00:00:{created_second:02d}Z",
        ready=True,
        blocked=False,
    )


def request_body(name: str, task_id: str) -> str:
    payload = {
        "agent_id": AGENT,
        "protocol": "beads-allocation/v0.2",
        "request_id": stable_ulid(f"issue-31:{name}"),
        "task_id": task_id,
        "type": "ALLOCATE_TASK",
    }
    return "/beads-v0.2 " + json.dumps(payload, sort_keys=True, separators=(",", ":"))


def allocated_fixture():
    repository = LocalCanonicalRepository()
    seed_local_fixture(repository, [task("task-a", 1), task("task-b", 2)])
    results = []
    for index, task_id in enumerate(("task-a", "task-b"), 1):
        parsed = parse_request(request_body(f"request-{index}", task_id).encode("utf-8"))
        command = AllocationCommand.from_parsed(parsed)
        context = RequestContext(
            CONTROL_REPOSITORY,
            ISSUE,
            100 + index,
            "8ft0-ai",
            AGENT,
        )
        service = AllocationService(repository, clock=lambda: NOW)
        result = service.process(command, context)
        if result.status != "ALLOCATED" or not result.canonical_git_ref_sha or not result.canonical_dolt_commit:
            raise AssertionError(f"fixture allocation failed: {result}")
        anchor = service.record_anchor(
            command.request_id,
            result.canonical_git_ref_sha,
            result.canonical_dolt_commit,
        )
        if anchor.reason_code in {"CANONICAL_PUSH_FAILED", "STALE_ALLOCATOR_RETRY_EXHAUSTED"}:
            raise AssertionError(f"fixture anchor failed: {anchor}")
        results.append((command.request_id, result))
    return repository, tuple(results)


def reconciler(repository, *, max_stale_retries=3):
    return ReconciliationService(
        repository,
        NoopGateway(),
        control_repository=CONTROL_REPOSITORY,
        issue_number=ISSUE,
        task_summary_lookup=lambda task_id: task_id,
        canonical_history=EmptyHistory(),
        clock=lambda: NOW,
        max_stale_retries=max_stale_retries,
    )


def request_state(repository: LocalCanonicalRepository, request_id: str):
    connection = repository.inspect()
    try:
        row = connection.execute(
            "SELECT * FROM allocation_requests WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        events = connection.execute(
            """SELECT event_type, details_json FROM allocation_events
               WHERE request_id = ? AND event_type IN ('PROJECTION_POSTED', 'PROJECTION_REPAIRED')""",
            (request_id,),
        ).fetchall()
        return dict(row), tuple(dict(event) for event in events)
    finally:
        connection.close()


class ReconciliationBootstrapStaleRetryTests(unittest.TestCase):
    def test_bootstrap_stale_once_retries_from_fresh_snapshot_and_records_one_event(self):
        base, ((request_id, result), _) = allocated_fixture()
        before, before_events = request_state(base, request_id)
        self.assertEqual(before_events, ())
        wrapped = BootstrapStaleRepository(base, failures=1)
        posted = PostedComment(9001, "https://github.example/comment/9001")

        repaired = reconciler(wrapped)._record_projection_posted(request_id, posted)

        self.assertFalse(repaired)
        self.assertEqual(wrapped.bootstrap_calls, 2)
        after, events = request_state(base, request_id)
        self.assertEqual(after["projection_status"], "POSTED")
        self.assertEqual(after["canonical_git_ref_sha"], result.canonical_git_ref_sha)
        self.assertEqual(after["canonical_dolt_commit"], result.canonical_dolt_commit)
        matching = [
            event
            for event in events
            if json.loads(event["details_json"])["comment_id"] == posted.comment_id
        ]
        self.assertEqual(len(matching), 1)

    def test_bootstrap_stale_exhaustion_raises_existing_reason_and_mutates_nothing(self):
        base, ((request_id, _), _) = allocated_fixture()
        before, before_events = request_state(base, request_id)
        before_publish_count = base.publish_count
        wrapped = BootstrapStaleRepository(base, failures=2)

        with self.assertRaisesRegex(ReconciliationError, "STALE_ALLOCATOR_RETRY_EXHAUSTED"):
            reconciler(wrapped, max_stale_retries=1)._record_projection_posted(
                request_id,
                PostedComment(9002, "https://github.example/comment/9002"),
            )

        self.assertEqual(wrapped.bootstrap_calls, 2)
        self.assertEqual(base.publish_count, before_publish_count)
        after, after_events = request_state(base, request_id)
        self.assertEqual(after, before)
        self.assertEqual(after_events, before_events)

    def test_close_timed_projection_metadata_writes_absorb_bootstrap_and_publish_stale(self):
        base, fixtures = allocated_fixture()
        wrapped = BootstrapStaleRepository(base, failures=1)
        barrier = threading.Barrier(2)

        def record(index: int):
            request_id, _ = fixtures[index]
            posted = PostedComment(
                9100 + index,
                f"https://github.example/comment/{9100 + index}",
            )
            barrier.wait(timeout=5)
            return reconciler(wrapped)._record_projection_posted(request_id, posted)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = tuple(pool.map(record, (0, 1)))

        self.assertEqual(results, (False, False))
        for index, (request_id, allocation_result) in enumerate(fixtures):
            row, events = request_state(base, request_id)
            self.assertEqual(row["projection_status"], "POSTED")
            self.assertEqual(row["canonical_git_ref_sha"], allocation_result.canonical_git_ref_sha)
            self.assertEqual(row["canonical_dolt_commit"], allocation_result.canonical_dolt_commit)
            matching = [
                event
                for event in events
                if json.loads(event["details_json"])["comment_id"] == 9100 + index
            ]
            self.assertEqual(len(matching), 1)


if __name__ == "__main__":
    unittest.main()
