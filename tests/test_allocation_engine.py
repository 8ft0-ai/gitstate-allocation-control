import hashlib
import threading
import unittest

from phase2.allocation_engine import AllocationService, seed_local_fixture
from phase2.allocation_store import AllocationStore, UnsupportedMutation
from phase2.allocation_types import (
    AllocationCommand,
    RequestContext,
    Task,
    stable_ulid,
)
from phase2.canonical import LocalCanonicalRepository, StaleCanonicalBase
from phase2.canonical_mutation import process_authorised_request
from phase2.parser import parse_request

NOW = "2026-08-15T00:00:00Z"
AGENT_A = "agent://human/alice/session/a"
AGENT_B = "agent://human/bob/session/b"


def command(kind, name, agent=AGENT_A, **changes):
    values = {
        "request_id": stable_ulid(f"request:{name}"),
        "request_type": kind,
        "payload_hash": hashlib.sha256(f"payload:{name}".encode()).hexdigest(),
        "agent_id": agent,
        "capabilities": (),
        "task_types": (),
        "max_priority": None,
        "task_id": None,
        "allocation_id": None,
        "reason": None,
    }
    values.update(changes)
    return AllocationCommand(**values)


def context(name, agent=AGENT_A, actor=None, operator=False):
    return RequestContext(
        "example/control",
        1,
        int.from_bytes(hashlib.sha256(name.encode()).digest()[:4], "big") + 1,
        actor or f"user:{agent}",
        agent,
        operator,
    )


def task(task_id, priority=1, created="2026-01-01T00:00:00Z", **changes):
    values = {
        "task_id": task_id,
        "task_type": "task",
        "status": "open",
        "assignee": None,
        "priority": priority,
        "created_at": created,
        "ready": True,
        "blocked": False,
        "labels": (),
    }
    values.update(changes)
    return Task(**values)


def service(repository, retries=3):
    return AllocationService(repository, clock=lambda: NOW, max_stale_retries=retries)


def rows(repository, table):
    connection = repository.inspect()
    try:
        return [dict(row) for row in connection.execute(f"SELECT * FROM {table}")]
    finally:
        connection.close()


class FirstBootstrapBarrier:
    def __init__(self, inner, parties=2):
        self.inner = inner
        self.barrier = threading.Barrier(parties)
        self.lock = threading.Lock()
        self.calls = 0

    def bootstrap(self):
        snapshot = self.inner.bootstrap()
        with self.lock:
            self.calls += 1
            wait = self.calls <= self.barrier.parties
        if wait:
            self.barrier.wait(timeout=10)
        return snapshot

    def publish(self, expected_old_sha, snapshot):
        return self.inner.publish(expected_old_sha, snapshot)


class AlwaysStale:
    def __init__(self, inner):
        self.inner = inner
        self.attempts = 0

    def bootstrap(self):
        return self.inner.bootstrap()

    def publish(self, expected_old_sha, snapshot):
        self.attempts += 1
        raise StaleCanonicalBase("STALE_EXPECTED_OLD_SHA")


class AllocationEngineTests(unittest.TestCase):
    def repository(self, *tasks):
        repository = LocalCanonicalRepository()
        seed_local_fixture(repository, tasks)
        return repository

    def test_priority_creation_time_and_bytewise_task_id_ordering(self):
        repository = self.repository(
            task("task-z", priority=2, created="2026-01-01T00:00:00Z"),
            task("task-b", priority=0, created="2026-01-02T00:00:00Z"),
            task("task-c", priority=0, created="2026-01-01T00:00:00Z"),
            task("task-a", priority=0, created="2026-01-01T00:00:00Z"),
        )
        result = service(repository).process(command("ALLOCATE_NEXT", "ordered"), context("ordered"))
        self.assertEqual(result.task_id, "task-a")
        self.assertEqual(result.reason_code, "ALLOCATED")

    def test_eligibility_filters_readiness_type_priority_and_capability(self):
        repository = self.repository(
            task("blocked", priority=0, blocked=True),
            task("unready", priority=0, ready=False),
            task("too-low", priority=3),
            task("needs-cap", priority=1, labels=("capability:gpu",)),
            task("eligible", priority=2, labels=("capability:linux",)),
        )
        result = service(repository).process(
            command(
                "ALLOCATE_NEXT",
                "filtered",
                capabilities=("linux",),
                task_types=("task",),
                max_priority=2,
            ),
            context("filtered"),
        )
        self.assertEqual(result.task_id, "eligible")

    def test_nominated_request_uses_ordinary_eligibility(self):
        repository = self.repository(task("task-1", labels=("capability:gpu",)))
        result = service(repository).process(
            command("ALLOCATE_TASK", "nominated", task_id="task-1"), context("nominated")
        )
        self.assertEqual(result.reason_code, "CAPABILITY_MISMATCH")

    def test_authorised_command_path_connects_strict_parser_to_engine(self):
        repository = self.repository(task("task-1"))
        request_id = stable_ulid("request:command-path")
        parsed = parse_request(
            (
                '/beads-v0.2 {"agent_id":"agent://human/alice/session/a",'
                '"capabilities":[],"protocol":"beads-allocation/v0.2",'
                f'"request_id":"{request_id}","task_types":["task"],'
                '"type":"ALLOCATE_NEXT"}'
            ).encode()
        )
        result = process_authorised_request(repository, parsed, context("command-path"))
        self.assertEqual((result.reason_code, result.task_id), ("ALLOCATED", "task-1"))

    def test_same_base_and_request_produce_same_result(self):
        left = self.repository(task("task-2"), task("task-1"))
        right = self.repository(task("task-2"), task("task-1"))
        request = command("ALLOCATE_NEXT", "deterministic")
        result_left = service(left).process(request, context("deterministic"))
        result_right = service(right).process(request, context("deterministic"))
        self.assertEqual(
            (result_left.task_id, result_left.allocation_id, result_left.reason_code),
            (result_right.task_id, result_right.allocation_id, result_right.reason_code),
        )

    def test_duplicate_and_payload_mismatch_do_not_advance_ref(self):
        repository = self.repository(task("task-1"))
        request = command("ALLOCATE_NEXT", "idempotent")
        first = service(repository).process(request, context("idempotent"))
        count = repository.publish_count
        duplicate = service(repository).process(request, context("duplicate-source"))
        self.assertEqual(duplicate.allocation_id, first.allocation_id)
        self.assertFalse(duplicate.ref_advanced)
        self.assertEqual(repository.publish_count, count)
        mismatch = service(repository).process(
            AllocationCommand(**{**request.__dict__, "payload_hash": "f" * 64}),
            context("mismatch-source"),
        )
        self.assertEqual(mismatch.reason_code, "REQUEST_ID_PAYLOAD_MISMATCH")
        self.assertFalse(mismatch.ref_advanced)
        self.assertEqual(repository.publish_count, count)

    def test_changed_source_comment_id_binding_is_immutable_without_ref_advance(self):
        repository = self.repository(task("task-1"))
        first_context = context("source-binding")
        first = service(repository).process(
            command("ALLOCATE_NEXT", "source-original"), first_context
        )
        count = repository.publish_count
        changed = service(repository).process(
            command("ALLOCATE_NEXT", "source-edited"),
            first_context,
        )
        self.assertEqual(changed.reason_code, "SOURCE_COMMENT_EDITED")
        self.assertFalse(changed.ref_advanced)
        self.assertEqual(repository.publish_count, count)
        self.assertEqual(rows(repository, "allocations")[0]["allocation_id"], first.allocation_id)

    def test_allocation_uniqueness_and_beads_mirror_are_atomic(self):
        repository = self.repository(task("task-1"))
        result = service(repository).process(command("ALLOCATE_NEXT", "atomic"), context("atomic"))
        allocation = rows(repository, "allocations")[0]
        active = rows(repository, "active_task_allocations")[0]
        mirrored = rows(repository, "beads_tasks")[0]
        self.assertEqual(allocation["allocation_id"], result.allocation_id)
        self.assertEqual(active, {"task_id": "task-1", "allocation_id": result.allocation_id})
        self.assertEqual((mirrored["status"], mirrored["assignee"]), ("assigned", AGENT_A))

    def test_mismatch_fails_closed_and_records_audit_finding(self):
        repository = self.repository(task("task-1"))
        grant = service(repository).process(command("ALLOCATE_NEXT", "first"), context("first"))
        snapshot = repository.bootstrap()
        snapshot.connection.execute(
            "UPDATE beads_tasks SET status = 'open', assignee = NULL WHERE task_id = 'task-1'"
        )
        repository.publish(snapshot.identity.git_ref_sha, snapshot)
        snapshot.close()
        result = service(repository).process(command("ALLOCATE_NEXT", "mismatch"), context("mismatch"))
        self.assertEqual(result.reason_code, "CANONICAL_OWNERSHIP_MISMATCH")
        self.assertEqual(rows(repository, "allocations")[0]["allocation_id"], grant.allocation_id)
        findings = [row for row in rows(repository, "allocation_events") if row["event_type"] == "AUDIT_FINDING"]
        self.assertEqual(len(findings), 1)

    def test_two_concurrent_next_requests_select_distinct_tasks(self):
        inner = self.repository(task("task-a"), task("task-b"))
        repository = FirstBootstrapBarrier(inner)
        results = []
        failures = []

        def run(name, agent):
            try:
                results.append(
                    service(repository).process(
                        command("ALLOCATE_NEXT", name, agent=agent), context(name, agent=agent)
                    )
                )
            except Exception as exc:  # pragma: no cover - asserted below
                failures.append(exc)

        threads = [
            threading.Thread(target=run, args=("concurrent-a", AGENT_A)),
            threading.Thread(target=run, args=("concurrent-b", AGENT_B)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
        self.assertEqual(failures, [])
        self.assertEqual({result.task_id for result in results}, {"task-a", "task-b"})
        self.assertTrue(any(result.retry_count == 1 for result in results))

    def test_two_nominated_requests_contend_for_one_task(self):
        inner = self.repository(task("task-a"))
        repository = FirstBootstrapBarrier(inner)
        results = []

        def run(name, agent):
            results.append(
                service(repository).process(
                    command("ALLOCATE_TASK", name, agent=agent, task_id="task-a"),
                    context(name, agent=agent),
                )
            )

        threads = [
            threading.Thread(target=run, args=("nom-a", AGENT_A)),
            threading.Thread(target=run, args=("nom-b", AGENT_B)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
        self.assertEqual({result.reason_code for result in results}, {"ALLOCATED", "TASK_ALREADY_ALLOCATED"})
        self.assertEqual(len(rows(inner, "active_task_allocations")), 1)

    def test_bounded_stale_retry_exhaustion(self):
        inner = self.repository(task("task-1"))
        repository = AlwaysStale(inner)
        result = service(repository, retries=2).process(
            command("ALLOCATE_NEXT", "always-stale"), context("always-stale")
        )
        self.assertEqual(result.reason_code, "STALE_ALLOCATOR_RETRY_EXHAUSTED")
        self.assertEqual(repository.attempts, 3)
        self.assertEqual(rows(inner, "allocation_requests"), [])

    def test_push_failure_creates_no_canonical_allocation(self):
        repository = self.repository(task("task-1"))
        repository.fail_next_pushes()
        result = service(repository).process(command("ALLOCATE_NEXT", "push-fail"), context("push-fail"))
        self.assertEqual(result.reason_code, "CANONICAL_PUSH_FAILED")
        self.assertEqual(rows(repository, "allocation_requests"), [])
        self.assertEqual(rows(repository, "allocations"), [])
        self.assertEqual(rows(repository, "beads_tasks")[0]["status"], "open")

    def test_authorised_release_preserves_history_and_allows_new_allocation(self):
        repository = self.repository(task("task-1"))
        first = service(repository).process(command("ALLOCATE_NEXT", "grant-1"), context("grant-1"))
        release = service(repository).process(
            command(
                "RELEASE",
                "release-1",
                allocation_id=first.allocation_id,
                reason="handoff",
            ),
            context("release-1"),
        )
        second = service(repository).process(command("ALLOCATE_NEXT", "grant-2"), context("grant-2"))
        self.assertEqual(release.reason_code, "RELEASED")
        self.assertNotEqual(first.allocation_id, second.allocation_id)
        allocations = rows(repository, "allocations")
        self.assertEqual({row["state"] for row in allocations}, {"ACTIVE", "RELEASED"})
        events = rows(repository, "allocation_events")
        self.assertEqual(sum(row["event_type"] == "ALLOCATED" for row in events), 2)
        self.assertEqual(sum(row["event_type"] == "RELEASED" for row in events), 1)

    def test_unauthorised_release_is_rejected_without_changing_ownership(self):
        repository = self.repository(task("task-1"))
        first = service(repository).process(command("ALLOCATE_NEXT", "owned"), context("owned"))
        result = service(repository).process(
            command(
                "RELEASE",
                "bad-release",
                agent=AGENT_B,
                allocation_id=first.allocation_id,
                reason="not mine",
            ),
            context("bad-release", agent=AGENT_B),
        )
        self.assertEqual(result.reason_code, "RELEASE_NOT_AUTHORISED")
        self.assertEqual(rows(repository, "allocations")[0]["state"], "ACTIVE")

    def test_anchor_recording_is_metadata_only_and_idempotent(self):
        repository = self.repository(task("task-1"))
        result = service(repository).process(command("ALLOCATE_NEXT", "anchor"), context("anchor"))
        before_tasks = rows(repository, "beads_tasks")
        before_allocations = rows(repository, "allocations")
        count = repository.publish_count
        anchored = service(repository).record_anchor(
            result.request_id, result.canonical_git_ref_sha, result.canonical_dolt_commit
        )
        self.assertTrue(anchored.ref_advanced)
        self.assertEqual(rows(repository, "beads_tasks"), before_tasks)
        self.assertEqual(rows(repository, "allocations"), before_allocations)
        events = rows(repository, "allocation_events")
        self.assertEqual(sum(row["event_type"] == "ANCHOR_RECORDED" for row in events), 1)
        duplicate = service(repository).record_anchor(
            result.request_id, result.canonical_git_ref_sha, result.canonical_dolt_commit
        )
        self.assertFalse(duplicate.ref_advanced)
        self.assertEqual(repository.publish_count, count + 1)

    def test_reconstruction_exposes_request_allocation_ownership_and_release(self):
        repository = self.repository(task("task-1"))
        first = service(repository).process(command("ALLOCATE_NEXT", "reconstruct-grant"), context("rg"))
        service(repository).process(
            command(
                "RELEASE",
                "reconstruct-release",
                allocation_id=first.allocation_id,
                reason="complete",
            ),
            context("rr"),
        )
        snapshot = repository.bootstrap()
        report = AllocationStore(snapshot.connection).reconstruct()
        snapshot.close()
        self.assertEqual(len(report["requests"]), 2)
        self.assertEqual(report["allocations"][0]["allocation_id"], first.allocation_id)
        self.assertEqual(report["allocations"][0]["state"], "RELEASED")
        self.assertEqual(report["active_ownership"], [])
        self.assertIn("ALLOCATED", {event["event_type"] for event in report["events"]})
        self.assertIn("RELEASED", {event["event_type"] for event in report["events"]})

    def test_unsupported_readiness_mutations_are_frozen(self):
        repository = self.repository(task("task-1"))
        snapshot = repository.bootstrap()
        store = AllocationStore(snapshot.connection)
        for mutation in (
            "CREATE_TASK",
            "CLOSE_TASK",
            "CHANGE_STATUS",
            "CHANGE_DEPENDENCY",
            "CHANGE_PRIORITY",
            "CHANGE_TYPE",
            "CHANGE_BLOCKER",
            "CHANGE_READINESS_METADATA",
        ):
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                UnsupportedMutation, "UNSUPPORTED_READINESS_MUTATION"
            ):
                service(repository).unsupported_mutation(store, mutation)
        snapshot.close()


if __name__ == "__main__":
    unittest.main()
