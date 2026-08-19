import unittest
from dataclasses import dataclass
from unittest.mock import patch

import phase2.workstream_d_live as live
from phase2.adversarial import CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID
from phase2.allocation_types import AllocationResult, Task, stable_ulid
from phase2.canonical import CanonicalIdentity, StaleCanonicalBase
from phase2.credentials import control_profile, state_profile
from phase2.inventory import InventoryAttestation
from phase2.projection import parse_projection
from phase2.reconciliation import PostedComment, ReconciliationService


TRUSTED_SHA = "a" * 40
PROTOCOL_SHA = live.PROTOCOL_AUTHORITY
RUN_ID = 32204037283


class _History:
    complete = True

    def accepted_revisions(self):
        return ()


@dataclass
class _Cursor:
    row: object

    def fetchone(self):
        return self.row

    def fetchall(self):
        return [] if self.row is None else [self.row]


class _Connection:
    def __init__(self, store):
        self.store = store

    def execute(self, sql, params=()):
        if "FROM allocations WHERE allocation_id" in sql:
            allocation_id = str(params[0])
            request_id = allocation_id.removeprefix("allocation-")
            return _Cursor(
                {
                    "allocation_id": allocation_id,
                    "task_id": f"task-{request_id}",
                    "state": "ACTIVE",
                    "granted_at": "2026-08-16T00:00:00Z",
                }
            )
        raise AssertionError(f"unexpected read query: {sql}")


class _ReadStore:
    def __init__(self, identities, agent_id):
        self.identities = identities
        self.agent_id = agent_id
        self.connection = _Connection(self)
        self.mutation_calls = 0

    def get_request(self, request_id):
        git_sha, dolt_commit, source_comment_id = self.identities[request_id]
        return {
            "request_id": request_id,
            "anchor_status": "RECORDED",
            "canonical_git_ref_sha": git_sha,
            "canonical_dolt_commit": dolt_commit,
            "status": "ALLOCATED",
            "result_code": "ALLOCATED",
            "allocation_id": f"allocation-{request_id}",
            "release_allocation_id": None,
            "agent_id": self.agent_id,
            "source_repository": live.CONTROL_REPOSITORY,
            "source_issue_number": 1,
            "source_comment_id": source_comment_id,
        }

    def task(self, task_id):
        return Task(
            task_id,
            "task",
            "allocated",
            self.agent_id,
            1,
            "2026-08-16T00:00:00Z",
            True,
            False,
        )

    def assert_ownership_invariant(self, task):
        return None


class _Snapshot:
    def __init__(self, store, identity):
        self.store = store
        self.identity = identity
        self.closed = False

    def close(self):
        self.closed = True


class _ScheduledReadRepository:
    def __init__(self, store, schedule):
        self.store_value = store
        self.schedule = list(schedule)
        self.bootstrap_calls = 0
        self.snapshots = []

    def bootstrap(self):
        self.bootstrap_calls += 1
        outcome = self.schedule.pop(0) if self.schedule else "ok"
        if outcome == "stale":
            raise StaleCanonicalBase("STALE_EXPECTED_OLD_SHA")
        snapshot = _Snapshot(
            self.store_value,
            CanonicalIdentity("refs/dolt/data", "f" * 40, "fresh-read-dolt"),
        )
        self.snapshots.append(snapshot)
        return snapshot

    def store(self, snapshot):
        return snapshot.store


class _AlwaysStaleRepository:
    def __init__(self):
        self.bootstrap_calls = 0

    def bootstrap(self):
        self.bootstrap_calls += 1
        raise StaleCanonicalBase("STALE_EXPECTED_OLD_SHA")

    def store(self, snapshot):
        raise AssertionError("store must not be opened after stale bootstrap")


class _ProjectionGateway:
    def __init__(self):
        self.posts = []

    def post_projection(self, issue_number, body):
        self.posts.append((issue_number, body))
        index = len(self.posts)
        return PostedComment(index, f"https://example.invalid/projection/{index}")

    def list_comments(self, issue_number):
        return ()

    def invalidate_projection(self, issue_number, comment, reason_code):
        raise AssertionError("not used")

    def post_summary(self, issue_number, body):
        raise AssertionError("not used")


class _UnusedControlAPI:
    pass


def _inventory():
    attestation = InventoryAttestation(
        123,
        456,
        "selected",
        (CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID),
        live.datetime.now(live.timezone.utc),
    )
    return live.ValidatedInventory(attestation, "inventory-digest")


def _token_scopes():
    return (
        live._scope_evidence(control_profile(CONTROL_REPOSITORY_ID)),
        live._scope_evidence(state_profile(STATE_REPOSITORY_ID)),
    )


def _backend(repository):
    namespace = live.AttemptNamespace.parse(
        f"wd-{RUN_ID}-1-0123456789abcdef", run_id=RUN_ID, run_attempt=1
    )
    backend = live.LiveFixtureBackend(
        repository,
        _UnusedControlAPI(),
        1,
        TRUSTED_SHA,
        PROTOCOL_SHA,
        _token_scopes(),
        _inventory(),
        namespace,
    )
    gateway = _ProjectionGateway()
    backend.gateway = gateway
    backend.reconciler.gateway = gateway
    return backend, gateway


class _AcceptedAllocationService:
    identities = {}

    def __init__(self, repository, *, clock=None, max_stale_retries=3, **kwargs):
        self.repository = repository

    def process(self, command, context):
        git_sha, dolt_commit, _ = self.identities[command.request_id]
        return AllocationResult(
            command.request_id,
            "ALLOCATED",
            "ALLOCATED",
            allocation_id=f"allocation-{command.request_id}",
            task_id=f"task-{command.request_id}",
            canonical_git_ref_sha=git_sha,
            canonical_dolt_commit=dolt_commit,
            ref_advanced=True,
        )

    def record_anchor(self, request_id, git_sha, dolt_commit):
        expected_git, expected_dolt, _ = self.identities[request_id]
        if (git_sha, dolt_commit) != (expected_git, expected_dolt):
            raise AssertionError("creation identity changed before anchor recording")
        return AllocationResult(request_id, "ALLOCATED", "ALLOCATED")


class PostAllocationReadStaleRetryTests(unittest.TestCase):
    def test_request_row_read_retries_one_bootstrap_stale_from_fresh_snapshot(self):
        request_id = stable_ulid("issue-32-request-row")
        identities = {request_id: ("1" * 40, "dolt-request-row", 101)}
        store = _ReadStore(identities, "agent://operator/test")
        repository = _ScheduledReadRepository(store, ("stale", "ok"))
        backend, _ = _backend(repository)

        row = backend._request_row(request_id)

        self.assertIsNotNone(row)
        self.assertEqual(row["canonical_git_ref_sha"], "1" * 40)
        self.assertEqual(repository.bootstrap_calls, 2)
        self.assertEqual(len(repository.snapshots), 1)
        self.assertTrue(repository.snapshots[0].closed)
        self.assertEqual(store.mutation_calls, 0)

    def test_request_row_read_exhausts_bounded_stale_without_opening_store(self):
        repository = _AlwaysStaleRepository()
        backend, _ = _backend(repository)

        with self.assertRaisesRegex(
            live.LiveExecutorError, "STALE_ALLOCATOR_RETRY_EXHAUSTED"
        ):
            backend._request_row(stable_ulid("issue-32-request-row-exhaustion"))

        self.assertEqual(
            repository.bootstrap_calls,
            live.POST_ALLOCATION_READ_MAX_STALE_RETRIES + 1,
        )

    def test_projection_read_retries_one_bootstrap_stale_and_preserves_creation_identity(self):
        request_id = stable_ulid("issue-32-canonical-projection")
        identities = {request_id: ("2" * 40, "dolt-projection", 102)}
        store = _ReadStore(identities, "agent://operator/test")
        repository = _ScheduledReadRepository(store, ("stale", "ok"))
        backend, _ = _backend(repository)

        projection = backend._canonical_projection(request_id)

        self.assertEqual(projection.canonical_git_ref_sha, "2" * 40)
        self.assertEqual(projection.canonical_dolt_commit, "dolt-projection")
        self.assertEqual(repository.bootstrap_calls, 2)
        self.assertTrue(repository.snapshots[0].closed)
        self.assertEqual(store.mutation_calls, 0)

    def test_projection_read_exhausts_bounded_stale_without_opening_store(self):
        repository = _AlwaysStaleRepository()
        backend, _ = _backend(repository)

        with self.assertRaisesRegex(
            live.LiveExecutorError, "STALE_ALLOCATOR_RETRY_EXHAUSTED"
        ):
            backend._canonical_projection(
                stable_ulid("issue-32-projection-exhaustion")
            )

        self.assertEqual(
            repository.bootstrap_calls,
            live.POST_ALLOCATION_READ_MAX_STALE_RETRIES + 1,
        )

    def test_close_timed_scenario1_post_allocation_reads_absorb_each_proven_stale_surface(self):
        first_id = stable_ulid("issue-32-close-first")
        second_id = stable_ulid("issue-32-close-second")
        identities = {
            first_id: ("3" * 40, "dolt-first", 201),
            second_id: ("4" * 40, "dolt-second", 202),
        }
        _AcceptedAllocationService.identities = identities

        first_store = _ReadStore(identities, "agent://operator/test")
        second_store = _ReadStore(identities, "agent://operator/test")
        # Worker one races while hashing its accepted request row. Worker two
        # races one step later while reading the canonical projection. Both
        # successful retries observe a newer snapshot identity, while the
        # accepted creation identities remain those stored on the request rows.
        first_repository = _ScheduledReadRepository(
            first_store, ("stale", "ok", "ok")
        )
        second_repository = _ScheduledReadRepository(
            second_store, ("ok", "stale", "ok")
        )
        first_backend, first_gateway = _backend(first_repository)
        second_backend, second_gateway = _backend(second_repository)

        with patch.object(live, "AllocationService", _AcceptedAllocationService), patch.object(
            ReconciliationService, "_record_projection_posted", return_value=False
        ) as metadata_record:
            records, spread = live._run_close_timed_calls(
                (
                    lambda: first_backend._process(
                        1,
                        1,
                        request_type="ALLOCATE_NEXT",
                        request_id=first_id,
                        source_override=(201, "https://example.invalid/source/201"),
                    ),
                    lambda: second_backend._process(
                        1,
                        2,
                        request_type="ALLOCATE_NEXT",
                        request_id=second_id,
                        source_override=(202, "https://example.invalid/source/202"),
                    ),
                )
            )

        by_request = {record.request_id: record for record in records}
        self.assertEqual(set(by_request), {first_id, second_id})
        for request_id, (git_sha, dolt_commit, _) in identities.items():
            record = by_request[request_id]
            self.assertEqual(record.accepted_ref, git_sha)
            self.assertEqual(record.dolt_commit, dolt_commit)
            self.assertTrue(record.canonical_row)
            self.assertTrue(record.projection_url)

        projected = []
        for gateway in (first_gateway, second_gateway):
            self.assertEqual(len(gateway.posts), 1)
            payload = parse_projection(gateway.posts[0][1])
            self.assertIsNotNone(payload)
            projected.append(payload)
        projected_by_request = {str(item["request_id"]): item for item in projected}
        for request_id, (git_sha, dolt_commit, _) in identities.items():
            self.assertEqual(
                projected_by_request[request_id]["canonical_git_ref_sha"], git_sha
            )
            self.assertEqual(
                projected_by_request[request_id]["canonical_dolt_commit"], dolt_commit
            )

        self.assertEqual(first_repository.bootstrap_calls, 3)
        self.assertEqual(second_repository.bootstrap_calls, 3)
        self.assertEqual(metadata_record.call_count, 2)
        self.assertEqual(first_store.mutation_calls, 0)
        self.assertEqual(second_store.mutation_calls, 0)
        self.assertLessEqual(spread, live.CLOSE_TIMED_MAX_SECONDS)


if __name__ == "__main__":
    unittest.main()
