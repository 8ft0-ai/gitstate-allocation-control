import subprocess
import threading
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

import phase2.workstream_d_live as live
from phase2.adversarial import (
    CONTROL_REPOSITORY_ID,
    STATE_REPOSITORY_ID,
    scenario_by_id,
)
from phase2.allocation_store import AllocationStore
from phase2.allocation_types import Task, stable_ulid
from phase2.canonical import (
    CanonicalIdentity,
    LocalCanonicalRepository,
    StaleCanonicalBase,
)
from phase2.credentials import control_profile, state_profile
from phase2.inventory import InventoryAttestation
from phase2.projection import parse_projection
from phase2.reconciliation import PostedComment


TRUSTED_SHA = "a" * 40
PROTOCOL_SHA = live.PROTOCOL_AUTHORITY
RUN_ID = 32204037283


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


class _InMemoryControlAPI:
    """Credential-free durable issue-comment fixture used by full scenario 1."""

    def __init__(self):
        self._lock = threading.Lock()
        self._next_comment_id = 1000
        self.comments = []

    def post(self, path, body):
        if not path.endswith("/comments") or not isinstance(body, dict):
            raise AssertionError(f"unexpected control API post: {path}")
        comment_body = body.get("body")
        if not isinstance(comment_body, str):
            raise AssertionError("comment body must be text")
        with self._lock:
            self._next_comment_id += 1
            comment_id = self._next_comment_id
            item = {
                "id": comment_id,
                "body": comment_body,
                "html_url": f"https://example.invalid/comments/{comment_id}",
            }
            self.comments.append(item)
            return dict(item)

    def get(self, path):
        if "/comments?" not in path:
            raise AssertionError(f"unexpected control API get: {path}")
        page = 1
        for field in path.split("?", 1)[1].split("&"):
            if field.startswith("page="):
                page = int(field.split("=", 1)[1])
        with self._lock:
            if page != 1:
                return []
            return [dict(item) for item in self.comments]

    def request(self, method, path, body=None):
        raise AssertionError(f"unexpected control API request: {method} {path}")

    def by_url(self):
        with self._lock:
            return {str(item["html_url"]): dict(item) for item in self.comments}


class _PostAllocationStaleRepository:
    """Real local canonical state plus deterministic post-anchor read stales.

    Allocation, anchor and projection-metadata publications all execute through
    the real LocalCanonicalRepository. Each close-timed worker receives one
    post-anchor read plan only after its allocation and anchor have both
    published successfully:

    * one worker fails the immediate request-row evidence bootstrap once;
    * the other reads the request row successfully, then fails the canonical
      projection bootstrap once.

    No mutation call is replayed by this wrapper.
    """

    def __init__(self, inner):
        self.inner = inner
        self._thread_state = threading.local()
        self._plan_lock = threading.Lock()
        self._publish_lock = threading.Lock()
        self._plans = [
            ("request_row", ["stale"]),
            ("canonical_projection", ["ok", "stale"]),
        ]
        self.stale_surfaces = []
        self.allocation_creation_refs = []

    @property
    def identity(self):
        return self.inner.identity

    @staticmethod
    def store(snapshot):
        return AllocationStore(snapshot.connection)

    def _state(self):
        if not threading.current_thread().name.startswith("wd-close"):
            return None
        state = getattr(self._thread_state, "value", None)
        if state is not None:
            return state
        with self._plan_lock:
            if not self._plans:
                raise AssertionError("unexpected additional close-timed worker")
            label, steps = self._plans.pop(0)
        state = {
            "label": label,
            "steps": list(steps),
            "successful_mutation_publishes": 0,
            "post_anchor_reads_armed": False,
        }
        self._thread_state.value = state
        return state

    def bootstrap(self):
        state = self._state()
        if state is not None and state["post_anchor_reads_armed"] and state["steps"]:
            step = state["steps"].pop(0)
            if step == "stale":
                with self._plan_lock:
                    self.stale_surfaces.append(str(state["label"]))
                raise StaleCanonicalBase("STALE_EXPECTED_OLD_SHA")
            if step != "ok":
                raise AssertionError(f"unknown read plan step: {step}")
        return self.inner.bootstrap()

    def publish(self, expected_old_sha, snapshot):
        # Keep the successful-publication witness ordered at the same boundary
        # as the canonical CAS. Failed stale publications are not counted.
        with self._publish_lock:
            accepted = self.inner.publish(expected_old_sha, snapshot)
            state = self._state()
            if state is not None:
                state["successful_mutation_publishes"] += 1
                if state["successful_mutation_publishes"] == 1:
                    self.allocation_creation_refs.append(accepted.git_ref_sha)
                if state["successful_mutation_publishes"] == 2:
                    state["post_anchor_reads_armed"] = True
            return accepted


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

    def test_close_timed_scenario1_reaches_complete_evidence_with_real_mutations(self):
        inner = LocalCanonicalRepository()
        repository = _PostAllocationStaleRepository(inner)
        control_api = _InMemoryControlAPI()
        namespace = live.AttemptNamespace.parse(
            f"wd-{RUN_ID}-1-0123456789abcdef", run_id=RUN_ID, run_attempt=1
        )
        trusted_sha = subprocess.check_output(
            ("git", "rev-parse", "HEAD"), text=True
        ).strip()

        def read_only_remote(root: Path):
            # LocalCanonicalRepository identities are canonical-state digests,
            # not Git commit objects. Scenario 1's real Git ancestry helper has
            # separate functional coverage; this regression isolates only that
            # unrelated transport adapter while retaining the actual creation
            # publication order recorded at the canonical CAS boundary.
            mirror = root / "state-read-only.git"
            mirror.mkdir()
            return mirror, repository.identity.git_ref_sha

        backend = live.LiveFixtureBackend(
            repository,
            control_api,
            1,
            trusted_sha,
            PROTOCOL_SHA,
            _token_scopes(),
            _inventory(),
            namespace,
            read_only_remote,
        )

        def creation_order(_mirror, _current_sha, refs):
            self.assertEqual(set(refs), set(repository.allocation_creation_refs))
            self.assertEqual(len(repository.allocation_creation_refs), 2)
            return tuple(repository.allocation_creation_refs)

        with patch.object(
            live, "_canonical_creation_ref_order", side_effect=creation_order
        ):
            evidence = backend.execute(scenario_by_id(1), namespace)

        # The complete scenario contract, not only two helper calls, must pass.
        evidence.validate()
        self.assertIs(backend.executed_records[1], evidence)
        self.assertEqual(
            sorted(repository.stale_surfaces),
            ["canonical_projection", "request_row"],
        )

        connection = inner.inspect()
        try:
            requests = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM allocation_requests ORDER BY request_id"
                ).fetchall()
            ]
            allocations = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM allocations ORDER BY allocation_id"
                ).fetchall()
            ]
            ownership = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM active_task_allocations ORDER BY task_id"
                ).fetchall()
            ]
            events = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM allocation_events ORDER BY event_id"
                ).fetchall()
            ]
        finally:
            connection.close()

        self.assertEqual(len(requests), 2)
        self.assertEqual({row["request_id"] for row in requests}, set(evidence.request_ids))
        self.assertEqual({row["status"] for row in requests}, {"ALLOCATED"})
        self.assertEqual({row["anchor_status"] for row in requests}, {"RECORDED"})
        self.assertEqual({row["projection_status"] for row in requests}, {"POSTED"})

        self.assertEqual(len(allocations), 2)
        self.assertEqual({row["state"] for row in allocations}, {"ACTIVE"})
        self.assertEqual(len({row["allocation_id"] for row in allocations}), 2)
        self.assertEqual(len({row["task_id"] for row in allocations}), 2)
        self.assertEqual(len(ownership), 2)
        self.assertEqual(
            {row["allocation_id"] for row in ownership},
            {row["allocation_id"] for row in allocations},
        )

        requests_by_id = {row["request_id"]: row for row in requests}
        projections_by_url = control_api.by_url()
        for terminal in evidence.terminal_requests:
            row = requests_by_id[terminal.request_id]
            self.assertEqual(row["canonical_git_ref_sha"], terminal.accepted_ref_sha)
            self.assertEqual(row["canonical_dolt_commit"], terminal.dolt_commit)

            request_events = [
                event for event in events if event["request_id"] == terminal.request_id
            ]
            self.assertEqual(
                sum(event["event_type"] == "ALLOCATED" for event in request_events), 1
            )
            self.assertEqual(
                sum(event["event_type"] == "REQUEST_TERMINAL" for event in request_events),
                1,
            )
            self.assertEqual(
                sum(event["event_type"] == "ANCHOR_RECORDED" for event in request_events),
                1,
            )
            projection_events = [
                event
                for event in request_events
                if event["event_type"] in {"PROJECTION_POSTED", "PROJECTION_REPAIRED"}
            ]
            self.assertEqual(len(projection_events), 1)
            self.assertEqual(projection_events[0]["event_type"], "PROJECTION_POSTED")
            self.assertEqual(
                projection_events[0]["canonical_git_ref_sha"],
                terminal.accepted_ref_sha,
            )
            self.assertEqual(
                projection_events[0]["canonical_dolt_commit"],
                terminal.dolt_commit,
            )

            projected = parse_projection(
                str(projections_by_url[terminal.projection_url]["body"])
            )
            self.assertIsNotNone(projected)
            self.assertEqual(
                projected["canonical_git_ref_sha"], terminal.accepted_ref_sha
            )
            self.assertEqual(
                projected["canonical_dolt_commit"], terminal.dolt_commit
            )

        # One seed publication + two allocation creations + two anchor records
        # + two real projection-metadata publications. Read retry adds none.
        self.assertEqual(inner.publish_count, 7)
        self.assertEqual(
            set(repository.allocation_creation_refs),
            set(evidence.accepted_ref_shas),
        )


if __name__ == "__main__":
    unittest.main()
