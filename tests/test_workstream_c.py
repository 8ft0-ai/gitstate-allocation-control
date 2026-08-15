import hashlib
import json
import unittest

from phase2.allocation_engine import AllocationService, seed_local_fixture
from phase2.allocation_types import AllocationCommand, RequestContext, Task, stable_ulid
from phase2.canonical import LocalCanonicalRepository
from phase2.parser import parse_request
from phase2.projection import CanonicalProjection, ProjectionError, parse_projection, render_projection
from phase2.projection_github import GitHubIssueGateway
from phase2.reconciliation import (
    CanonicalHistoryRevision,
    DurableComment,
    OperatorRecovery,
    PostedComment,
    ReconciliationService,
)

NOW = "2026-08-15T00:00:00Z"
LATER = "2026-08-17T00:00:00Z"
AGENT = "agent://human/alice/session/a"
CONTROL_REPOSITORY = "example/control"
ISSUE = 1


def task(task_id="task-a"):
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


def request_body(name="grant", *, task_id="task-a", agent=AGENT, capabilities=None):
    payload = {
        "agent_id": agent,
        "protocol": "beads-allocation/v0.2",
        "request_id": stable_ulid(f"request:{name}"),
        "task_id": task_id,
        "type": "ALLOCATE_TASK",
    }
    if capabilities is not None:
        payload["capabilities"] = capabilities
    return "/beads-v0.2 " + json.dumps(payload, sort_keys=True, separators=(",", ":"))


def release_command(name, allocation_id, *, reason="operator evidence"):
    return AllocationCommand(
        request_id=stable_ulid(f"request:{name}"),
        request_type="RELEASE",
        payload_hash=hashlib.sha256(f"payload:{name}".encode()).hexdigest(),
        agent_id=AGENT,
        allocation_id=allocation_id,
        reason=reason,
    )


def rows(repository, query, params=()):
    connection = repository.inspect()
    try:
        return [dict(row) for row in connection.execute(query, params).fetchall()]
    finally:
        connection.close()


class FakeCanonicalHistory:
    """Fixture for durable accepted first-parent Git/Dolt history."""

    def __init__(self, revisions, *, complete=True):
        self._revisions = tuple(revisions)
        self._complete = complete

    @property
    def complete(self):
        return self._complete

    def accepted_revisions(self):
        return self._revisions


class FakeGateway:
    def __init__(self, comments=()):
        self.comments = list(comments)
        self.next_id = 1000
        self.fail_projection_posts = 0
        self.fail_invalidation_posts = 0
        self.invalidation_attempts = 0
        self.invalidated = []
        self.summaries = []

    def list_comments(self, issue_number):
        self.assert_issue(issue_number)
        return list(self.comments)

    def assert_issue(self, issue_number):
        if issue_number != ISSUE:
            raise AssertionError(issue_number)

    def _append(self, body):
        comment = DurableComment(
            self.next_id,
            body,
            f"https://github.example/{CONTROL_REPOSITORY}/issues/{ISSUE}#issuecomment-{self.next_id}",
        )
        self.next_id += 1
        self.comments.append(comment)
        return PostedComment(comment.comment_id, comment.html_url)

    def post_projection(self, issue_number, body):
        self.assert_issue(issue_number)
        if self.fail_projection_posts:
            self.fail_projection_posts -= 1
            raise RuntimeError("injected projection failure")
        if parse_projection(body) is None:
            raise AssertionError("projection was not machine-readable")
        return self._append(body)

    def invalidate_projection(self, issue_number, comment, reason_code):
        self.assert_issue(issue_number)
        self.invalidation_attempts += 1
        if self.fail_invalidation_posts:
            self.fail_invalidation_posts -= 1
            raise RuntimeError("injected invalidation failure")
        self.invalidated.append((comment.comment_id, reason_code))
        return self._append(
            json.dumps(
                {
                    "execution_may_begin": False,
                    "projection_comment_id": comment.comment_id,
                    "projection_url": comment.html_url,
                    "protocol": "beads-allocation/v0.2",
                    "reason_code": reason_code,
                    "type": "PROJECTION_INVALIDATED",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )

    def post_summary(self, issue_number, body):
        self.assert_issue(issue_number)
        self.summaries.append(json.loads(body))
        return self._append(body)


class Fixture:
    def __init__(self, *, clock=NOW):
        self.repository = LocalCanonicalRepository()
        seed_local_fixture(self.repository, [task()])
        self.before_request_identity = self.repository.identity
        self.body = request_body()
        parsed = parse_request(self.body.encode())
        self.command = AllocationCommand.from_parsed(parsed)
        self.context = RequestContext(CONTROL_REPOSITORY, ISSUE, 101, "8ft0-ai", AGENT)
        self.result = AllocationService(self.repository, clock=lambda: clock).process(
            self.command, self.context
        )
        assert self.result.status == "ALLOCATED"
        assert self.result.canonical_git_ref_sha and self.result.canonical_dolt_commit
        self.creation_identity = self.repository.identity
        self.history = FakeCanonicalHistory(
            [
                CanonicalHistoryRevision(self.before_request_identity, frozenset()),
                CanonicalHistoryRevision(
                    self.creation_identity, frozenset({self.command.request_id})
                ),
            ]
        )
        self.source = DurableComment(
            101,
            self.body,
            f"https://github.example/{CONTROL_REPOSITORY}/issues/{ISSUE}#issuecomment-101",
        )

    def reconciler(self, gateway, *, now=NOW, handler=None, history=None):
        return ReconciliationService(
            self.repository,
            gateway,
            control_repository=CONTROL_REPOSITORY,
            issue_number=ISSUE,
            task_summary_lookup=lambda task_id: f"Summary for {task_id}",
            canonical_history=history or self.history,
            unprocessed_handler=handler,
            clock=lambda: now,
            stale_after_seconds=24 * 60 * 60,
        )


class ProjectionTests(unittest.TestCase):
    def test_allocated_envelope_is_complete_and_exactly_anchored(self):
        projection = CanonicalProjection(
            request_id=stable_ulid("request:projection"),
            result_status="ALLOCATED",
            reason_code="ALLOCATED",
            agent_id=AGENT,
            source_repository=CONTROL_REPOSITORY,
            source_issue_number=ISSUE,
            source_comment_id=101,
            canonical_git_ref_sha="a" * 40,
            canonical_dolt_commit="dolt-1",
            allocation_id=stable_ulid("allocation:projection"),
            task_id="task-a",
            task_summary="Synthetic task",
            grant_timestamp=NOW,
        )
        payload = parse_projection(render_projection(projection))
        self.assertIsNotNone(payload)
        self.assertTrue(payload["execution_may_begin"])
        self.assertEqual(payload["canonical_git_ref"], "refs/dolt/data")
        self.assertEqual(payload["canonical_git_ref_sha"], "a" * 40)
        self.assertEqual(payload["canonical_dolt_commit"], "dolt-1")
        self.assertIn("release_instruction", payload)

    def test_allocated_projection_fails_closed_on_ownership_mismatch(self):
        projection = CanonicalProjection(
            request_id=stable_ulid("request:bad"),
            result_status="ALLOCATED",
            reason_code="ALLOCATED",
            agent_id=AGENT,
            source_repository=CONTROL_REPOSITORY,
            source_issue_number=ISSUE,
            source_comment_id=101,
            canonical_git_ref_sha="b" * 40,
            canonical_dolt_commit="dolt-2",
            allocation_id=stable_ulid("allocation:bad"),
            task_id="task-a",
            task_summary="Synthetic task",
            grant_timestamp=NOW,
            ownership_valid=False,
        )
        with self.assertRaisesRegex(ProjectionError, "CANONICAL_OWNERSHIP_MISMATCH"):
            render_projection(projection)


class ReconciliationTests(unittest.TestCase):
    def test_pending_anchor_is_reconstructed_from_complete_durable_history_after_service_loss(self):
        fixture = Fixture()
        before = rows(
            fixture.repository,
            "SELECT * FROM allocation_requests WHERE request_id = ?",
            (fixture.command.request_id,),
        )[0]
        self.assertEqual(before["anchor_status"], "PENDING")
        self.assertIsNone(before["canonical_git_ref_sha"])
        self.assertIsNone(before["canonical_dolt_commit"])

        # The fresh service receives no remembered result/anchor tuple. It scans
        # the complete accepted canonical history and chooses the first revision
        # in which the durable request exists.
        fresh_history = FakeCanonicalHistory(fixture.history.accepted_revisions())
        gateway = FakeGateway([fixture.source])
        fixture.reconciler(gateway, history=fresh_history).reconcile("run-anchor-repair")

        after = rows(
            fixture.repository,
            "SELECT * FROM allocation_requests WHERE request_id = ?",
            (fixture.command.request_id,),
        )[0]
        self.assertEqual(after["anchor_status"], "RECORDED")
        self.assertEqual(after["canonical_git_ref_sha"], fixture.creation_identity.git_ref_sha)
        self.assertEqual(after["canonical_dolt_commit"], fixture.creation_identity.dolt_commit)
        anchors = rows(
            fixture.repository,
            """SELECT canonical_git_ref_sha, canonical_dolt_commit FROM allocation_events
               WHERE request_id = ? AND event_type = 'ANCHOR_RECORDED'""",
            (fixture.command.request_id,),
        )
        self.assertEqual(len(anchors), 1)
        self.assertEqual(anchors[0]["canonical_git_ref_sha"], fixture.creation_identity.git_ref_sha)
        self.assertEqual(anchors[0]["canonical_dolt_commit"], fixture.creation_identity.dolt_commit)

    def test_incomplete_history_fails_closed_and_does_not_manufacture_anchor(self):
        fixture = Fixture()
        history = FakeCanonicalHistory(fixture.history.accepted_revisions(), complete=False)
        gateway = FakeGateway([fixture.source])
        summary = fixture.reconciler(gateway, history=history).reconcile("run-incomplete-history")
        self.assertTrue(any("CANONICAL_HISTORY_INCOMPLETE" in error for error in summary.errors))
        request = rows(
            fixture.repository,
            "SELECT * FROM allocation_requests WHERE request_id = ?",
            (fixture.command.request_id,),
        )[0]
        self.assertEqual(request["anchor_status"], "PENDING")
        self.assertFalse(any(parse_projection(comment.body) for comment in gateway.comments))

    def test_projection_failure_is_canonically_marked_and_fresh_reconciler_repairs_it(self):
        fixture = Fixture()
        gateway = FakeGateway([fixture.source])
        gateway.fail_projection_posts = 1

        first = fixture.reconciler(gateway).reconcile("run-1")
        request = rows(
            fixture.repository,
            "SELECT * FROM allocation_requests WHERE request_id = ?",
            (fixture.command.request_id,),
        )[0]
        self.assertEqual(request["projection_status"], "MISSING")
        self.assertEqual(request["reconciliation_status"], "REQUIRED")
        self.assertTrue(any("PROJECTION_POST_FAILED" in error for error in first.errors))
        self.assertFalse(any(parse_projection(comment.body) for comment in gateway.comments))

        # A new service instance has no prior runner/workspace state. It uses
        # only the durable canonical repository, accepted history and comments.
        second = fixture.reconciler(gateway).reconcile("run-2")
        request = rows(
            fixture.repository,
            "SELECT * FROM allocation_requests WHERE request_id = ?",
            (fixture.command.request_id,),
        )[0]
        self.assertEqual(request["projection_status"], "POSTED")
        self.assertEqual(request["reconciliation_status"], "REPAIRED")
        self.assertEqual(len(second.projections_repaired), 1)
        visible = [parse_projection(comment.body) for comment in gateway.comments]
        visible = [payload for payload in visible if payload]
        self.assertEqual(len(visible), 1)
        self.assertTrue(visible[0]["execution_may_begin"])
        self.assertEqual(visible[0]["canonical_git_ref_sha"], fixture.creation_identity.git_ref_sha)
        self.assertEqual(visible[0]["canonical_dolt_commit"], fixture.creation_identity.dolt_commit)

    def test_orphan_projection_is_invalidated_and_audited_without_request_or_ownership(self):
        fixture = Fixture()
        orphan = CanonicalProjection(
            request_id=stable_ulid("request:orphan"),
            result_status="REJECTED",
            reason_code="NO_ELIGIBLE_TASK",
            agent_id=AGENT,
            source_repository=CONTROL_REPOSITORY,
            source_issue_number=ISSUE,
            source_comment_id=909,
            canonical_git_ref_sha="c" * 40,
            canonical_dolt_commit="orphan-dolt",
        )
        orphan_comment = DurableComment(
            9090,
            render_projection(orphan),
            f"https://github.example/{CONTROL_REPOSITORY}/issues/{ISSUE}#issuecomment-9090",
        )
        gateway = FakeGateway([fixture.source, orphan_comment])
        summary = fixture.reconciler(gateway).reconcile("run-orphan")

        self.assertIn((9090, "ORPHAN_PROJECTION"), gateway.invalidated)
        self.assertIn(9090, summary.orphan_projections_invalidated)
        self.assertEqual(
            rows(
                fixture.repository,
                "SELECT COUNT(*) AS count FROM allocation_requests WHERE request_id = ?",
                (orphan.request_id,),
            )[0]["count"],
            0,
        )
        audit = rows(
            fixture.repository,
            """SELECT * FROM allocation_events WHERE event_type = 'AUDIT_FINDING'
               AND request_id IS NULL AND audit_subject_type = 'PROJECTION_COMMENT'
               AND reason_code = 'ORPHAN_PROJECTION'""",
        )
        self.assertEqual(len(audit), 1)
        subject = audit[0]["audit_subject_id"]
        self.assertIn(CONTROL_REPOSITORY, subject)
        self.assertIn(f"issue:{ISSUE}", subject)
        self.assertIn("projection_comment:9090", subject)
        invalidation = rows(
            fixture.repository,
            """SELECT * FROM allocation_events WHERE event_type = 'AUDIT_FINDING'
               AND request_id IS NULL AND audit_subject_type = 'PROJECTION_COMMENT'
               AND reason_code = 'ORPHAN_PROJECTION_INVALIDATED'""",
        )
        self.assertEqual(len(invalidation), 1)
        self.assertEqual(invalidation[0]["audit_subject_id"], subject)
        details = json.loads(invalidation[0]["details_json"])
        self.assertEqual(details["projection_comment_id"], 9090)
        active = rows(fixture.repository, "SELECT * FROM allocations WHERE state = 'ACTIVE'")
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["allocation_id"], fixture.result.allocation_id)

    def test_orphan_invalidation_retries_after_post_failure_even_when_audit_already_exists(self):
        fixture = Fixture()
        orphan = CanonicalProjection(
            request_id=stable_ulid("request:orphan-retry"),
            result_status="REJECTED",
            reason_code="NO_ELIGIBLE_TASK",
            agent_id=AGENT,
            source_repository=CONTROL_REPOSITORY,
            source_issue_number=ISSUE,
            source_comment_id=919,
            canonical_git_ref_sha="d" * 40,
            canonical_dolt_commit="orphan-retry-dolt",
        )
        orphan_comment = DurableComment(
            9190,
            render_projection(orphan),
            f"https://github.example/{CONTROL_REPOSITORY}/issues/{ISSUE}#issuecomment-9190",
        )
        gateway = FakeGateway([fixture.source, orphan_comment])
        gateway.fail_invalidation_posts = 1

        first = fixture.reconciler(gateway).reconcile("run-orphan-fail")
        self.assertTrue(any("INVALIDATION_POST_FAILED" in error for error in first.errors))
        self.assertEqual(gateway.invalidation_attempts, 1)
        initial = rows(
            fixture.repository,
            """SELECT * FROM allocation_events WHERE event_type = 'AUDIT_FINDING'
               AND request_id IS NULL AND reason_code = 'ORPHAN_PROJECTION'""",
        )
        self.assertEqual(len(initial), 1)
        completed = rows(
            fixture.repository,
            """SELECT * FROM allocation_events WHERE event_type = 'AUDIT_FINDING'
               AND request_id IS NULL AND reason_code = 'ORPHAN_PROJECTION_INVALIDATED'""",
        )
        self.assertEqual(completed, [])

        second = fixture.reconciler(gateway).reconcile("run-orphan-retry")
        self.assertIn(9190, second.orphan_projections_invalidated)
        self.assertEqual(gateway.invalidation_attempts, 2)
        completed = rows(
            fixture.repository,
            """SELECT * FROM allocation_events WHERE event_type = 'AUDIT_FINDING'
               AND request_id IS NULL AND reason_code = 'ORPHAN_PROJECTION_INVALIDATED'""",
        )
        self.assertEqual(len(completed), 1)

        fixture.reconciler(gateway).reconcile("run-orphan-idempotent")
        self.assertEqual(gateway.invalidation_attempts, 2)

    def test_allocation_beads_mismatch_fails_closed_without_repair_or_projection(self):
        fixture = Fixture()
        snapshot = fixture.repository.bootstrap()
        snapshot.connection.execute("UPDATE beads_tasks SET assignee = 'agent://human/mallory/session/x'")
        fixture.repository.publish(snapshot.identity.git_ref_sha, snapshot)
        snapshot.close()
        gateway = FakeGateway([fixture.source])

        summary = fixture.reconciler(gateway).reconcile("run-mismatch")
        self.assertIn(fixture.command.request_id, summary.ownership_mismatches)
        self.assertFalse(any(parse_projection(comment.body) for comment in gateway.comments))
        task_row = rows(fixture.repository, "SELECT * FROM beads_tasks WHERE task_id = 'task-a'")[0]
        self.assertEqual(task_row["assignee"], "agent://human/mallory/session/x")
        request = rows(
            fixture.repository,
            "SELECT * FROM allocation_requests WHERE request_id = ?",
            (fixture.command.request_id,),
        )[0]
        self.assertEqual(request["projection_status"], "INVALID")
        self.assertEqual(request["reconciliation_status"], "ESCALATED")

    def test_post_ingress_source_edit_is_audited_without_changing_owner(self):
        fixture = Fixture()
        gateway = FakeGateway([fixture.source])
        fixture.reconciler(gateway).reconcile("run-initial")
        edited = request_body(capabilities=["extra"])
        gateway.comments = [
            DurableComment(fixture.source.comment_id, edited, fixture.source.html_url),
            *[comment for comment in gateway.comments if comment.comment_id != fixture.source.comment_id],
        ]

        summary = fixture.reconciler(gateway).reconcile("run-edit")
        self.assertIn(f"{fixture.command.request_id}:SOURCE_COMMENT_EDITED", summary.source_mutations)
        allocation = rows(
            fixture.repository,
            "SELECT * FROM allocations WHERE allocation_id = ?",
            (fixture.result.allocation_id,),
        )[0]
        self.assertEqual(allocation["state"], "ACTIVE")
        self.assertEqual(allocation["agent_id"], AGENT)
        findings = rows(
            fixture.repository,
            """SELECT reason_code FROM allocation_events WHERE request_id = ?
               AND event_type = 'AUDIT_FINDING'""",
            (fixture.command.request_id,),
        )
        self.assertIn("SOURCE_COMMENT_EDITED", {row["reason_code"] for row in findings})

    def test_duplicate_and_payload_mismatch_delivery_do_not_advance_ownership(self):
        fixture = Fixture()
        duplicate = DurableComment(
            202,
            fixture.body,
            f"https://github.example/{CONTROL_REPOSITORY}/issues/{ISSUE}#issuecomment-202",
        )
        mismatch_body = request_body(capabilities=["different"])
        mismatch = DurableComment(
            203,
            mismatch_body,
            f"https://github.example/{CONTROL_REPOSITORY}/issues/{ISSUE}#issuecomment-203",
        )
        gateway = FakeGateway([fixture.source, duplicate, mismatch])
        fixture.reconciler(gateway).reconcile("run-duplicates")
        visible = [parse_projection(comment.body) for comment in gateway.comments]
        visible = [payload for payload in visible if payload]
        by_source = {payload["source_comment_id"]: payload for payload in visible}
        self.assertEqual(by_source[202]["result_status"], "ALLOCATED")
        self.assertEqual(by_source[203]["reason_code"], "REQUEST_ID_PAYLOAD_MISMATCH")
        self.assertFalse(by_source[203]["execution_may_begin"])
        self.assertEqual(
            rows(fixture.repository, "SELECT COUNT(*) AS count FROM allocations")[0]["count"], 1
        )
        self.assertEqual(
            rows(fixture.repository, "SELECT COUNT(*) AS count FROM allocation_requests")[0]["count"], 1
        )

    def test_stale_allocation_is_reported_but_not_expired(self):
        fixture = Fixture(clock=NOW)
        gateway = FakeGateway([fixture.source])
        summary = fixture.reconciler(gateway, now=LATER).reconcile("run-stale")
        self.assertIn(fixture.result.allocation_id, summary.stale_allocations)
        allocation = rows(
            fixture.repository,
            "SELECT * FROM allocations WHERE allocation_id = ?",
            (fixture.result.allocation_id,),
        )[0]
        self.assertEqual(allocation["state"], "ACTIVE")

    def test_unprocessed_comment_is_handed_back_to_trusted_intake_without_canonical_inference(self):
        fixture = Fixture()
        new_body = request_body("unprocessed", task_id="task-b")
        unprocessed = DurableComment(
            404,
            new_body,
            f"https://github.example/{CONTROL_REPOSITORY}/issues/{ISSUE}#issuecomment-404",
        )
        seen = []
        gateway = FakeGateway([fixture.source, unprocessed])
        summary = fixture.reconciler(
            gateway, handler=lambda comment: seen.append(comment.comment_id)
        ).reconcile("run-unprocessed")
        self.assertIn(404, summary.unprocessed_comments)
        self.assertEqual(seen, [404])
        self.assertEqual(
            rows(fixture.repository, "SELECT COUNT(*) AS count FROM allocation_requests")[0]["count"], 1
        )


class OperatorRecoveryTests(unittest.TestCase):
    def test_operator_release_requires_operator_authority_and_retains_reason_evidence(self):
        fixture = Fixture()
        command = release_command("operator-release", fixture.result.allocation_id)
        non_operator = RequestContext(CONTROL_REPOSITORY, ISSUE, 501, "someone", AGENT, False)
        denied = OperatorRecovery(fixture.repository, clock=lambda: LATER).release(command, non_operator)
        self.assertEqual(denied.reason_code, "RELEASE_NOT_AUTHORISED")
        self.assertEqual(
            rows(fixture.repository, "SELECT state FROM allocations")[0]["state"], "ACTIVE"
        )

        operator = RequestContext(
            CONTROL_REPOSITORY,
            ISSUE,
            502,
            "8ft0-ai",
            "agent://operator/owner/session/recovery",
            True,
        )
        allowed = OperatorRecovery(fixture.repository, clock=lambda: LATER).release(command, operator)
        self.assertEqual(allowed.status, "RELEASED")
        allocation = rows(fixture.repository, "SELECT * FROM allocations")[0]
        self.assertEqual(allocation["state"], "RELEASED")
        events = rows(
            fixture.repository,
            "SELECT details_json FROM allocation_events WHERE event_type = 'RELEASED'",
        )
        self.assertEqual(json.loads(events[0]["details_json"])["reason"], "operator evidence")


class FakeAPI:
    def __init__(self):
        self.get_paths = []
        self.posts = []

    def get(self, path):
        self.get_paths.append(path)
        page = int(path.rsplit("page=", 1)[1])
        count = 100 if page == 1 else 1
        start = 1 if page == 1 else 101
        return [
            {
                "id": start + index,
                "body": f"comment-{start + index}",
                "html_url": f"https://github.example/example/control/issues/1#issuecomment-{start + index}",
            }
            for index in range(count)
        ]

    def post(self, path, body):
        self.posts.append((path, body))
        return {"id": 9999, "html_url": "https://github.example/comment/9999"}


class GitHubGatewayTests(unittest.TestCase):
    def test_comment_inventory_is_completely_paginated_and_writes_stay_on_control_issue(self):
        api = FakeAPI()
        gateway = GitHubIssueGateway(api, CONTROL_REPOSITORY)
        comments = gateway.list_comments(ISSUE)
        self.assertEqual(len(comments), 101)
        self.assertEqual(len(api.get_paths), 2)
        self.assertIn("page=1", api.get_paths[0])
        self.assertIn("page=2", api.get_paths[1])

        posted = gateway.post_projection(ISSUE, "{}")
        self.assertEqual(posted.comment_id, 9999)
        self.assertEqual(api.posts[-1][0], "/repos/example/control/issues/1/comments")


if __name__ == "__main__":
    unittest.main()
