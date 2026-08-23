import json
import urllib.parse
import unittest

import phase2.workstream_d_live as live
from phase2.projection_github import GitHubIssueGateway
from phase2.reconciliation import ReconciliationService


CONTROL_REPOSITORY = "example/control"
ISSUE = 1


def comment(comment_id: int, body: str) -> dict[str, object]:
    return {
        "id": comment_id,
        "body": body,
        "html_url": (
            f"https://github.example/{CONTROL_REPOSITORY}/issues/{ISSUE}"
            f"#issuecomment-{comment_id}"
        ),
    }


class PageAPI:
    def __init__(self, pages: dict[int, list[dict[str, object]]]):
        self.pages = pages
        self.calls: list[tuple[int, int]] = []
        self.posts: list[dict[str, object]] = []
        self.next_id = 1000

    def get(self, path: str):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
        page_size = int(query["per_page"][0])
        page = int(query["page"][0])
        self.calls.append((page_size, page))
        return list(self.pages.get(page, []))

    def post(self, path: str, payload: dict[str, object]):
        self.posts.append(dict(payload))
        value = {
            "id": self.next_id,
            "html_url": (
                f"https://github.example/{CONTROL_REPOSITORY}/issues/{ISSUE}"
                f"#issuecomment-{self.next_id}"
            ),
        }
        self.next_id += 1
        return value


class EmptyResult:
    def fetchall(self):
        return []


class EmptyConnection:
    def execute(self, query: str, params=()):
        return EmptyResult()


class EmptyStore:
    def __init__(self, connection: EmptyConnection):
        self.connection = connection


class EmptySnapshot:
    def __init__(self):
        self.connection = EmptyConnection()

    def close(self) -> None:
        return None


class RecoveredEmptyCanonicalRepository:
    def bootstrap(self):
        return EmptySnapshot()

    def store(self, snapshot: EmptySnapshot):
        return EmptyStore(snapshot.connection)


class EmptyHistory:
    complete = True

    def accepted_revisions(self):
        return ()


class Scenario3RecoveredHistoryRegressionTests(unittest.TestCase):
    def test_complete_pagination_exposes_historical_requests_but_only_current_target_recovers(self):
        current = live.AttemptNamespace.parse(
            "wd-32636614281-1-current1",
            run_id=32636614281,
            run_attempt=1,
        )
        historical = live.AttemptNamespace.parse(
            "wd-32548072030-1-history1",
            run_id=32548072030,
            run_attempt=1,
        )

        historical_rid, historical_body, _ = live._protocol_request_contract(
            historical,
            3,
            3,
            request_type="ALLOCATE_NEXT",
        )
        target_rid, target_body, _ = live._protocol_request_contract(
            current,
            3,
            3,
            request_type="ALLOCATE_NEXT",
        )
        filler = json.dumps(
            {
                "attempt_namespace": current.value,
                "fixture_mode": live.FIXTURE_MODE,
                "operation": "pagination-fixture",
                "scenario_id": 3,
                "sequence": 1000,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

        api = PageAPI(
            {
                1: [comment(10, historical_body), comment(20, filler)],
                2: [comment(30, target_body)],
            }
        )
        gateway = GitHubIssueGateway(
            api,
            CONTROL_REPOSITORY,
            page_size=2,
        )

        recovered: list[int] = []
        expected_agent = f"agent://operator/8ft0-ai/session/{current.value}"

        def recover_unprocessed(durable_comment) -> None:
            if live._scenario_3_recovery_matches_current_attempt(
                durable_comment,
                expected_comment_id=30,
                expected_request_id=target_rid,
                expected_agent_id=expected_agent,
            ):
                recovered.append(durable_comment.comment_id)

        summary = ReconciliationService(
            RecoveredEmptyCanonicalRepository(),
            gateway,
            control_repository=CONTROL_REPOSITORY,
            issue_number=ISSUE,
            task_summary_lookup=lambda task_id: f"synthetic fixture {task_id}",
            canonical_history=EmptyHistory(),
            unprocessed_handler=recover_unprocessed,
            clock=lambda: live.NOW,
        ).reconcile(f"{current.value}:scenario-3-recovered-history-regression")

        self.assertNotEqual(historical_rid, target_rid)
        self.assertEqual(api.calls, [(2, 1), (2, 2)])
        self.assertEqual(summary.unprocessed_comments, [10, 30])
        self.assertIn(10, summary.unprocessed_comments)
        self.assertEqual(recovered, [30])
        self.assertEqual(summary.errors, [])
        self.assertEqual(len(api.posts), 1)


if __name__ == "__main__":
    unittest.main()
