import io
import inspect
import json
import urllib.error
import urllib.parse
import unittest
from contextlib import redirect_stdout
from email.message import Message
from unittest.mock import patch

import phase2.github_api as github_api
import phase2.workstream_d_live as live
from phase2.projection_github import GitHubIssueGateway
from phase2.reconciliation import DurableComment


CONTROL_REPOSITORY = "example/control"
ISSUE = 1


def comment(comment_id: int, body: str | None = None) -> dict[str, object]:
    return {
        "id": comment_id,
        "body": body or f"comment-{comment_id}",
        "html_url": (
            f"https://github.example/{CONTROL_REPOSITORY}/issues/{ISSUE}"
            f"#issuecomment-{comment_id}"
        ),
    }


class PageAPI:
    def __init__(self, pages: dict[int, list[dict[str, object]]]):
        self.pages = pages
        self.calls: list[tuple[int, int]] = []

    def get(self, path: str):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
        page_size = int(query["per_page"][0])
        page = int(query["page"][0])
        self.calls.append((page_size, page))
        return list(self.pages.get(page, []))


class EndlessUniqueAPI:
    def __init__(self):
        self.calls: list[tuple[int, int]] = []

    def get(self, path: str):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
        page_size = int(query["per_page"][0])
        page = int(query["page"][0])
        self.calls.append((page_size, page))
        start = ((page - 1) * page_size) + 1
        return [comment(start + index) for index in range(page_size)]


def http_error(
    status: int,
    body: str,
    headers: dict[str, str] | None = None,
) -> urllib.error.HTTPError:
    message = Message()
    for name, value in (headers or {}).items():
        message[name] = value
    return urllib.error.HTTPError(
        "https://api.github.example/test",
        status,
        "fixture failure",
        message,
        io.BytesIO(body.encode("utf-8")),
    )


class PaginationSeamTests(unittest.TestCase):
    def test_default_gateway_stays_at_github_maximum_page_size_100(self):
        api = PageAPI(
            {
                1: [comment(index) for index in range(1, 101)],
                2: [comment(101)],
            }
        )
        comments = GitHubIssueGateway(api, CONTROL_REPOSITORY).list_comments(ISSUE)
        self.assertEqual(len(comments), 101)
        self.assertEqual(api.calls, [(100, 1), (100, 2)])

    def test_explicit_small_page_size_traverses_real_page_boundary_and_retains_targets(self):
        target_left = comment(11, "target-left")
        target_right = comment(12, "target-right")
        api = PageAPI(
            {
                1: [comment(10), target_left],
                2: [target_right, comment(13)],
                3: [],
            }
        )
        comments = GitHubIssueGateway(
            api,
            CONTROL_REPOSITORY,
            page_size=2,
        ).list_comments(ISSUE)
        ids = tuple(item.comment_id for item in comments)
        self.assertEqual(ids, (10, 11, 12, 13))
        self.assertIn(11, ids)
        self.assertIn(12, ids)
        self.assertEqual(api.calls, [(2, 1), (2, 2), (2, 3)])

    def test_page_size_seam_is_bounded_to_supported_github_range(self):
        for page_size in (0, -1, 101):
            with self.subTest(page_size=page_size):
                with self.assertRaisesRegex(ValueError, "page_size"):
                    GitHubIssueGateway(
                        PageAPI({}),
                        CONTROL_REPOSITORY,
                        page_size=page_size,
                    )

    def test_small_page_repeated_or_decreasing_ids_still_fail_closed(self):
        api = PageAPI(
            {
                1: [comment(1), comment(2)],
                2: [comment(2), comment(3)],
            }
        )
        gateway = GitHubIssueGateway(api, CONTROL_REPOSITORY, page_size=2)
        with self.assertRaisesRegex(ValueError, "repeated or decreasing"):
            gateway.list_comments(ISSUE)

    def test_small_page_nontermination_still_fails_closed_at_bound(self):
        api = EndlessUniqueAPI()
        gateway = GitHubIssueGateway(
            api,
            CONTROL_REPOSITORY,
            page_size=2,
            max_pages=2,
        )
        with self.assertRaisesRegex(ValueError, "did not terminate within bound"):
            gateway.list_comments(ISSUE)
        self.assertEqual(api.calls, [(2, 1), (2, 2)])

    def test_scenario_3_uses_only_bounded_fixture_pagination_writes(self):
        source = inspect.getsource(live.LiveFixtureBackend._scenario_3)
        self.assertNotIn("range(101)", source)
        self.assertIn("SCENARIO_3_FILLER_COUNT", source)
        self.assertIn(
            "comment_page_size=SCENARIO_3_FIXTURE_PAGE_SIZE",
            source,
        )
        self.assertEqual(live.SCENARIO_3_FIXTURE_PAGE_SIZE, 2)
        self.assertEqual(live.SCENARIO_3_FILLER_COUNT, 2)
        self.assertLess(live.SCENARIO_3_FILLER_COUNT, 80)

    def test_scenario_3_recovery_ignores_historical_attempt_but_keeps_it_visible(self):
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

        target_rid, target_body, _ = live._protocol_request_contract(
            current, 3, 3, request_type="ALLOCATE_NEXT"
        )
        _, historical_body, _ = live._protocol_request_contract(
            historical, 3, 3, request_type="ALLOCATE_NEXT"
        )

        api = PageAPI(
            {
                1: [
                    comment(10, historical_body),
                    comment(20, "pagination-fixture"),
                ],
                2: [comment(30, target_body)],
            }
        )
        listed = GitHubIssueGateway(
            api,
            CONTROL_REPOSITORY,
            page_size=2,
        ).list_comments(ISSUE)

        expected_agent = (
            f"agent://operator/8ft0-ai/session/{current.value}"
        )

        protocol_comments = tuple(
            item
            for item in listed
            if item.body.startswith("/beads-v0.2 ")
        )

        accepted = tuple(
            item.comment_id
            for item in protocol_comments
            if live._scenario_3_recovery_matches_current_attempt(
                item,
                expected_comment_id=30,
                expected_request_id=target_rid,
                expected_agent_id=expected_agent,
            )
        )

        self.assertEqual(
            tuple(item.comment_id for item in listed),
            (10, 20, 30),
        )
        self.assertEqual(
            tuple(item.comment_id for item in protocol_comments),
            (10, 30),
        )
        self.assertEqual(accepted, (30,))
        self.assertEqual(api.calls, [(2, 1), (2, 2)])

    def test_scenario_3_recovery_rejects_extra_current_attempt_request(self):
        current = live.AttemptNamespace.parse(
            "wd-32636614281-1-current1",
            run_id=32636614281,
            run_attempt=1,
        )

        target_rid, _, _ = live._protocol_request_contract(
            current, 3, 3, request_type="ALLOCATE_NEXT"
        )
        _, unexpected_body, _ = live._protocol_request_contract(
            current, 3, 4, request_type="ALLOCATE_NEXT"
        )

        unexpected = DurableComment(
            31,
            unexpected_body,
            "https://github.example/example/control/issues/1#issuecomment-31",
        )

        with self.assertRaisesRegex(
            live.LiveExecutorError,
            "SCENARIO_3_UNEXPECTED_UNPROCESSED_PROTOCOL_COMMENT",
        ):
            live._scenario_3_recovery_matches_current_attempt(
                unexpected,
                expected_comment_id=30,
                expected_request_id=target_rid,
                expected_agent_id=(
                    f"agent://operator/8ft0-ai/session/{current.value}"
                ),
            )

    def test_scenario_3_recovery_keeps_exact_target_binding(self):
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

        target_rid, _, _ = live._protocol_request_contract(
            current, 3, 3, request_type="ALLOCATE_NEXT"
        )
        _, wrong_request_body, _ = live._protocol_request_contract(
            current, 3, 4, request_type="ALLOCATE_NEXT"
        )
        _, wrong_namespace_body, _ = live._protocol_request_contract(
            historical,
            3,
            3,
            request_type="ALLOCATE_NEXT",
            request_id=target_rid,
        )

        expected_agent = (
            f"agent://operator/8ft0-ai/session/{current.value}"
        )

        for body in (wrong_request_body, wrong_namespace_body):
            target = DurableComment(
                30,
                body,
                "https://github.example/example/control/issues/1#issuecomment-30",
            )

            with self.assertRaisesRegex(
                live.LiveExecutorError,
                "SCENARIO_3_RECOVERY_REQUEST_BINDING_MISMATCH",
            ):
                live._scenario_3_recovery_matches_current_attempt(
                    target,
                    expected_comment_id=30,
                    expected_request_id=target_rid,
                    expected_agent_id=expected_agent,
                )


class RateLimitDiagnosticTests(unittest.TestCase):
    def _capture_api_error(
        self,
        status: int,
        body: str,
        headers: dict[str, str] | None = None,
    ) -> github_api.GitHubAPIError:
        error = http_error(status, body, headers)
        api = github_api.GitHubAPI("SECRET_FIXTURE_TOKEN", "https://api.github.example")
        with patch.object(github_api.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(github_api.GitHubAPIError) as raised:
                api.get("/fixture")
        return raised.exception

    def test_403_secondary_rate_limit_is_distinguished_from_permission_failure(self):
        error = self._capture_api_error(
            403,
            '{"message":"You have exceeded a secondary rate limit. SECRET_RAW_BODY"}',
            {"Retry-After": "17", "X-RateLimit-Remaining": "42"},
        )
        diagnostic = error.safe_diagnostic()
        self.assertTrue(error.rate_limited)
        self.assertEqual(diagnostic["http_status"], 403)
        self.assertEqual(diagnostic["retry_after"], "17")
        self.assertEqual(diagnostic["rate_limit_remaining"], "42")
        self.assertNotIn("SECRET_RAW_BODY", json.dumps(diagnostic, sort_keys=True))
        self.assertNotIn("SECRET_FIXTURE_TOKEN", json.dumps(diagnostic, sort_keys=True))

        forbidden = self._capture_api_error(
            403,
            '{"message":"Resource not accessible by integration"}',
        )
        self.assertFalse(forbidden.rate_limited)
        self.assertEqual(
            forbidden.safe_diagnostic(),
            {"http_status": 403, "rate_limited": False},
        )

    def test_429_is_rate_limited_and_whitelisted_headers_are_bounded(self):
        error = self._capture_api_error(
            429,
            '{"message":"slow down"}',
            {
                "Retry-After": "9" * 200,
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": "1234567890",
                "X-Untrusted-Header": "SECRET_HEADER_VALUE",
            },
        )
        diagnostic = error.safe_diagnostic()
        self.assertTrue(error.rate_limited)
        self.assertEqual(diagnostic["http_status"], 429)
        self.assertLessEqual(len(str(diagnostic["retry_after"])), 64)
        self.assertEqual(diagnostic["rate_limit_remaining"], "0")
        self.assertEqual(diagnostic["rate_limit_reset"], "1234567890")
        self.assertNotIn("SECRET_HEADER_VALUE", json.dumps(diagnostic, sort_keys=True))

    def test_live_failure_output_uses_safe_rate_limit_diagnostic_without_raw_body(self):
        error = github_api.GitHubAPIError(
            403,
            "SECRET_RAW_BODY token=SECRET_TOKEN",
            retry_after="17",
            rate_limit_remaining="42",
            rate_limited=True,
        )
        output = io.StringIO()
        with patch.object(live, "execute_live_suite", side_effect=error), redirect_stdout(output):
            self.assertEqual(live.main(), 1)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["reason_code"], "GITHUB_RATE_LIMITED")
        self.assertEqual(payload["http_status"], 403)
        self.assertEqual(payload["retry_after"], "17")
        self.assertEqual(payload["rate_limit_remaining"], "42")
        self.assertNotIn("SECRET_RAW_BODY", output.getvalue())
        self.assertNotIn("SECRET_TOKEN", output.getvalue())

    def test_live_failure_output_keeps_non_rate_limit_403_distinct(self):
        error = github_api.GitHubAPIError(
            403,
            "Resource not accessible by integration SECRET_RAW_BODY",
            rate_limited=False,
        )
        output = io.StringIO()
        with patch.object(live, "execute_live_suite", side_effect=error), redirect_stdout(output):
            self.assertEqual(live.main(), 1)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["reason_code"], "GITHUB_API_FORBIDDEN")
        self.assertEqual(payload["http_status"], 403)
        self.assertFalse(payload["rate_limited"])
        self.assertNotIn("SECRET_RAW_BODY", output.getvalue())


if __name__ == "__main__":
    unittest.main()
