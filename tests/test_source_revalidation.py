import base64
import json
import unittest
from unittest.mock import Mock, patch

from phase2.github_api import GitHubAPIError
from phase2.parser import PREFIX, parse_request
from phase2.source_revalidation import SourceRevalidationError, run

TRUSTED_SHA = "a" * 40


def request_body(comment_id=77):
    payload = {
        "agent_id": "agent://human/8ft0-ai/session/01",
        "capabilities": [],
        "protocol": "beads-allocation/v0.2",
        "request_id": f"01K{comment_id:023d}"[-26:],
        "task_types": [],
        "type": "ALLOCATE_NEXT",
    }
    return (PREFIX + json.dumps(payload, separators=(",", ":")).encode()).decode()


def candidate_record(comment_id=77, **changes):
    parsed = parse_request(request_body(comment_id).encode())
    value = {
        "comment_id": comment_id,
        "payload_hash": parsed.payload_hash,
        "principal": "User:1:8ft0-ai",
        "request_id": parsed.payload["request_id"],
    }
    value.update(changes)
    return value


def candidate_set(comment_ids=(77,), trusted_sha=TRUSTED_SHA, records=None):
    value = {
        "candidates": list(records) if records is not None else [candidate_record(item) for item in comment_ids],
        "trusted_sha": trusted_sha,
        "version": 1,
    }
    return base64.urlsafe_b64encode(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).decode().rstrip("=")


def decode(value):
    padding = "=" * (-len(value) % 4)
    return json.loads(base64.urlsafe_b64decode(value + padding))


def control_issue():
    return {"number": 1, "state": "open", "labels": [{"name": "phase-2-control"}]}


def comment(comment_id=77, *, body=None, edited=False, issue_number=1):
    return {
        "id": comment_id,
        "body": body or request_body(comment_id),
        "issue_url": f"https://api.github.test/repos/8ft0-ai/gitstate-allocation-control/issues/{issue_number}",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:01Z" if edited else "2026-01-01T00:00:00Z",
        "user": {"id": 1, "login": "8ft0-ai", "type": "User"},
    }


def environment(**changes):
    value = {
        "GITHUB_TOKEN": "read-only",
        "GITHUB_API_URL": "https://api.github.test",
        "PHASE2_CANDIDATE_SET": candidate_set(),
        "PHASE2_TRUSTED_SHA": TRUSTED_SHA,
    }
    value.update(changes)
    return value


class SourceRevalidationTests(unittest.TestCase):
    def _api(self, sources=None, issue=None):
        api = Mock()
        api.get.side_effect = [issue or control_issue(), *(sources or [comment()])]
        return api

    def test_valid_source_set_revalidates_without_app_credentials(self):
        api = self._api(sources=[comment(77), comment(78)])
        with patch("phase2.source_revalidation.GitHubAPI", return_value=api):
            result = run(environment(PHASE2_CANDIDATE_SET=candidate_set((77, 78))))
        self.assertEqual(result["action"], "live_check")
        self.assertEqual(result["candidate_count"], 2)
        self.assertEqual(result["rejection_count"], 0)
        self.assertEqual(result["source_comment_id"], 77)
        self.assertEqual(
            [item["comment_id"] for item in decode(result["candidate_set"])["candidates"]],
            [77, 78],
        )

    def test_one_edited_source_does_not_starve_later_valid_source(self):
        api = self._api(sources=[comment(77, edited=True), comment(78)])
        with patch("phase2.source_revalidation.GitHubAPI", return_value=api):
            result = run(environment(PHASE2_CANDIDATE_SET=candidate_set((77, 78))))
        self.assertEqual(result["action"], "live_check")
        self.assertEqual(result["candidate_count"], 1)
        self.assertEqual(result["source_comment_id"], 78)
        self.assertEqual(result["rejection_count"], 1)
        self.assertEqual(
            decode(result["rejection_set"])["rejections"],
            [{"reason_code": "SOURCE_COMMENT_EDITED_BEFORE_INGRESS", "source_comment_id": 77}],
        )

    def test_deleted_source_is_withdrawn_without_blocking_later_source(self):
        api = Mock()
        api.get.side_effect = [
            control_issue(),
            GitHubAPIError(404, "not found"),
            comment(78),
        ]
        with patch("phase2.source_revalidation.GitHubAPI", return_value=api):
            result = run(environment(PHASE2_CANDIDATE_SET=candidate_set((77, 78))))
        self.assertEqual(result["action"], "live_check")
        self.assertEqual(result["candidate_count"], 1)
        self.assertEqual(result["source_comment_id"], 78)
        self.assertEqual(
            decode(result["rejection_set"])["rejections"],
            [{"reason_code": "SOURCE_COMMENT_DELETED_BEFORE_INGRESS", "source_comment_id": 77}],
        )

    def test_all_withdrawn_sources_return_rejected(self):
        api = self._api(sources=[comment(77, edited=True)])
        with patch("phase2.source_revalidation.GitHubAPI", return_value=api):
            result = run(environment())
        self.assertEqual(result["action"], "rejected")
        self.assertEqual(result["reason_code"], "SOURCE_COMMENT_EDITED_BEFORE_INGRESS")
        self.assertEqual(result["candidate_count"], 0)

    def test_candidate_set_and_control_issue_mismatches_fail_closed(self):
        with self.assertRaises(SourceRevalidationError):
            run(environment(PHASE2_CANDIDATE_SET=candidate_set(trusted_sha="b" * 40)))

        api = self._api(sources=[comment(issue_number=2)])
        with patch("phase2.source_revalidation.GitHubAPI", return_value=api):
            with self.assertRaises(SourceRevalidationError) as error:
                run(environment())
        self.assertEqual(str(error.exception), "SOURCE_COMMENT_MISMATCH")

    def test_candidate_order_and_identity_fail_closed(self):
        with self.assertRaises(SourceRevalidationError) as error:
            run(
                environment(
                    PHASE2_CANDIDATE_SET=candidate_set(
                        records=[candidate_record(78), candidate_record(77)]
                    )
                )
            )
        self.assertEqual(str(error.exception), "INVALID_CANDIDATE_ORDER")

        api = self._api()
        tampered = candidate_record(77, request_id="01K00000000000000000000001")
        with patch("phase2.source_revalidation.GitHubAPI", return_value=api):
            result = run(environment(PHASE2_CANDIDATE_SET=candidate_set(records=[tampered])))
        self.assertEqual(result["action"], "rejected")
        self.assertEqual(result["rejection_count"], 1)
        self.assertEqual(
            decode(result["rejection_set"])["rejections"][0]["reason_code"],
            "AGENT_NOT_AUTHORISED",
        )


if __name__ == "__main__":
    unittest.main()
