import base64
import json
import unittest
from unittest.mock import Mock, patch

from phase2.parser import PREFIX, parse_request
from phase2.source_revalidation import SourceRevalidationError, run

TRUSTED_SHA = "a" * 40


def request_body():
    payload = {
        "agent_id": "agent://human/8ft0-ai/session/01",
        "capabilities": [],
        "protocol": "beads-allocation/v0.2",
        "request_id": "01K00000000000000000000000",
        "task_types": [],
        "type": "ALLOCATE_NEXT",
    }
    return (PREFIX + json.dumps(payload, separators=(",", ":")).encode()).decode()


def candidate(**changes):
    parsed = parse_request(request_body().encode())
    value = {
        "comment_id": 77,
        "payload_hash": parsed.payload_hash,
        "principal": "User:1:8ft0-ai",
        "request_id": parsed.payload["request_id"],
        "trusted_sha": TRUSTED_SHA,
    }
    value.update(changes)
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode()


def control_issue():
    return {"number": 1, "state": "open", "labels": [{"name": "phase-2-control"}]}


def comment(*, body=None, edited=False, issue_number=1):
    return {
        "id": 77,
        "body": body or request_body(),
        "issue_url": f"https://api.github.test/repos/8ft0-ai/gitstate-allocation-control/issues/{issue_number}",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:01Z" if edited else "2026-01-01T00:00:00Z",
        "user": {"id": 1, "login": "8ft0-ai", "type": "User"},
    }


def environment(**changes):
    value = {
        "GITHUB_TOKEN": "read-only",
        "GITHUB_API_URL": "https://api.github.test",
        "PHASE2_CANDIDATE": candidate(),
        "PHASE2_TRUSTED_SHA": TRUSTED_SHA,
    }
    value.update(changes)
    return value


class SourceRevalidationTests(unittest.TestCase):
    def _api(self, source=None, issue=None):
        api = Mock()
        api.get.side_effect = [issue or control_issue(), source or comment()]
        return api

    def test_valid_source_revalidates_without_app_credentials(self):
        api = self._api()
        with patch("phase2.source_revalidation.GitHubAPI", return_value=api):
            result = run(environment())
        self.assertEqual(
            result,
            {"action": "live_check", "report_issue_number": 1, "source_comment_id": 77},
        )

    def test_edited_source_is_rejected_before_app_credentials(self):
        api = self._api(source=comment(edited=True))
        with patch("phase2.source_revalidation.GitHubAPI", return_value=api):
            result = run(environment())
        self.assertEqual(result["action"], "rejected")
        self.assertEqual(result["reason_code"], "SOURCE_COMMENT_EDITED_BEFORE_INGRESS")

    def test_candidate_and_control_issue_mismatches_fail_closed(self):
        with self.assertRaises(SourceRevalidationError):
            run(environment(PHASE2_CANDIDATE=candidate(trusted_sha="b" * 40)))

        api = self._api(source=comment(issue_number=2))
        with patch("phase2.source_revalidation.GitHubAPI", return_value=api):
            with self.assertRaises(SourceRevalidationError) as error:
                run(environment())
        self.assertEqual(str(error.exception), "SOURCE_COMMENT_MISMATCH")

    def test_changed_request_identity_is_rejected(self):
        api = self._api()
        tampered = candidate(request_id="01K00000000000000000000001")
        with patch("phase2.source_revalidation.GitHubAPI", return_value=api):
            result = run(environment(PHASE2_CANDIDATE=tampered))
        self.assertEqual(result["action"], "rejected")
        self.assertEqual(result["reason_code"], "AGENT_NOT_AUTHORISED")


if __name__ == "__main__":
    unittest.main()
