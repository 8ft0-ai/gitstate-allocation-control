import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from phase2.parser import PREFIX
from phase2.static_intake import run

CONTROL_REPOSITORY = "8ft0-ai/gitstate-allocation-control"
CONTROL_REPOSITORY_ID = 1321106380
TRUSTED_SHA = "a" * 40


def request_comment(comment_id=77):
    payload = {
        "agent_id": "agent://human/8ft0-ai/session/01",
        "capabilities": [],
        "protocol": "beads-allocation/v0.2",
        "request_id": f"01K{comment_id:023d}"[-26:],
        "task_types": [],
        "type": "ALLOCATE_NEXT",
    }
    body = (PREFIX + json.dumps(payload, separators=(",", ":")).encode()).decode()
    return {
        "id": comment_id,
        "body": body,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "user": {"id": 1, "login": "8ft0-ai", "type": "User"},
    }


def control_issue(*, state="open", labels=None):
    return {
        "number": 1,
        "state": state,
        "labels": [{"name": "phase-2-control"}] if labels is None else labels,
    }


def event_file(value):
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
    json.dump(value, handle)
    handle.close()
    return handle.name


def base_event():
    return {
        "repository": {"full_name": CONTROL_REPOSITORY, "id": CONTROL_REPOSITORY_ID},
    }


def environment(event_name, event):
    return {
        "GITHUB_ACTOR": "8ft0-ai",
        "GITHUB_API_URL": "https://api.github.invalid",
        "GITHUB_EVENT_NAME": event_name,
        "GITHUB_EVENT_PATH": event_file(event),
        "GITHUB_TOKEN": "read-only",
        "PHASE2_TRUSTED_SHA": TRUSTED_SHA,
    }


def decode(value):
    padding = "=" * (-len(value) % 4)
    return json.loads(base64.urlsafe_b64decode(value + padding))


class StaticIntakeTests(unittest.TestCase):
    def tearDown(self):
        for path in getattr(self, "_paths", []):
            Path(path).unlink(missing_ok=True)

    def _env(self, event_name, event):
        env = environment(event_name, event)
        self._paths = getattr(self, "_paths", [])
        self._paths.append(env["GITHUB_EVENT_PATH"])
        return env

    def _api(self, issue=None, comments=None):
        api = Mock()
        api.get.return_value = issue or control_issue()
        api.request.return_value = ([request_comment()] if comments is None else comments, {})
        return api

    def test_schedule_scans_valid_control_surface(self):
        api = self._api()
        with patch("phase2.static_intake.GitHubAPI", return_value=api):
            result = run(self._env("schedule", base_event()))
        self.assertEqual(result["action"], "live_check")
        self.assertEqual(result["candidate_count"], 1)
        self.assertEqual(
            [item["comment_id"] for item in decode(result["candidate_set"])["candidates"]],
            [77],
        )
        api.get.assert_called_once()
        api.request.assert_called_once()

    def test_complete_candidate_set_survives_reconciliation_retry(self):
        comments = [request_comment(30), request_comment(31), request_comment(32)]
        api = self._api(comments=comments)
        with patch("phase2.static_intake.GitHubAPI", return_value=api):
            first = run(self._env("schedule", base_event()))
        api = self._api(comments=comments)
        with patch("phase2.static_intake.GitHubAPI", return_value=api):
            retry = run(self._env("schedule", base_event()))
        self.assertEqual(first["candidate_count"], 3)
        self.assertEqual(
            [item["comment_id"] for item in decode(first["candidate_set"])["candidates"]],
            [30, 31, 32],
        )
        self.assertEqual(first["candidate_set"], retry["candidate_set"])

    def test_rejected_comment_does_not_starve_later_valid_comment(self):
        edited = request_comment(40)
        edited["updated_at"] = "2026-01-01T00:00:01Z"
        api = self._api(comments=[edited, request_comment(41)])
        with patch("phase2.static_intake.GitHubAPI", return_value=api):
            result = run(self._env("schedule", base_event()))
        self.assertEqual(result["action"], "live_check")
        self.assertEqual(result["candidate_count"], 1)
        self.assertEqual(result["rejection_count"], 1)
        self.assertEqual(
            [item["comment_id"] for item in decode(result["candidate_set"])["candidates"]],
            [41],
        )
        self.assertEqual(
            decode(result["rejection_set"])["rejections"],
            [{"reason_code": "SOURCE_COMMENT_EDITED_BEFORE_INGRESS", "source_comment_id": 40}],
        )

    def test_control_surface_label_and_state_fail_closed(self):
        cases = [
            (control_issue(labels=[]), "CONTROL_SURFACE_MISMATCH"),
            (control_issue(state="closed"), "CONTROL_SURFACE_MISMATCH"),
        ]
        for issue, reason in cases:
            api = self._api(issue=issue)
            with self.subTest(issue=issue), patch("phase2.static_intake.GitHubAPI", return_value=api):
                result = run(self._env("schedule", base_event()))
            self.assertEqual(result, {"action": "blocked", "reason_code": reason})
            api.request.assert_not_called()

    def test_wrong_issue_protocol_request_is_rejected_without_scan(self):
        event = base_event()
        event.update({"issue": {"number": 99}, "comment": request_comment()})
        with patch("phase2.static_intake.GitHubAPI") as api:
            result = run(self._env("issue_comment", event))
        self.assertEqual(result["action"], "rejected")
        self.assertEqual(result["reason_code"], "NON_CONTROL_SURFACE")
        api.assert_not_called()

    def test_unrelated_comment_elsewhere_is_noop(self):
        event = base_event()
        event.update({"issue": {"number": 99}, "comment": {"id": 2, "body": "discussion"}})
        with patch("phase2.static_intake.GitHubAPI") as api:
            result = run(self._env("issue_comment", event))
        self.assertEqual(result, {"action": "noop"})
        api.assert_not_called()

    def test_manual_reconcile_uses_same_scan(self):
        event = base_event()
        event.update({"sender": {"login": "8ft0-ai"}, "inputs": {"operation": "reconcile"}})
        api = self._api(comments=[request_comment(10), request_comment(11)])
        with patch("phase2.static_intake.GitHubAPI", return_value=api):
            result = run(self._env("workflow_dispatch", event))
        self.assertEqual(result["action"], "live_check")
        self.assertEqual(result["candidate_count"], 2)
        api.request.assert_called_once()

    def test_manual_scope_probe_is_explicit_and_operator_authorised(self):
        event = base_event()
        event.update({"sender": {"login": "8ft0-ai"}, "inputs": {"operation": "scope_probe"}})
        api = self._api()
        with patch("phase2.static_intake.GitHubAPI", return_value=api):
            result = run(self._env("workflow_dispatch", event))
        self.assertEqual(result["action"], "scope_probe")
        api.get.assert_called_once()
        api.request.assert_not_called()

    def test_manual_operation_rejects_non_operator_and_unknown_mode(self):
        event = base_event()
        event.update({"sender": {"login": "intruder"}, "inputs": {"operation": "reconcile"}})
        env = self._env("workflow_dispatch", event)
        env["GITHUB_ACTOR"] = "intruder"
        with patch("phase2.static_intake.GitHubAPI") as api:
            result = run(env)
        self.assertEqual(result, {"action": "blocked", "reason_code": "OPERATOR_NOT_AUTHORISED"})
        api.assert_not_called()

        event = base_event()
        event.update({"sender": {"login": "8ft0-ai"}, "inputs": {"operation": "unexpected"}})
        with patch("phase2.static_intake.GitHubAPI") as api:
            result = run(self._env("workflow_dispatch", event))
        self.assertEqual(result, {"action": "blocked", "reason_code": "UNAPPROVED_MANUAL_OPERATION"})
        api.assert_not_called()

    def test_unapproved_event_and_invalid_sha_fail_closed(self):
        with patch("phase2.static_intake.GitHubAPI") as api:
            result = run(self._env("push", base_event()))
        self.assertEqual(result, {"action": "blocked", "reason_code": "UNAPPROVED_EVENT"})
        api.assert_not_called()

        env = self._env("schedule", base_event())
        env["PHASE2_TRUSTED_SHA"] = "main"
        with patch("phase2.static_intake.GitHubAPI") as api:
            result = run(env)
        self.assertEqual(result, {"action": "blocked", "reason_code": "INVALID_TRUSTED_SHA"})
        api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
