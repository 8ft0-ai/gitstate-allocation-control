from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from phase2 import current_observation_dispatch_relay as relay


CERT = base64.b64encode(b"public-certificate-der-fixture").decode("ascii")
REF_SHA = "1" * 40
REF = f"refs/tags/gitstate-current-observation/{REF_SHA}"
WORKFLOW_SHA = "2" * 40


def body(ref: str = REF, certificate: str = CERT) -> str:
    return json.dumps(
        {
            "ref": ref,
            "current_observation_recipient_cert_b64": certificate,
        },
        separators=(",", ":"),
    )


def event(request_body: str | None = None) -> dict[str, object]:
    return {
        "action": "opened",
        "repository": {"id": 123, "full_name": relay.FIXED_REPOSITORY},
        "sender": {"login": relay.FIXED_OWNER},
        "issue": {
            "id": 456,
            "number": 99,
            "title": relay.REQUEST_TITLE,
            "state": "open",
            "author_association": "OWNER",
            "user": {"login": relay.FIXED_OWNER},
            "body": body() if request_body is None else request_body,
        },
    }


def env() -> dict[str, str]:
    return {
        "GITHUB_REPOSITORY": relay.FIXED_REPOSITORY,
        "GITHUB_REPOSITORY_ID": "123",
        "GITHUB_EVENT_NAME": "issues",
        "GITHUB_ACTOR": relay.FIXED_OWNER,
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_WORKFLOW_SHA": WORKFLOW_SHA,
        "GITHUB_RUN_ID": "789",
    }


def current_issue(request_body: str | None = None) -> dict[str, object]:
    return {
        "id": 456,
        "number": 99,
        "title": relay.REQUEST_TITLE,
        "state": "open",
        "author_association": "OWNER",
        "user": {"login": relay.FIXED_OWNER},
        "body": body() if request_body is None else request_body,
    }


class FakeAPI:
    def __init__(
        self,
        *,
        outcome: relay.DispatchOutcome | None = None,
        marker_write_error: bool = False,
        final_tag_mismatch: bool = False,
    ) -> None:
        self.comments: list[dict[str, object]] = []
        self.dispatch_calls = 0
        self.create_calls = 0
        self.tag_reads = 0
        self.issue_reads = 0
        self.outcome = outcome or relay.DispatchOutcome(
            "ACCEPTED",
            http_status=200,
            workflow_run_id=321,
            run_url=(
                "https://api.github.com/repos/"
                f"{relay.FIXED_REPOSITORY}/actions/runs/321"
            ),
            html_url=f"https://github.com/{relay.FIXED_REPOSITORY}/actions/runs/321",
        )
        self.marker_write_error = marker_write_error
        self.final_tag_mismatch = final_tag_mismatch

    def get_issue(self, issue_number: int):
        self.issue_reads += 1
        self.assert_issue_number(issue_number)
        return current_issue()

    @staticmethod
    def assert_issue_number(issue_number: int) -> None:
        if issue_number != 99:
            raise AssertionError(issue_number)

    def list_issue_comments(self, issue_number: int):
        self.assert_issue_number(issue_number)
        return list(self.comments)

    def get_governed_tag(self, ref: str):
        if ref != REF:
            raise AssertionError(ref)
        self.tag_reads += 1
        sha = "f" * 40 if self.final_tag_mismatch and self.tag_reads >= 2 else REF_SHA
        return {"object": {"type": "commit", "sha": sha}}

    def create_consumption_comment(self, issue_number: int, marker_body: str):
        self.assert_issue_number(issue_number)
        self.create_calls += 1
        if self.marker_write_error:
            raise relay.RelayError("CONSUMPTION_MARKER_WRITE_AMBIGUOUS")
        comment = {
            "id": 700 + self.create_calls,
            "body": marker_body,
            "user": {"login": relay.BOT_LOGIN},
        }
        self.comments.append(comment)
        return dict(comment)

    def dispatch_current_observation(self, *, ref: str, certificate_b64: str):
        if ref != REF or certificate_b64 != CERT:
            raise AssertionError("dispatch input widened")
        self.dispatch_calls += 1
        return self.outcome


class RequestSchemaTests(unittest.TestCase):
    def test_accepts_exact_two_key_request(self):
        self.assertEqual(relay.parse_request_body(body()), (REF, CERT))

    def test_rejects_duplicate_key(self):
        request = (
            '{"ref":"%s","ref":"%s",'
            '"current_observation_recipient_cert_b64":"%s"}'
        ) % (REF, REF, CERT)
        with self.assertRaisesRegex(relay.RelayError, "REQUEST_BODY_INVALID"):
            relay.parse_request_body(request)

    def test_rejects_extra_key(self):
        request = json.dumps(
            {
                "ref": REF,
                "current_observation_recipient_cert_b64": CERT,
                "repository": "other/repo",
            },
            separators=(",", ":"),
        )
        with self.assertRaisesRegex(relay.RelayError, "REQUEST_SCHEMA_INVALID"):
            relay.parse_request_body(request)

    def test_rejects_non_exact_refs(self):
        bad = [
            "main",
            "HEAD",
            "refs/heads/main",
            "refs/tags/gitstate-current-observation/" + "a" * 39,
            "refs/tags/gitstate-current-observation/" + "A" * 40,
            "refs/tags/other/" + "a" * 40,
        ]
        for ref in bad:
            with self.subTest(ref=ref), self.assertRaises(relay.RelayError):
                relay.parse_request_body(body(ref=ref))

    def test_rejects_multiline_or_invalid_base64(self):
        with self.assertRaisesRegex(relay.RelayError, "REQUEST_BODY_INVALID"):
            relay.parse_request_body(body() + "\n")
        with self.assertRaisesRegex(relay.RelayError, "REQUEST_CERTIFICATE_INVALID"):
            relay.parse_request_body(body(certificate="***"))


class AuthorityAndReplayTests(unittest.TestCase):
    def test_validation_requires_exact_actor_event_and_current_issue(self):
        api = FakeAPI()
        values = env()
        request = relay.validate_request(values, api=api, event=event())
        self.assertEqual(request.attempt_identity, f"{relay.REQUEST_CONTRACT}:123:456")
        bad_values = dict(values)
        bad_values["GITHUB_ACTOR"] = "someone-else"
        with self.assertRaisesRegex(relay.RelayError, "GITHUB_ACTOR_MISMATCH"):
            relay.validate_request(bad_values, api=api, event=event())

    def test_first_attempt_consumes_then_dispatches_once(self):
        api = FakeAPI()
        request, marker_id, outcome = relay.consume_and_dispatch(
            env(), api=api, event=event()
        )
        self.assertEqual(request.ref, REF)
        self.assertEqual(marker_id, 701)
        self.assertEqual(outcome.outcome, "ACCEPTED")
        self.assertEqual(api.create_calls, 1)
        self.assertEqual(api.dispatch_calls, 1)
        self.assertEqual(api.tag_reads, 2)
        marker_body = str(api.comments[0]["body"])
        self.assertNotIn(CERT, marker_body)
        self.assertIn(request.body_sha256, marker_body)

    def test_consumed_rerun_cannot_redispatch(self):
        api = FakeAPI()
        relay.consume_and_dispatch(env(), api=api, event=event())
        with self.assertRaisesRegex(relay.RelayError, "REQUEST_ALREADY_CONSUMED"):
            relay.consume_and_dispatch(env(), api=api, event=event())
        self.assertEqual(api.dispatch_calls, 1)
        self.assertEqual(api.create_calls, 1)

    def test_ambiguous_marker_write_never_dispatches(self):
        api = FakeAPI(marker_write_error=True)
        with self.assertRaisesRegex(
            relay.RelayError, "CONSUMPTION_MARKER_WRITE_AMBIGUOUS"
        ):
            relay.consume_and_dispatch(env(), api=api, event=event())
        self.assertEqual(api.dispatch_calls, 0)

    def test_post_consumption_tag_movement_never_dispatches(self):
        api = FakeAPI(final_tag_mismatch=True)
        with self.assertRaisesRegex(relay.RelayError, "REQUEST_TAG_TARGET_MISMATCH"):
            relay.consume_and_dispatch(env(), api=api, event=event())
        self.assertEqual(api.create_calls, 1)
        self.assertEqual(api.dispatch_calls, 0)

    def test_user_spoof_marker_is_not_consumption(self):
        api = FakeAPI()
        request = relay.validate_request(env(), api=api, event=event())
        api.comments.append(
            {
                "id": 500,
                "body": relay._marker_body(request, env()),
                "user": {"login": relay.FIXED_OWNER},
            }
        )
        _, _, outcome = relay.consume_and_dispatch(env(), api=api, event=event())
        self.assertEqual(outcome.outcome, "ACCEPTED")
        self.assertEqual(api.dispatch_calls, 1)


class FakeResponse:
    def __init__(self, status: int, payload: object):
        self.status = status
        self._payload = (
            payload
            if isinstance(payload, bytes)
            else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )

    def read(self, amount: int = -1) -> bytes:
        return self._payload[:amount]


class FakeConnection:
    def __init__(self, response: FakeResponse, *, request_error: Exception | None = None):
        self.response = response
        self.request_error = request_error
        self.requests: list[tuple[str, str, bytes | None, dict[str, str]]] = []
        self.closed = False

    def request(self, method: str, path: str, body=None, headers=None):
        if self.request_error is not None:
            raise self.request_error
        self.requests.append((method, path, body, dict(headers or {})))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class DispatchTransportTests(unittest.TestCase):
    def client_with_connection(self, connection: FakeConnection):
        def factory(host: str, port: int, timeout: int):
            self.assertEqual(host, relay.API_HOST)
            self.assertEqual(port, 443)
            self.assertEqual(timeout, relay.HTTP_TIMEOUT_SECONDS)
            return connection

        return relay.GitHubRelayAPI("token", connection_factory=factory)

    def test_positive_200_with_exact_run_identity_is_accepted(self):
        run_id = 42
        connection = FakeConnection(
            FakeResponse(
                200,
                {
                    "workflow_run_id": run_id,
                    "run_url": (
                        "https://api.github.com/repos/"
                        f"{relay.FIXED_REPOSITORY}/actions/runs/{run_id}"
                    ),
                    "html_url": (
                        f"https://github.com/{relay.FIXED_REPOSITORY}/actions/runs/{run_id}"
                    ),
                },
            )
        )
        api = self.client_with_connection(connection)
        outcome = api.dispatch_current_observation(ref=REF, certificate_b64=CERT)
        self.assertEqual(outcome.outcome, "ACCEPTED")
        self.assertEqual(len(connection.requests), 1)
        method, path, sent_body, headers = connection.requests[0]
        self.assertEqual(method, "POST")
        self.assertEqual(path, relay.DISPATCH_ENDPOINT)
        self.assertEqual(headers["X-GitHub-Api-Version"], "2026-03-10")
        payload = json.loads(sent_body)
        self.assertEqual(
            payload,
            {
                "ref": REF,
                "inputs": {
                    "operation": "current_observation",
                    "current_observation_recipient_cert_b64": CERT,
                },
            },
        )

    def test_non_200_or_bad_success_body_is_terminal_unknown(self):
        api = self.client_with_connection(
            FakeConnection(FakeResponse(422, {"message": "x"}))
        )
        self.assertEqual(
            api.dispatch_current_observation(ref=REF, certificate_b64=CERT).outcome,
            "SENT_OR_ACCEPTANCE_UNKNOWN",
        )
        api = self.client_with_connection(FakeConnection(FakeResponse(200, {})))
        self.assertEqual(
            api.dispatch_current_observation(ref=REF, certificate_b64=CERT).outcome,
            "SENT_OR_ACCEPTANCE_UNKNOWN",
        )

    def test_transport_exception_is_terminal_unknown_and_not_retried(self):
        connection = FakeConnection(
            FakeResponse(200, {}),
            request_error=TimeoutError("ambiguous"),
        )
        api = self.client_with_connection(connection)
        outcome = api.dispatch_current_observation(ref=REF, certificate_b64=CERT)
        self.assertEqual(outcome.outcome, "SENT_OR_ACCEPTANCE_UNKNOWN")
        self.assertEqual(connection.requests, [])
        self.assertEqual(api.dispatch_calls, 1)

    def test_second_dispatch_call_is_structurally_rejected(self):
        connection = FakeConnection(FakeResponse(500, {}))
        api = self.client_with_connection(connection)
        api.dispatch_current_observation(ref=REF, certificate_b64=CERT)
        with self.assertRaisesRegex(
            relay.RelayError, "DISPATCH_MUTATION_COUNT_EXCEEDED"
        ):
            api.dispatch_current_observation(ref=REF, certificate_b64=CERT)


class PublicEvidenceTests(unittest.TestCase):
    def test_safe_payload_and_marker_never_echo_certificate(self):
        request = relay._event_request(env(), event())
        marker = relay._marker_body(request, env())
        payload = relay._safe_execution_payload(
            request=request,
            marker_id=777,
            outcome=relay.DispatchOutcome("NOT_SENT"),
        )
        self.assertNotIn(CERT, marker)
        self.assertNotIn(CERT, json.dumps(payload))

    def test_summary_does_not_echo_certificate(self):
        request = relay._event_request(env(), event())
        payload = relay._safe_execution_payload(
            request=request,
            marker_id=777,
            outcome=relay.DispatchOutcome("NOT_SENT"),
        )
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.md"
            values = env()
            values["GITHUB_STEP_SUMMARY"] = str(summary)
            self.assertTrue(relay._write_summary(values, payload))
            self.assertNotIn(CERT, summary.read_text(encoding="utf-8"))


class RepositoryContractTests(unittest.TestCase):
    def test_relay_workflow_is_additive_and_narrow(self):
        workflow = Path(
            ".github/workflows/current-observation-dispatch-relay.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("issues:", workflow)
        self.assertIn("types: [opened]", workflow)
        self.assertIn(
            "current-observation-relay-${{ github.event.issue.id }}", workflow
        )
        self.assertIn("contents: read", workflow)
        self.assertIn("issues: read", workflow)
        self.assertIn("issues: write", workflow)
        self.assertIn("actions: write", workflow)
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", workflow)
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertNotIn("phase-2-allocator", workflow)
        self.assertNotIn("secrets.", workflow)


if __name__ == "__main__":
    unittest.main()
