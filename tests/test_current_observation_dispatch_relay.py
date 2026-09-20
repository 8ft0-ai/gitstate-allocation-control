from __future__ import annotations

import base64
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from phase2 import current_observation
from phase2 import current_observation_dispatch_relay as relay


CERT = base64.b64encode(b"public-certificate-der-fixture").decode("ascii")
EXECUTION_SHA = "1" * 40
REF = f"refs/tags/gitstate-current-observation/{EXECUTION_SHA}"


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
        "GITHUB_TRIGGERING_ACTOR": relay.FIXED_OWNER,
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REF": relay.FIXED_EXECUTION_REF,
        "GITHUB_SHA": EXECUTION_SHA,
        "GITHUB_WORKFLOW_SHA": EXECUTION_SHA,
        "GITHUB_RUN_ID": "789",
        "GITHUB_RUN_ATTEMPT": "1",
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
        marker_write_error: bool = False,
        tag_target: str = EXECUTION_SHA,
        final_tag_target: str | None = None,
    ) -> None:
        self.comments: list[dict[str, object]] = []
        self.create_calls = 0
        self.tag_reads = 0
        self.issue_reads = 0
        self.marker_write_error = marker_write_error
        self.tag_target = tag_target
        self.final_tag_target = final_tag_target

    @staticmethod
    def assert_issue_number(issue_number: int) -> None:
        if issue_number != 99:
            raise AssertionError(issue_number)

    def get_issue(self, issue_number: int):
        self.issue_reads += 1
        self.assert_issue_number(issue_number)
        return current_issue()

    def list_issue_comments(self, issue_number: int):
        self.assert_issue_number(issue_number)
        return list(self.comments)

    def get_governed_tag(self, ref: str):
        if ref != REF:
            raise AssertionError(ref)
        self.tag_reads += 1
        target = self.tag_target
        if self.final_tag_target is not None and self.tag_reads >= 2:
            target = self.final_tag_target
        return {"object": {"type": "commit", "sha": target}}

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


class RequestSchemaTests(unittest.TestCase):
    def test_accepts_exact_two_key_request(self):
        self.assertEqual(relay.parse_request_body(body()), (REF, CERT))

    def test_rejects_duplicate_extra_multiline_and_non_exact_refs(self):
        duplicate = (
            '{"ref":"%s","ref":"%s",'
            '"current_observation_recipient_cert_b64":"%s"}'
        ) % (REF, REF, CERT)
        cases = [
            (duplicate, "REQUEST_BODY_INVALID"),
            (
                json.dumps(
                    {
                        "ref": REF,
                        "current_observation_recipient_cert_b64": CERT,
                        "extra": True,
                    },
                    separators=(",", ":"),
                ),
                "REQUEST_SCHEMA_INVALID",
            ),
            (body() + "\n", "REQUEST_BODY_INVALID"),
            (body(ref="refs/heads/main"), "REQUEST_REF_INVALID"),
            (
                body(
                    ref="refs/tags/gitstate-current-observation/" + ("A" * 40)
                ),
                "REQUEST_REF_INVALID",
            ),
            (body(certificate="***"), "REQUEST_CERTIFICATE_INVALID"),
        ]
        for request_body, code in cases:
            with self.subTest(code=code), self.assertRaisesRegex(relay.RelayError, code):
                relay.parse_request_body(request_body)


class PreConsumptionAuthorityTests(unittest.TestCase):
    def test_exact_identity_consumes_once_and_binds_attempt(self):
        api = FakeAPI()
        request, marker_id = relay.consume_request(env(), api=api, event=event())
        self.assertEqual(request.ref, REF)
        self.assertEqual(marker_id, 701)
        self.assertEqual(api.create_calls, 1)
        self.assertEqual(api.tag_reads, 2)
        marker = str(api.comments[0]["body"])
        self.assertNotIn(CERT, marker)
        self.assertIn('"relay_run_attempt":1', marker)
        self.assertIn(f'"relay_workflow_sha":"{EXECUTION_SHA}"', marker)
        self.assertIn(f'"validated_ref":"{REF}"', marker)

    def test_execution_identity_mismatches_are_zero_write(self):
        cases = [
            ("GITHUB_TRIGGERING_ACTOR", "someone-else", "GITHUB_TRIGGERING_ACTOR_MISMATCH"),
            ("GITHUB_RUN_ATTEMPT", "2", "GITHUB_RUN_ATTEMPT_MISMATCH"),
            ("GITHUB_REF", "refs/heads/other", "GITHUB_REF_MISMATCH"),
            ("GITHUB_WORKFLOW_SHA", "2" * 40, "EXECUTION_WORKFLOW_SHA_MISMATCH"),
            ("GITHUB_SHA", "2" * 40, "EXECUTION_WORKFLOW_SHA_MISMATCH"),
        ]
        for name, value, code in cases:
            values = env()
            values[name] = value
            api = FakeAPI()
            with self.subTest(name=name), self.assertRaisesRegex(relay.RelayError, code):
                relay.consume_request(values, api=api, event=event())
            self.assertEqual(api.create_calls, 0)

    def test_requested_tag_execution_sha_mismatch_is_zero_write(self):
        request_body = body(
            ref="refs/tags/gitstate-current-observation/" + ("2" * 40)
        )
        api = FakeAPI()
        with self.assertRaisesRegex(relay.RelayError, "REQUEST_EXECUTION_SHA_MISMATCH"):
            relay.consume_request(env(), api=api, event=event(request_body))
        self.assertEqual(api.create_calls, 0)
        self.assertEqual(api.tag_reads, 0)

    def test_direct_tag_target_mismatch_is_zero_write(self):
        api = FakeAPI(tag_target="f" * 40)
        with self.assertRaisesRegex(relay.RelayError, "REQUEST_TAG_TARGET_MISMATCH"):
            relay.consume_request(env(), api=api, event=event())
        self.assertEqual(api.create_calls, 0)

    def test_ambiguous_marker_write_is_terminal_without_second_consequence(self):
        api = FakeAPI(marker_write_error=True)
        with self.assertRaisesRegex(
            relay.RelayError, "CONSUMPTION_MARKER_WRITE_AMBIGUOUS"
        ):
            relay.consume_request(env(), api=api, event=event())
        self.assertEqual(api.create_calls, 1)

    def test_post_consumption_tag_movement_burns_request_fail_closed(self):
        api = FakeAPI(final_tag_target="f" * 40)
        progress = relay.ExecutionProgress()
        with self.assertRaisesRegex(relay.RelayError, "REQUEST_TAG_TARGET_MISMATCH"):
            relay.consume_request(env(), api=api, event=event(), progress=progress)
        self.assertEqual(api.create_calls, 1)
        self.assertEqual(progress.marker_id, 701)

    def test_prior_marker_and_serialised_duplicate_cannot_create_second_marker(self):
        api = FakeAPI()
        relay.consume_request(env(), api=api, event=event())
        with self.assertRaisesRegex(relay.RelayError, "REQUEST_ALREADY_CONSUMED"):
            relay.consume_request(env(), api=api, event=event())
        self.assertEqual(api.create_calls, 1)

        workflow = Path(
            ".github/workflows/current-observation-dispatch-relay.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "group: current-observation-relay-${{ github.event.issue.id }}",
            workflow,
        )
        self.assertIn("cancel-in-progress: false", workflow)

    def test_attempt_two_fails_before_existing_marker_discovery_or_write(self):
        api = FakeAPI()
        relay.consume_request(env(), api=api, event=event())
        values = env()
        values["GITHUB_RUN_ATTEMPT"] = "2"
        with self.assertRaisesRegex(relay.RelayError, "GITHUB_RUN_ATTEMPT_MISMATCH"):
            relay.consume_request(values, api=api, event=event())
        self.assertEqual(api.create_calls, 1)

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
        relay.consume_request(env(), api=api, event=event())
        self.assertEqual(api.create_calls, 1)


class ProtectedReconstructionTests(unittest.TestCase):
    def consumed_api(self) -> FakeAPI:
        api = FakeAPI()
        relay.consume_request(env(), api=api, event=event())
        return api

    def test_protected_job_reconstructs_exact_request_marker_and_subject(self):
        api = self.consumed_api()
        request = relay.reconstruct_protected_request(env(), api=api, event=event())
        self.assertEqual(request.ref, REF)
        self.assertGreaterEqual(api.tag_reads, 4)
        self.assertGreaterEqual(api.issue_reads, 4)

    def test_missing_duplicate_or_foreign_attempt_marker_blocks_protected_execution(self):
        api = FakeAPI()
        with self.assertRaisesRegex(
            relay.RelayError, "CONSUMPTION_MARKER_CARDINALITY_INVALID"
        ):
            relay.reconstruct_protected_request(env(), api=api, event=event())

        api = self.consumed_api()
        duplicate = dict(api.comments[0])
        duplicate["id"] = 999
        api.comments.append(duplicate)
        with self.assertRaisesRegex(
            relay.RelayError, "CONSUMPTION_MARKER_CARDINALITY_INVALID"
        ):
            relay.reconstruct_protected_request(env(), api=api, event=event())

        api = self.consumed_api()
        prefix, encoded = str(api.comments[0]["body"]).split("\n", 1)
        payload = json.loads(encoded)
        payload["relay_run_id"] = 999
        api.comments[0]["body"] = (
            prefix + "\n" + json.dumps(payload, sort_keys=True, separators=(",", ":"))
        )
        with self.assertRaisesRegex(relay.RelayError, "CONSUMPTION_MARKER_MISMATCH"):
            relay.reconstruct_protected_request(env(), api=api, event=event())

    def test_protected_rerun_is_rejected_before_observation_engine(self):
        api = self.consumed_api()
        values = env()
        values["GITHUB_RUN_ATTEMPT"] = "2"
        with mock.patch.object(current_observation, "main") as observation_main:
            with self.assertRaisesRegex(relay.RelayError, "GITHUB_RUN_ATTEMPT_MISMATCH"):
                relay._run_protected_observation(
                    values,
                    api=api,
                    event=event(),
                )
        observation_main.assert_not_called()

    def test_certificate_and_subject_are_reconstructed_inside_protected_job(self):
        api = self.consumed_api()
        seen: dict[str, str] = {}

        def observation_main(argv):
            seen["certificate"] = os.environ[current_observation.RECIPIENT_CERTIFICATE_ENV]
            seen["workflow_sha"] = os.environ[current_observation.WORKFLOW_SHA_ENV]
            seen["requested_ref"] = os.environ[current_observation.REQUESTED_REF_ENV]
            seen["operation"] = os.environ["INPUT_OPERATION"]
            return 0

        with mock.patch.object(current_observation, "main", side_effect=observation_main):
            code = relay._run_protected_observation(
                env(),
                api=api,
                event=event(),
            )
        self.assertEqual(code, 0)
        self.assertEqual(seen["certificate"], CERT)
        self.assertEqual(seen["workflow_sha"], EXECUTION_SHA)
        self.assertEqual(seen["requested_ref"], REF)
        self.assertEqual(seen["operation"], "current_observation")


class CurrentIssueAuthorityTests(unittest.TestCase):
    def test_rejects_each_current_issue_authority_mismatch(self):
        def api_with_current(mutator):
            class CurrentIssueAPI(FakeAPI):
                def get_issue(self, issue_number: int):
                    self.issue_reads += 1
                    self.assert_issue_number(issue_number)
                    value = current_issue()
                    mutator(value)
                    return value

            return CurrentIssueAPI()

        mutations = [
            (lambda value: value.__setitem__("id", 999), "CURRENT_ISSUE_IDENTITY_MISMATCH"),
            (
                lambda value: value["user"].__setitem__("login", "someone-else"),
                "CURRENT_ISSUE_CREATOR_MISMATCH",
            ),
            (
                lambda value: value.__setitem__("author_association", "MEMBER"),
                "CURRENT_ISSUE_AUTHOR_ASSOCIATION_MISMATCH",
            ),
            (lambda value: value.__setitem__("title", "wrong"), "CURRENT_ISSUE_TITLE_MISMATCH"),
            (lambda value: value.__setitem__("state", "closed"), "CURRENT_ISSUE_STATE_MISMATCH"),
            (
                lambda value: value.__setitem__(
                    "body", body(certificate=base64.b64encode(b"changed").decode("ascii"))
                ),
                "CURRENT_ISSUE_BODY_MISMATCH",
            ),
        ]
        for mutator, code in mutations:
            with self.subTest(code=code), self.assertRaisesRegex(relay.RelayError, code):
                relay.validate_request(env(), api=api_with_current(mutator), event=event())


class PaginationAndMarkerTests(unittest.TestCase):
    def test_comment_discovery_completely_paginates(self):
        api = relay.GitHubRelayAPI("token")
        first_page = [{"id": index} for index in range(relay.COMMENTS_PER_PAGE)]
        second_page = [{"id": 999}]
        with mock.patch.object(
            api, "_request_json", side_effect=[first_page, second_page]
        ) as request_json:
            comments = api.list_issue_comments(99)
        self.assertEqual(len(comments), relay.COMMENTS_PER_PAGE + 1)
        self.assertEqual(request_json.call_count, 2)

    def test_malformed_bot_marker_fails_closed(self):
        request = relay._event_request(env(), event())
        malformed = {
            "id": 501,
            "body": relay.CONSUMPTION_CONTRACT,
            "user": {"login": relay.BOT_LOGIN},
        }
        with self.assertRaisesRegex(relay.RelayError, "CONSUMPTION_MARKER_AMBIGUOUS"):
            relay._matching_markers([malformed], request)

    def test_duplicate_matching_marker_reread_fails_closed(self):
        class DuplicateMarkerAPI(FakeAPI):
            def create_consumption_comment(self, issue_number: int, marker_body: str):
                created = super().create_consumption_comment(issue_number, marker_body)
                duplicate = dict(created)
                duplicate["id"] = int(created["id"]) + 1
                self.comments.append(duplicate)
                return created

        api = DuplicateMarkerAPI()
        with self.assertRaisesRegex(
            relay.RelayError, "CONSUMPTION_MARKER_REREAD_INVALID"
        ):
            relay.consume_request(env(), api=api, event=event())
        self.assertEqual(api.create_calls, 1)


class AuditEvidenceTests(unittest.TestCase):
    def test_safe_payload_and_marker_never_echo_certificate(self):
        request = relay._event_request(env(), event())
        marker = relay._marker_body(request, env())
        payload = relay._safe_execution_payload(
            values=env(),
            request=request,
            marker_id=777,
        )
        self.assertNotIn(CERT, marker)
        self.assertNotIn(CERT, json.dumps(payload))
        self.assertEqual(payload["fixed_method"], "same_run_protected_job")
        self.assertFalse(payload["second_workflow_run"])

    def test_consume_cli_records_public_safe_audit_summary(self):
        api = FakeAPI()
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "event.json"
            event_path.write_text(json.dumps(event()), encoding="utf-8")
            summary_path = Path(directory) / "summary.md"
            values = env()
            values.update(
                {
                    "GITHUB_EVENT_PATH": str(event_path),
                    "GITHUB_TOKEN": "test-token",
                    "GITHUB_STEP_SUMMARY": str(summary_path),
                }
            )
            output = io.StringIO()
            with mock.patch.dict(os.environ, values, clear=True), mock.patch.object(
                relay, "GitHubRelayAPI", return_value=api
            ), redirect_stdout(output):
                code = relay.main(["consume"])
            self.assertEqual(code, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["status"], "CONSUMPTION_COMPLETE")
            self.assertEqual(payload["relay_run_attempt"], 1)
            self.assertNotIn(CERT, output.getvalue())
            summary = summary_path.read_text(encoding="utf-8")
            self.assertNotIn(CERT, summary)
            self.assertIn('"consumption_comment_id":701', summary)


class RepositoryContractTests(unittest.TestCase):
    def test_successor_workflow_has_one_same_run_protected_path(self):
        workflow = Path(
            ".github/workflows/current-observation-dispatch-relay.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("issues:", workflow)
        self.assertIn("types: [opened]", workflow)
        self.assertIn("  consume:\n    needs: validation\n", workflow)
        self.assertIn(
            "  current-observation-protected:\n    needs: consume\n",
            workflow,
        )
        self.assertIn("environment: phase-2-allocator", workflow)
        self.assertIn("issues: write", workflow)
        self.assertIn("issues: read", workflow)
        self.assertNotIn("actions: write", workflow)
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertIn("current_observation_dispatch_relay consume", workflow)
        self.assertIn("current_observation_dispatch_relay protected", workflow)
        self.assertIn(
            "group: current-observation-relay-${{ github.event.issue.id }}",
            workflow,
        )

    def test_no_outbound_dispatch_transport_survives(self):
        source = Path("phase2/current_observation_dispatch_relay.py").read_text(
            encoding="utf-8"
        )
        for forbidden in (
            "dispatch_current_observation",
            "DISPATCH_ENDPOINT",
            "SENT_OR_ACCEPTANCE_UNKNOWN",
            "workflow_run_id",
            "actions/workflows",
        ):
            self.assertNotIn(forbidden, source)

    def test_superseded_phase2_current_observation_route_is_absent(self):
        workflow = Path(".github/workflows/phase2-adversarial.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("current_observation", workflow)
        self.assertIn("operator_preflight", workflow)
        self.assertIn("live_scenario_suite", workflow)

    def test_read_side_connection_failure_is_structured(self):
        def fail_factory(host: str, port: int, timeout: int):
            raise OSError("no connection constructed")

        api = relay.GitHubRelayAPI("token", connection_factory=fail_factory)
        with self.assertRaisesRegex(relay.RelayError, "REQUEST_ISSUE_READ_FAILED"):
            api.get_issue(99)


if __name__ == "__main__":
    unittest.main()
