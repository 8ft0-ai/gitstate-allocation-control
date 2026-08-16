import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import phase2.workstream_d_live as live
import phase2.workstream_d_revocation as remediation
from phase2.adversarial import CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID
from phase2.credentials import control_profile, state_profile


TRUSTED_SHA = "a" * 40
RUN_ID = 31990000000


def valid_environment():
    return {
        "GITHUB_REPOSITORY": live.CONTROL_REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": TRUSTED_SHA,
        "EXPECTED_CONTROL_SHA": TRUSTED_SHA,
        "EXPECTED_PROTOCOL_SHA": live.PROTOCOL_AUTHORITY,
        "GITHUB_RUN_ID": str(RUN_ID),
        "GITHUB_RUN_ATTEMPT": "1",
        "ATTEMPT_NONCE": "abc123",
        "PHASE2_WORKSTREAM_D_EXECUTION_ENABLED": "true",
        "PHASE2_WORKSTREAM_D_FIXTURE_MODE": live.FIXTURE_MODE,
    }


class RecordingAPI:
    def __init__(self, token, api_url, calls, fail_token=None):
        self.token = token
        self.api_url = api_url
        self.calls = calls
        self.fail_token = fail_token

    def request(self, method, path, body=None):
        self.calls.append((self.token, method, path))
        if self.token == self.fail_token:
            raise RuntimeError("injected revoke failure")
        return None, {}


def lease(calls, *, fail_token=None):
    factory = lambda token, api_url: RecordingAPI(
        token, api_url, calls, fail_token=fail_token
    )
    return remediation.TruthfulCredentialLease(
        "control-token",
        "state-token",
        (
            live._scope_evidence(control_profile(CONTROL_REPOSITORY_ID)),
            live._scope_evidence(state_profile(STATE_REPOSITORY_ID)),
        ),
        "https://api.github.com",
        factory,
    )


class WorkstreamDRevocationRemediationTests(unittest.TestCase):
    def tearDown(self):
        remediation.TruthfulCredentialLease.last_instance = None

    def test_revoked_true_only_after_both_revocations_succeed(self):
        calls = []
        token_lease = lease(calls)
        token_lease.close()
        self.assertEqual(
            calls,
            [
                ("state-token", "DELETE", "/installation/token"),
                ("control-token", "DELETE", "/installation/token"),
            ],
        )
        self.assertEqual(token_lease.state_token, "")
        self.assertEqual(token_lease.control_token, "")
        self.assertEqual(token_lease.revoked_token_count, 2)
        self.assertTrue(token_lease.revocation_attempted)
        self.assertTrue(token_lease.revoked)
        self.assertIsNone(token_lease.revocation_error)

    def test_revocation_failure_attempts_both_clears_material_and_stays_unrevoked(self):
        calls = []
        token_lease = lease(calls, fail_token="state-token")
        with self.assertRaisesRegex(
            live.LiveExecutorError, "INSTALLATION_TOKEN_REVOCATION_FAILED"
        ):
            token_lease.close()
        self.assertEqual(
            calls,
            [
                ("state-token", "DELETE", "/installation/token"),
                ("control-token", "DELETE", "/installation/token"),
            ],
        )
        self.assertEqual(token_lease.state_token, "")
        self.assertEqual(token_lease.control_token, "")
        self.assertEqual(token_lease.revoked_token_count, 1)
        self.assertTrue(token_lease.revocation_attempted)
        self.assertFalse(token_lease.revoked)
        self.assertIsNotNone(token_lease.revocation_error)

    def test_primary_error_with_successful_revocation_emits_positive_cleanup_record(self):
        calls = []

        def failing_base(values):
            token_lease = lease(calls)
            try:
                raise RuntimeError("PRIMARY_FAILURE")
            finally:
                token_lease.close()

        output = io.StringIO()
        with patch.object(live, "execute_live_suite", side_effect=failing_base):
            with redirect_stdout(output):
                with self.assertRaisesRegex(RuntimeError, "PRIMARY_FAILURE"):
                    remediation.execute_live_suite(valid_environment())

        records = [json.loads(line) for line in output.getvalue().splitlines() if line]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], remediation.REVOCATION_STATUS)
        self.assertEqual(records[0]["installation_tokens_revoked"], 2)
        self.assertTrue(records[0]["credential_revoked"])
        self.assertFalse(records[0]["credential_material_emitted"])
        self.assertFalse(records[0]["workstream_e_authorised"])

    def test_revocation_failure_overrides_primary_error_and_emits_no_success_record(self):
        calls = []

        def failing_base(values):
            token_lease = lease(calls, fail_token="state-token")
            primary_error = RuntimeError("PRIMARY_FAILURE")
            try:
                token_lease.close()
            except Exception:
                pass
            raise primary_error

        output = io.StringIO()
        with patch.object(live, "execute_live_suite", side_effect=failing_base):
            with redirect_stdout(output):
                with self.assertRaisesRegex(
                    live.LiveExecutorError,
                    "INSTALLATION_TOKEN_REVOCATION_FAILED",
                ):
                    remediation.execute_live_suite(valid_environment())

        self.assertEqual(output.getvalue(), "")
        self.assertEqual(
            calls,
            [
                ("state-token", "DELETE", "/installation/token"),
                ("control-token", "DELETE", "/installation/token"),
            ],
        )

    def test_wrapper_restores_base_lease_class_after_execution(self):
        original = live.CredentialLease

        def successful_base(values):
            token_lease = live.CredentialLease(
                "control-token",
                "state-token",
                (
                    live._scope_evidence(control_profile(CONTROL_REPOSITORY_ID)),
                    live._scope_evidence(state_profile(STATE_REPOSITORY_ID)),
                ),
                "https://api.github.com",
                lambda token, api_url: RecordingAPI(token, api_url, []),
            )
            token_lease.close()
            return live.LiveSuiteResult(
                RUN_ID,
                1,
                f"wd-{RUN_ID}-1-abc123",
                TRUSTED_SHA,
                live.PROTOCOL_AUTHORITY,
                14,
                (),
                "f" * 64,
                True,
                True,
            )

        with patch.object(live, "execute_live_suite", side_effect=successful_base):
            with redirect_stdout(io.StringIO()):
                remediation.execute_live_suite(valid_environment())
        self.assertIs(live.CredentialLease, original)

    def test_remediation_entrypoint_is_bound_into_executable_identity_evidence(self):
        original = live.LIVE_EXECUTABLE_PATHS
        try:
            remediation._bind_executable_identity()
            self.assertIn(
                remediation.REMEDIATION_EXECUTABLE_PATH,
                live.LIVE_EXECUTABLE_PATHS,
            )
            self.assertEqual(
                live.LIVE_EXECUTABLE_PATHS.count(
                    remediation.REMEDIATION_EXECUTABLE_PATH
                ),
                1,
            )
        finally:
            live.LIVE_EXECUTABLE_PATHS = original

    def test_workflow_routes_only_live_execution_to_revocation_wrapper(self):
        workflow = Path(".github/workflows/phase2-adversarial.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'PYTHONPATH=. "$RUNTIME_PYTHON" -m phase2.workstream_d_revocation',
            workflow,
        )
        self.assertIn(
            "from phase2.workstream_d_live import context_from_environment",
            workflow,
        )
        self.assertNotIn(
            'PYTHONPATH=. "$RUNTIME_PYTHON" -m phase2.workstream_d_live\n',
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
