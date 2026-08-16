import inspect
import io
import json
import os
import subprocess
import sys
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import phase2.workstream_d_live as live
import phase2.workstream_d_remediated as remediation
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
        "BD_BIN": "/tmp/bd",
        "DOLT_BIN": "/tmp/dolt",
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
    return remediation.CredentialLease(
        "control-token",
        "state-token",
        (
            live._scope_evidence(control_profile(CONTROL_REPOSITORY_ID)),
            live._scope_evidence(state_profile(STATE_REPOSITORY_ID)),
        ),
        "https://api.github.com",
        factory,
    )


class WorkstreamDFailedAttemptRemediationTests(unittest.TestCase):
    def test_writable_dolt_server_receives_existing_state_git_auth_environment(self):
        captured = {}

        class FakeProcess:
            pass

        def fake_popen(command, **kwargs):
            captured["command"] = tuple(command)
            captured["kwargs"] = kwargs
            return FakeProcess()

        fake_pymysql = types.SimpleNamespace()
        credential_env = {
            "PATH": os.environ.get("PATH", ""),
            "GIT_ASKPASS": "/tmp/state-askpass.sh",
            "GIT_TERMINAL_PROMPT": "0",
            "PHASE2_STATE_TOKEN": "state-token",
        }
        with TemporaryDirectory() as directory:
            database = Path(directory) / "canonical"
            database.mkdir()
            with (
                patch.dict(sys.modules, {"pymysql": fake_pymysql}),
                patch.object(subprocess, "Popen", side_effect=fake_popen),
                patch.object(
                    remediation.WritableManagedDoltConnection,
                    "_connect",
                    return_value=object(),
                ),
            ):
                connection = remediation.WritableManagedDoltConnection(
                    database, "/tmp/dolt", credential_env
                )
            try:
                server_env = captured["kwargs"]["env"]
                self.assertEqual(server_env["PHASE2_STATE_TOKEN"], "state-token")
                self.assertEqual(server_env["GIT_ASKPASS"], "/tmp/state-askpass.sh")
                self.assertEqual(server_env["GIT_TERMINAL_PROMPT"], "0")
                self.assertEqual(captured["command"][1], "sql-server")
            finally:
                connection.log.close()

    def test_writable_dolt_auth_environment_is_local_and_fails_closed_if_incomplete(self):
        with patch.dict(os.environ, {}, clear=True):
            environment = remediation._writable_dolt_server_env(
                {
                    "GIT_ASKPASS": "/tmp/askpass",
                    "GIT_TERMINAL_PROMPT": "0",
                    "PHASE2_STATE_TOKEN": "state-token",
                }
            )
            self.assertEqual(environment["PHASE2_STATE_TOKEN"], "state-token")
            self.assertNotIn("PHASE2_STATE_TOKEN", os.environ)
        with self.assertRaisesRegex(
            live.LiveExecutorError, "WRITABLE_DOLT_GIT_AUTH_ENV_MISSING"
        ):
            remediation._writable_dolt_server_env(
                {"GIT_ASKPASS": "/tmp/askpass", "GIT_TERMINAL_PROMPT": "0"}
            )

    def test_read_only_reconstruction_remains_on_base_credential_free_connection(self):
        source = inspect.getsource(live.LiveFixtureBackend._fresh_git_reconstruction)
        self.assertIn("_credential_free_git_env()", source)
        self.assertIn(
            "ManagedDoltConnection(database, self.repository.dolt_bin)", source
        )
        self.assertNotIn("WritableManagedDoltConnection", source)

    def test_revoked_becomes_true_only_after_both_revocations_succeed(self):
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
        self.assertTrue(token_lease.revoked)

    def test_revocation_failure_attempts_both_clears_material_and_remains_unrevoked(self):
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
        self.assertFalse(token_lease.revoked)
        with self.assertRaisesRegex(
            live.LiveExecutorError, "INSTALLATION_TOKEN_REVOCATION_FAILED"
        ):
            token_lease.close()
        self.assertFalse(token_lease.revoked)

    def test_primary_failure_with_successful_revocation_emits_positive_cleanup_record(self):
        calls = []
        token_lease = lease(calls)
        output = io.StringIO()
        with (
            patch.object(
                remediation,
                "acquire_credentials",
                return_value=(token_lease, object()),
            ),
            patch.object(
                remediation,
                "bootstrap_fixture_repository",
                side_effect=RuntimeError("PRIMARY_FAILURE"),
            ),
            redirect_stdout(output),
        ):
            with self.assertRaisesRegex(RuntimeError, "PRIMARY_FAILURE"):
                remediation.execute_live_suite(valid_environment())

        records = [json.loads(line) for line in output.getvalue().splitlines() if line]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], remediation.REVOCATION_STATUS)
        self.assertTrue(records[0]["credential_revoked"])
        self.assertEqual(records[0]["installation_tokens_revoked"], 2)
        self.assertFalse(records[0]["credential_material_emitted"])
        self.assertTrue(token_lease.revoked)

    def test_revocation_failure_supersedes_primary_failure_and_emits_no_success_marker(self):
        calls = []
        token_lease = lease(calls, fail_token="state-token")
        output = io.StringIO()
        with (
            patch.object(
                remediation,
                "acquire_credentials",
                return_value=(token_lease, object()),
            ),
            patch.object(
                remediation,
                "bootstrap_fixture_repository",
                side_effect=RuntimeError("PRIMARY_FAILURE"),
            ),
            redirect_stdout(output),
        ):
            with self.assertRaisesRegex(
                live.LiveExecutorError, "INSTALLATION_TOKEN_REVOCATION_FAILED"
            ):
                remediation.execute_live_suite(valid_environment())

        self.assertEqual(output.getvalue(), "")
        self.assertEqual(token_lease.state_token, "")
        self.assertEqual(token_lease.control_token, "")
        self.assertFalse(token_lease.revoked)

    def test_remediation_entrypoint_is_bound_into_executable_identity_evidence(self):
        original = live.LIVE_EXECUTABLE_PATHS
        try:
            remediation._bind_executable_identity()
            self.assertIn(remediation.REMEDIATION_EXECUTABLE_PATH, live.LIVE_EXECUTABLE_PATHS)
            self.assertEqual(
                live.LIVE_EXECUTABLE_PATHS.count(
                    remediation.REMEDIATION_EXECUTABLE_PATH
                ),
                1,
            )
        finally:
            live.LIVE_EXECUTABLE_PATHS = original

    def test_adversarial_workflow_executes_remediated_module_only_in_live_suite_step(self):
        workflow = Path(".github/workflows/phase2-adversarial.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'PYTHONPATH=. "$RUNTIME_PYTHON" -m phase2.workstream_d_remediated',
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
