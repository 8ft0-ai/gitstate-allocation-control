import base64
import hashlib
import hmac
import json
import os
import shlex
import subprocess
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import phase2.workstream_d_live as live
import phase2.workstream_d_revocation as remediation
from phase2.credentials import (
    CredentialPolicyError,
    require_state_repository_access,
)
from phase2.github_api import GitHubAPIError


class FakeRepositoryAPI:
    def __init__(self, payload=None, error=None):
        self.payload = payload
        self.error = error
        self.paths = []

    def get(self, path):
        self.paths.append(path)
        if self.error is not None:
            raise self.error
        return self.payload


class LeaseAPI:
    def __init__(self, token, api_url, calls, repository_payload):
        self.token = token
        self.api_url = api_url
        self.calls = calls
        self.repository_payload = repository_payload

    def get(self, path):
        self.calls.append(("GET", path))
        return self.repository_payload

    def request(self, method, path, body=None):
        self.calls.append((method, path))
        return None, {}


def _start_basic_challenge(expected_password):
    evidence = {
        "authorised": False,
        "username_exact": False,
        "password_exact": False,
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            header = self.headers.get("Authorization", "")
            if header.startswith("Basic "):
                try:
                    raw = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
                    username, password = raw.split(":", 1)
                except (ValueError, UnicodeDecodeError):
                    username, password = "", ""
                evidence["authorised"] = True
                evidence["username_exact"] = hmac.compare_digest(
                    username, "x-access-token"
                )
                evidence["password_exact"] = hmac.compare_digest(
                    password, expected_password
                )
                raw = username = password = ""
                if evidence["username_exact"] and evidence["password_exact"]:
                    body = b"001e# service=git-upload-pack\n0000"
                    self.send_response(200)
                    self.send_header(
                        "Content-Type", "application/x-git-upload-pack-advertisement"
                    )
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="workstream-d-test"')
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, evidence


class WorkstreamDStateAuthDiagnosticTests(unittest.TestCase):
    def test_same_token_rest_probe_accepts_only_exact_state_repository_identity(self):
        expected_id = live.STATE_REPOSITORY_ID
        api = FakeRepositoryAPI(
            {"id": expected_id, "full_name": live.STATE_REPOSITORY}
        )
        require_state_repository_access(
            "fixture-token",
            "8ft0-ai",
            "gitstate-allocation-state",
            expected_id,
            "https://api.github.invalid",
            api_factory=lambda token, url: api,
        )
        self.assertEqual(api.paths, ["/repos/8ft0-ai/gitstate-allocation-state"])

        mismatches = (
            {"id": expected_id + 1, "full_name": live.STATE_REPOSITORY},
            {"id": expected_id, "full_name": "8ft0-ai/not-state"},
            None,
        )
        for payload in mismatches:
            with self.subTest(payload=payload):
                bad_api = FakeRepositoryAPI(payload)
                with self.assertRaisesRegex(
                    CredentialPolicyError,
                    "REST_STATE_REPOSITORY_IDENTITY_MISMATCH",
                ):
                    require_state_repository_access(
                        "fixture-token",
                        "8ft0-ai",
                        "gitstate-allocation-state",
                        expected_id,
                        "https://api.github.invalid",
                        api_factory=lambda token, url, api=bad_api: api,
                    )

    def test_same_token_rest_probe_denial_is_body_free_and_fail_closed(self):
        secret_body = "SECRET_RESPONSE_BODY_MUST_NOT_SURVIVE"
        for status in (403, 404):
            with self.subTest(status=status):
                api = FakeRepositoryAPI(error=GitHubAPIError(status, secret_body))
                with self.assertRaises(CredentialPolicyError) as raised:
                    require_state_repository_access(
                        "fixture-token",
                        "8ft0-ai",
                        "gitstate-allocation-state",
                        live.STATE_REPOSITORY_ID,
                        "https://api.github.invalid",
                        api_factory=lambda token, url, api=api: api,
                    )
                self.assertEqual(
                    str(raised.exception), "REST_STATE_REPOSITORY_ACCESS_DENIED"
                )
                self.assertIsNone(raised.exception.__context__)
                self.assertNotIn(secret_body, str(raised.exception))

    def test_state_access_wrapper_revokes_both_tokens_when_probe_fails(self):
        calls = []
        factory = lambda token, url: LeaseAPI(
            token,
            url,
            calls,
            {"id": live.STATE_REPOSITORY_ID + 1, "full_name": live.STATE_REPOSITORY},
        )
        lease = remediation.TruthfulCredentialLease(
            "control-fixture-token",
            "state-fixture-token",
            (),
            "https://api.github.invalid",
            factory,
        )
        wrapped = remediation._state_access_acquire(
            lambda *args, **kwargs: (lease, object())
        )
        with self.assertRaisesRegex(
            CredentialPolicyError, "REST_STATE_REPOSITORY_IDENTITY_MISMATCH"
        ):
            wrapped({}, object())
        self.assertEqual(lease.control_token, "")
        self.assertEqual(lease.state_token, "")
        self.assertTrue(lease.revoked)
        self.assertEqual(lease.revoked_token_count, 2)
        self.assertEqual(
            calls,
            [
                ("GET", "/repos/8ft0-ai/gitstate-allocation-state"),
                ("DELETE", "/installation/token"),
                ("DELETE", "/installation/token"),
            ],
        )

    def _git_auth_probe(self, token, *, askpass_mode="valid"):
        server, thread, evidence = _start_basic_challenge(token)
        try:
            with TemporaryDirectory() as directory:
                root = Path(directory)
                helper_marker = root / "helper-used"
                helper = root / "unrelated-helper.sh"
                helper.write_text(
                    "#!/bin/sh\n"
                    f"touch {shlex.quote(str(helper_marker))}\n"
                    "case \"$1\" in get) printf 'username=helper-user\\npassword=helper-password\\n' ;; esac\n",
                    encoding="utf-8",
                )
                helper.chmod(0o700)
                isolated_process_env = {
                    "PATH": os.environ.get("PATH", ""),
                    "LANG": os.environ.get("LANG", "C.UTF-8"),
                    "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": "credential.helper",
                    "GIT_CONFIG_VALUE_0": f"!{helper}",
                }
                with patch.dict(os.environ, isolated_process_env, clear=True):
                    with remediation._isolated_git_credentials():
                        env = live._state_git_env(root, token)
                        askpass = Path(env["GIT_ASKPASS"])
                        if askpass_mode == "missing":
                            askpass.unlink()
                        elif askpass_mode == "wrong":
                            askpass.write_text(
                                "#!/bin/sh\n"
                                "case \"$1\" in *Username*) printf '%s\\n' wrong-user ;; *) printf '%s\\n' wrong-password ;; esac\n",
                                encoding="utf-8",
                            )
                            askpass.chmod(0o700)
                        url = (
                            f"http://127.0.0.1:{server.server_address[1]}/state.git"
                        )
                        if askpass_mode == "valid":
                            completed = subprocess.run(
                                ["git", "ls-remote", "--refs", url],
                                cwd=root,
                                env=env,
                                check=False,
                                text=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                            )
                            diagnostic = {
                                "return_code": completed.returncode,
                                "stderr_sha256": hashlib.sha256(
                                    completed.stderr.encode(
                                        "utf-8", errors="replace"
                                    )
                                ).hexdigest(),
                            }
                        else:
                            with self.assertRaises(live.CommandFailure) as raised:
                                live._run(
                                    ["git", "ls-remote", "--refs", url],
                                    cwd=root,
                                    env=env,
                                    phase="state-baseline-probe",
                                )
                            diagnostic = raised.exception.safe_diagnostic()
                return evidence, helper_marker.exists(), diagnostic
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()

    def test_git_askpass_presents_exact_basic_credentials_for_variable_token_formats(self):
        tokens = (
            "ghs_short-variable-token",
            "ghs_1234567890.eyJhbGciOiJSUzI1NiJ9." + "a" * 96,
            "fixture-installation-token-with-non-40-length-123456789",
        )
        for token in tokens:
            with self.subTest(token_length=len(token)):
                evidence, helper_used, diagnostic = self._git_auth_probe(token)
                self.assertTrue(evidence["authorised"])
                self.assertTrue(evidence["username_exact"])
                self.assertTrue(evidence["password_exact"])
                self.assertFalse(helper_used)
                self.assertNotIn(token, json.dumps(diagnostic, sort_keys=True))
                self.assertEqual(len(diagnostic["stderr_sha256"]), 64)

    def test_missing_or_wrong_askpass_fails_without_helper_or_secret_diagnostics(self):
        token = "ghs_fixture-secret-that-must-not-appear-in-diagnostics"
        for mode in ("missing", "wrong"):
            with self.subTest(mode=mode):
                evidence, helper_used, diagnostic = self._git_auth_probe(
                    token, askpass_mode=mode
                )
                self.assertFalse(helper_used)
                self.assertEqual(
                    diagnostic["failure_phase"], "state-baseline-probe"
                )
                self.assertEqual(diagnostic["executable"], "git")
                self.assertNotEqual(diagnostic["return_code"], 0)
                self.assertEqual(len(diagnostic["stderr_sha256"]), 64)
                self.assertNotIn(token, json.dumps(diagnostic, sort_keys=True))
                if mode == "wrong":
                    self.assertTrue(evidence["authorised"])
                    self.assertFalse(evidence["username_exact"])
                    self.assertFalse(evidence["password_exact"])
                else:
                    self.assertFalse(evidence["authorised"])

    def test_git_credential_isolation_preserves_other_git_config_and_restores_environment(self):
        initial = {
            "PATH": os.environ.get("PATH", ""),
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.sslVerify",
            "GIT_CONFIG_VALUE_0": "false",
        }
        with patch.dict(os.environ, initial, clear=True):
            with remediation._isolated_git_credentials():
                self.assertEqual(os.environ["GIT_CONFIG_COUNT"], "2")
                self.assertEqual(os.environ["GIT_CONFIG_KEY_0"], "http.sslVerify")
                self.assertEqual(os.environ["GIT_CONFIG_VALUE_0"], "false")
                self.assertEqual(os.environ["GIT_CONFIG_KEY_1"], "credential.helper")
                self.assertEqual(os.environ["GIT_CONFIG_VALUE_1"], "")
            self.assertEqual(dict(os.environ), initial)


if __name__ == "__main__":
    unittest.main()
