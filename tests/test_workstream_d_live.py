import base64
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import phase2.workstream_d_live as live
from phase2.adversarial import CONTROL_REPOSITORY_ID, SCENARIO_IDS, STATE_REPOSITORY_ID
from phase2.credentials import control_profile, state_profile


TRUSTED_SHA = "a" * 40
PROTOCOL_SHA = live.PROTOCOL_AUTHORITY
RUN_ID = 31950000000


def encoded_inventory(*, repository_ids=(CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID), audited_at=None):
    value = {
        "app_id": 123,
        "installation_id": 456,
        "repository_selection": "selected",
        "repository_ids": list(repository_ids),
        "audited_at": (audited_at or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z"),
    }
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")


def valid_context(**overrides):
    values = dict(
        repository=live.CONTROL_REPOSITORY,
        ref="refs/heads/main",
        trusted_sha=TRUSTED_SHA,
        expected_control_sha=TRUSTED_SHA,
        protocol_sha=PROTOCOL_SHA,
        expected_protocol_sha=PROTOCOL_SHA,
        run_id=RUN_ID,
        run_attempt=1,
        attempt_nonce="abc123",
        enabled=True,
        fixture_mode=live.FIXTURE_MODE,
    )
    values.update(overrides)
    return live.LiveRunContext(**values)


class GuardedEnvironment(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.secret_read = False

    def __getitem__(self, key):
        if key == "PHASE2_ALLOCATOR_APP_PRIVATE_KEY":
            self.secret_read = True
        return super().__getitem__(key)


class FakeAPI:
    def __init__(self, token, api_url, calls):
        self.token = token
        self.api_url = api_url
        self.calls = calls

    def request(self, method, path, body=None):
        self.calls.append((self.token, method, path))
        return None, {}


class WorkstreamDLiveBoundaryTests(unittest.TestCase):
    def test_live_gate_accepts_only_exact_fixture_main_first_attempt(self):
        namespace = valid_context().validate()
        self.assertEqual(namespace.value, f"wd-{RUN_ID}-1-abc123")
        cases = (
            {"repository": "8ft0-ai/other"},
            {"ref": "refs/heads/feature"},
            {"trusted_sha": "b" * 40},
            {"protocol_sha": "c" * 40},
            {"run_attempt": 2},
            {"enabled": False},
            {"fixture_mode": "runtime"},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaises(Exception):
                    valid_context(**overrides).validate()

    def test_invalid_gate_never_reads_allocator_private_key(self):
        env = GuardedEnvironment(
            GITHUB_REPOSITORY=live.CONTROL_REPOSITORY,
            GITHUB_REF="refs/heads/not-main",
            GITHUB_SHA=TRUSTED_SHA,
            EXPECTED_CONTROL_SHA=TRUSTED_SHA,
            EXPECTED_PROTOCOL_SHA=PROTOCOL_SHA,
            GITHUB_RUN_ID=str(RUN_ID),
            GITHUB_RUN_ATTEMPT="1",
            ATTEMPT_NONCE="abc123",
            PHASE2_WORKSTREAM_D_EXECUTION_ENABLED="true",
            PHASE2_WORKSTREAM_D_FIXTURE_MODE=live.FIXTURE_MODE,
            PHASE2_ALLOCATOR_APP_PRIVATE_KEY="must-not-be-read",
        )
        with self.assertRaises(Exception):
            live.execute_live_suite(env)
        self.assertFalse(env.secret_read)

    def test_inventory_is_exact_current_two_repository_attestation(self):
        now = datetime.now(timezone.utc)
        accepted = live._decode_inventory(
            encoded_inventory(audited_at=now), app_id=123, installation_id=456, now=now
        )
        self.assertEqual(set(accepted.attestation.repository_ids), {CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID})
        for repositories in ((CONTROL_REPOSITORY_ID,), (CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID, 999)):
            with self.subTest(repositories=repositories):
                with self.assertRaises(Exception):
                    live._decode_inventory(
                        encoded_inventory(repository_ids=repositories, audited_at=now),
                        app_id=123,
                        installation_id=456,
                        now=now,
                    )
        with self.assertRaises(Exception):
            live._decode_inventory(
                encoded_inventory(audited_at=now - timedelta(hours=1)),
                app_id=123,
                installation_id=456,
                now=now,
            )

    def test_token_profiles_remain_exact_single_repository_profiles(self):
        control = control_profile(CONTROL_REPOSITORY_ID)
        state = state_profile(STATE_REPOSITORY_ID)
        self.assertEqual(control.repository_id, CONTROL_REPOSITORY_ID)
        self.assertEqual(control.permissions, {"contents": "read", "issues": "write", "metadata": "read"})
        self.assertEqual(state.repository_id, STATE_REPOSITORY_ID)
        self.assertEqual(state.permissions, {"contents": "write", "metadata": "read"})
        for record in (live._scope_evidence(control), live._scope_evidence(state)):
            record.validate()
            self.assertEqual(len(record.requested_repository_ids), 1)
            self.assertEqual(record.requested_repository_ids, record.returned_repository_ids)

    def test_lease_revokes_both_temporary_installation_tokens_and_clears_memory(self):
        calls = []
        factory = lambda token, api_url: FakeAPI(token, api_url, calls)
        lease = live.CredentialLease(
            "control-token",
            "state-token",
            (live._scope_evidence(control_profile(CONTROL_REPOSITORY_ID)), live._scope_evidence(state_profile(STATE_REPOSITORY_ID))),
            "https://api.github.com",
            factory,
        )
        lease.close()
        self.assertEqual(
            calls,
            [
                ("state-token", "DELETE", "/installation/token"),
                ("control-token", "DELETE", "/installation/token"),
            ],
        )
        self.assertEqual(lease.control_token, "")
        self.assertEqual(lease.state_token, "")
        self.assertTrue(lease.revoked)

    def test_state_remote_never_embeds_installation_token_in_url_or_git_config_value(self):
        self.assertEqual(live._remote_url(), "https://github.com/8ft0-ai/gitstate-allocation-state.git")
        self.assertNotIn("fixture-token", live._remote_url())
        with TemporaryDirectory() as directory:
            env = live._state_git_env(Path(directory), "fixture-token")
            script = Path(env["GIT_ASKPASS"]).read_text(encoding="utf-8")
            self.assertNotIn("fixture-token", script)
            self.assertEqual(env["PHASE2_STATE_TOKEN"], "fixture-token")

    def test_unexpected_canonical_state_fails_closed_before_bootstrap(self):
        with TemporaryDirectory() as directory:
            with patch.object(live, "_run", return_value="a" * 40 + "\trefs/dolt/data"):
                with self.assertRaisesRegex(live.LiveExecutorError, "UNEXPECTED_CANONICAL_STATE"):
                    live.assert_uninitialised_state("fixture-token", root=Path(directory))

    def test_only_scenarios_one_through_fourteen_are_dispatchable(self):
        self.assertEqual(tuple(SCENARIO_IDS), tuple(range(1, 15)))
        self.assertNotIn(15, SCENARIO_IDS)
        self.assertEqual(live.CONTROL_REPOSITORY_ID, CONTROL_REPOSITORY_ID)
        self.assertEqual(live.STATE_REPOSITORY_ID, STATE_REPOSITORY_ID)

    def test_live_module_is_not_imported_by_normal_phase2_package(self):
        package = Path("phase2/__init__.py").read_text(encoding="utf-8")
        self.assertNotIn("workstream_d_live", package)
        policy = json.loads(Path("policy/actors.json").read_text(encoding="utf-8"))
        self.assertEqual(policy["github_apps"], [])

    def test_workflow_keeps_pr_validation_credential_free_and_live_path_protected(self):
        workflow = Path(".github/workflows/phase2-adversarial.yml").read_text(encoding="utf-8")
        self.assertIn("live_scenario_suite", workflow)
        self.assertIn("environment: phase-2-allocator", workflow)
        self.assertIn("PHASE2_WORKSTREAM_D_FIXTURE_MODE", workflow)
        self.assertIn("PHASE2_OWNER_INVENTORY_ATTESTATION_B64", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertNotIn("pull_request:", workflow)
        contract = workflow.split("live-scenario-suite:", 1)[0]
        self.assertNotIn("PHASE2_ALLOCATOR_APP_PRIVATE_KEY", contract)

    def test_result_boundary_never_authorises_production_or_workstream_e(self):
        result = live.LiveSuiteResult(
            RUN_ID,
            1,
            f"wd-{RUN_ID}-1-abc123",
            TRUSTED_SHA,
            PROTOCOL_SHA,
            14,
            tuple("a" * 64 for _ in range(14)),
            "b" * 64,
            True,
            True,
        ).payload()
        self.assertFalse(result["production_approval"])
        self.assertFalse(result["workstream_e_authorised"])
        self.assertTrue(result["credential_revocation_required"])
        self.assertTrue(result["enablement_removal_required"])


if __name__ == "__main__":
    unittest.main()
