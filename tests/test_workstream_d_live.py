import base64
import inspect
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import phase2.workstream_d_live as live
from phase2.adversarial import (
    CONTROL_REPOSITORY_ID,
    EXPECTED_FAULT_OUTCOMES,
    SCENARIO_IDS,
    STATE_REPOSITORY_ID,
    scenario_by_id,
)
from phase2.credentials import control_profile, state_profile


TRUSTED_SHA = "a" * 40
PROTOCOL_SHA = live.PROTOCOL_AUTHORITY
RUN_ID = 31950000000


def encoded_inventory(
    *, repository_ids=(CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID), audited_at=None
):
    value = {
        "app_id": 123,
        "installation_id": 456,
        "repository_selection": "selected",
        "repository_ids": list(repository_ids),
        "audited_at": (audited_at or datetime.now(timezone.utc))
        .isoformat()
        .replace("+00:00", "Z"),
    }
    return base64.urlsafe_b64encode(
        json.dumps(value, separators=(",", ":")).encode()
    ).decode().rstrip("=")


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
        self.assertEqual(
            set(accepted.attestation.repository_ids),
            {CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID},
        )
        for repositories in (
            (CONTROL_REPOSITORY_ID,),
            (CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID, 999),
        ):
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
        self.assertEqual(
            control.permissions,
            {"contents": "read", "issues": "write", "metadata": "read"},
        )
        self.assertEqual(state.repository_id, STATE_REPOSITORY_ID)
        self.assertEqual(
            state.permissions, {"contents": "write", "metadata": "read"}
        )
        for record in (live._scope_evidence(control), live._scope_evidence(state)):
            record.validate()
            self.assertEqual(len(record.requested_repository_ids), 1)
            self.assertEqual(
                record.requested_repository_ids, record.returned_repository_ids
            )

    def test_lease_revokes_both_temporary_installation_tokens_and_clears_memory(self):
        calls = []
        factory = lambda token, api_url: FakeAPI(token, api_url, calls)
        lease = live.CredentialLease(
            "control-token",
            "state-token",
            (
                live._scope_evidence(control_profile(CONTROL_REPOSITORY_ID)),
                live._scope_evidence(state_profile(STATE_REPOSITORY_ID)),
            ),
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

    def test_fixture_repository_cleanup_removes_state_token_and_auth_helper(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            askpass = root / "state-askpass.sh"
            askpass.write_text("fixture")
            env = {"PHASE2_STATE_TOKEN": "secret", "GIT_ASKPASS": str(askpass)}
            fixture = live.FixtureRepositoryLease(object(), env, askpass)  # type: ignore[arg-type]
            fixture.close()
            self.assertNotIn("PHASE2_STATE_TOKEN", env)
            self.assertNotIn("GIT_ASKPASS", env)
            self.assertFalse(askpass.exists())

    def test_state_remote_never_embeds_installation_token_in_url_or_git_config_value(self):
        self.assertEqual(
            live._remote_url(),
            "https://github.com/8ft0-ai/gitstate-allocation-state.git",
        )
        self.assertNotIn("fixture-token", live._remote_url())
        with TemporaryDirectory() as directory:
            env = live._state_git_env(Path(directory), "fixture-token")
            script = Path(env["GIT_ASKPASS"]).read_text(encoding="utf-8")
            self.assertNotIn("fixture-token", script)
            self.assertEqual(env["PHASE2_STATE_TOKEN"], "fixture-token")

    def test_unexpected_canonical_state_fails_closed_before_bootstrap(self):
        with TemporaryDirectory() as directory:
            with patch.object(
                live, "_run", return_value="a" * 40 + "\trefs/dolt/data"
            ):
                with self.assertRaisesRegex(
                    live.LiveExecutorError, "UNEXPECTED_CANONICAL_STATE"
                ):
                    live.assert_uninitialised_state(
                        "fixture-token", root=Path(directory)
                    )

    def test_scenario_proof_cannot_synthesise_missing_assertions_or_faults(self):
        spec = scenario_by_id(1)
        proof = live.ScenarioProof(spec, valid_context().namespace)
        for index in range(len(spec.assertions)):
            proof.assertion(index, True, f"executed assertion {index}")
        with self.assertRaisesRegex(
            live.LiveExecutorError, "INCOMPLETE_FAULT_WITNESSES"
        ):
            proof.finalise()
        proof.fault(
            "close_timed_requests",
            True,
            EXPECTED_FAULT_OUTCOMES["close_timed_requests"],
        )
        assertions, faults = proof.finalise()
        self.assertEqual(tuple(item.name for item in assertions), spec.assertions)
        self.assertEqual(tuple(item.control for item in faults), spec.fault_controls)

    def test_scenario_proof_rejects_false_or_wrong_fault_outcome(self):
        spec = scenario_by_id(8)
        with self.assertRaisesRegex(live.LiveExecutorError, "FAULT_WITNESS_FAILED"):
            live.ScenarioProof(spec, valid_context().namespace).fault(
                "fail_projection_post", False, EXPECTED_FAULT_OUTCOMES["fail_projection_post"]
            )
        with self.assertRaisesRegex(live.LiveExecutorError, "FAULT_WITNESS_FAILED"):
            live.ScenarioProof(spec, valid_context().namespace).fault(
                "fail_projection_post", True, "not-the-contract-outcome"
            )

    def test_scenario13_identity_negatives_are_independent_and_reason_specific(self):
        policy = json.loads(Path("policy/actors.json").read_text(encoding="utf-8"))
        expected = {
            "missing_comment_app_attribution": "missing App attribution",
            "wrong_comment_app_id": "App attribution mismatch",
            "wrong_comment_app_slug": "App attribution mismatch",
            "wrong_bot_id": "unknown bot",
            "wrong_bot_login": "unknown bot",
            "misleading_event_installation": "missing App attribution",
            "human_namespace_impersonation": "human namespace mismatch",
        }
        for control, detail in expected.items():
            with self.subTest(control=control):
                self.assertEqual(
                    live._exercise_authorisation_negative(
                        control,
                        namespace=valid_context().namespace,
                        base_policy=policy,
                    ),
                    detail,
                )

    def test_scenario13_installation_negatives_do_not_mint_or_touch_canonical_state(self):
        for control in ("wrong_installation_mapping", "lost_control_repository_access"):
            with self.subTest(control=control):
                rejection, mint_calls, canonical_calls = live._exercise_installation_negative(
                    control
                )
                self.assertTrue(rejection)
                self.assertEqual(mint_calls, 0)
                self.assertEqual(canonical_calls, 0)

    def test_multi_repository_token_negative_is_real_multi_repository_shape(self):
        source = inspect.getsource(live.LiveFixtureBackend._scenario_13)
        self.assertIn(
            "(CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID)", source
        )
        self.assertNotIn('TokenProfile("control+state"', source)

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
        workflow = Path(".github/workflows/phase2-adversarial.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("live_scenario_suite", workflow)
        self.assertIn("environment: phase-2-allocator", workflow)
        self.assertIn("PHASE2_WORKSTREAM_D_FIXTURE_MODE", workflow)
        self.assertIn("PHASE2_OWNER_INVENTORY_ATTESTATION_B64", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertNotIn("pull_request:", workflow)
        contract = workflow.split("live-scenario-suite:", 1)[0]
        self.assertNotIn("PHASE2_ALLOCATOR_APP_PRIVATE_KEY", contract)

    def test_live_summary_is_pending_until_credential_revocation(self):
        source = inspect.getsource(live.execute_live_suite)
        self.assertIn("PENDING_CREDENTIAL_REVOCATION_AND_ENABLEMENT_REMOVAL", source)
        self.assertIn("lease.close()", source)
        main_source = inspect.getsource(live.main)
        self.assertIn("credential_revoked", main_source)

    def test_scenario14_supplies_both_clean_client_contracts(self):
        source = inspect.getsource(live.LiveFixtureBackend._scenario_14)
        self.assertIn("git_transcript", source)
        self.assertIn("api_transcript", source)
        self.assertIn("clients=(git_transcript, api_transcript)", source)

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

    def test_close_timed_scheduler_really_overlaps_calls(self):
        import threading

        lock = threading.Lock()
        both_entered = threading.Event()
        entered = 0

        def make(value):
            def call():
                nonlocal entered
                with lock:
                    entered += 1
                    if entered == 2:
                        both_entered.set()
                if not both_entered.wait(timeout=2):
                    raise AssertionError("close-timed calls did not overlap")
                return value
            return call

        values, spread = live._run_close_timed_calls((make("a"), make("b")))
        self.assertEqual(set(values), {"a", "b"})
        self.assertEqual(entered, 2)
        self.assertLessEqual(spread, live.CLOSE_TIMED_MAX_SECONDS)

    def test_queued_cancellation_really_prevents_callable_execution(self):
        executed = []
        self.assertTrue(live._cancel_queued_call(lambda: executed.append(True)))
        self.assertEqual(executed, [])

    def test_scenarios_1_2_and_3_bind_to_real_scheduling_helpers(self):
        scenario1 = inspect.getsource(live.LiveFixtureBackend._scenario_1)
        scenario2 = inspect.getsource(live.LiveFixtureBackend._scenario_2)
        scenario3 = inspect.getsource(live.LiveFixtureBackend._scenario_3)
        self.assertIn("_run_close_timed_calls", scenario1)
        self.assertIn("_run_close_timed_calls", scenario2)
        self.assertIn("_cancel_queued_call", scenario3)
        self.assertIn("queued_executed", scenario3)

    def test_pre_ingress_edit_uses_valid_request_authoriser_and_discovery_classifier(self):
        policy = json.loads(Path("policy/actors.json").read_text(encoding="utf-8"))
        request_id = "01J00000000000000000000000"
        original = {
            "protocol": "beads-allocation/v0.2",
            "type": "ALLOCATE_TASK",
            "request_id": request_id,
            "agent_id": "agent://operator/8ft0-ai/session/test",
            "task_id": "task-one",
        }
        edited = dict(original)
        edited["task_id"] = "task-two"
        original_body = "/beads-v0.2 " + json.dumps(
            original, sort_keys=True, separators=(",", ":")
        )
        edited_body = "/beads-v0.2 " + json.dumps(
            edited, sort_keys=True, separators=(",", ":")
        )
        comment = {
            "id": 123,
            "body": edited_body,
            "created_at": "2026-08-16T00:00:00Z",
            "updated_at": "2026-08-16T00:00:01Z",
            "user": {
                "login": live.FIXTURE_APP["actor_login"],
                "id": live.FIXTURE_APP["actor_id"],
                "type": "Bot",
            },
            "performed_via_github_app": {
                "id": live.FIXTURE_APP["app_id"],
                "slug": live.FIXTURE_APP["app_slug"],
            },
        }
        self.assertEqual(
            live._classify_edited_pre_ingress(
                comment,
                original_body=original_body,
                policy=policy,
            ),
            "SOURCE_COMMENT_EDITED_BEFORE_INGRESS",
        )

    def test_scenario_9_uses_accepted_pre_ingress_classifier(self):
        source = inspect.getsource(live.LiveFixtureBackend._scenario_9)
        self.assertIn("_classify_edited_pre_ingress", source)
        self.assertIn("SOURCE_COMMENT_EDITED_BEFORE_INGRESS", source)
        self.assertIn("/beads-v0.2 ", source)



if __name__ == "__main__":
    unittest.main()
