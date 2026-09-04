import hashlib
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import phase2.operator_runtime as runtime
import phase2.workstream_d_live as live
from phase2.operator_capsule import LIVE_PROFILE, PREFLIGHT_PROFILE, PROTOCOL_AUTHORITY_SHA, STATE_BASELINE_SHA
from phase2.operator_inventory import (
    CONTROL_REPOSITORY_ID,
    STATE_REPOSITORY_ID,
    InventoryEvidence,
)


TRUSTED_SHA = "a" * 40
RUN_ID = 32100000000
CAPSULE_ID = "b" * 32
CAPSULE_BODY_SHA = "c" * 64
CONSUMPTION_SHA = "d" * 64


def nonce():
    return hashlib.sha256(
        f"{RUN_ID}:1:{CAPSULE_ID}:{CAPSULE_BODY_SHA}".encode("ascii")
    ).hexdigest()[:16]


def valid_environment(operation="live_scenario_suite"):
    return {
        "GITHUB_REPOSITORY": live.CONTROL_REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": TRUSTED_SHA,
        "EXPECTED_CONTROL_SHA": TRUSTED_SHA,
        "EXPECTED_PROTOCOL_SHA": PROTOCOL_AUTHORITY_SHA,
        "EXPECTED_STATE_BASELINE": STATE_BASELINE_SHA,
        "GITHUB_RUN_ID": str(RUN_ID),
        "GITHUB_RUN_ATTEMPT": "1",
        "INPUT_OPERATION": operation,
        "OPERATION_PROFILE": LIVE_PROFILE if operation == "live_scenario_suite" else PREFLIGHT_PROFILE,
        "CAPSULE_ID": CAPSULE_ID,
        "CAPSULE_BODY_SHA256": CAPSULE_BODY_SHA,
        "CONSUMPTION_RECORD_SHA256": CONSUMPTION_SHA,
        "ATTEMPT_NONCE": nonce(),
        "PHASE2_POLICY": "policy/actors.json",
        "PHASE2_ALLOCATOR_APP_ID": "10",
        "PHASE2_ALLOCATOR_INSTALLATION_ID": "20",
        "PHASE2_STATE_REPOSITORY_ID": str(STATE_REPOSITORY_ID),
        "PHASE2_ALLOCATOR_APP_PRIVATE_KEY": "fixture-private-key",
        "PHASE2_WORKSTREAM_D_EXECUTION_ENABLED": "true",
        "PHASE2_WORKSTREAM_D_FIXTURE_MODE": live.FIXTURE_MODE,
        "GITHUB_API_URL": "https://api.github.invalid",
    }


def inventory_evidence():
    return InventoryEvidence(
        app_id=10,
        installation_id=20,
        repository_selection="selected",
        repository_ids=tuple(sorted((CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID))),
        audited_at="2026-08-18T12:00:00Z",
        run_id=RUN_ID,
        run_attempt=1,
        trusted_sha=TRUSTED_SHA,
        capsule_id=CAPSULE_ID,
        capsule_body_sha256=CAPSULE_BODY_SHA,
        inventory_token_permissions={"metadata": "read"},
        token_revoked=True,
        digest="e" * 64,
    )


class GuardedEnvironment(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.private_key_read = False

    def __getitem__(self, key):
        if key == "PHASE2_ALLOCATOR_APP_PRIVATE_KEY":
            self.private_key_read = True
        return super().__getitem__(key)


class FakeAppAPI:
    def get(self, path):
        if path.endswith("/installation"):
            return {
                "id": 20,
                "app_id": 10,
                "app_slug": "gitstate-phase-2-allocator",
                "repository_selection": "selected",
                "account": {"login": "8ft0-ai"},
            }
        raise AssertionError(path)


class OperatorRuntimeTests(unittest.TestCase):
    def test_legacy_runtime_preflight_is_retired_before_private_key_or_inventory_access(self):
        env = GuardedEnvironment(valid_environment("operator_preflight"))
        with patch.object(
            runtime,
            "_app_inventory_proof",
            side_effect=AssertionError("legacy preflight must not acquire inventory capability"),
        ), patch.object(runtime, "mint_token", side_effect=AssertionError("must not mint")):
            with self.assertRaisesRegex(
                runtime.OperatorRuntimeError,
                "OPERATOR_PREFLIGHT_PROJECTION_REQUIRED",
            ):
                runtime.preflight(env)
        self.assertFalse(env.private_key_read)

    def test_inventory_proof_precedes_existing_control_and_state_token_mints(self):
        env = valid_environment()
        context = runtime.context_from_environment(env)
        legacy = context.legacy_live_context(env)
        events = []

        def fake_inventory(*args, **kwargs):
            events.append("inventory-proved-and-revoked")
            return inventory_evidence()

        def fake_mint(api, installation_id, profile):
            events.append(f"mint-{profile.name}")
            return f"{profile.name}-token"

        with patch.object(runtime, "prove_installation_inventory", side_effect=fake_inventory), patch.object(
            runtime, "mint_token", side_effect=fake_mint
        ), patch.object(runtime, "require_cross_repository_denial"), patch.object(
            runtime, "require_public_repository_write_denial"
        ):
            lease, inventory = runtime._operator_acquire_credentials(
                env,
                legacy,
                api_factory=lambda token, url: FakeAppAPI(),
                jwt_factory=lambda app_id, key: "jwt",
            )

        self.assertEqual(
            events,
            ["inventory-proved-and-revoked", "mint-control", "mint-state"],
        )
        self.assertEqual(lease.control_token, "control-token")
        self.assertEqual(lease.state_token, "state-token")
        self.assertEqual(inventory.digest, "e" * 64)
        self.assertEqual(
            lease.token_scope_records[0].requested_repository_ids,
            (CONTROL_REPOSITORY_ID,),
        )
        self.assertEqual(
            lease.token_scope_records[1].requested_repository_ids,
            (STATE_REPOSITORY_ID,),
        )

    def test_live_adapter_pins_new_protocol_and_delegates_to_existing_revocation_stack(self):
        env = valid_environment()
        original_protocol = live.PROTOCOL_AUTHORITY
        original_acquire = live.acquire_credentials
        observed = {}

        def delegated(values):
            observed["protocol"] = live.PROTOCOL_AUTHORITY
            observed["acquire"] = live.acquire_credentials
            return live.LiveSuiteResult(
                RUN_ID,
                1,
                f"wd-{RUN_ID}-1-{nonce()}",
                TRUSTED_SHA,
                PROTOCOL_AUTHORITY_SHA,
                14,
                (),
                "e" * 64,
                True,
                True,
            )

        with patch.object(runtime.revocation, "execute_live_suite", side_effect=delegated):
            result = runtime.execute_live(env)

        self.assertEqual(observed["protocol"], PROTOCOL_AUTHORITY_SHA)
        self.assertIs(observed["acquire"], runtime._operator_acquire_credentials)
        self.assertEqual(result.protocol_sha, PROTOCOL_AUTHORITY_SHA)
        self.assertIs(live.acquire_credentials, original_acquire)
        self.assertEqual(live.PROTOCOL_AUTHORITY, original_protocol)
        self.assertIn(runtime.OPERATOR_EXECUTABLE_PATH, live.LIVE_EXECUTABLE_PATHS)

    def _run_main_with_live_error(self, exc):
        output = io.StringIO()
        with patch.object(runtime.sys, "argv", ["operator_runtime", "live"]), patch.object(
            runtime, "execute_live", side_effect=exc
        ), redirect_stdout(output):
            self.assertEqual(runtime.main(), 1)
        text = output.getvalue().strip()
        return text, json.loads(text)

    def test_structured_command_failure_output_is_whitelisted_and_non_secret(self):
        digest = hashlib.sha256(b"SECRET_STDERR_VALUE").hexdigest()
        exc = live.CommandFailure(
            "fixture-beads-init",
            "bd",
            17,
            digest,
        )
        text, payload = self._run_main_with_live_error(exc)
        self.assertEqual(
            payload,
            {
                "credential_material_emitted": False,
                "executable": "bd",
                "failure_phase": "fixture-beads-init",
                "reason_code": "COMMAND_FAILED",
                "return_code": 17,
                "status": "BLOCKED",
                "stderr_sha256": digest,
                "workstream_e_authorised": False,
            },
        )
        self.assertNotIn("SECRET_STDERR_VALUE", text)
        self.assertNotIn("token", text.lower())
        self.assertNotIn("private-key", text.lower())

    def test_structured_canonical_failure_output_is_phase_only(self):
        exc = live.FixtureBootstrapFailure("fixture-canonical-schema")
        text, payload = self._run_main_with_live_error(exc)
        self.assertEqual(
            payload,
            {
                "credential_material_emitted": False,
                "failure_phase": "fixture-canonical-schema",
                "reason_code": "FIXTURE_BOOTSTRAP_FAILED",
                "status": "BLOCKED",
                "workstream_e_authorised": False,
            },
        )
        self.assertNotIn("raw-cause", text)

    def test_unrelated_operator_error_retains_existing_reason_code_contract(self):
        _, payload = self._run_main_with_live_error(
            runtime.OperatorRuntimeError("OPERATOR_TEST_FAILURE:detail-not-retained")
        )
        self.assertEqual(payload["reason_code"], "OPERATOR_TEST_FAILURE")
        self.assertNotIn("failure_phase", payload)

    def test_workflow_has_projected_preflight_and_preserves_one_live_operator_entry(self):
        workflow = Path(".github/workflows/phase2-adversarial.yml").read_text(encoding="utf-8")
        self.assertIn("operator_preflight", workflow)
        self.assertIn("PYTHONPATH=. python3 -m phase2.preflight_runtime preflight", workflow)
        self.assertIn("PYTHONPATH=. python3 -m phase2.operator_capsule discover", workflow)
        self.assertIn("PYTHONPATH=. python3 -m phase2.operator_capsule consume", workflow)
        self.assertIn('PYTHONPATH=. "$RUNTIME_PYTHON" -m phase2.operator_runtime live', workflow)
        self.assertNotIn("expected_control_sha:\n", workflow)
        self.assertNotIn("expected_protocol_sha:\n", workflow)
        self.assertNotIn("attempt_nonce:\n", workflow)
        self.assertNotIn("inventory_attestation_b64:\n", workflow)
        self.assertNotIn("${{ inputs.inventory_attestation_b64 }}", workflow)
        self.assertEqual(
            workflow.count("${{ secrets.PHASE2_ALLOCATOR_APP_PRIVATE_KEY }}"),
            1,
        )


if __name__ == "__main__":
    unittest.main()