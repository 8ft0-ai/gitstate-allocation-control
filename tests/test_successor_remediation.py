import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import phase2.successor_capsule as capsule_runtime
import phase2.successor_runtime as runtime


CONTROL_SHA = "a" * 40
CAPSULE_ID = "b" * 32
CAPSULE_BODY_SHA256 = "c" * 64
MANIFEST_SHA256 = "d" * 64


def workflow_values() -> dict[str, str]:
    return {
        "GITHUB_REPOSITORY": capsule_runtime.CONTROL_REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": CONTROL_SHA,
        "GITHUB_RUN_ID": "9001",
        "GITHUB_RUN_ATTEMPT": "1",
        "INPUT_OPERATION": "live_scenario_suite",
        "GITHUB_TOKEN": "read-only-fixture-token",
        "EXPECTED_SUCCESSOR_CAPSULE_ID": CAPSULE_ID,
        "EXPECTED_SUCCESSOR_CAPSULE_BODY_SHA256": CAPSULE_BODY_SHA256,
        "EXPECTED_SUCCESSOR_MANIFEST_SHA256": MANIFEST_SHA256,
        "EXPECTED_SUCCESSOR_CAPSULE_COMMENT_ID": "8001",
    }


class GuardedEnvironment(dict):
    def __init__(self, *args, events: list[str], **kwargs):
        super().__init__(*args, **kwargs)
        self.events = events

    def __getitem__(self, key):
        if key == "PHASE2_ALLOCATOR_APP_PRIVATE_KEY":
            self.events.append("private-key-read")
        return super().__getitem__(key)


class SuccessorRemediationTests(unittest.TestCase):
    def test_discovery_requires_all_exact_bindings_before_api_access(self):
        required = (
            "EXPECTED_SUCCESSOR_CAPSULE_ID",
            "EXPECTED_SUCCESSOR_CAPSULE_BODY_SHA256",
            "EXPECTED_SUCCESSOR_MANIFEST_SHA256",
        )
        for missing in required:
            with self.subTest(missing=missing):
                values = workflow_values()
                values[missing] = ""
                with patch.object(capsule_runtime, "_api_from_environment") as api:
                    with self.assertRaisesRegex(
                        capsule_runtime.SuccessorCapsuleError,
                        "SUCCESSOR_DISPATCH_BINDING_REQUIRED",
                    ):
                        capsule_runtime.command_discover(values)
                api.assert_not_called()

    def test_discovery_rejects_malformed_bindings_before_api_access(self):
        cases = (
            ("EXPECTED_SUCCESSOR_CAPSULE_ID", "not-an-id", "EXPECTED_SUCCESSOR_CAPSULE_ID_INVALID"),
            ("EXPECTED_SUCCESSOR_CAPSULE_BODY_SHA256", "f" * 63, "EXPECTED_SUCCESSOR_CAPSULE_DIGEST_INVALID"),
            ("EXPECTED_SUCCESSOR_MANIFEST_SHA256", "g" * 64, "EXPECTED_SUCCESSOR_MANIFEST_DIGEST_INVALID"),
        )
        for key, value, reason in cases:
            with self.subTest(key=key):
                values = workflow_values()
                values[key] = value
                with patch.object(capsule_runtime, "_api_from_environment") as api:
                    with self.assertRaisesRegex(
                        capsule_runtime.SuccessorCapsuleError,
                        reason,
                    ):
                        capsule_runtime.command_discover(values)
                api.assert_not_called()

    def test_consumption_revalidates_bindings_before_api_or_issue_write_path(self):
        values = workflow_values()
        values["EXPECTED_SUCCESSOR_MANIFEST_SHA256"] = ""
        with patch.object(capsule_runtime, "_api_from_environment") as api, patch.object(
            capsule_runtime, "consume_capsule"
        ) as consume:
            with self.assertRaisesRegex(
                capsule_runtime.SuccessorCapsuleError,
                "SUCCESSOR_DISPATCH_BINDING_REQUIRED",
            ):
                capsule_runtime.command_consume(values)
        api.assert_not_called()
        consume.assert_not_called()

    def test_exact_binding_validator_preserves_valid_live_identity(self):
        values = workflow_values()
        self.assertEqual(
            capsule_runtime._require_live_dispatch_bindings(values),
            (CAPSULE_ID, CAPSULE_BODY_SHA256, MANIFEST_SHA256),
        )

    def test_successor_l1_and_l2_receive_external_enablement_observation(self):
        workflow = Path(".github/workflows/phase2-adversarial.yml").read_text()
        l1 = workflow.split("  successor-live-l1:", 1)[1].split(
            "  live-scenario-suite:", 1
        )[0]
        live = workflow.split("  live-scenario-suite:", 1)[1].split(
            "  operator-preflight:", 1
        )[0]
        binding = (
            "PHASE2_WORKSTREAM_D_EXECUTION_ENABLED: "
            "${{ vars.PHASE2_WORKSTREAM_D_EXECUTION_ENABLED }}"
        )
        self.assertIn(binding, l1)
        self.assertIn(binding, live)
        self.assertEqual(workflow.count(binding), 3)

    def test_nonempty_external_enablement_blocks_before_explicit_key_read(self):
        events: list[str] = []
        values = GuardedEnvironment(
            {
                "GITHUB_REPOSITORY": runtime.CONTROL_REPOSITORY,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_SHA": CONTROL_SHA,
                "GITHUB_RUN_ID": "9001",
                "GITHUB_RUN_ATTEMPT": "1",
                "OPERATION_PROFILE": runtime.LIVE_PROFILE,
                "CAPSULE_ID": CAPSULE_ID,
                "CAPSULE_COMMENT_ID": "8001",
                "CAPSULE_BODY_SHA256": CAPSULE_BODY_SHA256,
                "CONSUMPTION_COMMENT_ID": "8002",
                "CONSUMPTION_BODY_SHA256": "e" * 64,
                "MANIFEST_SHA256": MANIFEST_SHA256,
                "PROJECTION_COMMENT_ID": "7001",
                "PROJECTION_BODY_SHA256": "f" * 64,
                "ATTEMPT_NONCE": runtime.sha256_text(
                    f"9001:1:{CAPSULE_ID}:{CAPSULE_BODY_SHA256}"
                )[:16],
                "PHASE2_WORKSTREAM_D_EXECUTION_ENABLED": "true",
                "PHASE2_ALLOCATOR_APP_PRIVATE_KEY": "fixture-key",
            },
            events=events,
        )
        with patch.object(
            runtime,
            "evaluate_stage",
            side_effect=runtime.SuccessorRuntimeError("EXECUTION_ENABLEMENT_CHANGED"),
        ), patch.object(runtime.revocation, "execute_live_suite") as legacy:
            with self.assertRaisesRegex(
                runtime.SuccessorRuntimeError,
                "EXECUTION_ENABLEMENT_CHANGED",
            ):
                runtime.execute_live(values)
        self.assertNotIn("private-key-read", events)
        legacy.assert_not_called()

    def test_existing_history_and_key_regressions_remain_in_successor_suite(self):
        existing = Path("tests/test_successor_execution.py").read_text()
        self.assertIn("test_consumed_old_control_v2_does_not_block_current_successor", existing)
        self.assertIn("test_v2_consumption_manifest_must_match_capsule", existing)
        self.assertIn("test_execute_live_scrubs_allocator_key_before_legacy_stack", existing)
        self.assertIn("test_subprocess_environments_never_inherit_allocator_private_key", existing)


if __name__ == "__main__":
    unittest.main()
