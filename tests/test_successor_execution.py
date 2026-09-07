import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import phase2.successor_capsule as capsule_runtime
import phase2.successor_runtime as runtime
from phase2.operator_guard import GuardResult
from phase2.operator_inventory import CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID, InventoryEvidence
from phase2.operator_manifest import canonical_json, sha256_text
from phase2.successor_contract import (
    CAPSULE_CONTRACT, CAPSULE_PREFIX, CONSUMPTION_CONTRACT, CONSUMPTION_PREFIX,
    parse_capsule_comment, parse_operator_history,
)

CONTROL_SHA = "a" * 40
MANIFEST_SHA = "b" * 64
CAPSULE_ID = "c" * 32
OPERATION = "workstream-d-scenarios-1-14/v1"


def capsule_payload(*, created="2026-09-07T10:00:00Z", expires="2026-09-07T10:30:00Z"):
    approval_body = "approval source"
    return {
        "contract": CAPSULE_CONTRACT,
        "capsule_id": CAPSULE_ID,
        "operation": OPERATION,
        "projection": {"comment_id": 7001, "body_sha256": "d" * 64},
        "manifest_sha256": MANIFEST_SHA,
        "authority": {"record_id": "e" * 32, "body_sha256": "f" * 64},
        "manifest_approval": {
            "record_id": "1" * 32,
            "body_sha256": sha256_text(approval_body),
            "source": {
                "comment_id": 6001,
                "body": approval_body,
                "owner": "8ft0-ai",
                "created_at": "2026-09-07T09:59:00Z",
                "updated_at": "2026-09-07T09:59:00Z",
            },
        },
        "expected_control_sha": CONTROL_SHA,
        "preflight_run": {"run_id": 8001, "run_attempt": 1, "trusted_sha": CONTROL_SHA},
        "created_at": created,
        "expires_at": expires,
        "execution_authorised": True,
        "single_use": True,
        "workstream_e_authorised": False,
    }


def capsule_comment(comment_id=9001, **changes):
    value = capsule_payload(**changes)
    body = CAPSULE_PREFIX + canonical_json(value)
    return {
        "id": comment_id, "body": body, "user": {"login": "8ft0-ai"},
        "created_at": "2026-09-07T10:01:00Z", "updated_at": "2026-09-07T10:01:00Z",
    }


def consumption_comment(capsule, comment_id=9002):
    body_sha = sha256_text(capsule["body"])
    value = {
        "contract": CONSUMPTION_CONTRACT,
        "capsule_id": CAPSULE_ID,
        "capsule_comment_id": capsule["id"],
        "capsule_body_sha256": body_sha,
        "manifest_sha256": MANIFEST_SHA,
        "run_id": 8002,
        "run_attempt": 1,
        "trusted_sha": CONTROL_SHA,
        "operation": OPERATION,
        "consumed_at": "2026-09-07T10:05:00Z",
        "workstream_e_authorised": False,
    }
    body = CONSUMPTION_PREFIX + canonical_json(value)
    return {
        "id": comment_id, "body": body, "user": {"login": "github-actions[bot]"},
        "created_at": "2026-09-07T10:05:00Z", "updated_at": "2026-09-07T10:05:00Z",
    }


class CommentOnlyAPI:
    def __init__(self, comments): self.comments = comments
    def get(self, path):
        if "/issues/17/comments" in path:
            return self.comments if "page=1" in path else []
        raise AssertionError(path)


class GuardedEnvironment(dict):
    def __init__(self, *args, events, **kwargs):
        super().__init__(*args, **kwargs); self.events = events
    def __getitem__(self, key):
        if key == "PHASE2_ALLOCATOR_APP_PRIVATE_KEY": self.events.append("private-key-read")
        return super().__getitem__(key)


class SuccessorExecutionTests(unittest.TestCase):
    def test_expired_consumed_v2_capsule_remains_closed_history(self):
        cap = capsule_comment()
        records = parse_operator_history([cap, consumption_comment(cap)], require_closed=True)
        self.assertEqual([r.record_kind for r in records], [CAPSULE_CONTRACT, CONSUMPTION_CONTRACT])

    def test_expired_unconsumed_capsule_is_not_live_eligible(self):
        cap = capsule_comment()
        with self.assertRaisesRegex(capsule_runtime.SuccessorCapsuleError, "SUCCESSOR_CAPSULE_NOT_FOUND"):
            capsule_runtime.discover_capsule(
                CommentOnlyAPI([cap]), expected_control_sha=CONTROL_SHA,
                expected_operation=OPERATION, run_id=8002, run_attempt=1,
                now=datetime(2026, 9, 7, 11, 0, tzinfo=timezone.utc),
            )


    def test_consumed_old_control_v2_does_not_block_current_successor(self):
        old = capsule_comment()
        old_consumption = consumption_comment(old)

        current_control = "9" * 40
        current_capsule_id = "8" * 32
        current_manifest = "7" * 64
        payload = capsule_payload()
        payload["capsule_id"] = current_capsule_id
        payload["manifest_sha256"] = current_manifest
        payload["expected_control_sha"] = current_control
        payload["preflight_run"] = {
            "run_id": 8101, "run_attempt": 1, "trusted_sha": current_control
        }
        body = CAPSULE_PREFIX + canonical_json(payload)
        current = {
            "id": 9101,
            "body": body,
            "user": {"login": "8ft0-ai"},
            "created_at": "2026-09-07T10:01:00Z",
            "updated_at": "2026-09-07T10:01:00Z",
        }

        with patch.object(capsule_runtime, "validate_public_subject"):
            observed = capsule_runtime.discover_capsule(
                CommentOnlyAPI([old, old_consumption, current]),
                expected_control_sha=current_control,
                expected_operation=OPERATION,
                expected_capsule_id=current_capsule_id,
                expected_manifest_sha256=current_manifest,
                run_id=8102,
                run_attempt=1,
                now=datetime(2026, 9, 7, 10, 10, tzinfo=timezone.utc),
            )
        self.assertEqual(observed.capsule_id, current_capsule_id)
        self.assertEqual(observed.expected_control_sha, current_control)


    def test_malformed_consumed_historical_v2_still_blocks_discovery(self):
        old = capsule_comment()
        body_sha = sha256_text(old["body"])
        malformed_payload = {
            "contract": CONSUMPTION_CONTRACT,
            "capsule_id": CAPSULE_ID,
            "capsule_comment_id": old["id"],
            "capsule_body_sha256": body_sha,
            "manifest_sha256": MANIFEST_SHA,
            "run_id": 8002,
            "run_attempt": 1,
            "trusted_sha": "f" * 40,
            "operation": OPERATION,
            "consumed_at": "2026-09-07T10:05:00Z",
            "workstream_e_authorised": False,
        }
        malformed = {
            "id": 9002,
            "body": CONSUMPTION_PREFIX + canonical_json(malformed_payload),
            "user": {"login": "github-actions[bot]"},
            "created_at": "2026-09-07T10:05:00Z",
            "updated_at": "2026-09-07T10:05:00Z",
        }
        with self.assertRaisesRegex(
            capsule_runtime.SuccessorCapsuleError,
            "OPERATOR_HISTORY_CONSUMPTION_MISMATCH",
        ):
            capsule_runtime.discover_capsule(
                CommentOnlyAPI([old, malformed]),
                expected_control_sha=CONTROL_SHA,
                expected_operation=OPERATION,
                run_id=8003,
                run_attempt=1,
                now=datetime(2026, 9, 7, 10, 10, tzinfo=timezone.utc),
            )

    def test_subprocess_environments_never_inherit_allocator_private_key(self):
        with patch.dict(
            os.environ,
            {"PHASE2_ALLOCATOR_APP_PRIVATE_KEY": "fixture-key"},
            clear=False,
        ):
            credential_free = runtime.live._credential_free_git_env()
            with tempfile.TemporaryDirectory() as directory:
                state_env = runtime.live._state_git_env(Path(directory), "state-token")
        self.assertNotIn("PHASE2_ALLOCATOR_APP_PRIVATE_KEY", credential_free)
        self.assertNotIn("PHASE2_ALLOCATOR_APP_PRIVATE_KEY", state_env)
        self.assertEqual(state_env["PHASE2_STATE_TOKEN"], "state-token")

    def test_execute_live_scrubs_allocator_key_before_legacy_stack(self):
        values = {
            "GITHUB_REPOSITORY": runtime.CONTROL_REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": CONTROL_SHA,
            "GITHUB_RUN_ID": "8002",
            "GITHUB_RUN_ATTEMPT": "1",
            "OPERATION_PROFILE": OPERATION,
            "CAPSULE_ID": CAPSULE_ID,
            "CAPSULE_COMMENT_ID": "9001",
            "CAPSULE_BODY_SHA256": "2" * 64,
            "CONSUMPTION_COMMENT_ID": "9002",
            "CONSUMPTION_BODY_SHA256": "3" * 64,
            "MANIFEST_SHA256": MANIFEST_SHA,
            "PROJECTION_COMMENT_ID": "7001",
            "PROJECTION_BODY_SHA256": "4" * 64,
            "ATTEMPT_NONCE": sha256_text(f"8002:1:{CAPSULE_ID}:{'2' * 64}")[:16],
            "PHASE2_ALLOCATOR_APP_PRIVATE_KEY": "fixture-key",
        }
        manifest = SimpleNamespace(payload={"protocol_sha": "5" * 64})
        subject = SimpleNamespace(preflight_projection=SimpleNamespace(manifest=manifest))
        result = runtime.live.LiveSuiteResult(
            8002, 1, "wd-8002-1-test", CONTROL_SHA, "5" * 64, 14, (), "6" * 64, True, False
        )

        def legacy_stack(observed):
            self.assertNotIn("PHASE2_ALLOCATOR_APP_PRIVATE_KEY", observed)
            self.assertNotIn("PHASE2_ALLOCATOR_APP_PRIVATE_KEY", os.environ)
            return result

        with patch.dict(os.environ, values, clear=False), \
             patch.object(runtime, "evaluate_stage", return_value=(subject, GuardResult.pass_result())), \
             patch.object(runtime.revocation, "execute_live_suite", side_effect=legacy_stack):
            runtime.execute_live()
            self.assertNotIn("PHASE2_ALLOCATOR_APP_PRIVATE_KEY", os.environ)

    def test_l2_inventory_is_revoked_before_mutation_token_mint(self):
        events = []
        values = GuardedEnvironment({
            "PHASE2_ALLOCATOR_APP_ID": "10", "PHASE2_ALLOCATOR_INSTALLATION_ID": "20",
            "PHASE2_STATE_REPOSITORY_ID": str(STATE_REPOSITORY_ID),
            "PHASE2_ALLOCATOR_APP_PRIVATE_KEY": "fixture-key", "GITHUB_API_URL": "https://api.invalid",
        }, events=events)
        context = SimpleNamespace(run_id=8002, run_attempt=1, trusted_sha=CONTROL_SHA,
                                  capsule_id=CAPSULE_ID, capsule_body_sha256="2"*64)
        legacy = SimpleNamespace(validate=lambda: events.append("legacy-context-valid"))
        subject = SimpleNamespace(preflight_projection=SimpleNamespace(manifest=SimpleNamespace(sha256=MANIFEST_SHA)))
        inventory = InventoryEvidence(10, 20, "selected", tuple(sorted((CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID))),
                                      "2026-09-07T10:06:00Z", 8002, 1, CONTROL_SHA, CAPSULE_ID, "2"*64,
                                      {"metadata": "read"}, True, "3"*64)
        def evaluate(*args, stage, **kwargs):
            events.append(stage); return subject, GuardResult.pass_result()
        def prove(*args, **kwargs): events.append("inventory-proved-revoked"); return inventory
        def mint(api, installation_id, profile): events.append(f"mint-{profile.name}"); return f"{profile.name}-token"
        policy = {"control_repository": runtime.CONTROL_REPOSITORY, "control_repository_id": CONTROL_REPOSITORY_ID,
                  "allocator": {"app_id_env":"PHASE2_ALLOCATOR_APP_ID", "installation_id_env":"PHASE2_ALLOCATOR_INSTALLATION_ID",
                                "app_slug":"gitstate-phase-2-allocator", "owner":"8ft0-ai"},
                  "state_repository_id_env":"PHASE2_STATE_REPOSITORY_ID"}
        with patch.object(runtime, "evaluate_stage", side_effect=evaluate), patch.object(runtime, "load_policy", return_value=policy), \
             patch.object(runtime, "verify_live_installation", return_value={"repository_selection":"selected"}), \
             patch.object(runtime, "prove_installation_inventory", side_effect=prove), patch.object(runtime, "mint_token", side_effect=mint), \
             patch.object(runtime, "require_cross_repository_denial"), patch.object(runtime, "require_public_repository_write_denial"):
            lease, observed = runtime._mutation_credentials(
                values, context, legacy, private_key="fixture-key",
                api_factory=lambda token, url: object(),
                jwt_factory=lambda app_id, key: events.append("private-key-used") or "jwt",
            )
        self.assertIs(observed, inventory)
        self.assertEqual(events[:5], ["live_l1", "legacy-context-valid", "private-key-used", "inventory-proved-revoked", "live_l2"])
        self.assertEqual(events[5:], ["mint-control", "mint-state"])
        self.assertEqual(lease.control_token, "control-token")


    def test_invalidation_before_consumption_creates_no_consumption_record(self):
        cap_comment = capsule_comment()
        capsule = parse_capsule_comment(
            cap_comment, now=datetime(2026, 9, 7, 10, 10, tzinfo=timezone.utc),
            expected_control_sha=CONTROL_SHA, expected_operation=OPERATION,
        )
        self.assertIsNotNone(capsule)
        api = SimpleNamespace(posts=[])
        def post(path, body): api.posts.append((path, body)); return {"id": 9999}
        api.post = post
        with patch.object(capsule_runtime, "discover_capsule", return_value=capsule), \
             patch.object(capsule_runtime, "validate_public_subject", side_effect=capsule_runtime.SuccessorCapsuleError("GOVERNANCE_SUPERSEDED")):
            with self.assertRaisesRegex(capsule_runtime.SuccessorCapsuleError, "GOVERNANCE_SUPERSEDED"):
                capsule_runtime.consume_capsule(
                    api, expected_control_sha=CONTROL_SHA, expected_operation=OPERATION,
                    expected_capsule_id=CAPSULE_ID, expected_capsule_comment_id=9001,
                    expected_capsule_body_sha256=capsule.body_sha256, expected_manifest_sha256=MANIFEST_SHA,
                    run_id=8002, run_attempt=1, now=datetime(2026, 9, 7, 10, 10, tzinfo=timezone.utc),
                )
        self.assertEqual(api.posts, [])

    def test_invalidation_at_l2_blocks_before_control_or_state_token_mint(self):
        events = []
        values = GuardedEnvironment({
            "PHASE2_ALLOCATOR_APP_ID": "10", "PHASE2_ALLOCATOR_INSTALLATION_ID": "20",
            "PHASE2_STATE_REPOSITORY_ID": str(STATE_REPOSITORY_ID),
            "PHASE2_ALLOCATOR_APP_PRIVATE_KEY": "fixture-key", "GITHUB_API_URL": "https://api.invalid",
        }, events=events)
        context = SimpleNamespace(run_id=8002, run_attempt=1, trusted_sha=CONTROL_SHA,
                                  capsule_id=CAPSULE_ID, capsule_body_sha256="2"*64)
        legacy = SimpleNamespace(validate=lambda: events.append("legacy-context-valid"))
        subject = SimpleNamespace(preflight_projection=SimpleNamespace(manifest=SimpleNamespace(sha256=MANIFEST_SHA)))
        inventory = InventoryEvidence(10, 20, "selected", tuple(sorted((CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID))),
                                      "2026-09-07T10:06:00Z", 8002, 1, CONTROL_SHA, CAPSULE_ID, "2"*64,
                                      {"metadata": "read"}, True, "3"*64)
        def evaluate(*args, stage, **kwargs):
            events.append(stage)
            if stage == "live_l2": raise runtime.SuccessorRuntimeError("GOVERNANCE_SUPERSEDED")
            return subject, GuardResult.pass_result()
        def prove(*args, **kwargs): events.append("inventory-proved-revoked"); return inventory
        def mint(*args, **kwargs): events.append("MUTATION-TOKEN-MINTED"); return "token"
        policy = {"control_repository": runtime.CONTROL_REPOSITORY, "control_repository_id": CONTROL_REPOSITORY_ID,
                  "allocator": {"app_id_env":"PHASE2_ALLOCATOR_APP_ID", "installation_id_env":"PHASE2_ALLOCATOR_INSTALLATION_ID",
                                "app_slug":"gitstate-phase-2-allocator", "owner":"8ft0-ai"},
                  "state_repository_id_env":"PHASE2_STATE_REPOSITORY_ID"}
        with patch.object(runtime, "evaluate_stage", side_effect=evaluate), patch.object(runtime, "load_policy", return_value=policy), \
             patch.object(runtime, "verify_live_installation", return_value={"repository_selection":"selected"}), \
             patch.object(runtime, "prove_installation_inventory", side_effect=prove), patch.object(runtime, "mint_token", side_effect=mint):
            with self.assertRaisesRegex(runtime.SuccessorRuntimeError, "GOVERNANCE_SUPERSEDED"):
                runtime._mutation_credentials(
                    values, context, legacy, private_key="fixture-key",
                    api_factory=lambda token, url: object(),
                    jwt_factory=lambda app_id, key: "jwt",
                )
        self.assertNotIn("MUTATION-TOKEN-MINTED", events)
        self.assertEqual(events[-2:], ["inventory-proved-revoked", "live_l2"])

    def test_workflow_activates_successor_only_after_capability_denied_l1(self):
        workflow = Path(".github/workflows/phase2-adversarial.yml").read_text()
        self.assertIn("python3 -m phase2.successor_capsule discover", workflow)
        self.assertIn("python3 -m phase2.successor_capsule consume", workflow)
        self.assertIn("python3 -m phase2.successor_runtime l1", workflow)
        self.assertIn('-m phase2.successor_runtime live', workflow)
        self.assertNotIn("python3 -m phase2.operator_capsule discover", workflow)
        self.assertNotIn("python3 -m phase2.operator_capsule consume", workflow)
        self.assertLess(workflow.index("successor-live-l1:"), workflow.index("environment: phase-2-allocator"))
        self.assertEqual(workflow.count("${{ secrets.PHASE2_ALLOCATOR_APP_PRIVATE_KEY }}"), 1)


if __name__ == "__main__": unittest.main()
