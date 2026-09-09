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


class SuccessorFreshnessAndOpenHistoryTests(unittest.TestCase):
    @staticmethod
    def _approved_live_state():
        from tests.test_operator_guard import (
            APPROVAL_ID,
            AUTHORITY_ID,
            binding,
            governance_comment,
            governance_payload,
            make_state,
            manifest_subject,
            parsed_records,
            with_records,
        )

        _, _, authority, manifest, comments, observation = make_state()
        approved = governance_comment(
            104,
            governance_payload(
                "manifest_approval",
                APPROVAL_ID,
                manifest_subject(
                    manifest.sha256,
                    record_ids=(AUTHORITY_ID,),
                    comment_bindings=(binding(authority),),
                ),
                {"disposition": "approved"},
            ),
        )
        records = parsed_records(comments + [approved])
        return manifest, with_records(
            observation, manifest, records, stage="live_l1"
        )

    def test_live_l2_requires_private_freshness_and_detects_state_or_environment_movement(self):
        from tests.test_operator_guard import with_observation
        from phase2.operator_guard import evaluate_guards

        manifest, observation = self._approved_live_state()
        l2_missing = with_observation(
            observation,
            stage="live_l2",
            private_freshness_proven=False,
        )
        self.assertEqual(evaluate_guards(manifest, l2_missing).code, "READ_EVIDENCE_UNAVAILABLE")

        l2_state_moved = with_observation(
            observation,
            stage="live_l2",
            private_freshness_proven=True,
            state_commit_sha="9" * 40,
        )
        self.assertEqual(evaluate_guards(manifest, l2_state_moved).code, "STATE_BASELINE_CHANGED")

        l2_environment_moved = with_observation(
            observation,
            stage="live_l2",
            private_freshness_proven=True,
            environment_policy_sha256="9" * 64,
        )
        self.assertEqual(
            evaluate_guards(manifest, l2_environment_moved).code,
            "ENVIRONMENT_BOUNDARY_CHANGED",
        )

    def test_live_l1_does_not_claim_private_state_or_app_freshness(self):
        from tests.test_operator_guard import with_observation
        from phase2.operator_guard import evaluate_guards

        manifest, observation = self._approved_live_state()
        l1 = with_observation(
            observation,
            stage="live_l1",
            private_freshness_proven=False,
            state_commit_sha="9" * 40,
            state_digest_sha256="8" * 64,
            app_id=999,
            installation_id=998,
            selected_repository_ids=(997,),
            permission_profile_sha256="7" * 64,
        )
        self.assertTrue(evaluate_guards(manifest, l1).passed)

    def test_environment_policy_digest_is_current_canonical_material(self):
        payload = {
            "name": "phase-2-allocator",
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": False,
                    "reviewers": [
                        {"type": "User", "reviewer": {"id": 20, "login": "b"}},
                        {"type": "User", "reviewer": {"id": 10, "login": "a"}},
                    ],
                },
                {"type": "wait_timer", "wait_timer": 0},
            ],
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            },
        }
        first = runtime.environment_policy_sha256(payload, "phase-2-allocator")
        reordered = dict(payload)
        reordered["protection_rules"] = list(reversed(payload["protection_rules"]))
        self.assertEqual(
            first,
            runtime.environment_policy_sha256(reordered, "phase-2-allocator"),
        )
        moved = dict(payload)
        moved["deployment_branch_policy"] = {
            "protected_branches": False,
            "custom_branch_policies": True,
        }
        self.assertNotEqual(
            first,
            runtime.environment_policy_sha256(moved, "phase-2-allocator"),
        )
        reviewer_moved = dict(payload)
        reviewer_rule = dict(payload["protection_rules"][0])
        reviewer_rule["prevent_self_review"] = True
        reviewer_moved["protection_rules"] = [
            reviewer_rule,
            payload["protection_rules"][1],
        ]
        self.assertNotEqual(
            first,
            runtime.environment_policy_sha256(
                reviewer_moved, "phase-2-allocator"
            ),
        )

    def test_state_observation_token_is_read_only_and_revoked_before_return(self):
        from phase2.operator_inventory import STATE_REPOSITORY_ID

        events: list[str] = []

        class StateAPI:
            def get(self, path):
                events.append(f"get:{path}")
                if path == f"/repos/{runtime.STATE_REPOSITORY}/git/ref/heads/main":
                    return {"object": {"sha": "4" * 40}}
                if path == f"/repos/{runtime.STATE_REPOSITORY}/git/commits/{'4' * 40}":
                    return {"tree": {"sha": "5" * 40}}
                if path == f"/repos/8ft0-ai/gitstate-allocation-state":
                    return {"id": STATE_REPOSITORY_ID, "full_name": "8ft0-ai/gitstate-allocation-state"}
                raise AssertionError(path)

            def request_with_status(self, method, path):
                events.append(f"{method}:{path}")
                self.assertions = True
                return None, {}, 204

        state_api = StateAPI()
        seen_profile = []

        def mint(_app_api, _installation_id, profile):
            seen_profile.append(profile)
            events.append("mint-state-observation")
            return "read-only-state-token"

        with patch.object(runtime, "mint_token", side_effect=mint):
            commit, digest = runtime._observe_state_baseline(
                object(),
                installation_id=20,
                api_url="https://api.invalid",
                api_factory=lambda token, url: state_api,
            )
        self.assertEqual(commit, "4" * 40)
        self.assertEqual(
            seen_profile[0].permissions,
            {"contents": "read", "metadata": "read"},
        )
        self.assertEqual(events[-1], "DELETE:/installation/token")
        self.assertEqual(
            digest,
            runtime.state_observation_sha256(
                repository_id=STATE_REPOSITORY_ID,
                ref=runtime.STATE_REPOSITORY_REF,
                commit_sha="4" * 40,
                tree_sha="5" * 40,
            ),
        )

    def test_required_owner_observation_is_not_replayed_from_b2_projection(self):
        from datetime import datetime, timezone
        from tests.test_operator_guard import make_state

        owner_requirement = {
            "required": True,
            "observation_id": "owner-observation-1",
            "observation_sha256": "a" * 64,
            "valid_through": "2026-09-10T00:00:00Z",
        }
        _, _, _, manifest, _, _ = make_state(owner_observation=owner_requirement)
        subject = SimpleNamespace(
            preflight_projection=SimpleNamespace(
                manifest=manifest,
                bound_observation={
                    "app_id": 10,
                    "installation_id": 20,
                    "repository_selection": "selected",
                    "selected_repository_ids": [100, 200],
                    "permission_profile_sha256": "3" * 64,
                    "protocol_sha": "e" * 40,
                    "state_commit_sha": "f" * 40,
                    "state_digest_sha256": "1" * 64,
                    "environment_name": "phase-2-allocator",
                    "environment_policy_sha256": "2" * 64,
                    "execution_variable": runtime.EXECUTION_VARIABLE,
                    "owner_observation": {
                        "required": True,
                        "observation_id": "owner-observation-1",
                        "observation_sha256": "a" * 64,
                        "valid": True,
                    },
                },
            ),
            governance_history=SimpleNamespace(),
        )
        context = SimpleNamespace()

        class API:
            def get(self, path):
                if "/environments/phase-2-allocator" in path:
                    return {
                        "name": "phase-2-allocator",
                        "protection_rules": [],
                        "deployment_branch_policy": None,
                    }
                raise AssertionError(path)

        with patch.object(runtime.projection, "_control_identity", return_value=("b" * 40, "c" * 40, manifest.module_blobs)):
            with self.assertRaisesRegex(runtime.SuccessorRuntimeError, "READ_EVIDENCE_UNAVAILABLE"):
                runtime._guard_observation(
                    {},
                    context,
                    subject,
                    stage="live_l2",
                    api=API(),
                    evaluated_at=datetime(2026, 9, 9, tzinfo=timezone.utc),
                    actual_inventory=SimpleNamespace(
                        app_id=10,
                        installation_id=20,
                        repository_selection="selected",
                        repository_ids=(100, 200),
                    ),
                    state_observation=("f" * 40, "1" * 64),
                )

    def _capsule_comment_with(self, *, capsule_id: str, created: str, expires: str, comment_id: int, comment_time: str):
        from tests.test_successor_execution import capsule_payload
        from phase2.successor_contract import CAPSULE_PREFIX
        from phase2.operator_manifest import canonical_json

        payload = capsule_payload(created=created, expires=expires)
        payload["capsule_id"] = capsule_id
        body = CAPSULE_PREFIX + canonical_json(payload)
        return {
            "id": comment_id,
            "body": body,
            "user": {"login": "8ft0-ai"},
            "created_at": comment_time,
            "updated_at": comment_time,
        }

    def test_other_open_capsules_block_before_consumption_post(self):
        from datetime import datetime, timezone
        from tests.test_successor_execution import (
            CAPSULE_ID as CURRENT_ID,
            CONTROL_SHA,
            MANIFEST_SHA,
            OPERATION,
            CommentOnlyAPI,
            capsule_comment,
        )

        current = capsule_comment()
        cases = (
            self._capsule_comment_with(
                capsule_id="1" * 32,
                created="2026-09-07T09:00:00Z",
                expires="2026-09-07T09:30:00Z",
                comment_id=8991,
                comment_time="2026-09-07T09:01:00Z",
            ),
            self._capsule_comment_with(
                capsule_id="2" * 32,
                created="2026-09-07T11:00:00Z",
                expires="2026-09-07T11:30:00Z",
                comment_id=8992,
                comment_time="2026-09-07T11:01:00Z",
            ),
            self._capsule_comment_with(
                capsule_id="3" * 32,
                created="2026-09-07T10:00:00Z",
                expires="2026-09-07T10:30:00Z",
                comment_id=8993,
                comment_time="2026-09-07T10:01:00Z",
            ),
        )
        for other in cases:
            with self.subTest(other=other["id"]):
                api = CommentOnlyAPI([other, current])
                api.posts = []
                api.post = lambda path, body: api.posts.append((path, body)) or {"id": 9999}
                with patch.object(capsule_runtime, "validate_public_subject"):
                    with self.assertRaisesRegex(
                        capsule_runtime.SuccessorCapsuleError,
                        "OPERATOR_HISTORY_OPEN_SET_INVALID",
                    ):
                        capsule_runtime.discover_capsule(
                            api,
                            expected_control_sha=CONTROL_SHA,
                            expected_operation=OPERATION,
                            run_id=8002,
                            run_attempt=1,
                            expected_capsule_id=CURRENT_ID,
                            expected_capsule_body_sha256=runtime.sha256_text(current["body"]),
                            expected_manifest_sha256=MANIFEST_SHA,
                            now=datetime(2026, 9, 7, 10, 10, tzinfo=timezone.utc),
                        )
                self.assertEqual(api.posts, [])

    def test_closed_pair_after_manifest_baseline_blocks_current_consumption(self):
        from datetime import datetime, timezone
        from tests.test_successor_execution import (
            CAPSULE_ID,
            CONTROL_SHA,
            MANIFEST_SHA,
            OPERATION,
            CommentOnlyAPI,
            capsule_comment,
            consumption_comment,
        )

        old = self._capsule_comment_with(
            capsule_id="5" * 32,
            created="2026-09-07T09:00:00Z",
            expires="2026-09-07T09:30:00Z",
            comment_id=8901,
            comment_time="2026-09-07T09:01:00Z",
        )
        # Build a valid closed consumption for the old capsule with its own ID.
        from phase2.successor_contract import CONSUMPTION_PREFIX, CONSUMPTION_CONTRACT
        from phase2.operator_manifest import canonical_json, sha256_text
        old_payload = capsule_runtime.parse_capsule_comment(old, now=None).payload
        consumed_payload = {
            "contract": CONSUMPTION_CONTRACT,
            "capsule_id": str(old_payload["capsule_id"]),
            "capsule_comment_id": old["id"],
            "capsule_body_sha256": sha256_text(old["body"]),
            "manifest_sha256": str(old_payload["manifest_sha256"]),
            "run_id": 7900,
            "run_attempt": 1,
            "trusted_sha": str(old_payload["expected_control_sha"]),
            "operation": str(old_payload["operation"]),
            "consumed_at": "2026-09-07T09:05:00Z",
            "workstream_e_authorised": False,
        }
        old_consumption = {
            "id": 8902,
            "body": CONSUMPTION_PREFIX + canonical_json(consumed_payload),
            "user": {"login": "github-actions[bot]"},
            "created_at": "2026-09-07T09:05:00Z",
            "updated_at": "2026-09-07T09:05:00Z",
        }
        current = capsule_comment()
        api = CommentOnlyAPI([old, old_consumption, current])
        projection = SimpleNamespace(
            manifest=SimpleNamespace(
                operator_history=capsule_runtime.operator_history_baseline(())
            )
        )
        with patch.object(
            capsule_runtime, "validate_public_subject", return_value=projection
        ):
            with self.assertRaisesRegex(
                capsule_runtime.SuccessorCapsuleError,
                "OPERATOR_HISTORY_PRECONSUMPTION_INVALID",
            ):
                capsule_runtime.discover_capsule(
                    api,
                    expected_control_sha=CONTROL_SHA,
                    expected_operation=OPERATION,
                    run_id=8002,
                    run_attempt=1,
                    expected_capsule_id=CAPSULE_ID,
                    expected_capsule_body_sha256=sha256_text(current["body"]),
                    expected_manifest_sha256=MANIFEST_SHA,
                    now=datetime(2026, 9, 7, 10, 10, tzinfo=timezone.utc),
                )

    def test_history_change_between_discovery_and_consumption_blocks_before_post(self):
        from datetime import datetime, timezone
        from tests.test_successor_execution import (
            CAPSULE_ID, CONTROL_SHA, MANIFEST_SHA, OPERATION, capsule_comment,
        )

        current = capsule_comment()
        parsed = capsule_runtime.parse_capsule_comment(
            current,
            now=datetime(2026, 9, 7, 10, 10, tzinfo=timezone.utc),
            expected_control_sha=CONTROL_SHA,
            expected_operation=OPERATION,
        )
        self.assertIsNotNone(parsed)
        extra = self._capsule_comment_with(
            capsule_id="4" * 32,
            created="2026-09-07T10:00:00Z",
            expires="2026-09-07T10:30:00Z",
            comment_id=9010,
            comment_time="2026-09-07T10:01:00Z",
        )

        class ChangingAPI:
            def __init__(self):
                self.list_reads = 0
                self.posts = []

            def get(self, path):
                if "/issues/17/comments" in path:
                    if "page=1" in path:
                        self.list_reads += 1
                        return [current, extra]
                    return []
                raise AssertionError(path)

            def post(self, path, body):
                self.posts.append((path, body))
                return {"id": 9999}

        api = ChangingAPI()
        projection = SimpleNamespace(
            manifest=SimpleNamespace(
                operator_history=capsule_runtime.operator_history_baseline(())
            )
        )
        with patch.object(capsule_runtime, "discover_capsule", return_value=parsed), patch.object(
            capsule_runtime, "validate_public_subject", return_value=projection
        ):
            with self.assertRaisesRegex(
                capsule_runtime.SuccessorCapsuleError,
                "OPERATOR_HISTORY_PRECONSUMPTION_INVALID",
            ):
                capsule_runtime.consume_capsule(
                    api,
                    expected_control_sha=CONTROL_SHA,
                    expected_operation=OPERATION,
                    expected_capsule_id=CAPSULE_ID,
                    expected_capsule_comment_id=current["id"],
                    expected_capsule_body_sha256=parsed.body_sha256,
                    expected_manifest_sha256=MANIFEST_SHA,
                    run_id=8002,
                    run_attempt=1,
                    now=datetime(2026, 9, 7, 10, 10, tzinfo=timezone.utc),
                )
        self.assertEqual(api.posts, [])


if __name__ == "__main__":
    unittest.main()
