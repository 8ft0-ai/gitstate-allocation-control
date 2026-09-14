from __future__ import annotations

import json
import unittest
from pathlib import Path

from phase2 import current_observation as observation
from phase2.operator_inventory import CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID
from phase2.successor_contract import permission_profile_sha256
from phase2.successor_runtime import (
    _environment_policy_material as predecessor_environment_policy_material,
    environment_policy_sha256 as predecessor_environment_policy_sha256,
    state_observation_sha256 as predecessor_state_observation_sha256,
)


COMMIT_SHA = "b" * 40
TREE_SHA = "c" * 40


class MintingAppAPI:
    def __init__(self, responses):
        self.responses = list(responses)
        self.posts: list[tuple[str, dict]] = []

    def post(self, path: str, body: dict):
        self.posts.append((path, body))
        return self.responses.pop(0)


class TokenAPI:
    def __init__(self, token: str, get_handler):
        self.token = token
        self.get_handler = get_handler
        self.get_calls: list[str] = []
        self.delete_calls: list[str] = []
        self.delete_status = 204

    def get(self, path: str):
        self.get_calls.append(path)
        return self.get_handler(path)

    def request_with_status(self, method: str, path: str):
        if method != "DELETE" or path != "/installation/token":
            raise AssertionError((method, path))
        self.delete_calls.append(path)
        return None, {}, self.delete_status


class CurrentObservationUnitTests(unittest.TestCase):
    def test_literal_variable_absence_empty_and_non_empty_are_distinct(self):
        cases = (
            ({}, False, "not_defined"),
            ({observation.EXECUTION_VARIABLE: ""}, True, "defined_empty"),
            ({observation.EXECUTION_VARIABLE: "true"}, True, "defined_non_empty"),
        )
        for variables, defined, state in cases:
            with self.subTest(state=state):
                result = observation._observe_execution_variable(
                    json.dumps(variables, separators=(",", ":"))
                )
                self.assertEqual(result["defined"], defined)
                self.assertEqual(result["state"], state)
                self.assertNotIn("value", result)

    def test_literal_variable_evidence_fails_closed_on_malformed_or_ambiguous_json(self):
        for raw in (
            "",
            "[]",
            '{"PHASE2_WORKSTREAM_D_EXECUTION_ENABLED":null}',
            '{"PHASE2_WORKSTREAM_D_EXECUTION_ENABLED":"","PHASE2_WORKSTREAM_D_EXECUTION_ENABLED":"true"}',
        ):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(
                    observation.CurrentObservationError,
                    "EXECUTION_VARIABLE_EVIDENCE_AMBIGUOUS",
                ):
                    observation._observe_execution_variable(raw)

    def test_inventory_paginates_completely_then_revokes_on_exact_set_failure(self):
        app_api = MintingAppAPI(
            [
                {
                    "token": "inventory-token",
                    "permissions": {"metadata": "read"},
                    "repository_selection": "selected",
                }
            ]
        )

        def get_handler(path: str):
            page = int(path.rsplit("page=", 1)[1])
            if page == 1:
                return {
                    "total_count": 101,
                    "repositories": [{"id": index + 1} for index in range(100)],
                }
            if page == 2:
                return {"total_count": 101, "repositories": [{"id": 101}]}
            raise AssertionError(path)

        inventory_api = TokenAPI("inventory-token", get_handler)
        with self.assertRaisesRegex(
            observation.CurrentObservationError,
            "INVENTORY_EXACT_SET_MISMATCH",
        ):
            observation._observe_installation_inventory(
                app_api,
                installation_id=77,
                api_url="https://api.github.test",
                api_factory=lambda token, url: inventory_api,
            )
        self.assertEqual(len(inventory_api.get_calls), 2)
        self.assertEqual(inventory_api.delete_calls, ["/installation/token"])
        self.assertEqual(app_api.posts[0][1], {"permissions": {"metadata": "read"}})

    def test_inventory_post_mint_permission_failure_still_revokes(self):
        app_api = MintingAppAPI(
            [
                {
                    "token": "inventory-token",
                    "permissions": {"metadata": "write"},
                    "repository_selection": "selected",
                }
            ]
        )
        inventory_api = TokenAPI(
            "inventory-token",
            lambda path: {"total_count": 0, "repositories": []},
        )
        with self.assertRaisesRegex(Exception, "INVENTORY_TOKEN_PERMISSION_MISMATCH"):
            observation._observe_installation_inventory(
                app_api,
                installation_id=77,
                api_url="https://api.github.test",
                api_factory=lambda token, url: inventory_api,
            )
        self.assertEqual(inventory_api.delete_calls, ["/installation/token"])

    def test_inventory_client_construction_failure_still_attempts_revocation(self):
        app_api = MintingAppAPI(
            [
                {
                    "token": "inventory-token",
                    "permissions": {"metadata": "read"},
                    "repository_selection": "selected",
                }
            ]
        )
        revocation_api = TokenAPI("inventory-token", lambda path: None)
        calls = 0

        def api_factory(token: str, url: str):
            nonlocal calls
            del token, url
            calls += 1
            if calls == 1:
                raise RuntimeError("CLIENT_CONSTRUCTION_FAILED")
            return revocation_api

        with self.assertRaisesRegex(RuntimeError, "CLIENT_CONSTRUCTION_FAILED"):
            observation._observe_installation_inventory(
                app_api,
                installation_id=77,
                api_url="https://api.github.test",
                api_factory=api_factory,
            )
        self.assertEqual(revocation_api.delete_calls, ["/installation/token"])

    def test_inventory_revocation_requires_http_204(self):
        app_api = MintingAppAPI(
            [
                {
                    "token": "inventory-token",
                    "permissions": {"metadata": "read"},
                    "repository_selection": "selected",
                }
            ]
        )
        inventory_api = TokenAPI(
            "inventory-token",
            lambda path: {
                "total_count": 2,
                "repositories": [
                    {"id": CONTROL_REPOSITORY_ID},
                    {"id": STATE_REPOSITORY_ID},
                ],
            },
        )
        inventory_api.delete_status = 200
        with self.assertRaisesRegex(
            observation.CurrentObservationError,
            "INVENTORY_TOKEN_REVOCATION_FAILED",
        ):
            observation._observe_installation_inventory(
                app_api,
                installation_id=77,
                api_url="https://api.github.test",
                api_factory=lambda token, url: inventory_api,
            )

    def test_state_tree_sha_preserves_predecessor_digest_and_revokes(self):
        response = {
            "token": "state-token",
            "permissions": {"contents": "read", "metadata": "read"},
            "repositories": [{"id": STATE_REPOSITORY_ID}],
        }
        app_api = MintingAppAPI([response])

        def state_get(path: str):
            if path == "/repos/8ft0-ai/gitstate-allocation-state":
                return {
                    "id": STATE_REPOSITORY_ID,
                    "full_name": "8ft0-ai/gitstate-allocation-state",
                }
            if path.endswith("/git/ref/heads/main"):
                return {"object": {"sha": COMMIT_SHA}}
            if path.endswith(f"/git/commits/{COMMIT_SHA}"):
                return {"tree": {"sha": TREE_SHA}}
            raise AssertionError(path)

        state_api = TokenAPI("state-token", state_get)
        result = observation._observe_state_baseline(
            app_api,
            installation_id=77,
            api_url="https://api.github.test",
            api_factory=lambda token, url: state_api,
        )
        self.assertEqual(result["tree_sha"], TREE_SHA)
        self.assertEqual(
            result["digest_sha256"],
            predecessor_state_observation_sha256(
                repository_id=STATE_REPOSITORY_ID,
                ref=observation.STATE_REPOSITORY_REF,
                commit_sha=COMMIT_SHA,
                tree_sha=TREE_SHA,
            ),
        )
        self.assertEqual(state_api.delete_calls, ["/installation/token"])

    def test_state_post_mint_failure_still_revokes(self):
        response = {
            "token": "state-token",
            "permissions": {"contents": "read", "metadata": "read"},
            "repositories": [{"id": STATE_REPOSITORY_ID}],
        }
        app_api = MintingAppAPI([response])

        def state_get(path: str):
            if path == "/repos/8ft0-ai/gitstate-allocation-state":
                return {
                    "id": STATE_REPOSITORY_ID,
                    "full_name": "8ft0-ai/gitstate-allocation-state",
                }
            if path.endswith("/git/ref/heads/main"):
                return {"object": {"sha": "not-a-sha"}}
            raise AssertionError(path)

        state_api = TokenAPI("state-token", state_get)
        with self.assertRaisesRegex(
            observation.CurrentObservationError, "READ_EVIDENCE_AMBIGUOUS"
        ):
            observation._observe_state_baseline(
                app_api,
                installation_id=77,
                api_url="https://api.github.test",
                api_factory=lambda token, url: state_api,
            )
        self.assertEqual(state_api.delete_calls, ["/installation/token"])

    def test_state_client_construction_failure_still_attempts_revocation(self):
        response = {
            "token": "state-token",
            "permissions": {"contents": "read", "metadata": "read"},
            "repositories": [{"id": STATE_REPOSITORY_ID}],
        }
        app_api = MintingAppAPI([response])
        revocation_api = TokenAPI("state-token", lambda path: None)
        calls = 0

        def api_factory(token: str, url: str):
            nonlocal calls
            del token, url
            calls += 1
            if calls == 1:
                raise RuntimeError("CLIENT_CONSTRUCTION_FAILED")
            return revocation_api

        with self.assertRaisesRegex(RuntimeError, "CLIENT_CONSTRUCTION_FAILED"):
            observation._observe_state_baseline(
                app_api,
                installation_id=77,
                api_url="https://api.github.test",
                api_factory=api_factory,
            )
        self.assertEqual(revocation_api.delete_calls, ["/installation/token"])

    def test_pure_observation_digests_match_reviewed_predecessor(self):
        payload = {
            "name": observation.ENVIRONMENT_NAME,
            "protection_rules": [
                {"type": "wait_timer", "wait_timer": 0},
                {
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [
                        {"type": "User", "reviewer": {"id": 9}},
                        {"type": "Team", "reviewer": {"id": 4}},
                    ],
                },
                {"type": "branch_policy"},
            ],
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            },
        }
        self.assertEqual(
            observation._environment_policy_material(
                payload, observation.ENVIRONMENT_NAME
            ),
            predecessor_environment_policy_material(
                payload, observation.ENVIRONMENT_NAME
            ),
        )
        self.assertEqual(
            observation._environment_policy_sha256(
                payload, observation.ENVIRONMENT_NAME
            ),
            predecessor_environment_policy_sha256(
                payload, observation.ENVIRONMENT_NAME
            ),
        )
        self.assertEqual(observation.PERMISSION_PROFILE_SHA256, permission_profile_sha256())


class CurrentObservationEndToEndTests(unittest.TestCase):
    def test_output_is_sanitised_key_is_scrubbed_and_only_read_tokens_are_minted(self):
        environment_payload = {
            "name": observation.ENVIRONMENT_NAME,
            "protection_rules": [],
            "deployment_branch_policy": {
                "protected_branches": True,
                "custom_branch_policies": False,
            },
        }

        class ControlAPI:
            token = "github-token"

            def get(self, path: str):
                if path.endswith("/environments/phase-2-allocator"):
                    return environment_payload
                raise AssertionError(path)

        class AppAPI:
            token = "jwt-secret"

            def __init__(self):
                self.mints: list[dict] = []

            def get(self, path: str):
                if path == "/repos/8ft0-ai/gitstate-allocation-control/installation":
                    return {
                        "id": 456,
                        "app_id": 123,
                        "app_slug": "gitstate-phase-2-allocator",
                        "repository_selection": "selected",
                        "account": {"login": "8ft0-ai"},
                    }
                raise AssertionError(path)

            def post(self, path: str, body: dict):
                self.mints.append(body)
                if body == {"permissions": {"metadata": "read"}}:
                    return {
                        "token": "inventory-token-secret",
                        "permissions": {"metadata": "read"},
                        "repository_selection": "selected",
                    }
                if body == {
                    "repository_ids": [STATE_REPOSITORY_ID],
                    "permissions": {"contents": "read", "metadata": "read"},
                }:
                    return {
                        "token": "state-token-secret",
                        "permissions": {"contents": "read", "metadata": "read"},
                        "repositories": [{"id": STATE_REPOSITORY_ID}],
                    }
                raise AssertionError(body)

        inventory_api = TokenAPI(
            "inventory-token-secret",
            lambda path: {
                "total_count": 2,
                "repositories": [
                    {"id": STATE_REPOSITORY_ID},
                    {"id": CONTROL_REPOSITORY_ID},
                ],
            },
        )

        def state_get(path: str):
            if path == "/repos/8ft0-ai/gitstate-allocation-state":
                return {
                    "id": STATE_REPOSITORY_ID,
                    "full_name": "8ft0-ai/gitstate-allocation-state",
                }
            if path.endswith("/git/ref/heads/main"):
                return {"object": {"sha": COMMIT_SHA}}
            if path.endswith(f"/git/commits/{COMMIT_SHA}"):
                return {"tree": {"sha": TREE_SHA}}
            raise AssertionError(path)

        state_api = TokenAPI("state-token-secret", state_get)
        control_api = ControlAPI()
        app_api = AppAPI()

        def api_factory(token: str, url: str):
            del url
            return {
                "github-token": control_api,
                "jwt-secret": app_api,
                "inventory-token-secret": inventory_api,
                "state-token-secret": state_api,
            }[token]

        values = {
            "GITHUB_REPOSITORY": observation.CONTROL_REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "99",
            "GITHUB_RUN_ATTEMPT": "1",
            "INPUT_OPERATION": "current_observation",
            "GITHUB_TOKEN": "github-token",
            "GITHUB_API_URL": "https://api.github.test",
            "PHASE2_ALLOCATOR_APP_ID": "123",
            "PHASE2_ALLOCATOR_INSTALLATION_ID": "456",
            "PHASE2_ALLOCATOR_APP_PRIVATE_KEY": "private-key-secret",
            "PHASE2_CONFIGURATION_VARIABLES_JSON": json.dumps(
                {observation.EXECUTION_VARIABLE: ""}, separators=(",", ":")
            ),
            "PHASE2_STATE_REPOSITORY_ID": str(STATE_REPOSITORY_ID),
        }
        result = observation.run(
            values,
            api_factory=api_factory,
            jwt_factory=lambda app_id, key: (
                "jwt-secret"
                if app_id == 123 and key == "private-key-secret"
                else ""
            ),
        )
        rendered = json.dumps(result, sort_keys=True)
        for secret in (
            "private-key-secret",
            "jwt-secret",
            "inventory-token-secret",
            "state-token-secret",
            "github-token",
        ):
            self.assertNotIn(secret, rendered)
        self.assertNotIn("PHASE2_ALLOCATOR_APP_PRIVATE_KEY", values)
        self.assertEqual(result["execution_variable"]["state"], "defined_empty")
        self.assertEqual(result["state_baseline"]["tree_sha"], TREE_SHA)
        self.assertEqual(result["token_observation"]["mutation_capable_tokens_minted"], 0)
        self.assertEqual(inventory_api.delete_calls, ["/installation/token"])
        self.assertEqual(state_api.delete_calls, ["/installation/token"])
        self.assertEqual(
            app_api.mints,
            [
                {"permissions": {"metadata": "read"}},
                {
                    "repository_ids": [STATE_REPOSITORY_ID],
                    "permissions": {"contents": "read", "metadata": "read"},
                },
            ],
        )

    def test_private_key_is_removed_even_if_jwt_construction_fails(self):
        values = {
            "GITHUB_REPOSITORY": observation.CONTROL_REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "99",
            "GITHUB_RUN_ATTEMPT": "1",
            "INPUT_OPERATION": "current_observation",
            "GITHUB_TOKEN": "github-token",
            "PHASE2_ALLOCATOR_APP_ID": "123",
            "PHASE2_ALLOCATOR_INSTALLATION_ID": "456",
            "PHASE2_ALLOCATOR_APP_PRIVATE_KEY": "private-key-secret",
            "PHASE2_CONFIGURATION_VARIABLES_JSON": "{}",
            "PHASE2_STATE_REPOSITORY_ID": str(STATE_REPOSITORY_ID),
        }

        class ControlAPI:
            def get(self, path: str):
                if path.endswith("/environments/phase-2-allocator"):
                    return {
                        "name": observation.ENVIRONMENT_NAME,
                        "protection_rules": [],
                        "deployment_branch_policy": None,
                    }
                raise AssertionError(path)

        def fail_jwt(app_id: int, key: str) -> str:
            raise RuntimeError("JWT_SIGNING_FAILED")

        with self.assertRaisesRegex(RuntimeError, "JWT_SIGNING_FAILED"):
            observation.run(
                values,
                api_factory=lambda token, url: ControlAPI(),
                jwt_factory=fail_jwt,
            )
        self.assertNotIn("PHASE2_ALLOCATOR_APP_PRIVATE_KEY", values)


class CurrentObservationWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = Path(".github/workflows/phase2-adversarial.yml").read_text(
            encoding="utf-8"
        )
        cls.source = Path("phase2/current_observation.py").read_text(encoding="utf-8")

    def test_operation_dispatch_is_isolated_and_has_no_authority_dependencies(self):
        self.assertIn("          - current_observation\n", self.workflow)
        current = self.workflow.split("\n  current-observation:\n", 1)[1].split(
            "\n  operator-preflight:\n", 1
        )[0]
        self.assertIn("    needs: contract-check\n", current)
        self.assertIn("inputs.operation == 'current_observation'", current)
        self.assertIn("environment: phase-2-allocator", current)
        self.assertIn(
            "PHASE2_CONFIGURATION_VARIABLES_JSON: ${{ toJSON(vars) }}", current
        )
        self.assertNotIn("successor-capsule", current)
        self.assertNotIn("operator_preflight", current)
        self.assertNotIn("live-scenario-suite", current)
        self.assertNotIn("issues: write", current)
        self.assertNotIn(
            "PHASE2_WORKSTREAM_D_EXECUTION_ENABLED: ${{ vars.", current
        )

    def test_observation_runtime_has_no_live_or_mutation_profile_path(self):
        for forbidden in (
            "workstream_d_live",
            "workstream_d_revocation",
            "successor_capsule",
            "_mutation_credentials",
            "execute_live_suite",
            "control_profile",
            "state_profile(",
            '"contents": "write"',
            '"issues": "write"',
            "/variables?",
        ):
            self.assertNotIn(forbidden, self.source)

    def test_existing_contract_preflight_and_live_semantics_remain_present(self):
        expected = (
            "        default: contract_check\n",
            "  successor-capsule-discovery:\n    needs: contract-check\n    if: ${{ inputs.operation == 'live_scenario_suite' }}\n",
            "  live-scenario-suite:\n    needs: [contract-check, successor-capsule-consumption, successor-live-l1]\n    if: ${{ inputs.operation == 'live_scenario_suite' }}\n",
            "  operator-preflight:\n    needs: [contract-check]\n    if: ${{ inputs.operation == 'operator_preflight' }}\n",
            "python3 -m unittest discover -s tests -p 'test_operator*.py' -v",
            "PYTHONPATH=. python3 -m phase2.preflight_runtime preflight",
            'run: PYTHONPATH=. "$RUNTIME_PYTHON" -m phase2.successor_runtime live',
        )
        for snippet in expected:
            self.assertIn(snippet, self.workflow)


if __name__ == "__main__":
    unittest.main()
