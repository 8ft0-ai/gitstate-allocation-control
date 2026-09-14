from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from phase2 import current_observation as observation
from phase2.operator_inventory import CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID
from phase2.successor_contract import permission_profile_sha256
from phase2.successor_runtime import state_observation_sha256 as predecessor_state_observation_sha256


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


def environment_payload(*, can_admins_bypass=False, custom=False):
    return {
        "name": observation.ENVIRONMENT_NAME,
        "can_admins_bypass": can_admins_bypass,
        "protection_rules": [{"type": "branch_policy"}]
        if custom
        else [],
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        }
        if custom
        else None,
    }


def stable_environment_variable_handler(value: str | None):
    def get_handler(path: str):
        if path.endswith(f"/variables/{observation.EXECUTION_VARIABLE}"):
            if value is None:
                raise observation.GitHubAPIError(404, "synthetic not found")
            return {"name": observation.EXECUTION_VARIABLE, "value": value}
        if "/variables?" in path:
            variables = (
                []
                if value is None
                else [{"name": observation.EXECUTION_VARIABLE, "value": value}]
            )
            return {"total_count": len(variables), "variables": variables}
        raise AssertionError(path)

    return get_handler


class EphemeralRecipientMixin:
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.recipient_tempdir = tempfile.TemporaryDirectory(
            prefix="gitstate-recipient-test-"
        )
        root = Path(cls.recipient_tempdir.name)
        cls.recipient_key_path = root / "recipient-key.pem"
        cls.recipient_pem_path = root / "recipient-cert.pem"
        cls.recipient_der_path = root / "recipient-cert.der"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(cls.recipient_key_path),
                "-out",
                str(cls.recipient_pem_path),
                "-sha256",
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=gitstate-ephemeral-recipient",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
        subprocess.run(
            [
                "openssl",
                "x509",
                "-in",
                str(cls.recipient_pem_path),
                "-outform",
                "DER",
                "-out",
                str(cls.recipient_der_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
        cls.recipient_der = cls.recipient_der_path.read_bytes()
        cls.recipient_b64 = base64.b64encode(cls.recipient_der).decode("ascii")

    @classmethod
    def tearDownClass(cls):
        cls.recipient_tempdir.cleanup()
        super().tearDownClass()


class CurrentObservationUnitTests(unittest.TestCase):
    def test_literal_environment_variable_absence_empty_and_non_empty_are_distinct(self):
        cases = (
            ([], False, "not_defined"),
            (
                [{"name": observation.EXECUTION_VARIABLE, "value": ""}],
                True,
                "defined_empty",
            ),
            (
                [{"name": observation.EXECUTION_VARIABLE, "value": "true"}],
                True,
                "defined_non_empty",
            ),
        )
        for variables, defined, state in cases:
            with self.subTest(state=state):
                api = TokenAPI(
                    "environment-token",
                    stable_environment_variable_handler(
                        None if not variables else variables[0]["value"]
                    ),
                )
                result = observation._observe_execution_variable(api)
                self.assertEqual(result["defined"], defined)
                self.assertEqual(result["state"], state)
                self.assertNotIn("value", result)

    def test_environment_variable_pagination_is_complete_at_api_maximum_page_size(self):
        page_one = [
            {"name": f"OTHER_{index}", "value": "x"} for index in range(30)
        ]
        page_two = [{"name": observation.EXECUTION_VARIABLE, "value": ""}]

        def get_handler(path: str):
            if path.endswith(f"/variables/{observation.EXECUTION_VARIABLE}"):
                return {"name": observation.EXECUTION_VARIABLE, "value": ""}
            page = int(path.rsplit("page=", 1)[1])
            if page == 1:
                return {"total_count": 31, "variables": page_one}
            if page == 2:
                return {"total_count": 31, "variables": page_two}
            raise AssertionError(path)

        api = TokenAPI("environment-token", get_handler)
        result = observation._observe_execution_variable(api)
        self.assertEqual(result["state"], "defined_empty")
        self.assertEqual(len(api.get_calls), 6)
        self.assertEqual(
            sum("per_page=30&page=1" in path for path in api.get_calls), 2
        )
        self.assertEqual(
            sum("per_page=30&page=2" in path for path in api.get_calls), 2
        )

    def test_environment_variable_evidence_rejects_duplicate_or_malformed_entries(self):
        payloads = (
            {
                "total_count": 2,
                "variables": [
                    {"name": observation.EXECUTION_VARIABLE, "value": ""},
                    {"name": observation.EXECUTION_VARIABLE, "value": "true"},
                ],
            },
            {
                "total_count": 1,
                "variables": [{"name": observation.EXECUTION_VARIABLE, "value": None}],
            },
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                def get_handler(path: str, payload=payload):
                    if path.endswith(
                        f"/variables/{observation.EXECUTION_VARIABLE}"
                    ):
                        value = payload["variables"][0].get("value")
                        return {
                            "name": observation.EXECUTION_VARIABLE,
                            "value": value,
                        }
                    return payload

                api = TokenAPI("environment-token", get_handler)
                with self.assertRaisesRegex(
                    observation.CurrentObservationError,
                    "EXECUTION_VARIABLE_EVIDENCE_AMBIGUOUS",
                ):
                    observation._observe_execution_variable(api)

    def test_same_total_count_pagination_movement_cannot_report_absence(self):
        first_page = [
            {"name": f"OTHER_{index:02d}", "value": "x"} for index in range(30)
        ]
        first_tail = [{"name": "OTHER_30", "value": "x"}]
        second_page = first_page[:-1] + [
            {"name": observation.EXECUTION_VARIABLE, "value": "true"}
        ]
        second_tail = first_tail
        collection_reads = [
            {"total_count": 31, "variables": first_page},
            {"total_count": 31, "variables": first_tail},
            {"total_count": 31, "variables": second_page},
            {"total_count": 31, "variables": second_tail},
        ]

        def get_handler(path: str):
            if path.endswith(f"/variables/{observation.EXECUTION_VARIABLE}"):
                raise observation.GitHubAPIError(404, "synthetic not found")
            return collection_reads.pop(0)

        with self.assertRaisesRegex(
            observation.CurrentObservationError,
            "EXECUTION_VARIABLE_EVIDENCE_MOVED",
        ):
            observation._observe_execution_variable(
                TokenAPI("environment-token", get_handler)
            )

    def test_exact_execution_variable_movement_fails_closed(self):
        cases = (
            ("", "changed"),
            ("", None),
            (None, ""),
        )
        for first, second in cases:
            with self.subTest(first=first, second=second):
                exact_reads: list[str | None] = [first, second]

                def get_handler(path: str):
                    if path.endswith(
                        f"/variables/{observation.EXECUTION_VARIABLE}"
                    ):
                        value = exact_reads.pop(0)
                        if value is None:
                            raise observation.GitHubAPIError(
                                404, "synthetic not found"
                            )
                        return {
                            "name": observation.EXECUTION_VARIABLE,
                            "value": value,
                        }
                    variables = (
                        []
                        if first is None
                        else [
                            {
                                "name": observation.EXECUTION_VARIABLE,
                                "value": first,
                            }
                        ]
                    )
                    return {
                        "total_count": len(variables),
                        "variables": variables,
                    }

                with self.assertRaisesRegex(
                    observation.CurrentObservationError,
                    "EXECUTION_VARIABLE_EVIDENCE_MOVED",
                ):
                    observation._observe_execution_variable(
                        TokenAPI("environment-token", get_handler)
                    )

    def test_exact_404_is_ambiguous_when_complete_collection_contains_variable(self):
        def get_handler(path: str):
            if path.endswith(f"/variables/{observation.EXECUTION_VARIABLE}"):
                raise observation.GitHubAPIError(404, "synthetic not found")
            return {
                "total_count": 1,
                "variables": [
                    {"name": observation.EXECUTION_VARIABLE, "value": "true"}
                ],
            }

        with self.assertRaisesRegex(
            observation.CurrentObservationError,
            "EXECUTION_VARIABLE_EVIDENCE_AMBIGUOUS",
        ):
            observation._observe_execution_variable(
                TokenAPI("environment-token", get_handler)
            )

    def test_environment_token_scope_permissions_and_positive_revocation(self):
        response = {
            "token": "environment-token",
            "permissions": {"environments": "read", "metadata": "read"},
            "repositories": [{"id": CONTROL_REPOSITORY_ID}],
        }
        app_api = MintingAppAPI([response])
        environment_api = TokenAPI(
            "environment-token",
            stable_environment_variable_handler(None),
        )
        result = observation._observe_environment_variable(
            app_api,
            installation_id=77,
            api_url="https://api.github.test",
            api_factory=lambda token, url: environment_api,
        )
        self.assertEqual(result["state"], "not_defined")
        self.assertEqual(
            app_api.posts,
            [
                (
                    "/app/installations/77/access_tokens",
                    {
                        "repository_ids": [CONTROL_REPOSITORY_ID],
                        "permissions": {
                            "environments": "read",
                            "metadata": "read",
                        },
                    },
                )
            ],
        )
        self.assertEqual(environment_api.delete_calls, ["/installation/token"])

    def test_environment_token_permission_widening_still_revokes(self):
        response = {
            "token": "environment-token",
            "permissions": {"environments": "write", "metadata": "read"},
            "repositories": [{"id": CONTROL_REPOSITORY_ID}],
        }
        app_api = MintingAppAPI([response])
        revocation_api = TokenAPI("environment-token", lambda path: None)
        with self.assertRaisesRegex(
            observation.CurrentObservationError,
            "ENVIRONMENT_TOKEN_PERMISSION_MISMATCH",
        ):
            observation._observe_environment_variable(
                app_api,
                installation_id=77,
                api_url="https://api.github.test",
                api_factory=lambda token, url: revocation_api,
            )
        self.assertEqual(revocation_api.delete_calls, ["/installation/token"])

    def test_environment_token_client_construction_failure_still_attempts_revocation(self):
        response = {
            "token": "environment-token",
            "permissions": {"environments": "read", "metadata": "read"},
            "repositories": [{"id": CONTROL_REPOSITORY_ID}],
        }
        app_api = MintingAppAPI([response])
        revocation_api = TokenAPI("environment-token", lambda path: None)
        calls = 0

        def api_factory(token: str, url: str):
            nonlocal calls
            del token, url
            calls += 1
            if calls == 1:
                raise RuntimeError("CLIENT_CONSTRUCTION_FAILED")
            return revocation_api

        with self.assertRaisesRegex(RuntimeError, "CLIENT_CONSTRUCTION_FAILED"):
            observation._observe_environment_variable(
                app_api,
                installation_id=77,
                api_url="https://api.github.test",
                api_factory=api_factory,
            )
        self.assertEqual(revocation_api.delete_calls, ["/installation/token"])

    def test_environment_token_revocation_requires_http_204(self):
        response = {
            "token": "environment-token",
            "permissions": {"environments": "read", "metadata": "read"},
            "repositories": [{"id": CONTROL_REPOSITORY_ID}],
        }
        app_api = MintingAppAPI([response])
        environment_api = TokenAPI(
            "environment-token",
            stable_environment_variable_handler(None),
        )
        environment_api.delete_status = 200
        with self.assertRaisesRegex(
            observation.CurrentObservationError,
            "ENVIRONMENT_TOKEN_REVOCATION_FAILED",
        ):
            observation._observe_environment_variable(
                app_api,
                installation_id=77,
                api_url="https://api.github.test",
                api_factory=lambda token, url: environment_api,
            )

    def test_environment_observation_movement_still_revokes_token(self):
        response = {
            "token": "environment-token",
            "permissions": {"environments": "read", "metadata": "read"},
            "repositories": [{"id": CONTROL_REPOSITORY_ID}],
        }
        app_api = MintingAppAPI([response])
        exact_reads = ["", "changed"]

        def get_handler(path: str):
            if path.endswith(f"/variables/{observation.EXECUTION_VARIABLE}"):
                return {
                    "name": observation.EXECUTION_VARIABLE,
                    "value": exact_reads.pop(0),
                }
            return {
                "total_count": 1,
                "variables": [
                    {"name": observation.EXECUTION_VARIABLE, "value": ""}
                ],
            }

        environment_api = TokenAPI("environment-token", get_handler)
        with self.assertRaisesRegex(
            observation.CurrentObservationError,
            "EXECUTION_VARIABLE_EVIDENCE_MOVED",
        ):
            observation._observe_environment_variable(
                app_api,
                installation_id=77,
                api_url="https://api.github.test",
                api_factory=lambda token, url: environment_api,
            )
        self.assertEqual(environment_api.delete_calls, ["/installation/token"])

    def test_policy_binds_admin_bypass_and_custom_protection_rules(self):
        payload = environment_payload(can_admins_bypass=False)
        empty = {
            "total_count": 0,
            "custom_deployment_protection_rules": [],
        }
        custom = {
            "total_count": 1,
            "custom_deployment_protection_rules": [
                {
                    "id": 101,
                    "enabled": True,
                    "app": {"id": 202, "slug": "deployment-guard"},
                }
            ],
        }
        baseline = observation._environment_policy_material(
            payload,
            observation.ENVIRONMENT_NAME,
            custom_protection_rules=empty,
        )
        with_rule = observation._environment_policy_material(
            payload,
            observation.ENVIRONMENT_NAME,
            custom_protection_rules=custom,
        )
        bypassed_payload = dict(payload)
        bypassed_payload["can_admins_bypass"] = True
        with_bypass = observation._environment_policy_material(
            bypassed_payload,
            observation.ENVIRONMENT_NAME,
            custom_protection_rules=empty,
        )
        self.assertNotEqual(
            observation.sha256_text(observation.canonical_json(baseline)),
            observation.sha256_text(observation.canonical_json(with_rule)),
        )
        self.assertNotEqual(
            observation.sha256_text(observation.canonical_json(baseline)),
            observation.sha256_text(observation.canonical_json(with_bypass)),
        )

    def test_custom_branch_policy_without_branch_or_tag_type_fails_closed(self):
        payload = environment_payload(custom=True)
        with self.assertRaisesRegex(
            observation.CurrentObservationError,
            "CUSTOM_BRANCH_POLICY_TYPE_UNAVAILABLE",
        ):
            observation._environment_policy_material(
                payload,
                observation.ENVIRONMENT_NAME,
                branch_policies=[{"id": 10, "name": "main"}],
                custom_protection_rules={
                    "total_count": 0,
                    "custom_deployment_protection_rules": [],
                },
            )

    def test_typed_branch_and_tag_policies_are_canonicalised_deterministically(self):
        payload = environment_payload(custom=True)
        material = observation._environment_policy_material(
            payload,
            observation.ENVIRONMENT_NAME,
            branch_policies=[
                {"id": 2, "name": "v*", "type": "tag"},
                {"id": 1, "name": "main", "type": "branch"},
            ],
            custom_protection_rules={
                "total_count": 0,
                "custom_deployment_protection_rules": [],
            },
        )
        self.assertEqual(
            material["deployment_branch_policies"],
            [
                {"id": 1, "name": "main", "type": "branch"},
                {"id": 2, "name": "v*", "type": "tag"},
            ],
        )

    def test_environment_policy_double_scan_detects_movement(self):
        first = environment_payload(can_admins_bypass=False)
        second = environment_payload(can_admins_bypass=True)
        environment_reads = [first, first, second, second]

        class PolicyAPI:
            def get(self, path: str):
                if path.endswith("/deployment_protection_rules"):
                    return {
                        "total_count": 0,
                        "custom_deployment_protection_rules": [],
                    }
                if path.endswith("/environments/phase-2-allocator"):
                    return environment_reads.pop(0)
                raise AssertionError(path)

        with self.assertRaisesRegex(
            observation.CurrentObservationError,
            "ENVIRONMENT_POLICY_MOVED",
        ):
            observation._observe_environment_policy(PolicyAPI())

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

    def test_reviewed_live_permission_profile_digest_remains_unchanged(self):
        self.assertEqual(observation.PERMISSION_PROFILE_SHA256, permission_profile_sha256())


class CurrentObservationEndToEndTests(EphemeralRecipientMixin, unittest.TestCase):
    def test_output_is_sanitised_key_is_scrubbed_and_only_read_tokens_are_minted(self):
        policy_payload = environment_payload()
        empty_custom_rules = {
            "total_count": 0,
            "custom_deployment_protection_rules": [],
        }

        class ControlAPI:
            token = "github-token"

            def get(self, path: str):
                if path.endswith("/deployment_protection_rules"):
                    return empty_custom_rules
                if path.endswith("/environments/phase-2-allocator"):
                    return policy_payload
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
                    "repository_ids": [CONTROL_REPOSITORY_ID],
                    "permissions": {"environments": "read", "metadata": "read"},
                }:
                    return {
                        "token": "environment-token-secret",
                        "permissions": {"environments": "read", "metadata": "read"},
                        "repositories": [{"id": CONTROL_REPOSITORY_ID}],
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

        environment_api = TokenAPI(
            "environment-token-secret",
            stable_environment_variable_handler(""),
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
                "environment-token-secret": environment_api,
                "state-token-secret": state_api,
            }[token]

        values = {
            "GITHUB_REPOSITORY": observation.CONTROL_REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "99",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_ACTOR": observation.CONTROL_OWNER,
            "INPUT_OPERATION": "current_observation",
            observation.RECIPIENT_CERTIFICATE_ENV: self.recipient_b64,
            "GITHUB_TOKEN": "github-token",
            "GITHUB_API_URL": "https://api.github.test",
            "PHASE2_ALLOCATOR_APP_ID": "123",
            "PHASE2_ALLOCATOR_INSTALLATION_ID": "456",
            "PHASE2_ALLOCATOR_APP_PRIVATE_KEY": "private-key-secret",
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
            "environment-token-secret",
            "state-token-secret",
            "github-token",
        ):
            self.assertNotIn(secret, rendered)
        self.assertNotIn("PHASE2_ALLOCATOR_APP_PRIVATE_KEY", values)
        self.assertEqual(result["execution_variable"]["state"], "defined_empty")
        self.assertEqual(result["state_baseline"]["tree_sha"], TREE_SHA)
        self.assertEqual(
            result["token_observation"]["mutation_capable_tokens_minted"], 0
        )
        self.assertTrue(
            result["token_observation"]["environment_observation_token_revoked"]
        )
        self.assertEqual(inventory_api.delete_calls, ["/installation/token"])
        self.assertEqual(environment_api.delete_calls, ["/installation/token"])
        self.assertEqual(state_api.delete_calls, ["/installation/token"])
        self.assertEqual(
            app_api.mints,
            [
                {"permissions": {"metadata": "read"}},
                {
                    "repository_ids": [CONTROL_REPOSITORY_ID],
                    "permissions": {"environments": "read", "metadata": "read"},
                },
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
            "GITHUB_ACTOR": observation.CONTROL_OWNER,
            "INPUT_OPERATION": "current_observation",
            observation.RECIPIENT_CERTIFICATE_ENV: self.recipient_b64,
            "GITHUB_TOKEN": "github-token",
            "PHASE2_ALLOCATOR_APP_ID": "123",
            "PHASE2_ALLOCATOR_INSTALLATION_ID": "456",
            "PHASE2_ALLOCATOR_APP_PRIVATE_KEY": "private-key-secret",
            "PHASE2_STATE_REPOSITORY_ID": str(STATE_REPOSITORY_ID),
        }

        class ControlAPI:
            def get(self, path: str):
                if path.endswith("/deployment_protection_rules"):
                    return {
                        "total_count": 0,
                        "custom_deployment_protection_rules": [],
                    }
                if path.endswith("/environments/phase-2-allocator"):
                    return environment_payload()
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

    def test_actor_and_recipient_are_rejected_before_allocator_key_access(self):
        cases = (
            ("untrusted-actor", self.recipient_b64, "OBSERVATION_OWNER_ACTOR_REQUIRED"),
            (observation.CONTROL_OWNER, "not-base64!", "RECIPIENT_CERTIFICATE_INVALID"),
        )
        for actor, certificate, reason in cases:
            with self.subTest(reason=reason):
                values = {
                    "GITHUB_REPOSITORY": observation.CONTROL_REPOSITORY,
                    "GITHUB_REF": "refs/heads/main",
                    "GITHUB_SHA": "a" * 40,
                    "GITHUB_RUN_ID": "99",
                    "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_ACTOR": actor,
                    "INPUT_OPERATION": "current_observation",
                    observation.RECIPIENT_CERTIFICATE_ENV: certificate,
                    "PHASE2_ALLOCATOR_APP_PRIVATE_KEY": "untouched-private-key",
                }
                jwt_called = False

                def unexpected_jwt(app_id: int, key: str) -> str:
                    nonlocal jwt_called
                    jwt_called = True
                    raise AssertionError((app_id, key))

                with self.assertRaisesRegex(
                    observation.CurrentObservationError, reason
                ):
                    observation.run(
                        values,
                        api_factory=lambda token, url: (_ for _ in ()).throw(
                            AssertionError((token, url))
                        ),
                        jwt_factory=unexpected_jwt,
                    )
                self.assertFalse(jwt_called)
                self.assertEqual(
                    values["PHASE2_ALLOCATOR_APP_PRIVATE_KEY"],
                    "untouched-private-key",
                )


class CurrentObservationCLITests(EphemeralRecipientMixin, unittest.TestCase):
    def private_observation(self) -> dict[str, object]:
        return {
            "status": "GITSTATE_CURRENT_OBSERVATION_COMPLETE",
            "operation": "current_observation",
            "run_id": 99,
            "run_attempt": 1,
            "trusted_sha": "a" * 40,
            "allocator_app": {
                "app_id": "PRIVATE-APP-ID-SENTINEL",
                "installation_id": "PRIVATE-INSTALLATION-ID-SENTINEL",
            },
            "installation_inventory": {
                "selected_repository_ids": [
                    "PRIVATE-REPOSITORY-ID-SENTINEL"
                ]
            },
            "state_baseline": {
                "repository": "PRIVATE-STATE-REPOSITORY-SENTINEL",
                "commit_sha": "PRIVATE-STATE-COMMIT-SENTINEL",
                "tree_sha": "PRIVATE-STATE-TREE-SENTINEL",
                "sha256": "PRIVATE-STATE-DIGEST-SENTINEL",
            },
            "protected_environment": {
                "policy": "PRIVATE-POLICY-MATERIAL-SENTINEL",
                "policy_sha256": "PRIVATE-POLICY-DIGEST-SENTINEL",
            },
            "execution_variable": "PRIVATE-EXECUTION-VARIABLE-SENTINEL",
        }

    def test_cli_stdout_is_public_safe_and_envelope_round_trips_exactly(self):
        private_payload = self.private_observation()
        cli_environment = {
            "GITHUB_ACTOR": observation.CONTROL_OWNER,
            observation.RECIPIENT_CERTIFICATE_ENV: self.recipient_b64,
        }
        output = io.StringIO()
        with mock.patch.dict(os.environ, cli_environment, clear=False), mock.patch.object(
            observation, "run", return_value=private_payload
        ) as run_mock, redirect_stdout(output):
            exit_code = observation.main([])

        self.assertEqual(exit_code, 0)
        run_mock.assert_called_once()
        rendered = output.getvalue()
        envelope = json.loads(rendered)
        for sentinel in (
            "PRIVATE-APP-ID-SENTINEL",
            "PRIVATE-INSTALLATION-ID-SENTINEL",
            "PRIVATE-REPOSITORY-ID-SENTINEL",
            "PRIVATE-STATE-REPOSITORY-SENTINEL",
            "PRIVATE-STATE-COMMIT-SENTINEL",
            "PRIVATE-STATE-TREE-SENTINEL",
            "PRIVATE-STATE-DIGEST-SENTINEL",
            "PRIVATE-POLICY-MATERIAL-SENTINEL",
            "PRIVATE-POLICY-DIGEST-SENTINEL",
            "PRIVATE-EXECUTION-VARIABLE-SENTINEL",
        ):
            self.assertNotIn(sentinel, rendered)

        ciphertext = base64.b64decode(envelope["ciphertext_b64"], validate=True)
        self.assertEqual(
            envelope["recipient_certificate_sha256"],
            hashlib.sha256(self.recipient_der).hexdigest(),
        )
        self.assertEqual(
            envelope["ciphertext_sha256"], hashlib.sha256(ciphertext).hexdigest()
        )
        decrypt_result = subprocess.run(
            [
                "openssl",
                "cms",
                "-decrypt",
                "-binary",
                "-inform",
                "DER",
                "-recip",
                str(self.recipient_pem_path),
                "-inkey",
                str(self.recipient_key_path),
            ],
            input=ciphertext,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
        )
        self.assertEqual(
            decrypt_result.returncode,
            0,
            decrypt_result.stderr.decode("utf-8", "replace"),
        )
        decrypted = decrypt_result.stdout
        self.assertEqual(
            decrypted.decode("utf-8"), observation.canonical_json(private_payload)
        )
        self.assertFalse(envelope["private_observation_plaintext_emitted"])
        self.assertFalse(envelope["plaintext_temporary_file_created"])
        self.assertTrue(envelope["authenticated_public_key_encryption"])

    def test_recipient_binding_mismatch_fails_closed(self):
        mismatched = observation.RecipientCertificate(
            der=self.recipient_der,
            sha256="0" * 64,
        )
        with self.assertRaisesRegex(
            observation.CurrentObservationError,
            "RECIPIENT_CERTIFICATE_MISMATCH",
        ):
            observation._seal_observation(self.private_observation(), mismatched)


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
        self.assertNotIn("PHASE2_CONFIGURATION_VARIABLES_JSON", current)
        self.assertNotIn("toJSON(vars)", current)
        self.assertNotIn("successor-capsule", current)
        self.assertNotIn("operator_preflight", current)
        self.assertNotIn("live-scenario-suite", current)
        self.assertNotIn("issues: write", current)
        self.assertNotIn(
            "PHASE2_WORKSTREAM_D_EXECUTION_ENABLED: ${{ vars.", current
        )
        self.assertIn(
            "INPUT_CURRENT_OBSERVATION_RECIPIENT_CERT_B64: ${{ inputs.current_observation_recipient_cert_b64 }}",
            current,
        )
        self.assertIn(
            "current_observation_recipient_cert_b64:\n",
            self.workflow,
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
            '"environments": "write"',
            "PHASE2_CONFIGURATION_VARIABLES_JSON",
        ):
            self.assertNotIn(forbidden, self.source)
        self.assertIn('"environments": "read"', self.source)
        self.assertIn("/variables", self.source)

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
