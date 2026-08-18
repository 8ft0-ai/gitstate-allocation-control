import unittest
from datetime import datetime, timezone

from phase2.credentials import CredentialPolicyError, TokenProfile, token_request
from phase2.operator_inventory import (
    CONTROL_REPOSITORY_ID,
    EXPECTED_REPOSITORY_IDS,
    INVENTORY_PERMISSIONS,
    STATE_REPOSITORY_ID,
    InventoryProofError,
    inventory_token_request,
    prove_installation_inventory,
)


class FakeTokenAPI:
    def __init__(self, pages, calls, *, revoke_status=204):
        self.pages = pages
        self.calls = calls
        self.revoke_status = revoke_status

    def get(self, path):
        self.calls.append(("inventory", "GET", path))
        page = int(path.split("page=")[-1])
        return self.pages.get(page, {"total_count": 0, "repositories": []})

    def request_with_status(self, method, path, body=None):
        self.calls.append(("inventory", method, path))
        return None, {}, self.revoke_status


class FakeAppAPI:
    def __init__(self, calls, response=None):
        self.calls = calls
        self.response = response or {
            "token": "inventory-token",
            "permissions": dict(INVENTORY_PERMISSIONS),
            "repository_selection": "selected",
        }

    def post(self, path, body):
        self.calls.append(("app", "POST", path, body))
        return dict(self.response)


class OperatorInventoryTests(unittest.TestCase):
    def test_inventory_request_is_installation_wide_metadata_read_only(self):
        request = inventory_token_request()
        self.assertEqual(request, {"permissions": {"metadata": "read"}})
        self.assertNotIn("repository_ids", request)
        self.assertNotIn("repositories", request)
        self.assertEqual(set(request["permissions"]), {"metadata"})

    def test_inventory_profile_cannot_be_used_as_existing_runtime_token_profile(self):
        with self.assertRaises(CredentialPolicyError):
            token_request(
                TokenProfile(
                    "inventory",
                    CONTROL_REPOSITORY_ID,
                    {"metadata": "read"},
                )
            )

    def test_exact_inventory_is_fully_enumerated_then_revoked(self):
        calls = []
        pages = {
            1: {
                "total_count": 2,
                "repositories": [
                    {"id": CONTROL_REPOSITORY_ID},
                    {"id": STATE_REPOSITORY_ID},
                ],
            }
        }
        token_api = FakeTokenAPI(pages, calls)
        evidence = prove_installation_inventory(
            FakeAppAPI(calls),
            installation_id=20,
            app_id=10,
            repository_selection="selected",
            run_id=123,
            run_attempt=1,
            trusted_sha="a" * 40,
            capsule_id="b" * 32,
            capsule_body_sha256="c" * 64,
            api_url="https://api.github.invalid",
            api_factory=lambda token, url: token_api,
            now=datetime(2026, 8, 18, 12, tzinfo=timezone.utc),
        )
        self.assertEqual(evidence.repository_ids, EXPECTED_REPOSITORY_IDS)
        self.assertTrue(evidence.token_revoked)
        self.assertEqual(len(evidence.digest), 64)
        self.assertEqual(evidence.payload()["repository_count"], 2)
        self.assertEqual(evidence.payload()["inventory_token_permissions"], {"metadata": "read"})
        self.assertEqual(
            calls,
            [
                (
                    "app",
                    "POST",
                    "/app/installations/20/access_tokens",
                    {"permissions": {"metadata": "read"}},
                ),
                (
                    "inventory",
                    "GET",
                    "/installation/repositories?per_page=100&page=1",
                ),
                ("inventory", "DELETE", "/installation/token"),
            ],
        )

    def test_extra_or_missing_repository_fails_but_token_is_still_revoked(self):
        for ids in (
            [CONTROL_REPOSITORY_ID],
            [CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID, 999],
        ):
            calls = []
            pages = {
                1: {
                    "total_count": len(ids),
                    "repositories": [{"id": value} for value in ids],
                }
            }
            with self.subTest(ids=ids):
                with self.assertRaisesRegex(InventoryProofError, "INVENTORY_EXACT_SET_MISMATCH"):
                    prove_installation_inventory(
                        FakeAppAPI(calls),
                        installation_id=20,
                        app_id=10,
                        repository_selection="selected",
                        run_id=123,
                        run_attempt=1,
                        trusted_sha="a" * 40,
                        capsule_id="b" * 32,
                        capsule_body_sha256="c" * 64,
                        api_url="https://api.github.invalid",
                        api_factory=lambda token, url: FakeTokenAPI(pages, calls),
                    )
                self.assertIn(("inventory", "DELETE", "/installation/token"), calls)

    def test_incomplete_pagination_fails_closed_and_revokes(self):
        calls = []
        pages = {
            1: {
                "total_count": 101,
                "repositories": [{"id": i + 1} for i in range(50)],
            }
        }
        with self.assertRaisesRegex(InventoryProofError, "INVENTORY_PAGINATION_INCOMPLETE"):
            prove_installation_inventory(
                FakeAppAPI(calls),
                installation_id=20,
                app_id=10,
                repository_selection="selected",
                run_id=123,
                run_attempt=1,
                trusted_sha="a" * 40,
                capsule_id="b" * 32,
                capsule_body_sha256="c" * 64,
                api_url="https://api.github.invalid",
                api_factory=lambda token, url: FakeTokenAPI(pages, calls),
            )
        self.assertIn(("inventory", "DELETE", "/installation/token"), calls)

    def test_permission_widening_fails_without_inventory_use_but_still_revokes(self):
        calls = []
        app = FakeAppAPI(
            calls,
            response={
                "token": "inventory-token",
                "permissions": {"metadata": "read", "contents": "read"},
                "repository_selection": "selected",
            },
        )
        token_api = FakeTokenAPI({}, calls)
        with self.assertRaisesRegex(InventoryProofError, "INVENTORY_TOKEN_PERMISSION_MISMATCH"):
            prove_installation_inventory(
                app,
                installation_id=20,
                app_id=10,
                repository_selection="selected",
                run_id=123,
                run_attempt=1,
                trusted_sha="a" * 40,
                capsule_id="b" * 32,
                capsule_body_sha256="c" * 64,
                api_url="https://api.github.invalid",
                api_factory=lambda token, url: token_api,
            )
        self.assertEqual(
            calls,
            [
                (
                    "app",
                    "POST",
                    "/app/installations/20/access_tokens",
                    {"permissions": {"metadata": "read"}},
                ),
                ("inventory", "DELETE", "/installation/token"),
            ],
        )

    def test_revocation_must_return_204(self):
        calls = []
        pages = {
            1: {
                "total_count": 2,
                "repositories": [
                    {"id": CONTROL_REPOSITORY_ID},
                    {"id": STATE_REPOSITORY_ID},
                ],
            }
        }
        with self.assertRaisesRegex(InventoryProofError, "INVENTORY_TOKEN_REVOCATION_FAILED"):
            prove_installation_inventory(
                FakeAppAPI(calls),
                installation_id=20,
                app_id=10,
                repository_selection="selected",
                run_id=123,
                run_attempt=1,
                trusted_sha="a" * 40,
                capsule_id="b" * 32,
                capsule_body_sha256="c" * 64,
                api_url="https://api.github.invalid",
                api_factory=lambda token, url: FakeTokenAPI(
                    pages, calls, revoke_status=200
                ),
            )


if __name__ == "__main__":
    unittest.main()
