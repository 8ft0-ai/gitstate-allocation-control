import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from phase2.credentials import (
    CredentialPolicyError,
    TokenProfile,
    control_profile,
    require_cross_repository_denial,
    require_public_repository_write_denial,
    state_profile,
    token_request,
    validate_token_response,
)
from phase2.github_api import GitHubAPIError
from phase2.inventory import InventoryAttestation, InventoryError


def attestation(**changes):
    value = {
        "app_id": 10,
        "installation_id": 20,
        "repository_selection": "selected",
        "repository_ids": [1001, 2002],
        "audited_at": "2026-01-01T00:00:00Z",
    }
    value.update(changes)
    return InventoryAttestation.from_dict(value)


def validate(value):
    value.validate(
        app_id=10,
        installation_id=20,
        expected_repository_ids={1001, 2002},
        now=datetime(2026, 1, 1, 1, tzinfo=timezone.utc),
        max_age_seconds=7200,
    )


class CredentialsInventoryTests(unittest.TestCase):
    def test_exact_profiles(self):
        self.assertEqual(
            token_request(control_profile(1001)),
            {
                "repository_ids": [1001],
                "permissions": {"contents": "read", "issues": "write", "metadata": "read"},
            },
        )
        self.assertEqual(
            token_request(state_profile(2002)),
            {
                "repository_ids": [2002],
                "permissions": {"contents": "write", "metadata": "read"},
            },
        )

    def test_unapproved_profiles_fail_before_mint(self):
        profiles = [
            TokenProfile("default", 1001, {}),
            TokenProfile("control", 0, {"contents": "read", "issues": "write", "metadata": "read"}),
            TokenProfile("control", 1001, {"contents": "write", "issues": "write", "metadata": "read"}),
            TokenProfile("state", 2002, {"contents": "write", "issues": "write", "metadata": "read"}),
        ]
        for profile in profiles:
            with self.subTest(profile=profile):
                with self.assertRaises(CredentialPolicyError):
                    token_request(profile)

    def test_returned_scope_exact(self):
        profile = control_profile(1001)
        valid = {"token": "ephemeral", "repositories": [{"id": 1001}], "permissions": profile.permissions}
        self.assertEqual(validate_token_response(valid, profile), "ephemeral")
        with self.assertRaises(CredentialPolicyError):
            validate_token_response({**valid, "repositories": [{"id": 1001}, {"id": 2002}]}, profile)
        with self.assertRaises(CredentialPolicyError):
            validate_token_response({**valid, "permissions": {**profile.permissions, "workflows": "write"}}, profile)

    def test_cross_repository_denial_requires_private_404(self):
        api = Mock()
        api.get.side_effect = GitHubAPIError(404, "not found")
        with patch("phase2.credentials.GitHubAPI", return_value=api):
            require_cross_repository_denial("control-token", 2002, "https://api.github.invalid")

        api = Mock()
        api.get.side_effect = GitHubAPIError(403, "forbidden")
        with patch("phase2.credentials.GitHubAPI", return_value=api):
            with self.assertRaises(CredentialPolicyError) as error:
                require_cross_repository_denial("control-token", 2002, "https://api.github.invalid")
        self.assertEqual(str(error.exception), "UNEXPECTED_CROSS_REPOSITORY_RESULT")

    def test_public_write_denial_probe_is_non_destructive_and_fail_closed(self):
        api = Mock()
        api.request.side_effect = GitHubAPIError(403, "forbidden")
        with patch("phase2.credentials.GitHubAPI", return_value=api):
            require_public_repository_write_denial(
                "state-token", "example", "control", "https://api.github.invalid"
            )
        _, path, payload = api.request.call_args.args
        self.assertEqual(path, "/repos/example/control/contents/.phase2-cross-scope-probe")
        self.assertEqual(payload["sha"], "0" * 40)
        self.assertEqual(payload["content"], "")

        api = Mock()
        api.request.side_effect = GitHubAPIError(422, "validation failed")
        with patch("phase2.credentials.GitHubAPI", return_value=api):
            with self.assertRaises(CredentialPolicyError) as error:
                require_public_repository_write_denial(
                    "state-token", "example", "control", "https://api.github.invalid"
                )
        self.assertEqual(str(error.exception), "CROSS_REPOSITORY_WRITE_ACCESS_PRESENT")

    def test_inventory_gate(self):
        validate(attestation())
        cases = [
            (attestation(repository_ids=[1001]), "REPOSITORY_INVENTORY_MISMATCH"),
            (attestation(repository_ids=[1001, 2002, 3003]), "REPOSITORY_INVENTORY_MISMATCH"),
            (attestation(invalidated=True), "INVALIDATED_ATTESTATION"),
            (attestation(audited_at="2025-12-31T20:00:00Z"), "STALE_ATTESTATION"),
            (attestation(repository_selection="all"), "INVALID_REPOSITORY_SELECTION"),
        ]
        for value, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(InventoryError) as error:
                    validate(value)
                self.assertEqual(str(error.exception), reason)


if __name__ == "__main__":
    unittest.main()
