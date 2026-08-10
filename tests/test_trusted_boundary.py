import unittest
from unittest.mock import Mock, patch

from phase2.credentials import CredentialPolicyError
from phase2.trusted_intake import run


def environment(action="live_check"):
    return {
        "GITHUB_TOKEN": "bounded-workflow-token",
        "GITHUB_API_URL": "https://api.github.invalid",
        "PHASE2_ACTION": action,
        "PHASE2_ALLOCATOR_APP_ID": "10",
        "PHASE2_ALLOCATOR_INSTALLATION_ID": "20",
        "PHASE2_ALLOCATOR_APP_PRIVATE_KEY": "not-used-by-mocked-signer",
        "PHASE2_SOURCE_COMMENT_ID": "77",
        "PHASE2_STATE_REPOSITORY_ID": "2002",
        "PHASE2_TRUSTED_SHA": "a" * 40,
    }


class TrustedBoundaryTests(unittest.TestCase):
    def test_live_installation_failure_mints_no_token(self):
        workflow_api, app_api = Mock(), Mock()
        with (
            patch("phase2.trusted_intake.GitHubAPI", side_effect=[workflow_api, app_api]),
            patch("phase2.trusted_intake.create_app_jwt", return_value="jwt"),
            patch(
                "phase2.trusted_intake.verify_live_installation",
                side_effect=CredentialPolicyError("lost access"),
            ),
            patch("phase2.trusted_intake.mint_token") as mint,
        ):
            result = run(environment())
        self.assertEqual(result["status"], "LIVE_CHECK_REJECTED")
        self.assertFalse(result["state_token_requested"])
        mint.assert_not_called()
        workflow_api.post.assert_called_once()

    def test_regular_intake_never_mints_state_token(self):
        workflow_api, app_api = Mock(), Mock()
        with (
            patch("phase2.trusted_intake.GitHubAPI", side_effect=[workflow_api, app_api]),
            patch("phase2.trusted_intake.create_app_jwt", return_value="jwt"),
            patch("phase2.trusted_intake.verify_live_installation"),
            patch("phase2.trusted_intake.mint_token") as mint,
        ):
            result = run(environment())
        self.assertEqual(result["status"], "LIVE_CHECK_PASSED")
        self.assertFalse(result["state_token_requested"])
        self.assertFalse(result["canonical_accessed"])
        mint.assert_not_called()

    def test_scope_probe_uses_two_separate_tokens(self):
        app_api = Mock()
        values = environment("scope_probe")
        with (
            patch("phase2.trusted_intake.GitHubAPI", side_effect=[Mock(), app_api]),
            patch("phase2.trusted_intake.create_app_jwt", return_value="jwt"),
            patch("phase2.trusted_intake.verify_live_installation"),
            patch(
                "phase2.trusted_intake.mint_token",
                side_effect=["control-token", "state-token"],
            ) as mint,
            patch("phase2.trusted_intake.require_cross_repository_denial"),
            patch("phase2.trusted_intake.require_public_repository_write_denial"),
        ):
            result = run(values)
        self.assertEqual(result["status"], "SCOPE_PROBE_PASSED")
        self.assertEqual(mint.call_count, 2)
        self.assertNotEqual(
            mint.call_args_list[0].args[2].repository_id,
            mint.call_args_list[1].args[2].repository_id,
        )

    def test_scope_probe_rejects_same_repository_identity(self):
        values = environment("scope_probe")
        values["PHASE2_STATE_REPOSITORY_ID"] = "1321106380"
        with (
            patch("phase2.trusted_intake.GitHubAPI", side_effect=[Mock(), Mock()]),
            patch("phase2.trusted_intake.create_app_jwt", return_value="jwt"),
            patch("phase2.trusted_intake.verify_live_installation"),
        ):
            with self.assertRaises(CredentialPolicyError) as error:
                run(values)
        self.assertEqual(str(error.exception), "INVALID_REPOSITORY_SCOPE")

    def test_unapproved_trusted_action_fails_before_signing(self):
        with patch("phase2.trusted_intake.create_app_jwt") as signer:
            with self.assertRaises(CredentialPolicyError):
                run(environment("allocate"))
        signer.assert_not_called()


if __name__ == "__main__":
    unittest.main()
