import re
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
WORKFLOW = (ROOT / ".github/workflows/phase2-intake.yml").read_text()


class WorkflowPolicyTests(unittest.TestCase):
    def test_required_triggers_concurrency_and_manual_modes(self):
        self.assertIn("types: [created, edited, deleted]", WORKFLOW)
        self.assertIn("schedule:", WORKFLOW)
        self.assertIn("workflow_dispatch:", WORKFLOW)
        self.assertIn("default: reconcile", WORKFLOW)
        self.assertIn("- reconcile", WORKFLOW)
        self.assertIn("- scope_probe", WORKFLOW)
        self.assertIn("group: beads-allocation-v0.2-${{ github.repository }}", WORKFLOW)
        self.assertIn("cancel-in-progress: false", WORKFLOW)

    def test_full_sha_pins_use_supported_action_revisions(self):
        workflows = "\n".join(path.read_text() for path in (ROOT / ".github/workflows").glob("*.yml"))
        uses = re.findall(r"uses:\s+([^\s]+)", workflows)
        self.assertTrue(uses)
        self.assertTrue(all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", item) for item in uses))
        self.assertNotIn("11bd71901bbe5b1630ceea73d27597364c9af683", workflows)
        self.assertNotIn("60a0d83039c74a4aee543508d2ffcb1c3799cdea", workflows)

    def test_static_job_boundary(self):
        static = WORKFLOW.split("  report-static-rejection:", 1)[0]
        self.assertNotIn("actions/checkout", static)
        self.assertNotIn("PHASE2_ALLOCATOR_APP_PRIVATE_KEY", static)
        self.assertNotIn("issues: write", static)
        self.assertIn("github.workflow_sha", static)
        self.assertIn("phase2/control_surface.py", static)

    def test_source_revalidation_is_credential_free_and_read_only(self):
        source = WORKFLOW.split("  source-revalidation:", 1)[1].split("  report-source-rejection:", 1)[0]
        self.assertIn("phase2.source_revalidation", source)
        self.assertIn("issues: read", source)
        self.assertNotIn("issues: write", source)
        self.assertNotIn("PHASE2_ALLOCATOR_APP_PRIVATE_KEY", source)
        self.assertNotIn("PHASE2_STATE_REPOSITORY_ID", source)
        self.assertIn("persist-credentials: false", source)

    def test_trusted_key_step_requires_successful_source_or_explicit_scope_probe(self):
        trusted = WORKFLOW.split("  trusted-live-check:", 1)[1]
        self.assertIn("environment: phase-2-allocator", trusted)
        self.assertIn("needs.source-revalidation.outputs.action == 'live_check'", trusted)
        self.assertIn("needs.static-authorisation.outputs.action == 'scope_probe'", trusted)
        self.assertIn("vars.PHASE2_INTAKE_ENABLED == 'true'", trusted)
        self.assertIn("ref: ${{ needs.static-authorisation.outputs.trusted_sha }}", trusted)
        self.assertIn("persist-credentials: false", trusted)
        self.assertEqual(WORKFLOW.count("secrets.PHASE2_ALLOCATOR_APP_PRIVATE_KEY"), 1)
        self.assertEqual(WORKFLOW.count("secrets.PHASE2_STATE_REPOSITORY_ID"), 1)

    def test_control_surface_policy_is_immutable_and_explicit(self):
        policy = (ROOT / "policy/actors.json").read_text()
        self.assertIn('"allocation_issue_number": 1', policy)
        self.assertIn('"allocation_issue_required_label": "phase-2-control"', policy)
        self.assertIn('"allocation_issue_required_state": "open"', policy)

    def test_protected_repository_identity_uses_environment_indirection(self):
        policy = (ROOT / "policy/actors.json").read_text()
        trusted = (ROOT / "phase2/trusted_intake.py").read_text()
        self.assertIn('"state_repository_id_env": "PHASE2_STATE_REPOSITORY_ID"', policy)
        self.assertNotRegex(policy, r'"state_repository_id"\s*:\s*\d')
        self.assertNotRegex(trusted, r"state_id\s*=\s*\d")
        self.assertNotRegex(trusted, r"/repos/[^/\s]+/[^/\s]*state[^/\s]*")


if __name__ == "__main__":
    unittest.main()
