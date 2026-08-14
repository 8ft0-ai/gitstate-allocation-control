import unittest
from pathlib import Path

from phase2.workflow_policy import WorkflowPolicyError, validate_workflow

ROOT = Path(__file__).parents[1]
WORKFLOW = (ROOT / ".github/workflows/phase2-intake.yml").read_text()


class WorkflowPolicyTests(unittest.TestCase):
    def assertInvalid(self, workflow, code):
        with self.assertRaises(WorkflowPolicyError) as error:
            validate_workflow(workflow)
        self.assertEqual(str(error.exception), code)

    def test_current_workflow_semantics(self):
        validate_workflow(WORKFLOW)

    def test_rejects_untrusted_source_checkout(self):
        unsafe = WORKFLOW.replace(
            "          ref: ${{ needs.static-authorisation.outputs.trusted_sha }}",
            "          ref: ${{ github.head_ref }}",
            1,
        )
        self.assertInvalid(unsafe, "UNTRUSTED_CHECKOUT_REF")

    def test_rejects_app_secret_in_source_job(self):
        marker = "          PHASE2_CANDIDATE_SET: ${{ needs.static-authorisation.outputs.candidate_set }}"
        unsafe = WORKFLOW.replace(
            marker,
            marker + "\n          PHASE2_ALLOCATOR_APP_PRIVATE_KEY: ${{ secrets.PHASE2_ALLOCATOR_APP_PRIVATE_KEY }}",
            1,
        )
        self.assertInvalid(unsafe, "SOURCE_SECRET_PRESENT")

    def test_rejects_trusted_job_without_source_dependency(self):
        unsafe = WORKFLOW.replace(
            "    needs: [static-authorisation, source-revalidation]",
            "    needs: [static-authorisation]",
            1,
        )
        self.assertInvalid(unsafe, "INVALID_TRUSTED_DEPENDENCIES")

    def test_rejects_static_issue_write_permission(self):
        marker = (
            "  static-authorisation:\n"
            "    runs-on: ubuntu-24.04\n"
            "    permissions:\n"
            "      contents: read\n"
            "      issues: read"
        )
        unsafe = WORKFLOW.replace(marker, marker[:-4] + "write", 1)
        self.assertInvalid(unsafe, "INVALID_STATIC_PERMISSIONS")

    def test_rejects_unpinned_action(self):
        unsafe = WORKFLOW.replace(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/checkout@v4",
            1,
        )
        self.assertInvalid(unsafe, "UNPINNED_ACTION")

    def test_rejects_weakened_trusted_condition(self):
        unsafe = WORKFLOW.replace(
            "      always() &&",
            "      false && always() &&",
            1,
        )
        self.assertInvalid(unsafe, "INVALID_TRUSTED_CONDITION")

    def test_rejects_concurrency_cancellation(self):
        unsafe = WORKFLOW.replace("  cancel-in-progress: false", "  cancel-in-progress: true", 1)
        self.assertInvalid(unsafe, "INVALID_CONCURRENCY")

    def test_rejects_manual_scope_probe_default(self):
        unsafe = WORKFLOW.replace("        default: reconcile", "        default: scope_probe", 1)
        self.assertInvalid(unsafe, "INVALID_TRIGGERS")

    def test_rejects_extra_job_even_if_required_fragments_remain(self):
        unsafe = WORKFLOW + (
            "\n  unsafe-helper:\n"
            "    runs-on: ubuntu-24.04\n"
            "    permissions:\n"
            "      contents: read\n"
            "    steps:\n"
            "      - name: Harmless-looking extra job\n"
            "        run: true\n"
        )
        self.assertInvalid(unsafe, "UNAPPROVED_JOB_GRAPH")


if __name__ == "__main__":
    unittest.main()
