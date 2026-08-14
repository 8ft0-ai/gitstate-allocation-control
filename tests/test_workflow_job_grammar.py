import unittest
from pathlib import Path

from phase2.workflow_policy import WorkflowPolicyError, validate_workflow

ROOT = Path(__file__).parents[1]
WORKFLOW = (ROOT / ".github/workflows/phase2-intake.yml").read_text()


class WorkflowJobGrammarTests(unittest.TestCase):
    def assertInvalid(self, workflow: str, code: str) -> None:
        with self.assertRaises(WorkflowPolicyError) as error:
            validate_workflow(workflow)
        self.assertEqual(str(error.exception), code)

    def test_rejects_inline_flow_map_job(self):
        unsafe = WORKFLOW + (
            "\n  unsafe-helper: {runs-on: ubuntu-24.04, permissions: {contents: write}, "
            "steps: [{run: \"echo unsafe\"}]}\n"
        )
        self.assertInvalid(unsafe, "UNAPPROVED_JOB_GRAPH")

    def test_rejects_quoted_direct_job_key(self):
        unsafe = WORKFLOW + (
            "\n  'unsafe-helper':\n"
            "    runs-on: ubuntu-24.04\n"
            "    permissions:\n"
            "      contents: write\n"
            "    steps:\n"
            "      - run: echo unsafe\n"
        )
        self.assertInvalid(unsafe, "UNAPPROVED_JOB_GRAPH")


if __name__ == "__main__":
    unittest.main()
