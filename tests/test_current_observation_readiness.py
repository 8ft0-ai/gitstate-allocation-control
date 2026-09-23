import copy
import unittest

from phase2.current_observation_readiness import (
    NEXT_BOUNDARY,
    READINESS_CONTRACT,
    READINESS_STATUS_READY,
    ReadinessHandoffError,
    parse_readiness_handoff,
    readiness_body_sha256,
    readiness_payload_sha256,
    render_readiness_handoff,
)


SUBJECT = "a" * 40
PREVIOUS = "b" * 40
TREE = "c" * 40
REVIEWED = "d" * 40


def payload():
    return {
        "all_5_current_observation_governed_blobs_identical": True,
        "authorises_gitstate_successor": False,
        "authorises_observation_request": False,
        "current_main": SUBJECT,
        "fresh_runtime_subject": SUBJECT,
        "fresh_runtime_subject_differs_from_previous": True,
        "fresh_runtime_tree": TREE,
        "functional_current_observation_semantics_changed": False,
        "future_same_run_identity_gate": {
            "github_run_attempt": 1,
            "github_sha": SUBJECT,
            "github_workflow_sha": SUBJECT,
            "requested_tag_sha": SUBJECT,
        },
        "gitstate_lab_accessed": False,
        "handoff_role": "implementation/readiness only",
        "immutable_tag_ruleset": {
            "bypass_actors": [],
            "deletion_prohibited": True,
            "enforcement": "active",
            "id": 23694184,
            "include": ["refs/tags/gitstate-current-observation/*"],
            "name": "gitstate-current-observation-immutable-tags-v1",
            "target": "tag",
            "update_prohibited": True,
        },
        "matching_observation_consumption_count": 0,
        "matching_observation_execution_count": 0,
        "matching_observation_request_count": 0,
        "matching_observation_rerun_count": 0,
        "merge_method": "squash",
        "next_boundary": NEXT_BOUNDARY,
        "observation_consumption_created": False,
        "observation_executed": False,
        "observation_request_created": False,
        "pr": 48,
        "previous_runtime_subject": PREVIOUS,
        "protected_execution_tag": f"refs/tags/gitstate-current-observation/{SUBJECT}",
        "protected_tag_compare_status": "identical",
        "protected_tag_object_type": "commit",
        "protected_tag_target": SUBJECT,
        "readiness_status": READINESS_STATUS_READY,
        "readme_blob_identical_to_reviewed_candidate": True,
        "repository": "8ft0-ai/gitstate-allocation-control",
        "reviewed_head": REVIEWED,
        "workflow_rerun": False,
        "workstream_d_executed": False,
        "workstream_e_authorised": False,
    }


class CurrentObservationReadinessTests(unittest.TestCase):
    def test_v2_handoff_is_canonical_content_addressable_and_explicitly_ready(self):
        body = render_readiness_handoff(payload())
        parsed = parse_readiness_handoff(body)
        self.assertTrue(body.startswith(READINESS_CONTRACT + "\n"))
        self.assertEqual(parsed["readiness_status"], READINESS_STATUS_READY)
        self.assertEqual(len(readiness_body_sha256(body)), 64)
        self.assertEqual(len(readiness_payload_sha256(body)), 64)
        self.assertNotEqual(readiness_body_sha256(body), readiness_payload_sha256(body))

    def test_missing_or_wrong_status_fails_closed(self):
        missing = payload()
        del missing["readiness_status"]
        with self.assertRaisesRegex(ReadinessHandoffError, "READINESS_SCHEMA_MISMATCH"):
            render_readiness_handoff(missing)

        wrong = payload()
        wrong["readiness_status"] = "READY"
        with self.assertRaisesRegex(ReadinessHandoffError, "READINESS_STATUS_INVALID"):
            render_readiness_handoff(wrong)

    def test_prior_attempt_or_subject_reuse_fails_closed(self):
        attempted = payload()
        attempted["matching_observation_request_count"] = 1
        with self.assertRaisesRegex(ReadinessHandoffError, "READINESS_PRIOR_ATTEMPT_EXISTS"):
            render_readiness_handoff(attempted)

        reused = payload()
        reused["previous_runtime_subject"] = SUBJECT
        with self.assertRaisesRegex(ReadinessHandoffError, "READINESS_SUBJECT_REUSED"):
            render_readiness_handoff(reused)

    def test_noncanonical_payload_fails_closed(self):
        body = render_readiness_handoff(payload())
        prefix, raw = body.split("\n", 1)
        noncanonical = prefix + "\n" + raw.replace(":", ": ", 1)
        with self.assertRaises(ReadinessHandoffError):
            parse_readiness_handoff(noncanonical)


if __name__ == "__main__":
    unittest.main()
