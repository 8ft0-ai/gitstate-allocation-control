import copy
import unittest

from phase2.current_observation_readiness import (
    READINESS_CONTRACT,
    READINESS_STATUS_READY,
)
from phase2.governance_state import (
    GovernanceStateError,
    build_governance_history,
    governance_history_baseline,
    parse_governance_comments_for_manifest,
    parse_guarded_execution_manifest,
    reduce_governance_history_v3,
)
from phase2.governance_state_v3 import (
    EXTERNAL_PROPOSAL_FIELDS,
    external_proposal_lineage_id,
    external_proposal_record_id,
)
from phase2.operator_guard import GuardObservation, evaluate_guards
from phase2.operator_manifest import (
    GOVERNANCE_CONTRACT,
    GOVERNANCE_PREFIX,
    MANIFEST_V3_CONTRACT,
    ModuleBlob,
    OperatorContractError,
    canonical_json,
    parse_execution_manifest,
    sha256_text,
)
from phase2.preflight_projection import (
    PROJECTION_CONTRACT,
    PROJECTION_PREFIX,
    parse_projection_comment,
)


ISSUE = 40
OPERATION = "workstream-d-scenarios-1-14/v1"
CONTROL = "8ft0-ai/gitstate-allocation-control"
CONTROL_SHA = "a" * 40
TREE_SHA = "b" * 40
WORKFLOW_SHA = "c" * 40
MODULE_SHA = "d" * 40
PROTOCOL_SHA = "e" * 40
STATE_SHA = "f" * 40
STATE_DIGEST = "1" * 64
POLICY_DIGEST = "2" * 64
PERMISSION_DIGEST = "3" * 64
PROPOSAL_COMMENT_ID = 100
MANIFEST_COMMENT_ID = 200
LINEAGE = "gitstate-lab#40/v3-first-manifest/8"


def binding(comment):
    return {"comment_id": comment["id"], "body_sha256": sha256_text(comment["body"])}


def external_payload(*, readiness_contract=READINESS_CONTRACT, readiness_status=READINESS_STATUS_READY):
    return {
        "contract": GOVERNANCE_CONTRACT,
        "record_type": "proposal",
        "proposal_contract": "gitstate-v3-first-manifest-proposal/v4",
        "governing_issue": ISSUE,
        "operation": OPERATION,
        "manifest_contract": MANIFEST_V3_CONTRACT,
        "lineage_id": LINEAGE,
        "implementation": {
            "repository": CONTROL,
            "commit": CONTROL_SHA,
            "tree": TREE_SHA,
            "workflow": WORKFLOW_SHA,
            "module_blobs": [{"path": "phase2/operator_runtime.py", "blob_sha": MODULE_SHA}],
            "protocol_sha": PROTOCOL_SHA,
            "protected_tag": f"refs/tags/gitstate-current-observation/{CONTROL_SHA}",
            "relay_workflow": "4" * 40,
            "relay_module": "5" * 40,
            "policy_blob": "6" * 40,
        },
        "governance": {"bindings": [], "history": {}},
        "transport_preparation": {"projection_contract": "gitstate-preflight-projection/v1"},
        "current_observation_execution": {"architecture_contract": "CURRENT_OBSERVATION_SAME_RUN_PROTECTED_EXECUTION_ARCHITECTURE/v2"},
        "external_readiness": {
            "repository": CONTROL,
            "pr": 48,
            "comment_id": 900,
            "contract": readiness_contract,
            "body_sha256": "7" * 64,
            "payload_sha256": "8" * 64,
            "provenance_class": "supplied immutable external handoff",
            "subject_commit": CONTROL_SHA,
            "subject_tree": TREE_SHA,
            "protected_tag": f"refs/tags/gitstate-current-observation/{CONTROL_SHA}",
            "readiness_status": readiness_status,
            "matching_request_count_at_handoff": 0,
            "matching_consumption_count_at_handoff": 0,
            "matching_execution_count_at_handoff": 0,
            "matching_rerun_count_at_handoff": 0,
        },
        "constraints": {"single_use": True, "execution": False},
    }


def external_comment(payload=None):
    payload = external_payload() if payload is None else payload
    body = "proposal fixture\n" + GOVERNANCE_PREFIX + canonical_json(payload)
    return {
        "id": PROPOSAL_COMMENT_ID,
        "body": body,
        "user": {"login": "8ft0-ai"},
        "created_at": "2026-09-23T12:00:00Z",
        "updated_at": "2026-09-23T12:00:00Z",
    }


def core_manifest_payload(proposal):
    return {
        "contract": MANIFEST_V3_CONTRACT,
        "operation": OPERATION,
        "governing_issue": ISSUE,
        "executor": {
            "repository": CONTROL,
            "commit_sha": CONTROL_SHA,
            "tree_sha": TREE_SHA,
            "workflow_blob_sha": WORKFLOW_SHA,
            "module_blobs": [
                {"path": "phase2/operator_runtime.py", "blob_sha": MODULE_SHA}
            ],
        },
        "protocol_sha": PROTOCOL_SHA,
        "proposal": binding(proposal),
        "state_baseline": {"commit_sha": STATE_SHA, "digest_sha256": STATE_DIGEST},
        "operator_history": {"through_id": 0, "history_sha256": sha256_text("")},
        "workflow_history": {"through_id": 0, "history_sha256": sha256_text("")},
        "allocator_app": {
            "app_id": 10,
            "installation_id": 20,
            "repository_selection": "selected",
            "selected_repository_ids": [100, 200],
            "permission_profile_sha256": PERMISSION_DIGEST,
            "owner_observation": {"required": False},
        },
        "environment": {
            "name": "phase-2-allocator",
            "policy_sha256": POLICY_DIGEST,
            "execution_variable": "PHASE2_WORKSTREAM_D_EXECUTION_ENABLED",
            "execution_variable_expected_absent": True,
        },
        "single_use": True,
        "workstream_e_authorised": False,
    }


def make_manifest(proposal=None):
    proposal = external_comment() if proposal is None else proposal
    core_payload = core_manifest_payload(proposal)
    core = parse_execution_manifest(canonical_json(core_payload))
    records = parse_governance_comments_for_manifest(
        core, [proposal], expected_owner="8ft0-ai", expected_issue=ISSUE
    )
    baseline = governance_history_baseline(records)
    guarded = dict(core_payload)
    guarded["governance_history"] = {
        "through_id": baseline.through_id,
        "history_sha256": baseline.history_sha256,
    }
    manifest = parse_guarded_execution_manifest(canonical_json(guarded))
    history = build_governance_history(manifest.sha256, records)
    return proposal, manifest, history, guarded, records


def observation(manifest, history):
    from datetime import datetime, timezone
    return GuardObservation(
        stage="preflight",
        read_status="complete",
        evaluated_at=datetime(2026, 9, 23, 12, 5, tzinfo=timezone.utc),
        operation=OPERATION,
        control_repository=CONTROL,
        control_commit_sha=CONTROL_SHA,
        control_tree_sha=TREE_SHA,
        workflow_blob_sha=WORKFLOW_SHA,
        module_blobs=(ModuleBlob("phase2/operator_runtime.py", MODULE_SHA),),
        protocol_sha=PROTOCOL_SHA,
        state_commit_sha=STATE_SHA,
        state_digest_sha256=STATE_DIGEST,
        operator_history=manifest.operator_history,
        workflow_history=manifest.workflow_history,
        app_id=10,
        installation_id=20,
        repository_selection="selected",
        selected_repository_ids=(100, 200),
        permission_profile_sha256=PERMISSION_DIGEST,
        owner_observation=None,
        environment_name="phase-2-allocator",
        environment_policy_sha256=POLICY_DIGEST,
        execution_variable="PHASE2_WORKSTREAM_D_EXECUTION_ENABLED",
        execution_variable_absent=True,
        governance_history=history,
        manifest_approval_proven=False,
        private_freshness_proven=True,
    )


class ExternalProposalCompatibilityTests(unittest.TestCase):
    def test_exact_external_proposal_adapts_to_private_v3_preflight_identity(self):
        proposal, manifest, history, _, records = make_manifest()
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.record_type, "proposal")
        self.assertEqual(record.comment_id, PROPOSAL_COMMENT_ID)
        self.assertEqual(record.body_sha256, sha256_text(proposal["body"]))
        self.assertEqual(record.record_id, external_proposal_record_id(PROPOSAL_COMMENT_ID, record.body_sha256))
        self.assertEqual(record.lineage_id, external_proposal_lineage_id(LINEAGE))
        state = reduce_governance_history_v3(manifest, history, stage="preflight")
        self.assertEqual(state.proposal.record_id, record.record_id)
        self.assertTrue(evaluate_guards(manifest, observation(manifest, history)).passed)

    def test_external_proposal_contract_version_is_exact(self):
        proposal_payload = external_payload()
        proposal_payload["proposal_contract"] = "gitstate-v3-first-manifest-proposal/v3"
        proposal = external_comment(proposal_payload)
        core = parse_execution_manifest(canonical_json(core_manifest_payload(proposal)))
        with self.assertRaisesRegex(OperatorContractError, "GOVERNANCE_EXTERNAL_PROPOSAL_CONTRACT_INVALID"):
            parse_governance_comments_for_manifest(
                core, [proposal], expected_owner="8ft0-ai", expected_issue=ISSUE
            )

    def test_external_proposal_requires_readiness_v2_and_exact_ready_status(self):
        for contract, status in (
            ("gitstate-current-observation-runtime-subject-readiness-reconciliation/v1", READINESS_STATUS_READY),
            (READINESS_CONTRACT, "READY"),
        ):
            proposal = external_comment(external_payload(readiness_contract=contract, readiness_status=status))
            core = parse_execution_manifest(canonical_json(core_manifest_payload(proposal)))
            with self.assertRaisesRegex(OperatorContractError, "GOVERNANCE_EXTERNAL_READINESS_MISMATCH"):
                parse_governance_comments_for_manifest(
                    core, [proposal], expected_owner="8ft0-ai", expected_issue=ISSUE
                )

    def test_external_proposal_schema_and_bound_implementation_fail_closed(self):
        extra = external_payload()
        extra["unexpected"] = False
        proposal = external_comment(extra)
        core = parse_execution_manifest(canonical_json(core_manifest_payload(proposal)))
        with self.assertRaisesRegex(OperatorContractError, "GOVERNANCE_SCHEMA_MISMATCH"):
            parse_governance_comments_for_manifest(
                core, [proposal], expected_owner="8ft0-ai", expected_issue=ISSUE
            )

        mismatch = external_payload()
        mismatch["implementation"]["commit"] = "9" * 40
        proposal = external_comment(mismatch)
        core = parse_execution_manifest(canonical_json(core_manifest_payload(proposal)))
        with self.assertRaisesRegex(OperatorContractError, "GOVERNANCE_EXTERNAL_IMPLEMENTATION_MISMATCH"):
            parse_governance_comments_for_manifest(
                core, [proposal], expected_owner="8ft0-ai", expected_issue=ISSUE
            )

    def test_projection_parser_uses_manifest_aware_external_proposal_adapter(self):
        proposal, manifest, history, guarded, _ = make_manifest()
        projection_payload = {
            "contract": PROJECTION_CONTRACT,
            "projection_id": "8" * 32,
            "manifest_comment_id": MANIFEST_COMMENT_ID,
            "manifest_sha256": manifest.sha256,
            "manifest": guarded,
            "governance_sources": [
                {
                    "comment_id": proposal["id"],
                    "body": proposal["body"],
                    "owner": proposal["user"]["login"],
                    "created_at": proposal["created_at"],
                    "updated_at": proposal["updated_at"],
                }
            ],
            "observation": {
                "protocol_sha": PROTOCOL_SHA,
                "state_commit_sha": STATE_SHA,
                "state_digest_sha256": STATE_DIGEST,
                "app_id": 10,
                "installation_id": 20,
                "repository_selection": "selected",
                "selected_repository_ids": [100, 200],
                "permission_profile_sha256": PERMISSION_DIGEST,
                "owner_observation": {"required": False},
                "environment_name": "phase-2-allocator",
                "environment_policy_sha256": POLICY_DIGEST,
                "execution_variable": "PHASE2_WORKSTREAM_D_EXECUTION_ENABLED",
            },
            "execution_authorised": False,
            "workstream_e_authorised": False,
        }
        body = PROJECTION_PREFIX + canonical_json(projection_payload)
        parsed = parse_projection_comment(
            {
                "id": 350,
                "body": body,
                "user": {"login": "8ft0-ai"},
                "created_at": "2026-09-23T12:10:00Z",
                "updated_at": "2026-09-23T12:10:00Z",
            }
        )
        self.assertEqual(parsed.manifest.manifest_comment_id, MANIFEST_COMMENT_ID)
        self.assertEqual(parsed.governance_history.baseline, history.baseline)
        self.assertTrue(evaluate_guards(parsed.manifest, observation(parsed.manifest, parsed.governance_history)).passed)


if __name__ == "__main__":
    unittest.main()
