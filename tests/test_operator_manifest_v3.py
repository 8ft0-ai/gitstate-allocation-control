from datetime import datetime, timezone
import unittest

from phase2.governance_state import (
    GovernanceStateError,
    attach_manifest_comment_id,
    build_governance_history,
    governance_history_baseline,
    parse_governance_comments_v2,
    parse_guarded_execution_manifest,
    reduce_governance_history_v3,
)
from phase2.operator_guard import GuardObservation, GuardObservationV3, evaluate_guards
from phase2.operator_manifest import (
    GOVERNANCE_CONTRACT,
    GOVERNANCE_PREFIX,
    MANIFEST_CONTRACT,
    MANIFEST_V2_CONTRACT,
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
from phase2.transition_witness import (
    TRANSITION_WITNESS_CONTRACT,
    TRANSITION_WITNESS_PREFIX,
    TransitionWitnessError,
    parse_transition_witness,
)


ISSUE = 15
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
LINEAGE = "4" * 32
PROPOSAL_ID = "1" * 32
APPROVAL_ID = "2" * 32
READINESS_ID = "3" * 32
AUTHORITY_ID = "5" * 32
WITNESS_ID = "6" * 32
REVOCATION_ID = "7" * 32
CONSUMPTION_ID = "8" * 32
SECOND_AUTHORITY_ID = "9" * 32
MANIFEST_COMMENT_ID = 200
PREFLIGHT_COMMENT_ID = 300
COMPLETION_COMMENT_ID = 500
WITNESS_COMMENT_ID = 600
NOW = datetime(2026, 9, 12, 1, 0, 0, tzinfo=timezone.utc)


def binding(comment):
    return {"comment_id": comment["id"], "body_sha256": sha256_text(comment["body"])}


def governance_payload(record_type, record_id, subject, details):
    return {
        "contract": GOVERNANCE_CONTRACT,
        "record_id": record_id,
        "record_type": record_type,
        "governing_issue": ISSUE,
        "operation": OPERATION,
        "subject": subject,
        "details": details,
        "workstream_e_authorised": False,
    }


def governance_comment(comment_id, payload):
    body = "fixture\n" + GOVERNANCE_PREFIX + canonical_json(payload)
    return {
        "id": comment_id,
        "body": body,
        "user": {"login": "8ft0-ai"},
        "created_at": "2026-09-12T01:00:00Z",
        "updated_at": "2026-09-12T01:00:00Z",
    }


def proposal_comment():
    return governance_comment(
        100,
        governance_payload(
            "proposal",
            PROPOSAL_ID,
            {"lineage_id": LINEAGE, "record_ids": [], "comment_bindings": []},
            {"disposition": "proposed"},
        ),
    )


def manifest_subject(manifest, *, record_ids, comment_bindings):
    return {
        "manifest_sha256": manifest.sha256,
        "manifest_comment_id": MANIFEST_COMMENT_ID,
        "record_ids": list(record_ids),
        "comment_bindings": list(comment_bindings),
    }


def authority_subject(manifest, *, record_ids, comment_bindings):
    return {
        "lineage_id": LINEAGE,
        **manifest_subject(
            manifest,
            record_ids=record_ids,
            comment_bindings=comment_bindings,
        ),
    }


def v3_manifest_payload(proposal, baseline):
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
        "governance_history": {
            "through_id": baseline.through_id,
            "history_sha256": baseline.history_sha256,
        },
        "state_baseline": {"commit_sha": STATE_SHA, "digest_sha256": STATE_DIGEST},
        "operator_history": {
            "through_id": 0,
            "history_sha256": sha256_text(""),
        },
        "workflow_history": {
            "through_id": 0,
            "history_sha256": sha256_text(""),
        },
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


def make_manifest():
    proposal = proposal_comment()
    records = parse_governance_comments_v2(
        [proposal], expected_owner="8ft0-ai", expected_issue=ISSUE
    )
    baseline = governance_history_baseline(records)
    payload = v3_manifest_payload(proposal, baseline)
    manifest = attach_manifest_comment_id(
        parse_guarded_execution_manifest(canonical_json(payload)),
        MANIFEST_COMMENT_ID,
    )
    return proposal, manifest, payload


def history(manifest, comments):
    records = parse_governance_comments_v2(
        comments, expected_owner="8ft0-ai", expected_issue=ISSUE
    )
    return build_governance_history(manifest.sha256, records)


def preflight_evidence_comment():
    body = "/gitstate-preflight-result-v1 " + canonical_json(
        {
            "capability_mode": "capability-denied",
            "disposition": "PASS",
            "run_attempt": 1,
        }
    )
    return {
        "id": PREFLIGHT_COMMENT_ID,
        "body": body,
        "user": {"login": "8ft0-ai"},
        "created_at": "2026-09-12T01:02:00Z",
        "updated_at": "2026-09-12T01:02:00Z",
    }


def approval_comment(manifest, proposal, preflight):
    return governance_comment(
        400,
        governance_payload(
            "manifest_approval",
            APPROVAL_ID,
            manifest_subject(
                manifest,
                record_ids=(PROPOSAL_ID,),
                comment_bindings=(binding(proposal), binding(preflight)),
            ),
            {"disposition": "approved"},
        ),
    )


def witness_comment(manifest, proposal, preflight, approval, *, run_attempt=1):
    payload = {
        "contract": TRANSITION_WITNESS_CONTRACT,
        "witness_id": WITNESS_ID,
        "governing_issue": ISSUE,
        "operation": OPERATION,
        "proposal": binding(proposal),
        "manifest": {"comment_id": MANIFEST_COMMENT_ID, "sha256": manifest.sha256},
        "preflight_evidence": binding(preflight),
        "preflight_disposition": "PASS",
        "run_attempt": run_attempt,
        "capability_mode": "capability-denied",
        "manifest_approval": {
            "record_id": APPROVAL_ID,
            "comment_id": approval["id"],
            "body_sha256": sha256_text(approval["body"]),
        },
        "architecture_completion": {
            "issue_number": 40,
            "comment_id": COMPLETION_COMMENT_ID,
            "body_sha256": "7" * 64,
            "disposition": "COMPLETE",
        },
        "workstream_e_authorised": False,
    }
    body = TRANSITION_WITNESS_PREFIX + canonical_json(payload)
    return {
        "id": WITNESS_COMMENT_ID,
        "body": body,
        "user": {"login": "8ft0-ai"},
        "created_at": "2026-09-12T01:05:00Z",
        "updated_at": "2026-09-12T01:05:00Z",
    }


def readiness_comment(proposal, approval, witness):
    return governance_comment(
        700,
        governance_payload(
            "readiness",
            READINESS_ID,
            {
                "lineage_id": LINEAGE,
                "record_ids": [PROPOSAL_ID, APPROVAL_ID],
                "comment_bindings": [binding(proposal), binding(approval), binding(witness)],
            },
            {"disposition": "ready"},
        ),
    )


def authority_comment(
    manifest,
    proposal,
    approval,
    witness,
    readiness,
    *,
    comment_id=800,
    record_id=AUTHORITY_ID,
):
    return governance_comment(
        comment_id,
        governance_payload(
            "authority",
            record_id,
            authority_subject(
                manifest,
                record_ids=(PROPOSAL_ID, APPROVAL_ID, READINESS_ID),
                comment_bindings=(
                    binding(proposal),
                    binding(approval),
                    binding(witness),
                    binding(readiness),
                ),
            ),
            {
                "disposition": "granted",
                "execution_authorised": True,
                "single_use": True,
            },
        ),
    )


def lifecycle_comment(record_type, record_id, manifest, authority, comment_id):
    details = (
        {"run_id": 123, "run_attempt": 1}
        if record_type == "consumption"
        else {"reason": "invalidated", "public_invalidation": {"required": False}}
    )
    return governance_comment(
        comment_id,
        governance_payload(
            record_type,
            record_id,
            manifest_subject(
                manifest,
                record_ids=(AUTHORITY_ID,),
                comment_bindings=(binding(authority),),
            ),
            details,
        ),
    )


def complete_chain():
    proposal, manifest, payload = make_manifest()
    preflight = preflight_evidence_comment()
    approval = approval_comment(manifest, proposal, preflight)
    witness_raw = witness_comment(manifest, proposal, preflight, approval)
    witness = parse_transition_witness(
        witness_raw,
        expected_owner="8ft0-ai",
        expected_issue=ISSUE,
        expected_operation=OPERATION,
    )
    readiness = readiness_comment(proposal, approval, witness_raw)
    authority = authority_comment(manifest, proposal, approval, witness_raw, readiness)
    governance = history(manifest, [proposal, approval, readiness, authority])
    return (
        proposal,
        manifest,
        payload,
        preflight,
        approval,
        witness_raw,
        witness,
        readiness,
        authority,
        governance,
    )


def observation(manifest, governance, *, stage="preflight", witness=None):
    cls = GuardObservationV3 if witness is not None else GuardObservation
    kwargs = dict(
        stage=stage,
        read_status="complete",
        evaluated_at=NOW,
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
        governance_history=governance,
        manifest_approval_proven=False,
        private_freshness_proven=stage != "live_l2",
    )
    if witness is not None:
        kwargs["transition_witness"] = witness
    return cls(**kwargs)


class OperatorManifestV3Tests(unittest.TestCase):
    def test_v3_is_additive_pre_readiness_and_pre_authority(self):
        _, manifest, payload = make_manifest()
        core = dict(payload)
        core.pop("governance_history")
        parsed = parse_execution_manifest(canonical_json(core))
        self.assertEqual(parsed.payload["contract"], MANIFEST_V3_CONTRACT)
        self.assertNotIn("readiness", parsed.payload)
        self.assertNotIn("authority", parsed.payload)
        with self.assertRaisesRegex(OperatorContractError, "V3_MANIFEST_HAS_NO_READINESS"):
            _ = parsed.readiness
        with self.assertRaisesRegex(
            OperatorContractError, "V3_MANIFEST_HAS_NO_LIVE_AUTHORITY"
        ):
            _ = parsed.authority

    def test_v3_preflight_reduces_exact_proposal_only(self):
        proposal, manifest, _ = make_manifest()
        governance = history(manifest, [proposal])
        state = reduce_governance_history_v3(manifest, governance, stage="preflight")
        self.assertEqual(state.proposal.record_id, PROPOSAL_ID)
        self.assertEqual(state.readiness_status, "not_established")
        self.assertEqual(state.authority_status, "not_granted")
        self.assertTrue(evaluate_guards(manifest, observation(manifest, governance)).passed)

    def test_transition_witness_is_exact_attempt_one_capability_denied_pass(self):
        proposal, manifest, _ = make_manifest()
        preflight = preflight_evidence_comment()
        approval = approval_comment(manifest, proposal, preflight)
        parsed = parse_transition_witness(
            witness_comment(manifest, proposal, preflight, approval),
            expected_owner="8ft0-ai",
            expected_issue=ISSUE,
            expected_operation=OPERATION,
        )
        self.assertEqual(parsed.manifest_sha256, manifest.sha256)
        self.assertEqual(parsed.preflight_evidence.comment_id, PREFLIGHT_COMMENT_ID)
        self.assertEqual(parsed.preflight_evidence.body_sha256, sha256_text(preflight["body"]))
        with self.assertRaisesRegex(TransitionWitnessError, "ATTEMPT_INVALID"):
            parse_transition_witness(
                witness_comment(manifest, proposal, preflight, approval, run_attempt=2),
                expected_owner="8ft0-ai",
                expected_issue=ISSUE,
                expected_operation=OPERATION,
            )

    def test_live_requires_exact_witness_readiness_and_manifest_bound_authority(self):
        (
            proposal,
            manifest,
            _,
            _,
            approval,
            witness_raw,
            witness,
            _,
            _,
            governance,
        ) = complete_chain()
        state = reduce_governance_history_v3(
            manifest, governance, transition_witness=witness, stage="live"
        )
        self.assertEqual(state.approval_status, "approved")
        self.assertEqual(state.transition_status, "complete")
        self.assertEqual(state.readiness_status, "ready")
        self.assertEqual(state.authority_status, "active")
        self.assertEqual(state.active_authority.record_id, AUTHORITY_ID)
        self.assertTrue(
            evaluate_guards(
                manifest,
                observation(manifest, governance, stage="live_l1", witness=witness),
            ).passed
        )
        missing = evaluate_guards(
            manifest, observation(manifest, governance, stage="live_l1")
        )
        self.assertEqual(missing.code, "GOVERNANCE_RECORD_INVALID")

        bad_readiness = governance_comment(
            700,
            governance_payload(
                "readiness",
                READINESS_ID,
                {
                    "lineage_id": LINEAGE,
                    "record_ids": [PROPOSAL_ID, APPROVAL_ID],
                    "comment_bindings": [binding(proposal), binding(approval)],
                },
                {"disposition": "ready"},
            ),
        )
        bad_authority = authority_comment(
            manifest, proposal, approval, witness_raw, bad_readiness
        )
        with self.assertRaisesRegex(GovernanceStateError, "GOVERNANCE_RECORD_INVALID"):
            reduce_governance_history_v3(
                manifest,
                history(manifest, [proposal, approval, bad_readiness, bad_authority]),
                transition_witness=witness,
                stage="live",
            )

    def test_v3_authority_revocation_consumption_and_ambiguity_fail_closed(self):
        (
            proposal,
            manifest,
            _,
            _,
            approval,
            witness_raw,
            witness,
            readiness,
            authority,
            _,
        ) = complete_chain()

        revocation = lifecycle_comment(
            "revocation", REVOCATION_ID, manifest, authority, 900
        )
        with self.assertRaisesRegex(GovernanceStateError, "GOVERNANCE_SUPERSEDED"):
            reduce_governance_history_v3(
                manifest,
                history(
                    manifest,
                    [proposal, approval, readiness, authority, revocation],
                ),
                transition_witness=witness,
                stage="live",
            )

        consumption = lifecycle_comment(
            "consumption", CONSUMPTION_ID, manifest, authority, 900
        )
        with self.assertRaisesRegex(GovernanceStateError, "AUTHORITY_CONSUMED"):
            reduce_governance_history_v3(
                manifest,
                history(
                    manifest,
                    [proposal, approval, readiness, authority, consumption],
                ),
                transition_witness=witness,
                stage="live",
            )

        second = authority_comment(
            manifest,
            proposal,
            approval,
            witness_raw,
            readiness,
            comment_id=801,
            record_id=SECOND_AUTHORITY_ID,
        )
        with self.assertRaisesRegex(GovernanceStateError, "GOVERNANCE_AMBIGUOUS"):
            reduce_governance_history_v3(
                manifest,
                history(manifest, [proposal, approval, readiness, authority, second]),
                transition_witness=witness,
                stage="live",
            )

    def test_v3_projection_attaches_identity_and_remains_non_authorising(self):
        proposal, manifest, payload = make_manifest()
        projection_payload = {
            "contract": PROJECTION_CONTRACT,
            "projection_id": "8" * 32,
            "manifest_comment_id": MANIFEST_COMMENT_ID,
            "manifest_sha256": manifest.sha256,
            "manifest": payload,
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
        projection = parse_projection_comment(
            {
                "id": 350,
                "body": body,
                "user": {"login": "8ft0-ai"},
                "created_at": "2026-09-12T01:03:00Z",
                "updated_at": "2026-09-12T01:03:00Z",
            }
        )
        self.assertEqual(projection.manifest.manifest_comment_id, MANIFEST_COMMENT_ID)
        self.assertIs(projection.payload["execution_authorised"], False)
        self.assertIs(projection.payload["workstream_e_authorised"], False)

    def test_historical_contract_identifiers_are_unchanged(self):
        self.assertEqual(MANIFEST_CONTRACT, "gitstate-live-execution-manifest/v1")
        self.assertEqual(MANIFEST_V2_CONTRACT, "gitstate-live-execution-manifest/v2")


if __name__ == "__main__":
    unittest.main()
