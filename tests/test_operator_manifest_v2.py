from datetime import datetime, timezone
import unittest

from phase2.governance_state import (
    GovernanceStateError,
    attach_manifest_comment_id,
    build_governance_history,
    governance_history_baseline,
    parse_governance_comments_v2,
    parse_guarded_execution_manifest,
    reduce_governance_history_v2,
)
from phase2.operator_guard import GuardObservation, evaluate_guards
from phase2.operator_manifest import (
    GOVERNANCE_CONTRACT,
    GOVERNANCE_PREFIX,
    MANIFEST_CONTRACT,
    MANIFEST_V2_CONTRACT,
    ModuleBlob,
    OperatorContractError,
    canonical_json,
    parse_execution_manifest,
    parse_governance_comments,
    sha256_text,
)


ISSUE = 12345
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
PROPOSAL = "1" * 32
READINESS = "2" * 32
LEGACY_AUTHORITY = "3" * 32
APPROVAL = "5" * 32
LIVE_AUTHORITY = "6" * 32
REVOCATION = "7" * 32
CONSUMPTION = "8" * 32
MANIFEST_COMMENT_ID = 9001
NOW = datetime(2026, 9, 12, 0, 0, 0, tzinfo=timezone.utc)


def binding(comment):
    return {
        "comment_id": comment["id"],
        "body_sha256": sha256_text(comment["body"]),
    }


def record_payload(record_type, record_id, subject, details):
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


def comment(comment_id, payload):
    body = "fixture\n" + GOVERNANCE_PREFIX + canonical_json(payload)
    return {
        "id": comment_id,
        "body": body,
        "user": {"login": "8ft0-ai"},
        "created_at": "2026-09-12T00:00:00Z",
        "updated_at": "2026-09-12T00:00:00Z",
    }


def lineage_subject(*, record_ids=(), comment_bindings=()):
    return {
        "lineage_id": LINEAGE,
        "record_ids": list(record_ids),
        "comment_bindings": list(comment_bindings),
    }


def exact_manifest_subject(manifest, *, record_ids=(), comment_bindings=()):
    return {
        "manifest_sha256": manifest.sha256,
        "manifest_comment_id": MANIFEST_COMMENT_ID,
        "record_ids": list(record_ids),
        "comment_bindings": list(comment_bindings),
    }


def exact_authority_subject(manifest, *, record_ids=(), comment_bindings=()):
    value = exact_manifest_subject(
        manifest, record_ids=record_ids, comment_bindings=comment_bindings
    )
    return {"lineage_id": LINEAGE, **value}


def lineage_comments():
    proposal = comment(
        101,
        record_payload(
            "proposal",
            PROPOSAL,
            lineage_subject(),
            {"disposition": "proposed"},
        ),
    )
    readiness = comment(
        102,
        record_payload(
            "readiness",
            READINESS,
            lineage_subject(
                record_ids=(PROPOSAL,),
                comment_bindings=(binding(proposal),),
            ),
            {"disposition": "ready"},
        ),
    )
    legacy_authority = comment(
        103,
        record_payload(
            "authority",
            LEGACY_AUTHORITY,
            lineage_subject(
                record_ids=(PROPOSAL, READINESS),
                comment_bindings=(binding(proposal), binding(readiness)),
            ),
            {
                "disposition": "granted",
                "execution_authorised": True,
                "single_use": True,
            },
        ),
    )
    return proposal, readiness, legacy_authority


def manifest_value(proposal, readiness, baseline):
    return {
        "contract": MANIFEST_V2_CONTRACT,
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
        "readiness": binding(readiness),
        "governance_history": {
            "through_id": baseline.through_id,
            "history_sha256": baseline.history_sha256,
        },
        "state_baseline": {
            "commit_sha": STATE_SHA,
            "digest_sha256": STATE_DIGEST,
        },
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
    proposal, readiness, legacy = lineage_comments()
    pre_records = parse_governance_comments(
        [proposal, readiness],
        expected_owner="8ft0-ai",
        expected_issue=ISSUE,
    )
    baseline = governance_history_baseline(pre_records)
    raw = canonical_json(manifest_value(proposal, readiness, baseline))
    manifest = attach_manifest_comment_id(
        parse_guarded_execution_manifest(raw),
        MANIFEST_COMMENT_ID,
    )
    return proposal, readiness, legacy, manifest


def history(manifest, comments):
    records = parse_governance_comments_v2(
        comments, expected_owner="8ft0-ai", expected_issue=ISSUE
    )
    return build_governance_history(manifest.sha256, records)


def observation(manifest, governance_history, *, stage="preflight", proven=False):
    return GuardObservation(
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
        governance_history=governance_history,
        manifest_approval_proven=proven,
        private_freshness_proven=False,
    )


def approval_and_authority(manifest, proposal, readiness):
    approval = comment(
        104,
        record_payload(
            "manifest_approval",
            APPROVAL,
            exact_manifest_subject(
                manifest,
                record_ids=(PROPOSAL, READINESS),
                comment_bindings=(binding(proposal), binding(readiness)),
            ),
            {"disposition": "approved"},
        ),
    )
    authority = comment(
        105,
        record_payload(
            "authority",
            LIVE_AUTHORITY,
            exact_authority_subject(
                manifest,
                record_ids=(PROPOSAL, READINESS, APPROVAL),
                comment_bindings=(
                    binding(proposal),
                    binding(readiness),
                    binding(approval),
                ),
            ),
            {
                "disposition": "granted",
                "execution_authorised": True,
                "single_use": True,
            },
        ),
    )
    return approval, authority


class OperatorManifestV2Tests(unittest.TestCase):
    def test_v2_manifest_is_additive_preauthority_and_digest_bound(self):
        _, _, _, manifest = make_manifest()
        self.assertEqual(manifest.payload["contract"], MANIFEST_V2_CONTRACT)
        self.assertNotIn("authority", manifest.payload)
        core = dict(manifest.payload)
        core.pop("governance_history")
        parsed = parse_execution_manifest(canonical_json(core))
        self.assertEqual(parsed.payload["contract"], MANIFEST_V2_CONTRACT)
        with self.assertRaisesRegex(
            OperatorContractError, "V2_MANIFEST_HAS_NO_LIVE_AUTHORITY"
        ):
            _ = parsed.authority

        invalid = dict(core)
        invalid["authority"] = binding(lineage_comments()[2])
        with self.assertRaisesRegex(
            OperatorContractError, "MANIFEST_SCHEMA_MISMATCH"
        ):
            parse_execution_manifest(canonical_json(invalid))

    def test_legacy_v1_authority_is_nontransferable_but_does_not_block_preflight(self):
        proposal, readiness, legacy, manifest = make_manifest()
        governance = history(manifest, [proposal, readiness, legacy])
        result = evaluate_guards(manifest, observation(manifest, governance))
        self.assertTrue(result.passed)
        with self.assertRaisesRegex(
            GovernanceStateError, "AUTHORITY_NOT_GRANTED"
        ):
            reduce_governance_history_v2(
                manifest,
                governance,
                manifest_comment_id=MANIFEST_COMMENT_ID,
                require_live_authority=True,
            )

    def test_live_guard_requires_separate_exact_authority_proof(self):
        proposal, readiness, legacy, manifest = make_manifest()
        governance = history(manifest, [proposal, readiness, legacy])
        blocked = evaluate_guards(
            manifest,
            observation(manifest, governance, stage="live_l1", proven=False),
        )
        self.assertEqual(blocked.code, "AUTHORITY_NOT_GRANTED")
        passed = evaluate_guards(
            manifest,
            observation(manifest, governance, stage="live_l1", proven=True),
        )
        self.assertTrue(passed.passed)

    def test_exact_manifest_approval_and_authority_reduce_to_active(self):
        proposal, readiness, legacy, manifest = make_manifest()
        approval, authority = approval_and_authority(
            manifest, proposal, readiness
        )
        governance = history(
            manifest, [proposal, readiness, legacy, approval, authority]
        )
        state = reduce_governance_history_v2(
            manifest,
            governance,
            manifest_comment_id=MANIFEST_COMMENT_ID,
            require_live_authority=True,
        )
        self.assertEqual(state.approval_status, "approved")
        self.assertEqual(state.authority_status, "active")
        self.assertEqual(state.active_authority.record_id, LIVE_AUTHORITY)

    def test_lineage_matching_authority_for_other_manifest_fails_closed(self):
        proposal, readiness, legacy, manifest = make_manifest()
        approval, authority = approval_and_authority(
            manifest, proposal, readiness
        )
        payload = dict(
            parse_governance_comments_v2(
                [authority], expected_owner="8ft0-ai", expected_issue=ISSUE
            )[0].payload
        )
        subject = dict(payload["subject"])
        subject["manifest_comment_id"] = MANIFEST_COMMENT_ID + 1
        payload["subject"] = subject
        wrong = comment(105, payload)
        governance = history(
            manifest, [proposal, readiness, legacy, approval, wrong]
        )
        with self.assertRaisesRegex(
            GovernanceStateError, "GOVERNANCE_RECORD_INVALID"
        ):
            reduce_governance_history_v2(
                manifest,
                governance,
                manifest_comment_id=MANIFEST_COMMENT_ID,
                require_live_authority=True,
            )

    def test_revoked_consumed_and_ambiguous_v2_authority_fail_closed(self):
        proposal, readiness, legacy, manifest = make_manifest()
        approval, authority = approval_and_authority(
            manifest, proposal, readiness
        )
        revocation = comment(
            106,
            record_payload(
                "revocation",
                REVOCATION,
                exact_manifest_subject(
                    manifest,
                    record_ids=(LIVE_AUTHORITY,),
                    comment_bindings=(binding(authority),),
                ),
                {
                    "reason": "revoked",
                    "public_invalidation": {"required": False},
                },
            ),
        )
        revoked = history(
            manifest,
            [proposal, readiness, legacy, approval, authority, revocation],
        )
        with self.assertRaisesRegex(
            GovernanceStateError, "GOVERNANCE_SUPERSEDED"
        ):
            reduce_governance_history_v2(
                manifest,
                revoked,
                manifest_comment_id=MANIFEST_COMMENT_ID,
                require_live_authority=True,
            )

        consumption = comment(
            106,
            record_payload(
                "consumption",
                CONSUMPTION,
                exact_manifest_subject(
                    manifest,
                    record_ids=(LIVE_AUTHORITY,),
                    comment_bindings=(binding(authority),),
                ),
                {"run_id": 123, "run_attempt": 1},
            ),
        )
        consumed = history(
            manifest,
            [proposal, readiness, legacy, approval, authority, consumption],
        )
        with self.assertRaisesRegex(
            GovernanceStateError, "AUTHORITY_CONSUMED"
        ):
            reduce_governance_history_v2(
                manifest,
                consumed,
                manifest_comment_id=MANIFEST_COMMENT_ID,
                require_live_authority=True,
            )

        second = comment(
            106,
            record_payload(
                "authority",
                "9" * 32,
                exact_authority_subject(
                    manifest,
                    record_ids=(PROPOSAL, READINESS, APPROVAL),
                    comment_bindings=(
                        binding(proposal),
                        binding(readiness),
                        binding(approval),
                    ),
                ),
                {
                    "disposition": "granted",
                    "execution_authorised": True,
                    "single_use": True,
                },
            ),
        )
        ambiguous = history(
            manifest,
            [proposal, readiness, legacy, approval, authority, second],
        )
        with self.assertRaisesRegex(
            GovernanceStateError, "GOVERNANCE_AMBIGUOUS"
        ):
            reduce_governance_history_v2(
                manifest,
                ambiguous,
                manifest_comment_id=MANIFEST_COMMENT_ID,
                require_live_authority=True,
            )

    def test_historical_v1_contract_constant_remains_v1(self):
        self.assertEqual(MANIFEST_CONTRACT, "gitstate-live-execution-manifest/v1")


if __name__ == "__main__":
    unittest.main()
