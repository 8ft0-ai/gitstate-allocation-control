from datetime import datetime, timezone
import inspect
import unittest

import phase2.governance_state as governance_state_module
import phase2.operator_guard as guard_module
from phase2.governance_state import GovernanceHistory, build_governance_history
from phase2.operator_guard import GuardObservation, OwnerObservation, evaluate_guards
from phase2.operator_manifest import (
    GOVERNANCE_CONTRACT,
    GOVERNANCE_PREFIX,
    MANIFEST_CONTRACT,
    ModuleBlob,
    canonical_json,
    parse_execution_manifest,
    parse_governance_comments,
    sha256_text,
)


ISSUE = 12345
CONTROL_REPOSITORY = "8ft0-ai/gitstate-allocation-control"
OPERATION = "workstream-d-scenarios-1-14/v1"
CONTROL_SHA = "a" * 40
TREE_SHA = "b" * 40
WORKFLOW_BLOB = "c" * 40
MODULE_BLOB = "d" * 40
PROTOCOL_SHA = "e" * 40
STATE_SHA = "f" * 40
STATE_DIGEST = "1" * 64
POLICY_DIGEST = "2" * 64
PERMISSION_DIGEST = "3" * 64
EXECUTION_VARIABLE = "PHASE2_WORKSTREAM_D_EXECUTION_ENABLED"
LINEAGE_ID = "4" * 32
PROPOSAL_ID = "5" * 32
READINESS_ID = "6" * 32
AUTHORITY_ID = "7" * 32
APPROVAL_ID = "8" * 32
REVOCATION_ID = "9" * 32
CONSUMPTION_ID = "a" * 32
TERMINAL_ID = "b" * 32
EVALUATED_AT = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)


def binding(comment):
    return {"comment_id": comment["id"], "body_sha256": sha256_text(comment["body"])}


def lineage_subject(*, record_ids=(), comment_bindings=()):
    return {
        "lineage_id": LINEAGE_ID,
        "record_ids": list(record_ids),
        "comment_bindings": list(comment_bindings),
    }


def manifest_subject(manifest_sha, *, record_ids=(), comment_bindings=()):
    return {
        "manifest_sha256": manifest_sha,
        "record_ids": list(record_ids),
        "comment_bindings": list(comment_bindings),
    }


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


def governance_comment(comment_id, payload, *, human="bounded rationale"):
    body = human + "\n" + GOVERNANCE_PREFIX + canonical_json(payload)
    return {
        "id": comment_id,
        "body": body,
        "user": {"login": "8ft0-ai"},
        "created_at": "2026-09-02T00:00:00Z",
        "updated_at": "2026-09-02T00:00:00Z",
    }


def lineage_comments(*, readiness_disposition="ready"):
    proposal = governance_comment(
        101,
        governance_payload("proposal", PROPOSAL_ID, lineage_subject(), {"disposition": "proposed"}),
    )
    readiness = governance_comment(
        102,
        governance_payload(
            "readiness",
            READINESS_ID,
            lineage_subject(record_ids=(PROPOSAL_ID,), comment_bindings=(binding(proposal),)),
            {"disposition": readiness_disposition},
        ),
    )
    authority = governance_comment(
        103,
        governance_payload(
            "authority",
            AUTHORITY_ID,
            lineage_subject(
                record_ids=(PROPOSAL_ID, READINESS_ID),
                comment_bindings=(binding(proposal), binding(readiness)),
            ),
            {"disposition": "granted", "execution_authorised": True, "single_use": True},
        ),
    )
    return proposal, readiness, authority


def manifest_payload(proposal, readiness, authority, *, owner_observation=None, state_digest=STATE_DIGEST):
    if owner_observation is None:
        owner_observation = {"required": False}
    return {
        "contract": MANIFEST_CONTRACT,
        "operation": OPERATION,
        "governing_issue": ISSUE,
        "executor": {
            "repository": CONTROL_REPOSITORY,
            "commit_sha": CONTROL_SHA,
            "tree_sha": TREE_SHA,
            "workflow_blob_sha": WORKFLOW_BLOB,
            "module_blobs": [{"path": "phase2/operator_runtime.py", "blob_sha": MODULE_BLOB}],
        },
        "protocol_sha": PROTOCOL_SHA,
        "proposal": binding(proposal),
        "readiness": binding(readiness),
        "authority": binding(authority),
        "state_baseline": {"commit_sha": STATE_SHA, "digest_sha256": state_digest},
        "operator_history": {"through_id": 0, "history_sha256": sha256_text("")},
        "workflow_history": {"through_id": 0, "history_sha256": sha256_text("")},
        "allocator_app": {
            "app_id": 10,
            "installation_id": 20,
            "repository_selection": "selected",
            "selected_repository_ids": [100, 200],
            "permission_profile_sha256": PERMISSION_DIGEST,
            "owner_observation": owner_observation,
        },
        "environment": {
            "name": "phase-2-allocator",
            "policy_sha256": POLICY_DIGEST,
            "execution_variable": EXECUTION_VARIABLE,
            "execution_variable_expected_absent": True,
        },
        "single_use": True,
        "workstream_e_authorised": False,
    }


def observation_for(manifest, records, *, owner_observation=None):
    return GuardObservation(
        stage="preflight",
        read_status="complete",
        evaluated_at=EVALUATED_AT,
        operation=OPERATION,
        control_repository=CONTROL_REPOSITORY,
        control_commit_sha=CONTROL_SHA,
        control_tree_sha=TREE_SHA,
        workflow_blob_sha=WORKFLOW_BLOB,
        module_blobs=(ModuleBlob("phase2/operator_runtime.py", MODULE_BLOB),),
        protocol_sha=PROTOCOL_SHA,
        state_commit_sha=STATE_SHA,
        state_digest_sha256=manifest.payload["state_baseline"]["digest_sha256"],
        operator_history=manifest.operator_history,
        workflow_history=manifest.workflow_history,
        app_id=10,
        installation_id=20,
        repository_selection="selected",
        selected_repository_ids=(100, 200),
        permission_profile_sha256=PERMISSION_DIGEST,
        owner_observation=owner_observation,
        environment_name="phase-2-allocator",
        environment_policy_sha256=POLICY_DIGEST,
        execution_variable=EXECUTION_VARIABLE,
        execution_variable_absent=True,
        governance_history=build_governance_history(manifest.sha256, records),
    )


def make_state(*, readiness_disposition="ready", owner_observation=None, state_digest=STATE_DIGEST):
    proposal, readiness, authority = lineage_comments(readiness_disposition=readiness_disposition)
    manifest = parse_execution_manifest(
        canonical_json(
            manifest_payload(
                proposal,
                readiness,
                authority,
                owner_observation=owner_observation,
                state_digest=state_digest,
            )
        )
    )
    comments = [proposal, readiness, authority]
    records = parse_governance_comments(comments, expected_owner="8ft0-ai", expected_issue=ISSUE)
    return proposal, readiness, authority, manifest, comments, observation_for(manifest, records)


def with_observation(observation, **changes):
    values = dict(observation.__dict__)
    values.update(changes)
    return GuardObservation(**values)


def with_records(observation, manifest, records, **changes):
    return with_observation(
        observation,
        governance_history=build_governance_history(manifest.sha256, records),
        **changes,
    )


class OperatorGuardTests(unittest.TestCase):
    def test_preflight_passes_with_semantic_governance_and_ordinary_later_comment(self):
        _, _, _, manifest, comments, observation = make_state()
        comments.append(
            {
                "id": 999,
                "body": "ordinary later rationale does not revoke authority",
                "user": {"login": "8ft0-ai"},
                "created_at": "2026-09-02T01:00:00Z",
                "updated_at": "2026-09-02T01:00:00Z",
            }
        )
        records = parse_governance_comments(comments, expected_owner="8ft0-ai", expected_issue=ISSUE)
        self.assertTrue(evaluate_guards(manifest, with_records(observation, manifest, records)).passed)

    def test_stale_readiness_binding_and_bad_lineage_fail_closed(self):
        proposal, readiness, authority, manifest, _, observation = make_state()
        stale_readiness = governance_comment(
            readiness["id"],
            governance_payload(
                "readiness",
                READINESS_ID,
                lineage_subject(record_ids=(PROPOSAL_ID,), comment_bindings=(binding(proposal),)),
                {"disposition": "not_ready"},
            ),
        )
        records = parse_governance_comments(
            [proposal, stale_readiness, authority], expected_owner="8ft0-ai", expected_issue=ISSUE
        )
        self.assertEqual(
            evaluate_guards(manifest, with_records(observation, manifest, records)).code,
            "GOVERNANCE_RECORD_INVALID",
        )

    def test_consumed_authority_remains_consumed_across_successor_manifest(self):
        proposal, readiness, authority, first, comments, _ = make_state()
        successor = parse_execution_manifest(
            canonical_json(manifest_payload(proposal, readiness, authority, state_digest="9" * 64))
        )
        consumption = governance_comment(
            104,
            governance_payload(
                "consumption",
                CONSUMPTION_ID,
                manifest_subject(
                    first.sha256,
                    record_ids=(AUTHORITY_ID,),
                    comment_bindings=(binding(authority),),
                ),
                {"run_id": 12345, "run_attempt": 1},
            ),
        )
        records = parse_governance_comments(
            comments + [consumption], expected_owner="8ft0-ai", expected_issue=ISSUE
        )
        self.assertEqual(evaluate_guards(successor, observation_for(successor, records)).code, "AUTHORITY_CONSUMED")

    def test_revoked_authority_remains_revoked_across_successor_manifest(self):
        proposal, readiness, authority, first, comments, _ = make_state()
        successor = parse_execution_manifest(
            canonical_json(manifest_payload(proposal, readiness, authority, state_digest="9" * 64))
        )
        revocation = governance_comment(
            104,
            governance_payload(
                "revocation",
                REVOCATION_ID,
                manifest_subject(
                    first.sha256,
                    record_ids=(AUTHORITY_ID,),
                    comment_bindings=(binding(authority),),
                ),
                {"reason": "owner revoked", "public_invalidation": {"required": False}},
            ),
        )
        records = parse_governance_comments(
            comments + [revocation], expected_owner="8ft0-ai", expected_issue=ISSUE
        )
        self.assertEqual(evaluate_guards(successor, observation_for(successor, records)).code, "GOVERNANCE_SUPERSEDED")

    def test_old_manifest_approval_invalidation_does_not_poison_successor_manifest(self):
        proposal, readiness, authority, first, comments, _ = make_state()
        old_approval = governance_comment(
            104,
            governance_payload(
                "manifest_approval",
                APPROVAL_ID,
                manifest_subject(
                    first.sha256,
                    record_ids=(AUTHORITY_ID,),
                    comment_bindings=(binding(authority),),
                ),
                {"disposition": "approved"},
            ),
        )
        old_revocation = governance_comment(
            105,
            governance_payload(
                "revocation",
                REVOCATION_ID,
                manifest_subject(
                    first.sha256,
                    record_ids=(APPROVAL_ID,),
                    comment_bindings=(binding(old_approval),),
                ),
                {"reason": "manifest superseded", "public_invalidation": {"required": False}},
            ),
        )
        successor = parse_execution_manifest(
            canonical_json(manifest_payload(proposal, readiness, authority, state_digest="9" * 64))
        )
        records = parse_governance_comments(
            comments + [old_approval, old_revocation], expected_owner="8ft0-ai", expected_issue=ISSUE
        )
        self.assertTrue(evaluate_guards(successor, observation_for(successor, records)).passed)

    def test_lifecycle_targets_require_exact_record_and_body_bindings(self):
        proposal, _, authority, manifest, comments, observation = make_state()
        empty_target_revocation = governance_comment(
            104,
            governance_payload(
                "revocation",
                REVOCATION_ID,
                manifest_subject(manifest.sha256),
                {"reason": "bad", "public_invalidation": {"required": False}},
            ),
        )
        empty_binding_consumption = governance_comment(
            104,
            governance_payload(
                "consumption",
                CONSUMPTION_ID,
                manifest_subject(manifest.sha256, record_ids=(AUTHORITY_ID,)),
                {"run_id": 12345, "run_attempt": 1},
            ),
        )
        partial_binding_revocation = governance_comment(
            104,
            governance_payload(
                "revocation",
                REVOCATION_ID,
                manifest_subject(
                    manifest.sha256,
                    record_ids=(PROPOSAL_ID, AUTHORITY_ID),
                    comment_bindings=(binding(proposal),),
                ),
                {"reason": "partial binding", "public_invalidation": {"required": False}},
            ),
        )
        wrong_target_consumption = governance_comment(
            104,
            governance_payload(
                "consumption",
                CONSUMPTION_ID,
                manifest_subject(manifest.sha256, record_ids=(PROPOSAL_ID,)),
                {"run_id": 12345, "run_attempt": 1},
            ),
        )
        for lifecycle in (
            empty_target_revocation,
            empty_binding_consumption,
            partial_binding_revocation,
            wrong_target_consumption,
        ):
            records = parse_governance_comments(
                comments + [lifecycle], expected_owner="8ft0-ai", expected_issue=ISSUE
            )
            self.assertEqual(
                evaluate_guards(manifest, with_records(observation, manifest, records)).code,
                "GOVERNANCE_RECORD_INVALID",
            )

        exact_revocation = governance_comment(
            104,
            governance_payload(
                "revocation",
                REVOCATION_ID,
                manifest_subject(
                    manifest.sha256,
                    record_ids=(PROPOSAL_ID, AUTHORITY_ID),
                    comment_bindings=(binding(proposal), binding(authority)),
                ),
                {"reason": "exact targets", "public_invalidation": {"required": False}},
            ),
        )
        exact_records = parse_governance_comments(
            comments + [exact_revocation], expected_owner="8ft0-ai", expected_issue=ISSUE
        )
        self.assertEqual(
            evaluate_guards(manifest, with_records(observation, manifest, exact_records)).code,
            "GOVERNANCE_SUPERSEDED",
        )

    def test_terminal_requires_exact_consumption_binding_and_run_identity(self):
        _, _, authority, manifest, comments, observation = make_state()
        consumption = governance_comment(
            104,
            governance_payload(
                "consumption",
                CONSUMPTION_ID,
                manifest_subject(
                    manifest.sha256,
                    record_ids=(AUTHORITY_ID,),
                    comment_bindings=(binding(authority),),
                ),
                {"run_id": 12345, "run_attempt": 1},
            ),
        )
        valid_terminal = governance_comment(
            105,
            governance_payload(
                "terminal",
                TERMINAL_ID,
                manifest_subject(
                    manifest.sha256,
                    record_ids=(CONSUMPTION_ID,),
                    comment_bindings=(binding(consumption),),
                ),
                {"conclusion": "failure", "run_id": 12345, "run_attempt": 1},
            ),
        )
        valid_records = parse_governance_comments(
            comments + [consumption, valid_terminal], expected_owner="8ft0-ai", expected_issue=ISSUE
        )
        self.assertEqual(
            evaluate_guards(manifest, with_records(observation, manifest, valid_records)).code,
            "AUTHORITY_CONSUMED",
        )

        wrong_run = governance_comment(
            105,
            governance_payload(
                "terminal",
                TERMINAL_ID,
                manifest_subject(
                    manifest.sha256,
                    record_ids=(CONSUMPTION_ID,),
                    comment_bindings=(binding(consumption),),
                ),
                {"conclusion": "failure", "run_id": 99999, "run_attempt": 1},
            ),
        )
        wrong_records = parse_governance_comments(
            comments + [consumption, wrong_run], expected_owner="8ft0-ai", expected_issue=ISSUE
        )
        self.assertEqual(
            evaluate_guards(manifest, with_records(observation, manifest, wrong_records)).code,
            "GOVERNANCE_RECORD_INVALID",
        )

        orphan = governance_comment(
            104,
            governance_payload(
                "terminal",
                TERMINAL_ID,
                manifest_subject(manifest.sha256, record_ids=(CONSUMPTION_ID,)),
                {"conclusion": "failure", "run_id": 12345, "run_attempt": 1},
            ),
        )
        orphan_records = parse_governance_comments(
            comments + [orphan], expected_owner="8ft0-ai", expected_issue=ISSUE
        )
        self.assertEqual(
            evaluate_guards(manifest, with_records(observation, manifest, orphan_records)).code,
            "GOVERNANCE_RECORD_INVALID",
        )

    def test_second_simultaneously_active_authority_is_ambiguous(self):
        proposal, readiness, _, manifest, comments, observation = make_state()
        second = governance_comment(
            104,
            governance_payload(
                "authority",
                "c" * 32,
                lineage_subject(
                    record_ids=(PROPOSAL_ID, READINESS_ID),
                    comment_bindings=(binding(proposal), binding(readiness)),
                ),
                {"disposition": "granted", "execution_authorised": True, "single_use": True},
            ),
        )
        records = parse_governance_comments(
            comments + [second], expected_owner="8ft0-ai", expected_issue=ISSUE
        )
        self.assertEqual(
            evaluate_guards(manifest, with_records(observation, manifest, records)).code,
            "GOVERNANCE_AMBIGUOUS",
        )

    def test_live_stage_derives_unique_manifest_approval_from_history(self):
        _, _, authority, manifest, comments, observation = make_state()
        approval = governance_comment(
            104,
            governance_payload(
                "manifest_approval",
                APPROVAL_ID,
                manifest_subject(
                    manifest.sha256,
                    record_ids=(AUTHORITY_ID,),
                    comment_bindings=(binding(authority),),
                ),
                {"disposition": "approved"},
            ),
        )
        records = parse_governance_comments(
            comments + [approval], expected_owner="8ft0-ai", expected_issue=ISSUE
        )
        live = with_records(observation, manifest, records, stage="live_l1")
        self.assertTrue(evaluate_guards(manifest, live).passed)
        self.assertEqual(
            evaluate_guards(manifest, with_observation(observation, stage="live_l1")).code,
            "AUTHORITY_NOT_GRANTED",
        )

    def test_conflicting_active_manifest_approvals_are_ambiguous(self):
        _, _, authority, manifest, comments, observation = make_state()
        approved = governance_comment(
            104,
            governance_payload(
                "manifest_approval",
                APPROVAL_ID,
                manifest_subject(
                    manifest.sha256,
                    record_ids=(AUTHORITY_ID,),
                    comment_bindings=(binding(authority),),
                ),
                {"disposition": "approved"},
            ),
        )
        rejected = governance_comment(
            105,
            governance_payload(
                "manifest_approval",
                "c" * 32,
                manifest_subject(
                    manifest.sha256,
                    record_ids=(AUTHORITY_ID,),
                    comment_bindings=(binding(authority),),
                ),
                {"disposition": "rejected"},
            ),
        )
        records = parse_governance_comments(
            comments + [approved, rejected], expected_owner="8ft0-ai", expected_issue=ISSUE
        )
        self.assertEqual(
            evaluate_guards(manifest, with_records(observation, manifest, records, stage="live_l1")).code,
            "GOVERNANCE_AMBIGUOUS",
        )

    def test_explicit_supersession_is_required_to_replace_manifest_approval(self):
        _, _, authority, manifest, comments, observation = make_state()
        approved = governance_comment(
            104,
            governance_payload(
                "manifest_approval",
                APPROVAL_ID,
                manifest_subject(
                    manifest.sha256,
                    record_ids=(AUTHORITY_ID,),
                    comment_bindings=(binding(authority),),
                ),
                {"disposition": "approved"},
            ),
        )
        supersession = governance_comment(
            105,
            governance_payload(
                "supersession",
                REVOCATION_ID,
                manifest_subject(
                    manifest.sha256,
                    record_ids=(APPROVAL_ID,),
                    comment_bindings=(binding(approved),),
                ),
                {"reason": "replace decision", "public_invalidation": {"required": False}},
            ),
        )
        rejected = governance_comment(
            106,
            governance_payload(
                "manifest_approval",
                "c" * 32,
                manifest_subject(
                    manifest.sha256,
                    record_ids=(AUTHORITY_ID,),
                    comment_bindings=(binding(authority),),
                ),
                {"disposition": "rejected"},
            ),
        )
        records = parse_governance_comments(
            comments + [approved, supersession, rejected], expected_owner="8ft0-ai", expected_issue=ISSUE
        )
        self.assertEqual(
            evaluate_guards(manifest, with_records(observation, manifest, records, stage="live_l1")).code,
            "AUTHORITY_NOT_GRANTED",
        )

        rejected_first = governance_comment(
            104,
            governance_payload(
                "manifest_approval",
                APPROVAL_ID,
                manifest_subject(
                    manifest.sha256,
                    record_ids=(AUTHORITY_ID,),
                    comment_bindings=(binding(authority),),
                ),
                {"disposition": "rejected"},
            ),
        )
        supersede_rejected = governance_comment(
            105,
            governance_payload(
                "supersession",
                REVOCATION_ID,
                manifest_subject(
                    manifest.sha256,
                    record_ids=(APPROVAL_ID,),
                    comment_bindings=(binding(rejected_first),),
                ),
                {"reason": "replace decision", "public_invalidation": {"required": False}},
            ),
        )
        approved_second = governance_comment(
            106,
            governance_payload(
                "manifest_approval",
                "c" * 32,
                manifest_subject(
                    manifest.sha256,
                    record_ids=(AUTHORITY_ID,),
                    comment_bindings=(binding(authority),),
                ),
                {"disposition": "approved"},
            ),
        )
        replacement_records = parse_governance_comments(
            comments + [rejected_first, supersede_rejected, approved_second],
            expected_owner="8ft0-ai",
            expected_issue=ISSUE,
        )
        self.assertTrue(
            evaluate_guards(
                manifest,
                with_records(observation, manifest, replacement_records, stage="live_l1"),
            ).passed
        )

    def test_governance_history_is_manifest_bound_and_fails_on_snapshot_shrinkage(self):
        _, _, authority, manifest, comments, observation = make_state()
        consumption = governance_comment(
            104,
            governance_payload(
                "consumption",
                CONSUMPTION_ID,
                manifest_subject(
                    manifest.sha256,
                    record_ids=(AUTHORITY_ID,),
                    comment_bindings=(binding(authority),),
                ),
                {"run_id": 12345, "run_attempt": 1},
            ),
        )
        full_records = parse_governance_comments(
            comments + [consumption], expected_owner="8ft0-ai", expected_issue=ISSUE
        )
        full_history = build_governance_history(manifest.sha256, full_records)
        self.assertEqual(
            evaluate_guards(manifest, with_observation(observation, governance_history=full_history)).code,
            "AUTHORITY_CONSUMED",
        )

        shrunk = GovernanceHistory(
            manifest_sha256=manifest.sha256,
            baseline=full_history.baseline,
            records=full_history.records[:-1],
        )
        self.assertEqual(
            evaluate_guards(manifest, with_observation(observation, governance_history=shrunk)).code,
            "GOVERNANCE_HISTORY_CHANGED",
        )

        wrong_manifest = GovernanceHistory(
            manifest_sha256="0" * 64,
            baseline=full_history.baseline,
            records=full_history.records,
        )
        self.assertEqual(
            evaluate_guards(manifest, with_observation(observation, governance_history=wrong_manifest)).code,
            "GOVERNANCE_HISTORY_CHANGED",
        )

    def test_owner_observation_deadline_is_enforced_in_common_guard(self):
        owner_requirement = {
            "required": True,
            "observation_id": "owner-observation-1",
            "observation_sha256": "a" * 64,
            "valid_through": "2026-09-02T23:59:59Z",
        }
        _, _, _, manifest, _, observation = make_state(owner_observation=owner_requirement)
        self.assertEqual(evaluate_guards(manifest, observation).code, "READ_EVIDENCE_UNAVAILABLE")
        valid = with_observation(
            observation,
            evaluated_at=datetime(2026, 9, 2, 23, 59, 58, tzinfo=timezone.utc),
            owner_observation=OwnerObservation("owner-observation-1", "a" * 64, True),
        )
        self.assertTrue(evaluate_guards(manifest, valid).passed)
        at_deadline = with_observation(
            valid,
            evaluated_at=datetime(2026, 9, 2, 23, 59, 59, tzinfo=timezone.utc),
        )
        self.assertEqual(evaluate_guards(manifest, at_deadline).code, "APP_BOUNDARY_CHANGED")

    def test_mutable_identity_and_observation_failures_are_typed(self):
        _, _, _, manifest, _, observation = make_state()
        result = evaluate_guards(manifest, with_observation(observation, control_commit_sha="9" * 40))
        self.assertEqual((result.code, result.category), ("CONTROL_IDENTITY_CHANGED", "mutable_invalidator"))
        unavailable = evaluate_guards(manifest, with_observation(observation, read_status="unavailable"))
        self.assertEqual((unavailable.code, unavailable.category), ("READ_EVIDENCE_UNAVAILABLE", "observation_incomplete"))
        malformed = evaluate_guards(
            manifest,
            with_observation(observation, selected_repository_ids=(200, 100)),
        )
        self.assertEqual((malformed.code, malformed.category), ("OBSERVATION_SHAPE_UNSUPPORTED", "implementation_defect"))

    def test_guard_modules_have_no_mutation_token_or_dispatch_dependency(self):
        source = inspect.getsource(guard_module) + inspect.getsource(governance_state_module)
        for forbidden in (
            "github_api",
            "credentials",
            "mint_token",
            "workflow_dispatch",
            "update_ref",
            "workstream_d_live",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
