import inspect
import unittest

import phase2.operator_guard as guard_module
from phase2.operator_guard import GuardObservation, OwnerObservation, evaluate_guards
from phase2.operator_manifest import (
    CommentBinding,
    GOVERNANCE_CONTRACT,
    GOVERNANCE_PREFIX,
    MANIFEST_CONTRACT,
    ModuleBlob,
    canonical_json,
    parse_execution_manifest,
    parse_governance_comments,
    sha256_text,
)


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


def binding(comment):
    return {"comment_id": comment["id"], "body_sha256": sha256_text(comment["body"])}


def binding_object(comment):
    return CommentBinding(comment["id"], sha256_text(comment["body"]))


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
        "governing_issue": 40,
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
        governance_payload(
            "proposal",
            PROPOSAL_ID,
            lineage_subject(),
            {"disposition": "proposed"},
        ),
        human="proposal semantics",
    )
    readiness = governance_comment(
        102,
        governance_payload(
            "readiness",
            READINESS_ID,
            lineage_subject(record_ids=(PROPOSAL_ID,), comment_bindings=(binding(proposal),)),
            {"disposition": readiness_disposition},
        ),
        human="readiness semantics",
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
        human="authority semantics without historical prose literals",
    )
    return proposal, readiness, authority


def manifest_payload(proposal, readiness, authority, *, owner_observation=None):
    if owner_observation is None:
        owner_observation = {"required": False}
    return {
        "contract": MANIFEST_CONTRACT,
        "operation": OPERATION,
        "governing_issue": 40,
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
        "state_baseline": {"commit_sha": STATE_SHA, "digest_sha256": STATE_DIGEST},
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
        operation=OPERATION,
        control_repository=CONTROL_REPOSITORY,
        control_commit_sha=CONTROL_SHA,
        control_tree_sha=TREE_SHA,
        workflow_blob_sha=WORKFLOW_BLOB,
        module_blobs=(ModuleBlob("phase2/operator_runtime.py", MODULE_BLOB),),
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
        owner_observation=owner_observation,
        environment_name="phase-2-allocator",
        environment_policy_sha256=POLICY_DIGEST,
        execution_variable=EXECUTION_VARIABLE,
        execution_variable_absent=True,
        governance_records=records,
    )


def make_state(*, readiness_disposition="ready", owner_observation=None):
    proposal, readiness, authority = lineage_comments(readiness_disposition=readiness_disposition)
    manifest = parse_execution_manifest(
        canonical_json(manifest_payload(proposal, readiness, authority, owner_observation=owner_observation))
    )
    comments = [proposal, readiness, authority]
    records = parse_governance_comments(comments, expected_owner="8ft0-ai", expected_issue=40)
    return proposal, readiness, authority, manifest, comments, observation_for(manifest, records)


def with_observation(observation, **changes):
    values = dict(observation.__dict__)
    values.update(changes)
    return GuardObservation(**values)


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
        observation = with_observation(
            observation,
            governance_records=parse_governance_comments(
                comments, expected_owner="8ft0-ai", expected_issue=40
            ),
        )
        result = evaluate_guards(manifest, observation)
        self.assertTrue(result.passed)
        self.assertEqual(result.code, "PASS")

    def test_stale_readiness_binding_is_caught_without_prose_matching(self):
        proposal, readiness, authority, manifest, _, observation = make_state()
        stale_readiness = governance_comment(
            readiness["id"],
            governance_payload(
                "readiness",
                READINESS_ID,
                lineage_subject(record_ids=(PROPOSAL_ID,), comment_bindings=(binding(proposal),)),
                {"disposition": "not_ready"},
            ),
            human="different readiness state",
        )
        records = parse_governance_comments(
            [proposal, stale_readiness, authority], expected_owner="8ft0-ai", expected_issue=40
        )
        result = evaluate_guards(manifest, with_observation(observation, governance_records=records))
        self.assertEqual(result.code, "GOVERNANCE_RECORD_INVALID")
        self.assertEqual(result.category, "authority_security")

    def test_lineage_requires_exact_prior_comment_bindings(self):
        proposal, _, _ = lineage_comments()
        bad_readiness = governance_comment(
            102,
            governance_payload(
                "readiness",
                READINESS_ID,
                lineage_subject(
                    record_ids=(PROPOSAL_ID,),
                    comment_bindings=({"comment_id": proposal["id"], "body_sha256": "0" * 64},),
                ),
                {"disposition": "ready"},
            ),
        )
        authority = governance_comment(
            103,
            governance_payload(
                "authority",
                AUTHORITY_ID,
                lineage_subject(
                    record_ids=(PROPOSAL_ID, READINESS_ID),
                    comment_bindings=(binding(proposal), binding(bad_readiness)),
                ),
                {"disposition": "granted", "execution_authorised": True, "single_use": True},
            ),
        )
        manifest = parse_execution_manifest(
            canonical_json(manifest_payload(proposal, bad_readiness, authority))
        )
        records = parse_governance_comments(
            [proposal, bad_readiness, authority], expected_owner="8ft0-ai", expected_issue=40
        )
        result = evaluate_guards(manifest, observation_for(manifest, records))
        self.assertEqual(result.code, "GOVERNANCE_RECORD_INVALID")

    def test_explicit_revocation_of_lineage_or_consumption_fails_closed(self):
        _, _, _, manifest, comments, observation = make_state()
        for target in (PROPOSAL_ID, READINESS_ID, AUTHORITY_ID):
            with self.subTest(target=target):
                revocation = governance_comment(
                    104,
                    governance_payload(
                        "revocation",
                        REVOCATION_ID,
                        manifest_subject(manifest.sha256, record_ids=(target,)),
                        {"reason": "owner revoked", "public_invalidation": {"required": False}},
                    ),
                )
                records = parse_governance_comments(
                    comments + [revocation], expected_owner="8ft0-ai", expected_issue=40
                )
                result = evaluate_guards(
                    manifest, with_observation(observation, governance_records=records)
                )
                self.assertEqual(result.code, "GOVERNANCE_SUPERSEDED")

        consumption = governance_comment(
            105,
            governance_payload(
                "consumption",
                CONSUMPTION_ID,
                manifest_subject(manifest.sha256, record_ids=(AUTHORITY_ID,)),
                {"run_id": 12345, "run_attempt": 1},
            ),
        )
        records = parse_governance_comments(
            comments + [consumption], expected_owner="8ft0-ai", expected_issue=40
        )
        result = evaluate_guards(manifest, with_observation(observation, governance_records=records))
        self.assertEqual(result.code, "AUTHORITY_CONSUMED")

    def test_second_simultaneously_active_authority_is_ambiguous(self):
        proposal, readiness, _, manifest, comments, observation = make_state()
        second = governance_comment(
            104,
            governance_payload(
                "authority",
                "b" * 32,
                lineage_subject(
                    record_ids=(PROPOSAL_ID, READINESS_ID),
                    comment_bindings=(binding(proposal), binding(readiness)),
                ),
                {"disposition": "granted", "execution_authorised": True, "single_use": True},
            ),
        )
        records = parse_governance_comments(
            comments + [second], expected_owner="8ft0-ai", expected_issue=40
        )
        result = evaluate_guards(manifest, with_observation(observation, governance_records=records))
        self.assertEqual(result.code, "GOVERNANCE_AMBIGUOUS")

    def test_live_stages_require_exact_manifest_approval_and_authority_binding(self):
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
            comments + [approval], expected_owner="8ft0-ai", expected_issue=40
        )
        live = with_observation(
            observation,
            stage="live_l1",
            governance_records=records,
            manifest_approval=binding_object(approval),
        )
        self.assertTrue(evaluate_guards(manifest, live).passed)
        self.assertEqual(
            evaluate_guards(manifest, with_observation(live, manifest_approval=None)).code,
            "AUTHORITY_NOT_GRANTED",
        )
        wrong = with_observation(
            live, manifest_approval=CommentBinding(approval["id"], "0" * 64)
        )
        self.assertEqual(evaluate_guards(manifest, wrong).code, "GOVERNANCE_RECORD_INVALID")

        weak_approval = governance_comment(
            105,
            governance_payload(
                "manifest_approval",
                "c" * 32,
                manifest_subject(manifest.sha256, record_ids=(AUTHORITY_ID,)),
                {"disposition": "approved"},
            ),
        )
        weak_records = parse_governance_comments(
            comments + [weak_approval], expected_owner="8ft0-ai", expected_issue=40
        )
        weak_live = with_observation(
            observation,
            stage="live_l1",
            governance_records=weak_records,
            manifest_approval=binding_object(weak_approval),
        )
        self.assertEqual(evaluate_guards(manifest, weak_live).code, "GOVERNANCE_RECORD_INVALID")

    def test_mutable_identity_failures_are_typed_and_do_not_refresh_authority(self):
        _, _, _, manifest, _, observation = make_state()
        cases = [
            ({"control_repository": "8ft0-ai/other"}, "CONTROL_IDENTITY_CHANGED"),
            ({"control_commit_sha": "9" * 40}, "CONTROL_IDENTITY_CHANGED"),
            ({"workflow_blob_sha": "9" * 40}, "WORKFLOW_IDENTITY_CHANGED"),
            ({"protocol_sha": "9" * 40}, "PROTOCOL_IDENTITY_CHANGED"),
            ({"state_commit_sha": "9" * 40}, "STATE_BASELINE_CHANGED"),
            (
                {"operator_history": type(manifest.operator_history)(0, "9" * 64)},
                "OPERATOR_HISTORY_CHANGED",
            ),
            (
                {"workflow_history": type(manifest.workflow_history)(0, "9" * 64)},
                "WORKFLOW_HISTORY_CHANGED",
            ),
            ({"app_id": 99}, "APP_BOUNDARY_CHANGED"),
            ({"environment_name": "other"}, "ENVIRONMENT_BOUNDARY_CHANGED"),
            ({"execution_variable": "OTHER_ENABLE"}, "ENVIRONMENT_BOUNDARY_CHANGED"),
            ({"execution_variable_absent": False}, "EXECUTION_ENABLEMENT_CHANGED"),
        ]
        for changes, code in cases:
            with self.subTest(code=code):
                result = evaluate_guards(manifest, with_observation(observation, **changes))
                self.assertEqual(result.code, code)
                self.assertEqual(result.category, "mutable_invalidator")
        operation = evaluate_guards(manifest, with_observation(observation, operation="other/v1"))
        self.assertEqual(operation.code, "AUTHORITY_NOT_GRANTED")
        self.assertEqual(operation.category, "authority_security")

    def test_malformed_complete_observation_is_implementation_defect(self):
        _, _, _, manifest, _, observation = make_state()
        for changes in (
            {"control_commit_sha": "not-a-sha"},
            {"selected_repository_ids": (200, 100)},
            {"module_blobs": ()},
            {"execution_variable_absent": "true"},
        ):
            with self.subTest(changes=changes):
                result = evaluate_guards(manifest, with_observation(observation, **changes))
                self.assertEqual(result.code, "OBSERVATION_SHAPE_UNSUPPORTED")
                self.assertEqual(result.category, "implementation_defect")

    def test_read_evidence_statuses_and_owner_observation_fail_closed(self):
        _, _, _, manifest, _, observation = make_state()
        for status, code in (
            ("unavailable", "READ_EVIDENCE_UNAVAILABLE"),
            ("rate_limited", "READ_EVIDENCE_RATE_LIMITED"),
            ("ambiguous", "READ_EVIDENCE_AMBIGUOUS"),
        ):
            with self.subTest(status=status):
                result = evaluate_guards(manifest, with_observation(observation, read_status=status))
                self.assertEqual(result.code, code)
                self.assertEqual(result.category, "observation_incomplete")

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
            owner_observation=OwnerObservation("owner-observation-1", "a" * 64, True),
        )
        self.assertTrue(evaluate_guards(manifest, valid).passed)
        stale = with_observation(
            observation,
            owner_observation=OwnerObservation("other", "a" * 64, True),
        )
        self.assertEqual(evaluate_guards(manifest, stale).code, "APP_BOUNDARY_CHANGED")

    def test_guard_module_has_no_mutation_token_or_dispatch_dependency(self):
        source = inspect.getsource(guard_module)
        for forbidden in (
            "github_api",
            "credentials",
            "mint_token",
            "workflow_dispatch",
            "update_ref",
            "workstream_d_live",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
