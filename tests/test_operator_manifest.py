import json
import unittest

from phase2.operator_manifest import (
    GOVERNANCE_CONTRACT,
    GOVERNANCE_PREFIX,
    MANIFEST_CONTRACT,
    V1_CAPSULE_CONTRACT,
    V1_CAPSULE_PREFIX,
    V1_CONSUMPTION_CONTRACT,
    V1_CONSUMPTION_PREFIX,
    OperatorContractError,
    WorkflowHistoryRecord,
    canonical_json,
    canonical_operator_history,
    canonical_workflow_history,
    operator_history_baseline,
    parse_execution_manifest,
    parse_governance_comment,
    parse_governance_comments,
    parse_v1_operator_history,
    parse_v1_operator_history_comment,
    sha256_text,
    workflow_history_baseline,
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
LINEAGE_ID = "4" * 32
PROPOSAL_ID = "5" * 32
READINESS_ID = "6" * 32
AUTHORITY_ID = "7" * 32
APPROVAL_ID = "8" * 32


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


def governance_comment(comment_id, payload, *, human="bounded rationale", edited=False):
    body = human + "\n" + GOVERNANCE_PREFIX + canonical_json(payload)
    return {
        "id": comment_id,
        "body": body,
        "user": {"login": "8ft0-ai"},
        "created_at": "2026-09-02T00:00:00Z",
        "updated_at": "2026-09-02T00:01:00Z" if edited else "2026-09-02T00:00:00Z",
    }


def lineage_comments():
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
                comment_bindings=(binding(proposal), binding(readiness)),
            ),
            {"disposition": "granted", "execution_authorised": True, "single_use": True},
        ),
    )
    return proposal, readiness, authority


def manifest_payload(proposal, readiness, authority, **changes):
    value = {
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
    value.update(changes)
    return value


def make_manifest(**changes):
    proposal, readiness, authority = lineage_comments()
    raw = canonical_json(manifest_payload(proposal, readiness, authority, **changes))
    return proposal, readiness, authority, raw, parse_execution_manifest(raw)


def v1_capsule_comment(
    comment_id=201,
    *,
    comment_time="2026-08-18T12:01:00Z",
    created_at="2026-08-18T12:00:00Z",
    expires_at="2026-08-18T12:30:00Z",
    capsule_id="b" * 32,
    workstream_e=False,
    **changes,
):
    payload = {
        "contract": V1_CAPSULE_CONTRACT,
        "capsule_id": capsule_id,
        "governance_contract": "gitstate-private-governance/v1",
        "governance_record_id": "c" * 32,
        "review_record_id": "d" * 32,
        "review_record_sha256": "e" * 64,
        "authority_record_id": "f" * 32,
        "authority_record_sha256": "0" * 64,
        "operation": OPERATION,
        "expected_control_sha": CONTROL_SHA,
        "expected_protocol_sha": PROTOCOL_SHA,
        "expected_state_baseline": STATE_SHA,
        "created_at": created_at,
        "expires_at": expires_at,
        "single_use": True,
        "workstream_e_authorised": workstream_e,
    }
    payload.update(changes)
    return {
        "id": comment_id,
        "body": V1_CAPSULE_PREFIX + canonical_json(payload),
        "user": {"login": "8ft0-ai"},
        "created_at": comment_time,
        "updated_at": comment_time,
    }


def v1_consumption_comment(capsule, comment_id=202, *, trusted_sha=CONTROL_SHA, run_attempt=1, run_id=32100000000):
    capsule_payload = json.loads(capsule["body"][len(V1_CAPSULE_PREFIX) :])
    payload = {
        "contract": V1_CONSUMPTION_CONTRACT,
        "capsule_id": capsule_payload["capsule_id"],
        "capsule_comment_id": capsule["id"],
        "capsule_body_sha256": sha256_text(capsule["body"]),
        "run_id": run_id,
        "run_attempt": run_attempt,
        "trusted_sha": trusted_sha,
        "operation": capsule_payload["operation"],
        "consumed_at": "2026-08-18T12:05:00Z",
        "workstream_e_authorised": False,
    }
    return {
        "id": comment_id,
        "body": V1_CONSUMPTION_PREFIX + canonical_json(payload),
        "user": {"login": "github-actions[bot]"},
        "created_at": "2026-08-18T12:05:00Z",
        "updated_at": "2026-08-18T12:05:00Z",
    }


class OperatorManifestTests(unittest.TestCase):
    def test_manifest_is_canonical_exact_and_digest_bound(self):
        _, _, _, raw, parsed = make_manifest()
        self.assertEqual(parsed.sha256, sha256_text(raw))
        self.assertEqual(parsed.authority.comment_id, 103)
        with self.assertRaisesRegex(OperatorContractError, "MANIFEST_IDENTITY_MISMATCH"):
            parse_execution_manifest(raw, expected_sha256="0" * 64)
        with self.assertRaisesRegex(OperatorContractError, "NONCANONICAL_JSON"):
            parse_execution_manifest(raw.replace(",", ", ", 1))
        value = json.loads(raw)
        value["unexpected"] = "no"
        with self.assertRaisesRegex(OperatorContractError, "MANIFEST_SCHEMA_MISMATCH"):
            parse_execution_manifest(canonical_json(value))

    def test_parsed_manifest_and_governance_are_deeply_immutable(self):
        proposal, _, _, _, manifest = make_manifest()
        record = parse_governance_comment(proposal, expected_owner="8ft0-ai", expected_issue=ISSUE)
        with self.assertRaises(TypeError):
            manifest.payload["operation"] = "changed"
        with self.assertRaises(TypeError):
            manifest.payload["executor"]["commit_sha"] = "9" * 40
        with self.assertRaises(TypeError):
            manifest.payload["executor"]["module_blobs"][0]["blob_sha"] = "9" * 40
        with self.assertRaises(TypeError):
            record.payload["details"]["disposition"] = "changed"
        with self.assertRaises(TypeError):
            record.payload["subject"]["record_ids"] += ("9" * 32,)

    def test_manifest_rejects_unsupported_values_and_non_deterministic_sets(self):
        proposal, readiness, authority = lineage_comments()
        value = manifest_payload(proposal, readiness, authority)
        value["environment"]["name"] = None
        with self.assertRaisesRegex(OperatorContractError, "UNSUPPORTED_JSON_VALUE"):
            parse_execution_manifest(canonical_json(value))
        value = manifest_payload(proposal, readiness, authority)
        value["allocator_app"]["selected_repository_ids"] = [200, 100]
        with self.assertRaisesRegex(OperatorContractError, "MANIFEST_APP_BOUNDARY_INVALID"):
            parse_execution_manifest(canonical_json(value))

    def test_governance_transport_is_owner_bound_immutable_and_duplicate_safe(self):
        proposal, _, _ = lineage_comments()
        record = parse_governance_comment(
            proposal,
            expected_owner="8ft0-ai",
            expected_issue=ISSUE,
            expected_body_sha256=sha256_text(proposal["body"]),
        )
        self.assertEqual(record.record_type, "proposal")
        edited = dict(proposal)
        edited["updated_at"] = "2026-09-02T00:02:00Z"
        with self.assertRaisesRegex(OperatorContractError, "GOVERNANCE_SOURCE_EDITED"):
            parse_governance_comment(edited, expected_owner="8ft0-ai", expected_issue=ISSUE)
        duplicate_id = governance_comment(
            104,
            governance_payload("proposal", PROPOSAL_ID, lineage_subject(), {"disposition": "proposed"}),
        )
        with self.assertRaisesRegex(OperatorContractError, "GOVERNANCE_DUPLICATE_RECORD_ID"):
            parse_governance_comments([proposal, duplicate_id], expected_owner="8ft0-ai", expected_issue=ISSUE)

    def test_manifest_targeted_governance_records_do_not_create_digest_cycles(self):
        proposal, readiness, authority, raw, manifest = make_manifest()
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
            [proposal, readiness, authority, approval], expected_owner="8ft0-ai", expected_issue=ISSUE
        )
        self.assertEqual(records[-1].manifest_sha256, manifest.sha256)
        self.assertEqual(parse_execution_manifest(raw).sha256, manifest.sha256)

    def test_v1_history_requires_closed_consumed_history_and_canonical_digest(self):
        capsule = v1_capsule_comment()
        with self.assertRaisesRegex(OperatorContractError, "OPERATOR_HISTORY_UNCONSUMED_CAPSULE"):
            parse_v1_operator_history([capsule])
        consumption = v1_consumption_comment(capsule)
        records = parse_v1_operator_history([consumption, capsule])
        expected = (
            f"{capsule['id']}\t{V1_CAPSULE_CONTRACT}\t{sha256_text(capsule['body'])}\n"
            f"{consumption['id']}\t{V1_CONSUMPTION_CONTRACT}\t{sha256_text(consumption['body'])}\n"
        )
        self.assertEqual(canonical_operator_history(records), expected)
        self.assertEqual(operator_history_baseline(records).history_sha256, sha256_text(expected))

    def test_v1_projection_time_matches_active_runtime_skew_boundary(self):
        at_lower_boundary = v1_capsule_comment(
            comment_time="2026-08-18T11:59:00Z",
            created_at="2026-08-18T12:00:00Z",
        )
        self.assertIsNotNone(parse_v1_operator_history_comment(at_lower_boundary))

        before_lower_boundary = v1_capsule_comment(
            comment_time="2026-08-18T11:58:59Z",
            created_at="2026-08-18T12:00:00Z",
        )
        with self.assertRaisesRegex(OperatorContractError, "OPERATOR_HISTORY_CAPSULE_TIME_INVALID"):
            parse_v1_operator_history_comment(before_lower_boundary)

        at_expiry = v1_capsule_comment(
            comment_time="2026-08-18T12:30:00Z",
            expires_at="2026-08-18T12:30:00Z",
        )
        self.assertIsNotNone(parse_v1_operator_history_comment(at_expiry))

        after_expiry = v1_capsule_comment(
            comment_time="2026-08-18T12:30:01Z",
            expires_at="2026-08-18T12:30:00Z",
        )
        with self.assertRaisesRegex(OperatorContractError, "OPERATOR_HISTORY_CAPSULE_TIME_INVALID"):
            parse_v1_operator_history_comment(after_expiry)

    def test_v1_history_fails_closed_on_replay_or_mismatch(self):
        capsule = v1_capsule_comment()
        consumption = v1_consumption_comment(capsule)
        with self.assertRaisesRegex(OperatorContractError, "OPERATOR_HISTORY_ORPHAN_CONSUMPTION"):
            parse_v1_operator_history([consumption])
        with self.assertRaisesRegex(OperatorContractError, "OPERATOR_HISTORY_DUPLICATE_CAPSULE"):
            parse_v1_operator_history([capsule, v1_capsule_comment(203)])
        with self.assertRaisesRegex(OperatorContractError, "OPERATOR_HISTORY_CONSUMPTION_MISMATCH"):
            parse_v1_operator_history([capsule, v1_consumption_comment(capsule, trusted_sha="9" * 40)])
        with self.assertRaisesRegex(OperatorContractError, "WORKSTREAM_E_NOT_AUTHORISED"):
            parse_v1_operator_history([v1_capsule_comment(workstream_e=True)])

    def test_workflow_history_binds_dispatch_identity_not_terminal_conclusion(self):
        failure = [WorkflowHistoryRecord(100, 1, CONTROL_SHA, OPERATION, "failure")]
        cancelled = [WorkflowHistoryRecord(100, 1, CONTROL_SHA, OPERATION, "cancelled")]
        self.assertEqual(canonical_workflow_history(failure), canonical_workflow_history(cancelled))
        self.assertEqual(
            workflow_history_baseline(failure).history_sha256,
            workflow_history_baseline(cancelled).history_sha256,
        )


if __name__ == "__main__":
    unittest.main()
