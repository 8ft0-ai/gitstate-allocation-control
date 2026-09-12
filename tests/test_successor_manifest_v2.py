from datetime import datetime, timezone
import unittest

from phase2.governance_state import (
    attach_manifest_comment_id,
    build_governance_history,
    governance_history_baseline,
    parse_guarded_execution_manifest,
)
from phase2.operator_manifest import (
    GOVERNANCE_CONTRACT,
    GOVERNANCE_PREFIX,
    MANIFEST_V2_CONTRACT,
    canonical_json,
    parse_governance_comments,
    sha256_text,
)
from phase2.successor_contract import (
    APPROVAL_ATTESTATION_V2_CONTRACT,
    APPROVAL_ATTESTATION_V2_PREFIX,
    SuccessorCapsule,
    SuccessorContractError,
    parse_manifest_approval_attestation,
    validate_capsule_governance,
)


ISSUE = 12345
OPERATION = "workstream-d-scenarios-1-14/v1"
MANIFEST_COMMENT_ID = 9001
PROPOSAL_ID = "1" * 32
READINESS_ID = "2" * 32
LEGACY_AUTHORITY_ID = "3" * 32
APPROVAL_ID = "5" * 32
AUTHORITY_ID = "6" * 32
ATTESTATION_ID = "7" * 32
CAPSULE_ID = "8" * 32
LINEAGE = "4" * 32


def binding(comment):
    return {
        "comment_id": comment["id"],
        "body_sha256": sha256_text(comment["body"]),
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


def governance_comment(comment_id, payload):
    body = "fixture\n" + GOVERNANCE_PREFIX + canonical_json(payload)
    return {
        "id": comment_id,
        "body": body,
        "user": {"login": "8ft0-ai"},
        "created_at": "2026-09-12T00:00:00Z",
        "updated_at": "2026-09-12T00:00:00Z",
    }


def fixture_manifest():
    proposal = governance_comment(
        101,
        governance_payload(
            "proposal",
            PROPOSAL_ID,
            {
                "lineage_id": LINEAGE,
                "record_ids": [],
                "comment_bindings": [],
            },
            {"disposition": "proposed"},
        ),
    )
    readiness = governance_comment(
        102,
        governance_payload(
            "readiness",
            READINESS_ID,
            {
                "lineage_id": LINEAGE,
                "record_ids": [PROPOSAL_ID],
                "comment_bindings": [binding(proposal)],
            },
            {"disposition": "ready"},
        ),
    )
    legacy_authority = governance_comment(
        103,
        governance_payload(
            "authority",
            LEGACY_AUTHORITY_ID,
            {
                "lineage_id": LINEAGE,
                "record_ids": [PROPOSAL_ID, READINESS_ID],
                "comment_bindings": [binding(proposal), binding(readiness)],
            },
            {
                "disposition": "granted",
                "execution_authorised": True,
                "single_use": True,
            },
        ),
    )
    pre_records = parse_governance_comments(
        [proposal, readiness],
        expected_owner="8ft0-ai",
        expected_issue=ISSUE,
    )
    baseline = governance_history_baseline(pre_records)
    payload = {
        "contract": MANIFEST_V2_CONTRACT,
        "operation": OPERATION,
        "governing_issue": ISSUE,
        "executor": {
            "repository": "8ft0-ai/gitstate-allocation-control",
            "commit_sha": "a" * 40,
            "tree_sha": "b" * 40,
            "workflow_blob_sha": "c" * 40,
            "module_blobs": [
                {"path": "phase2/operator_runtime.py", "blob_sha": "d" * 40}
            ],
        },
        "protocol_sha": "e" * 40,
        "proposal": binding(proposal),
        "readiness": binding(readiness),
        "governance_history": {
            "through_id": baseline.through_id,
            "history_sha256": baseline.history_sha256,
        },
        "state_baseline": {
            "commit_sha": "f" * 40,
            "digest_sha256": "1" * 64,
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
            "permission_profile_sha256": "3" * 64,
            "owner_observation": {"required": False},
        },
        "environment": {
            "name": "phase-2-allocator",
            "policy_sha256": "2" * 64,
            "execution_variable": "PHASE2_WORKSTREAM_D_EXECUTION_ENABLED",
            "execution_variable_expected_absent": True,
        },
        "single_use": True,
        "workstream_e_authorised": False,
    }
    manifest = attach_manifest_comment_id(
        parse_guarded_execution_manifest(canonical_json(payload)),
        MANIFEST_COMMENT_ID,
    )
    full_records = parse_governance_comments(
        [proposal, readiness, legacy_authority],
        expected_owner="8ft0-ai",
        expected_issue=ISSUE,
    )
    return manifest, build_governance_history(manifest.sha256, full_records)


def attestation_payload(manifest, *, manifest_comment_id=MANIFEST_COMMENT_ID):
    exact = {
        "manifest_comment_id": manifest_comment_id,
        "manifest_sha256": manifest.sha256,
    }
    return {
        "contract": APPROVAL_ATTESTATION_V2_CONTRACT,
        "attestation_id": ATTESTATION_ID,
        "manifest_comment_id": manifest_comment_id,
        "manifest_sha256": manifest.sha256,
        "authority": {
            "record_id": AUTHORITY_ID,
            "body_sha256": "a" * 64,
            **exact,
        },
        "approval": {
            "record_id": APPROVAL_ID,
            "body_sha256": "b" * 64,
            **exact,
        },
        "disposition": "approved",
        "execution_authorised": True,
        "single_use": True,
        "workstream_e_authorised": False,
    }


def attestation_comment(payload):
    body = APPROVAL_ATTESTATION_V2_PREFIX + canonical_json(payload)
    return {
        "id": 501,
        "body": body,
        "user": {"login": "8ft0-ai"},
        "created_at": "2026-09-12T00:01:00Z",
        "updated_at": "2026-09-12T00:01:00Z",
    }


def capsule(manifest, attestation, *, authority_digest="a" * 64):
    payload = {
        "contract": "gitstate-operator/v2",
        "capsule_id": CAPSULE_ID,
        "operation": OPERATION,
        "projection": {
            "comment_id": 401,
            "body_sha256": "c" * 64,
        },
        "manifest_sha256": manifest.sha256,
        "authority": {
            "record_id": AUTHORITY_ID,
            "body_sha256": authority_digest,
        },
        "manifest_approval": {
            "record_id": APPROVAL_ID,
            "body_sha256": "b" * 64,
            "attestation_id": ATTESTATION_ID,
            "attestation_body_sha256": attestation.body_sha256,
        },
        "expected_control_sha": "a" * 40,
        "preflight_run": {
            "run_id": 300,
            "run_attempt": 1,
            "trusted_sha": "a" * 40,
        },
        "created_at": "2026-09-12T00:02:00Z",
        "expires_at": "2026-09-12T00:32:00Z",
        "execution_authorised": True,
        "single_use": True,
        "workstream_e_authorised": False,
    }
    return SuccessorCapsule(
        payload,
        601,
        "d" * 64,
        sha256_text(canonical_json(payload)),
        datetime(2026, 9, 12, 0, 2, tzinfo=timezone.utc),
    )


class SuccessorManifestV2Tests(unittest.TestCase):
    def test_v2_attestation_proves_exact_manifest_identity_for_authority_and_approval(self):
        manifest, history = fixture_manifest()
        parsed = parse_manifest_approval_attestation(
            attestation_comment(attestation_payload(manifest))
        )
        self.assertIsNotNone(parsed)
        subject = capsule(manifest, parsed)
        self.assertIs(
            validate_capsule_governance(
                subject, manifest, history, parsed
            ),
            history,
        )

    def test_attestation_rejects_authority_or_approval_identity_migration(self):
        manifest, _ = fixture_manifest()
        payload = attestation_payload(manifest)
        payload["authority"] = dict(payload["authority"])
        payload["authority"]["manifest_comment_id"] = MANIFEST_COMMENT_ID + 1
        with self.assertRaisesRegex(
            SuccessorContractError,
            "SUCCESSOR_APPROVAL_ATTESTATION_MANIFEST_BINDING_MISMATCH",
        ):
            parse_manifest_approval_attestation(attestation_comment(payload))

    def test_capsule_authority_digest_must_equal_exact_attested_authority(self):
        manifest, history = fixture_manifest()
        parsed = parse_manifest_approval_attestation(
            attestation_comment(attestation_payload(manifest))
        )
        subject = capsule(manifest, parsed, authority_digest="9" * 64)
        with self.assertRaisesRegex(
            SuccessorContractError,
            "SUCCESSOR_CAPSULE_APPROVAL_BINDING_MISMATCH",
        ):
            validate_capsule_governance(
                subject, manifest, history, parsed
            )

    def test_v2_attestation_is_single_use_and_never_authorises_workstream_e(self):
        manifest, _ = fixture_manifest()
        payload = attestation_payload(manifest)
        payload["single_use"] = False
        with self.assertRaisesRegex(
            SuccessorContractError,
            "SUCCESSOR_APPROVAL_ATTESTATION_AUTHORITY_INVALID",
        ):
            parse_manifest_approval_attestation(attestation_comment(payload))

        payload = attestation_payload(manifest)
        payload["workstream_e_authorised"] = True
        with self.assertRaisesRegex(
            SuccessorContractError, "WORKSTREAM_E_NOT_AUTHORISED"
        ):
            parse_manifest_approval_attestation(attestation_comment(payload))


if __name__ == "__main__":
    unittest.main()
