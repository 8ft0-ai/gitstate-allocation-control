import unittest

from phase2.governance_state import parse_guarded_execution_manifest
from phase2.operator_guard import evaluate_guards
from phase2.operator_manifest import canonical_json, parse_governance_comments
from test_operator_guard import (
    APPROVAL_ID,
    AUTHORITY_ID,
    ISSUE,
    PROPOSAL_ID,
    READINESS_ID,
    binding,
    governance_comment,
    governance_payload,
    lineage_subject,
    manifest_payload,
    manifest_subject,
    make_state,
    observation_for,
    with_records,
)


class OperatorGuardOrderingTests(unittest.TestCase):
    def _assert_invalid_lineage(self, proposal, readiness, authority):
        records = parse_governance_comments(
            [proposal, readiness, authority],
            expected_owner="8ft0-ai",
            expected_issue=ISSUE,
        )
        manifest = parse_guarded_execution_manifest(
            canonical_json(
                manifest_payload(
                    proposal,
                    readiness,
                    authority,
                    governance_records=records,
                )
            )
        )
        result = evaluate_guards(manifest, observation_for(manifest, records))
        self.assertEqual(result.code, "GOVERNANCE_RECORD_INVALID")

    def test_readiness_cannot_bind_a_later_proposal(self):
        proposal = governance_comment(
            102,
            governance_payload(
                "proposal",
                PROPOSAL_ID,
                lineage_subject(),
                {"disposition": "proposed"},
            ),
        )
        readiness = governance_comment(
            101,
            governance_payload(
                "readiness",
                READINESS_ID,
                lineage_subject(
                    record_ids=(PROPOSAL_ID,),
                    comment_bindings=(binding(proposal),),
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
                    comment_bindings=(binding(readiness), binding(proposal)),
                ),
                {"disposition": "granted", "execution_authorised": True, "single_use": True},
            ),
        )
        self._assert_invalid_lineage(proposal, readiness, authority)

    def test_authority_cannot_bind_a_later_readiness(self):
        proposal = governance_comment(
            101,
            governance_payload(
                "proposal",
                PROPOSAL_ID,
                lineage_subject(),
                {"disposition": "proposed"},
            ),
        )
        readiness = governance_comment(
            103,
            governance_payload(
                "readiness",
                READINESS_ID,
                lineage_subject(
                    record_ids=(PROPOSAL_ID,),
                    comment_bindings=(binding(proposal),),
                ),
                {"disposition": "ready"},
            ),
        )
        authority = governance_comment(
            102,
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
        self._assert_invalid_lineage(proposal, readiness, authority)

    def test_manifest_approval_cannot_precede_manifest_history_anchor(self):
        _, _, authority, manifest, comments, observation = make_state()
        approval = governance_comment(
            100,
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
            comments + [approval],
            expected_owner="8ft0-ai",
            expected_issue=ISSUE,
        )
        live = with_records(observation, manifest, records, stage="live_l1")
        self.assertEqual(evaluate_guards(manifest, live).code, "GOVERNANCE_HISTORY_CHANGED")


if __name__ == "__main__":
    unittest.main()
