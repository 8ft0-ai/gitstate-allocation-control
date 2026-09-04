from __future__ import annotations

from collections.abc import Mapping
from dataclasses import FrozenInstanceError, replace
import unittest

import phase2.operator_guard as guard_module
from phase2.governance_state import (
    GovernanceHistory,
    GovernanceStateError,
    build_governance_history,
)
from phase2.operator_guard import evaluate_guards
from phase2.operator_manifest import GovernanceRecord
from test_operator_guard import (
    APPROVAL_ID,
    AUTHORITY_ID,
    ISSUE,
    binding,
    governance_comment,
    governance_payload,
    make_state,
    manifest_subject,
    parsed_records,
    with_observation,
)


def thaw(value):
    if isinstance(value, Mapping):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw(item) for item in value]
    return value


class OperatorGuardEvidenceTests(unittest.TestCase):
    def test_history_reparses_source_before_reducer_and_ignores_forged_semantics(self):
        _, _, authority, manifest, comments, observation = make_state()
        rejected = governance_comment(
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
        records = parsed_records(comments + [rejected])
        authentic = records[-1]
        forged_payload = thaw(authentic.payload)
        forged_payload["details"]["disposition"] = "approved"
        forged_payload["subject"]["manifest_sha256"] = "0" * 64
        forged = GovernanceRecord(
            forged_payload,
            authentic.comment_id,
            authentic.body_sha256,
            authentic.source,
        )
        history = build_governance_history(manifest.sha256, records[:-1] + (forged,))
        live = with_observation(
            observation,
            stage="live_l1",
            governance_history=history,
        )
        result = evaluate_guards(manifest, live)
        self.assertFalse(result.passed)
        self.assertEqual(result.code, "AUTHORITY_NOT_GRANTED")

    def test_history_rejects_source_body_tamper_against_previous_baseline(self):
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
        records = parsed_records(comments + [approved])
        full_history = build_governance_history(manifest.sha256, records)
        valid = with_observation(
            observation,
            stage="live_l1",
            governance_history=full_history,
        )
        self.assertTrue(evaluate_guards(manifest, valid).passed)

        source = full_history.records[-1]
        tampered = replace(source, body=source.body.replace('"approved"', '"rejected"'))
        history = GovernanceHistory(
            manifest_sha256=manifest.sha256,
            baseline=full_history.baseline,
            records=full_history.records[:-1] + (tampered,),
        )
        result = evaluate_guards(
            manifest,
            with_observation(valid, governance_history=history),
        )
        self.assertEqual(result.code, "GOVERNANCE_HISTORY_CHANGED")

    def test_history_rejects_wrong_owner_and_edited_source(self):
        _, _, _, manifest, _, observation = make_state()
        source = observation.governance_history.records[0]
        mutations = (
            replace(source, owner="attacker"),
            replace(source, updated_at="2026-09-02T00:01:00Z"),
        )
        for mutated in mutations:
            history = GovernanceHistory(
                manifest_sha256=manifest.sha256,
                baseline=observation.governance_history.baseline,
                records=(mutated,) + observation.governance_history.records[1:],
            )
            result = evaluate_guards(
                manifest,
                with_observation(observation, governance_history=history),
            )
            self.assertEqual(result.code, "GOVERNANCE_HISTORY_CHANGED")

    def test_malformed_rehydrated_source_is_typed_history_failure(self):
        _, _, _, manifest, _, observation = make_state()
        malformed = GovernanceHistory(
            manifest_sha256=manifest.sha256,
            baseline=observation.governance_history.baseline,
            records=(object(),),
        )
        result = evaluate_guards(
            manifest,
            with_observation(observation, governance_history=malformed),
        )
        self.assertEqual(
            (result.code, result.category),
            ("GOVERNANCE_HISTORY_CHANGED", "authority_security"),
        )

    def test_build_history_rejects_semantic_record_without_parser_source(self):
        _, _, _, manifest, comments, _ = make_state()
        authentic = parsed_records(comments)[0]
        unbound = GovernanceRecord(
            authentic.payload,
            authentic.comment_id,
            authentic.body_sha256,
        )
        with self.assertRaisesRegex(GovernanceStateError, "GOVERNANCE_HISTORY_CHANGED"):
            build_governance_history(manifest.sha256, (unbound,))

    def test_unexpected_reducer_exception_is_typed_evaluator_defect(self):
        _, _, _, manifest, _, observation = make_state()
        original = guard_module.reduce_governance_history

        def broken_reducer(*_args, **_kwargs):
            raise RuntimeError("unexpected evaluator defect")

        guard_module.reduce_governance_history = broken_reducer
        try:
            result = evaluate_guards(manifest, observation)
        finally:
            guard_module.reduce_governance_history = original
        self.assertEqual(
            (result.code, result.category),
            ("GUARD_EVALUATOR_DEFECT", "implementation_defect"),
        )

    def test_governance_source_evidence_is_immutable(self):
        _, _, _, _, comments, _ = make_state()
        source = parsed_records(comments)[0].source
        self.assertIsNotNone(source)
        with self.assertRaises(FrozenInstanceError):
            source.owner = "attacker"


if __name__ == "__main__":
    unittest.main()
