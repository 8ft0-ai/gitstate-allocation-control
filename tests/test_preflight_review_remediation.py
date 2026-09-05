from __future__ import annotations

import unittest

import phase2.preflight_runtime as runtime
from phase2.governance_state import parse_guarded_execution_manifest
from phase2.operator_manifest import canonical_json
from test_operator_preflight_projection import (
    EVALUATED_AT,
    FakeReadOnlyAPI,
    current_run,
    invalidation_comment,
    projection_comment,
    projection_payload,
    thaw,
    valid_environment,
)


class CarrierSnapshotChangeAPI(FakeReadOnlyAPI):
    def __init__(self, *, first_comments, second_comments, workflow_runs):
        super().__init__(
            projection_comments=first_comments,
            workflow_runs=workflow_runs,
        )
        self.first_comments = list(first_comments)
        self.second_comments = list(second_comments)
        self.carrier_scans = 0

    def get(self, path):
        if "/issues/28/comments" in path and "page=1" in path:
            self.carrier_scans += 1
            self.projection_comments = (
                self.first_comments if self.carrier_scans == 1 else self.second_comments
            )
        return super().get(path)


def projection_with_execution_variable(name: str):
    _, payload = projection_payload()
    value = thaw(payload)
    manifest_value = thaw(value["manifest"])
    manifest_value["environment"]["execution_variable"] = name
    manifest = parse_guarded_execution_manifest(canonical_json(manifest_value))
    value["manifest"] = thaw(manifest.payload)
    value["manifest_sha256"] = manifest.sha256
    value["observation"]["execution_variable"] = name
    return projection_comment(payload=value)


class PreflightReviewRemediationTests(unittest.TestCase):
    def test_projection_cannot_select_an_alternate_execution_enable_variable(self):
        projection = projection_with_execution_variable("PHASE2_UNUSED_ENABLE_SWITCH")
        api = FakeReadOnlyAPI(
            projection_comments=[projection],
            workflow_runs=[current_run(projection)],
        )
        with self.assertRaisesRegex(
            runtime.PreflightRuntimeError,
            "PREFLIGHT_EXECUTION_VARIABLE_IDENTITY_MISMATCH",
        ):
            runtime.run_preflight(
                valid_environment(projection),
                api_factory=lambda token, url: api,
                now=EVALUATED_AT,
            )

    def test_real_execution_enable_variable_present_blocks_projected_snapshot(self):
        projection = projection_comment()
        api = FakeReadOnlyAPI(
            projection_comments=[projection],
            workflow_runs=[current_run(projection)],
        )
        env = valid_environment(projection)
        env[runtime.WORKSTREAM_D_EXECUTION_VARIABLE] = "true"
        record = runtime.run_preflight(
            env,
            api_factory=lambda token, url: api,
            now=EVALUATED_AT,
        )
        self.assertFalse(record["projection_valid"])
        self.assertEqual(
            record["projected_snapshot_guard_code"],
            "EXECUTION_ENABLEMENT_CHANGED",
        )
        self.assertFalse(record["execution_authorised"])

    def test_stable_public_carrier_evidence_binds_snapshot_digest(self):
        projection = projection_comment()
        api = FakeReadOnlyAPI(
            projection_comments=[projection],
            workflow_runs=[current_run(projection)],
        )
        record = runtime.run_preflight(
            valid_environment(projection),
            api_factory=lambda token, url: api,
            now=EVALUATED_AT,
        )
        digest = record["public_carrier_snapshot_sha256"]
        self.assertIsInstance(digest, str)
        self.assertEqual(len(digest), 64)
        self.assertEqual(len(api.graphql_queries), 2)
        carrier_reads = [
            path for path in api.gets if "/issues/28/comments" in path and "page=1" in path
        ]
        self.assertEqual(len(carrier_reads), 2)

    def test_invalidation_added_between_carrier_scans_blocks(self):
        projection = projection_comment()
        tombstone = invalidation_comment(projection)
        api = CarrierSnapshotChangeAPI(
            first_comments=[projection],
            second_comments=[projection, tombstone],
            workflow_runs=[current_run(projection)],
        )
        with self.assertRaisesRegex(
            runtime.PreflightRuntimeError,
            "PUBLIC_CARRIER_CHANGED",
        ):
            runtime.run_preflight(
                valid_environment(projection),
                api_factory=lambda token, url: api,
                now=EVALUATED_AT,
            )
        self.assertEqual(api.carrier_scans, 2)

    def test_projection_edit_between_carrier_scans_blocks(self):
        projection = projection_comment()
        edited_projection = dict(projection)
        edited_projection["updated_at"] = "2026-09-04T00:00:01Z"
        api = CarrierSnapshotChangeAPI(
            first_comments=[projection],
            second_comments=[edited_projection],
            workflow_runs=[current_run(projection)],
        )
        with self.assertRaisesRegex(
            runtime.PreflightRuntimeError,
            "PUBLIC_CARRIER_CHANGED",
        ):
            runtime.run_preflight(
                valid_environment(projection),
                api_factory=lambda token, url: api,
                now=EVALUATED_AT,
            )
        self.assertEqual(api.carrier_scans, 2)

    def test_new_projection_added_between_carrier_scans_blocks(self):
        projection = projection_comment()
        _, extra_payload = projection_payload(projection_id="7" * 32)
        extra_projection = projection_comment(2001, payload=extra_payload)
        api = CarrierSnapshotChangeAPI(
            first_comments=[projection],
            second_comments=[projection, extra_projection],
            workflow_runs=[current_run(projection)],
        )
        with self.assertRaisesRegex(
            runtime.PreflightRuntimeError,
            "PUBLIC_CARRIER_CHANGED",
        ):
            runtime.run_preflight(
                valid_environment(projection),
                api_factory=lambda token, url: api,
                now=EVALUATED_AT,
            )
        self.assertEqual(api.carrier_scans, 2)


if __name__ == "__main__":
    unittest.main()
