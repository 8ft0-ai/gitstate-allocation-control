from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

import phase2.preflight_projection as preflight
import phase2.preflight_runtime as runtime
from phase2.preflight_carrier_ledger import LEDGER_BASE_SHA
from test_operator_preflight_projection import (
    EVALUATED_AT,
    TRUSTED_SHA,
    current_run,
    invalidation_comment,
    projection_comment,
    valid_environment,
)
from test_preflight_carrier_ledger import (
    GENESIS_SHA,
    LedgerProductionAPI,
    _invalidation_record,
    _ledger,
    _projection_record,
)


MOVED_SHA = "9" * 40


class AdvancingMainAPI(LedgerProductionAPI):
    """Production-provider double whose protected-main head can advance mid-run."""

    def __init__(self, *, branch_heads, **kwargs):
        super().__init__(**kwargs)
        self.branch_heads = list(branch_heads)
        self.main_reads = 0

    def get(self, path):
        branch_path = f"/repos/{preflight.CONTROL_REPOSITORY}/branches/main"
        if path == branch_path:
            self.gets.append(path)
            if self.main_reads >= len(self.branch_heads):
                raise AssertionError("unexpected extra protected-main read")
            branch_head = self.branch_heads[self.main_reads]
            self.main_reads += 1
            return {
                "protected": True,
                "commit": {"sha": branch_head},
            }
        return super().get(path)


class PreflightFinalMainFenceTests(unittest.TestCase):
    def _api(self, *, branch_heads, include_moved_invalidation=False):
        projection = projection_comment()
        projection_record = _projection_record(projection)
        ledger_by_ref = {
            LEDGER_BASE_SHA: None,
            GENESIS_SHA: _ledger([]),
            TRUSTED_SHA: _ledger([projection_record]),
        }
        parents = {
            TRUSTED_SHA: GENESIS_SHA,
            GENESIS_SHA: LEDGER_BASE_SHA,
        }

        if include_moved_invalidation:
            tombstone = invalidation_comment(projection)
            invalidation_record = _invalidation_record(
                projection,
                tombstone,
                sequence=2,
                previous=projection_record["record_sha256"],
            )
            ledger_by_ref[MOVED_SHA] = _ledger(
                [projection_record, invalidation_record]
            )
            parents[MOVED_SHA] = TRUSTED_SHA

        api = AdvancingMainAPI(
            projection=projection,
            ledger_by_ref=ledger_by_ref,
            parents=parents,
            workflow_runs=[current_run(projection)],
            branch_heads=branch_heads,
        )
        return projection, api

    def test_positive_projection_is_fenced_by_two_stable_main_reads(self):
        projection, api = self._api(branch_heads=[TRUSTED_SHA, TRUSTED_SHA])

        output = io.StringIO()
        with redirect_stdout(output):
            record = runtime.run_preflight(
                valid_environment(projection),
                api_factory=lambda token, url: api,
                now=EVALUATED_AT,
            )

        self.assertTrue(record["projection_valid"])
        self.assertEqual(api.main_reads, 2)
        self.assertIn('"projection_valid":true', output.getvalue())
        self.assertFalse(api.posts)

    def test_invalidation_append_between_main_fences_blocks_positive_evidence(self):
        projection, api = self._api(
            branch_heads=[TRUSTED_SHA, MOVED_SHA],
            include_moved_invalidation=True,
        )

        # The entry fence observes M1 and validates the M1 ledger. Before the
        # positive evidence can be constructed, protected main advances to M2,
        # whose fixture ledger contains the matching durable invalidation.
        output = io.StringIO()
        with redirect_stdout(output):
            with self.assertRaisesRegex(
                RuntimeError,
                "PUBLIC_CARRIER_LEDGER_MAIN_MOVED",
            ):
                runtime.run_preflight(
                    valid_environment(projection),
                    api_factory=lambda token, url: api,
                    now=EVALUATED_AT,
                )

        self.assertEqual(api.main_reads, 2)
        self.assertNotIn('"projection_valid":true', output.getvalue())
        self.assertEqual(output.getvalue(), "")
        self.assertFalse(api.posts)


if __name__ == "__main__":
    unittest.main()
