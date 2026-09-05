from __future__ import annotations

import unittest

import phase2.preflight_projection as preflight
import phase2.preflight_runtime as runtime
from phase2.preflight_carrier_ledger import LEDGER_BASE_SHA, LEDGER_PATH
from test_operator_preflight_projection import (
    EVALUATED_AT,
    TRUSTED_SHA,
    current_run,
    projection_comment,
    valid_environment,
)
from test_preflight_carrier_ledger import (
    GENESIS_SHA,
    LedgerProductionAPI,
    _ledger,
    _projection_record,
)


PUBLISHED_LEDGER_SHA = "1" * 40


class PublishedProjectionAPI(LedgerProductionAPI):
    """Model comment-first publication followed by one protected-main ledger append."""

    def __init__(self, *, projection, changed_files):
        projection_record = _projection_record(projection)
        run = dict(current_run(projection))
        run["head_sha"] = PUBLISHED_LEDGER_SHA
        super().__init__(
            projection=projection,
            ledger_by_ref={
                LEDGER_BASE_SHA: None,
                GENESIS_SHA: _ledger([]),
                TRUSTED_SHA: _ledger([]),
                PUBLISHED_LEDGER_SHA: _ledger([projection_record]),
            },
            parents={
                PUBLISHED_LEDGER_SHA: TRUSTED_SHA,
                TRUSTED_SHA: GENESIS_SHA,
                GENESIS_SHA: LEDGER_BASE_SHA,
            },
            workflow_runs=[run],
            branch_head=PUBLISHED_LEDGER_SHA,
        )
        self.changed_files = list(changed_files)

    def get(self, path):
        current_commit = (
            f"/repos/{preflight.CONTROL_REPOSITORY}/commits/{PUBLISHED_LEDGER_SHA}"
        )
        if path == current_commit:
            self.gets.append(path)
            return {
                "sha": PUBLISHED_LEDGER_SHA,
                "parents": [{"sha": TRUSTED_SHA}],
                "commit": {"tree": {"sha": "9" * 40}},
                "files": [
                    {"filename": filename, "status": "modified"}
                    for filename in self.changed_files
                ],
            }
        return super().get(path)


def _published_environment(projection):
    env = valid_environment(projection)
    env["GITHUB_SHA"] = PUBLISHED_LEDGER_SHA
    return env


class PreflightControlAnchorTests(unittest.TestCase):
    def test_comment_first_projection_survives_exact_ledger_only_main_advance(self):
        projection = projection_comment()
        api = PublishedProjectionAPI(
            projection=projection,
            changed_files=[LEDGER_PATH],
        )

        record = runtime.run_preflight(
            _published_environment(projection),
            api_factory=lambda token, url: api,
            now=EVALUATED_AT,
        )

        self.assertTrue(record["projection_valid"])
        self.assertEqual(record["trusted_sha"], PUBLISHED_LEDGER_SHA)
        self.assertFalse(record["private_freshness_proven"])
        self.assertFalse(api.posts)

    def test_non_ledger_main_change_after_projection_anchor_fails_closed(self):
        projection = projection_comment()
        api = PublishedProjectionAPI(
            projection=projection,
            changed_files=[LEDGER_PATH, "phase2/preflight_runtime.py"],
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "PUBLIC_CARRIER_LEDGER_CONTROL_DRIFT",
        ):
            runtime.run_preflight(
                _published_environment(projection),
                api_factory=lambda token, url: api,
                now=EVALUATED_AT,
            )

        self.assertFalse(api.posts)


if __name__ == "__main__":
    unittest.main()
