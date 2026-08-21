import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import phase2.operator_runtime as operator_runtime
import phase2.workstream_d_anchor_repair as remediation
import phase2.workstream_d_live as live
from phase2.adversarial import scenario_by_id
from phase2.canonical import LocalCanonicalRepository, StaleCanonicalBase
from test_post_allocation_read_stale_retry import (
    PROTOCOL_SHA,
    RUN_ID,
    _AlwaysStaleRepository,
    _InMemoryControlAPI,
    _PostAllocationStaleRepository,
    _ReadStore,
    _ScheduledReadRepository,
    _inventory,
    _token_scopes,
)


class AnchorRepairLiveStaleRetryTests(unittest.TestCase):
    def test_anchor_repair_request_read_retries_one_stale_from_fresh_snapshot(self):
        request_id = "0" * 26
        identities = {request_id: ("1" * 40, "dolt-anchor-read", 101)}
        store = _ReadStore(identities, "agent://operator/test")
        repository = _ScheduledReadRepository(store, ("stale", "ok"))

        row = remediation._request_row(repository, request_id)

        self.assertIsNotNone(row)
        self.assertEqual(row["canonical_git_ref_sha"], "1" * 40)
        self.assertEqual(repository.bootstrap_calls, 2)
        self.assertEqual(len(repository.snapshots), 1)
        self.assertTrue(repository.snapshots[0].closed)
        self.assertEqual(store.mutation_calls, 0)

    def test_anchor_repair_request_read_exhausts_existing_bounded_budget(self):
        repository = _AlwaysStaleRepository()

        with self.assertRaisesRegex(
            live.LiveExecutorError, "STALE_ALLOCATOR_RETRY_EXHAUSTED"
        ):
            remediation._request_row(repository, "0" * 26)

        self.assertEqual(
            repository.bootstrap_calls,
            live.POST_ALLOCATION_READ_MAX_STALE_RETRIES + 1,
        )

    def test_every_worker_stale_phase_emits_only_whitelisted_secret_free_evidence(self):
        secret = "ghs_fixture_secret_that_must_not_escape"

        def raw_stale():
            raise StaleCanonicalBase(f"STALE_EXPECTED_OLD_SHA:{secret}")

        expected_phases = {
            "allocation-process",
            "anchor-record",
            "anchor-repair",
            "request-row-read",
            "request-row-identity-read",
            "projection-read",
            "projection-metadata-record",
        }
        self.assertEqual(remediation._STALE_FAILURE_PHASES, expected_phases)

        for phase in sorted(expected_phases):
            with self.subTest(phase=phase):
                with self.assertRaises(remediation.StalePhaseFailure) as caught:
                    remediation._with_stale_phase(phase, raw_stale)

                failure = caught.exception
                self.assertEqual(str(failure), "STALE_EXPECTED_OLD_SHA")
                self.assertEqual(failure.safe_diagnostic(), {"failure_phase": phase})
                payload = operator_runtime._blocked_payload(failure)
                self.assertEqual(
                    payload,
                    {
                        "status": "BLOCKED",
                        "reason_code": "STALE_EXPECTED_OLD_SHA",
                        "failure_phase": phase,
                        "credential_material_emitted": False,
                        "workstream_e_authorised": False,
                    },
                )
                self.assertNotIn(secret, repr(payload))

        with self.assertRaisesRegex(ValueError, "invalid stale failure phase"):
            remediation.StalePhaseFailure("unreviewed-phase")

    def test_actual_anchor_repair_backend_completes_close_timed_scenario1_after_bounded_read_stales(self):
        inner = LocalCanonicalRepository()
        repository = _PostAllocationStaleRepository(inner)
        control_api = _InMemoryControlAPI()
        namespace = live.AttemptNamespace.parse(
            f"wd-{RUN_ID}-1-0123456789abcdef", run_id=RUN_ID, run_attempt=1
        )
        trusted_sha = subprocess.check_output(
            ("git", "rev-parse", "HEAD"), text=True
        ).strip()

        def read_only_remote(root: Path):
            mirror = root / "state-read-only.git"
            mirror.mkdir()
            return mirror, repository.identity.git_ref_sha

        backend = remediation.AnchorRepairLiveFixtureBackend(
            repository,
            control_api,
            1,
            trusted_sha,
            PROTOCOL_SHA,
            _token_scopes(),
            _inventory(),
            namespace,
            read_only_remote,
        )

        def creation_order(_mirror, _current_sha, refs):
            self.assertEqual(set(refs), set(repository.allocation_creation_refs))
            self.assertEqual(len(repository.allocation_creation_refs), 2)
            return tuple(repository.allocation_creation_refs)

        with patch.object(
            live, "_canonical_creation_ref_order", side_effect=creation_order
        ):
            evidence = backend.execute(scenario_by_id(1), namespace)

        evidence.validate()
        self.assertIs(backend.executed_records[1], evidence)
        self.assertEqual(
            sorted(repository.stale_surfaces),
            ["canonical_projection", "request_row"],
        )

        connection = inner.inspect()
        try:
            requests = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM allocation_requests ORDER BY request_id"
                ).fetchall()
            ]
            allocations = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM allocations ORDER BY allocation_id"
                ).fetchall()
            ]
            events = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM allocation_events ORDER BY event_id"
                ).fetchall()
            ]
        finally:
            connection.close()

        self.assertEqual(len(requests), 2)
        self.assertEqual({row["status"] for row in requests}, {"ALLOCATED"})
        self.assertEqual({row["anchor_status"] for row in requests}, {"RECORDED"})
        self.assertEqual({row["projection_status"] for row in requests}, {"POSTED"})
        self.assertEqual(len(allocations), 2)
        self.assertEqual(len({row["allocation_id"] for row in allocations}), 2)
        for request in requests:
            request_events = [
                event for event in events if event["request_id"] == request["request_id"]
            ]
            self.assertEqual(
                sum(event["event_type"] == "ALLOCATED" for event in request_events), 1
            )
            self.assertEqual(
                sum(event["event_type"] == "ANCHOR_RECORDED" for event in request_events), 1
            )
            self.assertEqual(
                sum(event["event_type"] == "PROJECTION_POSTED" for event in request_events), 1
            )

        # One seed + two allocation + two anchor + two projection metadata writes.
        # The bounded fresh-read retries add no canonical mutation.
        self.assertEqual(inner.publish_count, 7)


if __name__ == "__main__":
    unittest.main()
