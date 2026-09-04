from __future__ import annotations

import unittest

import phase2.preflight_runtime as runtime
from test_operator_preflight_projection import (
    EVALUATED_AT,
    FakeReadOnlyAPI,
    RUN_ID,
    current_run,
    invalidation_comment,
    projection_comment,
    valid_environment,
    workflow_run,
)


class CarrierDeletionRaceAPI(FakeReadOnlyAPI):
    def __init__(self, *, projection_comments, workflow_runs, deletion):
        super().__init__(
            projection_comments=projection_comments,
            workflow_runs=workflow_runs,
        )
        self.deletion = deletion
        self.carrier_inventory_read = False
        self.deletion_checks = 0

    def graphql_query(self, query, variables):
        self.graphql_queries.append((query, dict(variables)))
        if variables.get("after") is not None:
            raise AssertionError("race fixture uses one deletion-history page per bracket")
        self.deletion_checks += 1
        nodes = [self.deletion] if self.carrier_inventory_read else []
        return {
            "data": {
                "repository": {
                    "issue": {
                        "timelineItems": {
                            "nodes": nodes,
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }
            }
        }

    def get(self, path):
        value = super().get(path)
        if "/issues/28/comments" in path:
            self.carrier_inventory_read = True
        return value


class CarrierPaginationRaceAPI(CarrierDeletionRaceAPI):
    def get(self, path):
        value = super(CarrierDeletionRaceAPI, self).get(path)
        if "/issues/28/comments" in path and "page=1" in path:
            self.carrier_inventory_read = True
        return value


class PreflightMonotonicityTests(unittest.TestCase):
    def test_tombstone_deleted_during_carrier_observation_cannot_produce_pass(self):
        projection = projection_comment()
        tombstone = invalidation_comment(projection)
        deletion = {
            "__typename": "CommentDeletedEvent",
            "id": "CDE_kwDOrace",
            "createdAt": "2026-09-04T00:03:00Z",
        }
        api = CarrierDeletionRaceAPI(
            projection_comments=[projection],
            workflow_runs=[current_run(projection)],
            deletion=deletion,
        )
        with self.assertRaisesRegex(
            runtime.PreflightRuntimeError,
            "PUBLIC_CARRIER_DELETION_DETECTED",
        ):
            runtime.run_preflight(
                valid_environment(projection),
                api_factory=lambda token, url: api,
                now=EVALUATED_AT,
            )
        self.assertEqual(api.deletion_checks, 2)
        self.assertTrue(api.carrier_inventory_read)
        self.assertFalse(api.posts)
        self.assertNotIn(tombstone, api.projection_comments)

    def test_deletion_between_comment_pages_is_caught_by_trailing_history_check(self):
        projection = projection_comment(1001)
        ordinary = [
            {
                "id": index,
                "body": f"ordinary public carrier record {index}",
                "user": {"login": "8ft0-ai"},
                "created_at": "2026-09-04T00:00:00Z",
                "updated_at": "2026-09-04T00:00:00Z",
            }
            for index in range(1, 101)
        ]
        deletion = {
            "__typename": "CommentDeletedEvent",
            "id": "CDE_kwDOpagination",
            "createdAt": "2026-09-04T00:04:00Z",
        }
        api = CarrierPaginationRaceAPI(
            projection_comments=ordinary + [projection],
            workflow_runs=[current_run(projection)],
            deletion=deletion,
        )
        with self.assertRaisesRegex(
            runtime.PreflightRuntimeError,
            "PUBLIC_CARRIER_DELETION_DETECTED",
        ):
            runtime.run_preflight(
                valid_environment(projection),
                api_factory=lambda token, url: api,
                now=EVALUATED_AT,
            )
        self.assertTrue(any("page=2" in path for path in api.gets))
        self.assertEqual(api.deletion_checks, 2)

    def test_deleted_unrelated_dispatch_cannot_restore_same_projection(self):
        projection = projection_comment()
        title = current_run(projection)["display_title"]
        visible_api = FakeReadOnlyAPI(
            projection_comments=[projection],
            workflow_runs=[
                workflow_run(499, title=title, run_number=1),
                workflow_run(500, title="contract_check", run_number=2),
                workflow_run(RUN_ID, title=title, run_number=3),
            ],
        )
        with self.assertRaisesRegex(runtime.PreflightRuntimeError, "WORKFLOW_HISTORY_CHANGED"):
            runtime.run_preflight(
                valid_environment(projection),
                api_factory=lambda token, url: visible_api,
                now=EVALUATED_AT,
            )

        after_deletion_api = FakeReadOnlyAPI(
            projection_comments=[projection],
            workflow_runs=[
                workflow_run(499, title=title, run_number=1),
                workflow_run(RUN_ID, title=title, run_number=3),
            ],
        )
        with self.assertRaisesRegex(runtime.PreflightRuntimeError, "WORKFLOW_HISTORY_CHANGED"):
            runtime.run_preflight(
                valid_environment(projection),
                api_factory=lambda token, url: after_deletion_api,
                now=EVALUATED_AT,
            )

    def test_duplicate_or_missing_workflow_run_ordinal_fails_closed(self):
        projection = projection_comment()
        title = current_run(projection)["display_title"]
        cases = [
            [
                workflow_run(500, title=title, run_number=1),
                workflow_run(RUN_ID, title=title, run_number=1),
            ],
            [
                workflow_run(500, title=title, run_number=1),
                workflow_run(RUN_ID, title=title, run_number=3),
            ],
        ]
        for runs in cases:
            with self.subTest(runs=runs):
                api = FakeReadOnlyAPI(
                    projection_comments=[projection],
                    workflow_runs=runs,
                )
                with self.assertRaisesRegex(
                    runtime.PreflightRuntimeError,
                    "WORKFLOW_HISTORY_CHANGED",
                ):
                    runtime.run_preflight(
                        valid_environment(projection),
                        api_factory=lambda token, url: api,
                        now=EVALUATED_AT,
                    )


if __name__ == "__main__":
    unittest.main()
