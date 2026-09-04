from __future__ import annotations

import unittest

import phase2.preflight_runtime as runtime
from test_operator_preflight_projection import (
    EVALUATED_AT,
    FakeReadOnlyAPI,
    current_run,
    projection_comment,
    valid_environment,
)


class CarrierLockAPI(FakeReadOnlyAPI):
    def __init__(self, *, locked: bool, projection_comments, workflow_runs):
        super().__init__(
            projection_comments=projection_comments,
            workflow_runs=workflow_runs,
        )
        self.locked = locked

    def graphql_query(self, query, variables):
        payload = super().graphql_query(query, variables)
        payload["data"]["repository"]["issue"]["locked"] = self.locked
        return payload


class PreflightCarrierLockTests(unittest.TestCase):
    def test_unlocked_public_carrier_fails_closed(self):
        projection = projection_comment()
        api = CarrierLockAPI(
            locked=False,
            projection_comments=[projection],
            workflow_runs=[current_run(projection)],
        )
        with self.assertRaisesRegex(
            runtime.PreflightRuntimeError,
            "PUBLIC_CARRIER_NOT_LOCKED",
        ):
            runtime.run_preflight(
                valid_environment(projection),
                api_factory=lambda token, url: api,
                now=EVALUATED_AT,
            )
        self.assertTrue(api.graphql_queries)
        self.assertIn("locked", api.graphql_queries[0][0])
        self.assertFalse(api.posts)

    def test_locked_public_carrier_preserves_projection_validation(self):
        projection = projection_comment()
        api = CarrierLockAPI(
            locked=True,
            projection_comments=[projection],
            workflow_runs=[current_run(projection)],
        )
        record = runtime.run_preflight(
            valid_environment(projection),
            api_factory=lambda token, url: api,
            now=EVALUATED_AT,
        )
        self.assertTrue(record["projection_valid"])
        self.assertFalse(record["private_freshness_proven"])
        self.assertFalse(record["execution_authorised"])
        self.assertEqual(len(api.graphql_queries), 2)
        self.assertTrue(all("locked" in query for query, _ in api.graphql_queries))
        self.assertFalse(api.posts)


if __name__ == "__main__":
    unittest.main()
