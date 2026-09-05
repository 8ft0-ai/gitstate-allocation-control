from __future__ import annotations

import unittest

import phase2.preflight_runtime as runtime
from phase2.github_api import GitHubAPI
from test_operator_preflight_projection import (
    EVALUATED_AT,
    FakeReadOnlyAPI,
    current_run,
    invalidation_comment,
    projection_comment,
    valid_environment,
)


def _timeline_comment(comment):
    return {
        "__typename": "IssueComment",
        "databaseId": comment["id"],
        "body": comment["body"],
        "author": {"login": comment["user"]["login"]},
        "createdAt": comment["created_at"],
        "updatedAt": comment["updated_at"],
    }


class ReviewedDeletionVisibilitySkewAPI(GitHubAPI):
    """Reproduce the reviewed REST/GraphQL visibility skew deterministically.

    The legacy REST carrier inventory has already stopped returning the deleted
    tombstone while the deletion-only GraphQL feed is still clean. The unified
    production timeline remains at the coherent pre-delete carrier view, so it
    still contains the tombstone and must fail closed without reconciling the
    independently lagging surfaces.
    """

    def __init__(self, *, projection, tombstone, workflow_runs):
        self.projection = projection
        self.tombstone = tombstone
        self.backing = FakeReadOnlyAPI(
            projection_comments=[projection],
            workflow_runs=workflow_runs,
        )
        self.graphql_queries = []
        self.gets = self.backing.gets
        self.posts = []
        self.rest_carrier_reads = 0
        self.deletion_only_reads = 0
        self.combined_timeline_reads = 0

    def graphql_query(self, query, variables):
        self.graphql_queries.append((query, dict(variables)))
        if variables.get("after") is not None:
            raise AssertionError("reviewed-race fixture uses one timeline page")

        if "ISSUE_COMMENT" in query:
            self.combined_timeline_reads += 1
            nodes = [
                _timeline_comment(self.projection),
                _timeline_comment(self.tombstone),
            ]
            return {
                "data": {
                    "repository": {
                        "issue": {
                            "locked": True,
                            "timelineItems": {
                                "totalCount": 2,
                                "filteredCount": 2,
                                "pageCount": 2,
                                "updatedAt": "2026-09-04T00:02:00Z",
                                "nodes": nodes,
                                "pageInfo": {
                                    "hasNextPage": False,
                                    "endCursor": None,
                                },
                            },
                        }
                    }
                }
            }

        self.deletion_only_reads += 1
        return {
            "data": {
                "repository": {
                    "issue": {
                        "locked": True,
                        "timelineItems": {
                            "nodes": [],
                            "pageInfo": {
                                "hasNextPage": False,
                                "endCursor": None,
                            },
                        },
                    }
                }
            }
        }

    def get(self, path):
        if f"/issues/{runtime.projection.PROJECTION_ISSUE_NUMBER}/comments" in path:
            self.gets.append(path)
            self.rest_carrier_reads += 1
            page = int(path.rsplit("page=", 1)[1])
            return [self.projection] if page == 1 else []
        return self.backing.get(path)

    def post(self, path, body):
        self.posts.append((path, body))
        raise AssertionError("preflight must never issue a write")


class ReviewedDeletionVisibilityRaceTests(unittest.TestCase):
    def test_reviewed_rest_graphql_deletion_skew_cannot_produce_projection_valid(self):
        projection = projection_comment()
        tombstone = invalidation_comment(projection)
        api = ReviewedDeletionVisibilitySkewAPI(
            projection=projection,
            tombstone=tombstone,
            workflow_runs=[current_run(projection)],
        )

        owner, name = runtime.projection.CONTROL_REPOSITORY.split("/", 1)
        deletion_variables = {
            "owner": owner,
            "name": name,
            "number": runtime.projection.PROJECTION_ISSUE_NUMBER,
            "after": None,
        }

        # Pin the exact reviewed failure state: both legacy REST inventories
        # omit the tombstone and both deletion-only GraphQL brackets are clean.
        for _ in range(2):
            legacy_inventory = api.get(
                f"/repos/{runtime.projection.CONTROL_REPOSITORY}/issues/"
                f"{runtime.projection.PROJECTION_ISSUE_NUMBER}/comments?per_page=100&page=1"
            )
            self.assertEqual([comment["id"] for comment in legacy_inventory], [projection["id"]])
            deletion_payload = api.graphql_query(
                runtime.PUBLIC_CARRIER_DELETION_QUERY,
                deletion_variables,
            )
            nodes = deletion_payload["data"]["repository"]["issue"]["timelineItems"]["nodes"]
            self.assertEqual(nodes, [])

        api.rest_carrier_reads = 0
        api.deletion_only_reads = 0
        api.combined_timeline_reads = 0

        record = runtime.run_preflight(
            valid_environment(projection),
            api_factory=lambda token, url: api,
            now=EVALUATED_AT,
        )

        self.assertFalse(record["projection_valid"])
        self.assertEqual(record["projected_snapshot_guard_code"], "GOVERNANCE_SUPERSEDED")
        self.assertFalse(record["private_freshness_proven"])
        self.assertEqual(api.rest_carrier_reads, 0)
        self.assertEqual(api.deletion_only_reads, 0)
        self.assertEqual(api.combined_timeline_reads, 2)
        self.assertFalse(api.posts)


if __name__ == "__main__":
    unittest.main()
