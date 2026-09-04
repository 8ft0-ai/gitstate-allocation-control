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


def issue_comment_node(comment):
    return {
        "__typename": "IssueComment",
        "databaseId": comment["id"],
        "body": comment["body"],
        "author": {"login": comment["user"]["login"]},
        "createdAt": comment["created_at"],
        "updatedAt": comment["updated_at"],
    }


def deletion_node(identifier="CDE_kwDOsingle"):
    return {
        "__typename": "CommentDeletedEvent",
        "id": identifier,
        "createdAt": "2026-09-04T00:03:00Z",
    }


def page(nodes, *, updated_at="2026-09-04T00:10:00Z", total_count=None, locked=True):
    return {
        "nodes": list(nodes),
        "updated_at": updated_at,
        "total_count": total_count,
        "locked": locked,
    }


class TimelineGitHubAPI(GitHubAPI):
    """Network-free production-provider double for the single timeline contract."""

    def __init__(self, *, scans, projection_comments, workflow_runs):
        self.scans = [list(scan) for scan in scans]
        self.scan_index = -1
        self.backing = FakeReadOnlyAPI(
            projection_comments=projection_comments,
            workflow_runs=workflow_runs,
        )
        self.graphql_queries = []
        self.gets = self.backing.gets
        self.posts = []

    def graphql_query(self, query, variables):
        self.graphql_queries.append((query, dict(variables)))
        after = variables.get("after")
        if after is None:
            self.scan_index += 1
            page_index = 0
        elif isinstance(after, str) and after.startswith("timeline-cursor-"):
            page_index = int(after.rsplit("-", 1)[1])
        else:
            raise AssertionError("unexpected timeline cursor")

        if self.scan_index >= len(self.scans):
            raise AssertionError("unexpected extra timeline scan")
        scan = self.scans[self.scan_index]
        if page_index >= len(scan):
            raise AssertionError("unexpected timeline page")
        spec = scan[page_index]
        nodes = list(spec["nodes"])
        scan_total = sum(len(item["nodes"]) for item in scan)
        total_count = spec["total_count"] if spec["total_count"] is not None else scan_total
        remaining = sum(len(item["nodes"]) for item in scan[page_index:])
        has_next = page_index + 1 < len(scan)
        return {
            "data": {
                "repository": {
                    "issue": {
                        "locked": spec["locked"],
                        "timelineItems": {
                            "totalCount": total_count,
                            "filteredCount": remaining,
                            "pageCount": len(nodes),
                            "updatedAt": spec["updated_at"],
                            "nodes": nodes,
                            "pageInfo": {
                                "hasNextPage": has_next,
                                "endCursor": (
                                    f"timeline-cursor-{page_index + 1}" if has_next else None
                                ),
                            },
                        },
                    }
                }
            }
        }

    def get(self, path):
        if f"/issues/{runtime.projection.PROJECTION_ISSUE_NUMBER}/comments" in path:
            raise AssertionError("production carrier path must not read REST issue comments")
        return self.backing.get(path)

    def post(self, path, body):
        self.posts.append((path, body))
        raise AssertionError("preflight must never issue a write")


class PreflightSingleTimelineTests(unittest.TestCase):
    def test_production_carrier_uses_one_timeline_surface_and_never_rest_comments(self):
        projection = projection_comment()
        nodes = [issue_comment_node(projection)]
        api = TimelineGitHubAPI(
            scans=[[page(nodes)], [page(nodes)]],
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
        self.assertEqual(len(api.graphql_queries), 2)
        self.assertFalse(api.posts)
        self.assertFalse(
            any(
                f"/issues/{runtime.projection.PROJECTION_ISSUE_NUMBER}/comments" in path
                for path in api.gets
            )
        )
        for query, _ in api.graphql_queries:
            self.assertIn("ISSUE_COMMENT", query)
            self.assertIn("COMMENT_DELETED_EVENT", query)
            self.assertIn("totalCount", query)
            self.assertIn("updatedAt", query)

    def test_rest_visibility_divergence_cannot_hide_visible_timeline_invalidation(self):
        projection = projection_comment()
        tombstone = invalidation_comment(projection)
        nodes = [issue_comment_node(projection), issue_comment_node(tombstone)]
        api = TimelineGitHubAPI(
            scans=[[page(nodes)], [page(nodes)]],
            # Deliberately divergent legacy REST fixture: the tombstone is absent.
            projection_comments=[projection],
            workflow_runs=[],
        )

        record = runtime.run_preflight(
            valid_environment(projection),
            api_factory=lambda token, url: api,
            now=EVALUATED_AT,
        )

        self.assertFalse(record["projection_valid"])
        self.assertEqual(record["projected_snapshot_guard_code"], "GOVERNANCE_SUPERSEDED")
        self.assertFalse(api.posts)

    def test_deletion_event_on_later_timeline_page_permanently_blocks(self):
        projection = projection_comment()
        api = TimelineGitHubAPI(
            scans=[
                [
                    page(
                        [issue_comment_node(projection)],
                        total_count=2,
                    ),
                    page(
                        [deletion_node()],
                        total_count=2,
                    ),
                ]
            ],
            projection_comments=[projection],
            workflow_runs=[current_run(projection)],
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
        self.assertEqual(len(api.graphql_queries), 2)
        self.assertFalse(api.posts)

    def test_timeline_metadata_change_during_pagination_fails_closed(self):
        projection = projection_comment()
        api = TimelineGitHubAPI(
            scans=[
                [
                    page(
                        [issue_comment_node(projection)],
                        updated_at="2026-09-04T00:10:00Z",
                        total_count=2,
                    ),
                    page(
                        [issue_comment_node(projection_comment(2001))],
                        updated_at="2026-09-04T00:11:00Z",
                        total_count=2,
                    ),
                ]
            ],
            projection_comments=[projection],
            workflow_runs=[],
        )

        with self.assertRaisesRegex(runtime.PreflightRuntimeError, "PUBLIC_CARRIER_CHANGED"):
            runtime._read_public_carrier_timeline_scan(api)

    def test_timeline_change_between_complete_scans_fails_closed(self):
        projection = projection_comment()
        nodes = [issue_comment_node(projection)]
        api = TimelineGitHubAPI(
            scans=[
                [page(nodes, updated_at="2026-09-04T00:10:00Z")],
                [page(nodes, updated_at="2026-09-04T00:11:00Z")],
            ],
            projection_comments=[projection],
            workflow_runs=[current_run(projection)],
        )

        with self.assertRaisesRegex(runtime.PreflightRuntimeError, "PUBLIC_CARRIER_CHANGED"):
            runtime.run_preflight(
                valid_environment(projection),
                api_factory=lambda token, url: api,
                now=EVALUATED_AT,
            )

    def test_incomplete_timeline_count_fails_closed(self):
        projection = projection_comment()
        api = TimelineGitHubAPI(
            scans=[[page([issue_comment_node(projection)], total_count=2)]],
            projection_comments=[projection],
            workflow_runs=[],
        )

        with self.assertRaisesRegex(runtime.PreflightRuntimeError, "READ_EVIDENCE_AMBIGUOUS"):
            runtime._read_public_carrier_timeline_scan(api)


if __name__ == "__main__":
    unittest.main()
