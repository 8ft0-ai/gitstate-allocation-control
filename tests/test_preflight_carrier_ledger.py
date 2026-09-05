from __future__ import annotations

import base64
import unittest

import phase2.preflight_projection as preflight
import phase2.preflight_runtime as runtime
from phase2.github_api import GitHubAPI, GitHubAPIError
from phase2.operator_manifest import canonical_json, sha256_text
from phase2.preflight_carrier_ledger import (
    LEDGER_BASE_SHA,
    LEDGER_CONTRACT,
    LEDGER_PATH,
    ZERO_SHA256,
)
from test_operator_preflight_projection import (
    EVALUATED_AT,
    TRUSTED_SHA,
    FakeReadOnlyAPI,
    current_run,
    invalidation_comment,
    projection_comment,
    valid_environment,
)


GENESIS_SHA = "e" * 40
PROJECTION_COMMIT_SHA = "d" * 40
INVALIDATION_COMMIT_SHA = "f" * 40


def _record_hash(record):
    unsigned = {key: value for key, value in record.items() if key != "record_sha256"}
    return sha256_text(canonical_json(unsigned))


def _projection_record(projection, *, sequence=1, previous=ZERO_SHA256):
    parsed = preflight.parse_projection_comment(projection)
    assert parsed is not None
    record = {
        "sequence": sequence,
        "kind": "projection",
        "record_id": parsed.projection_id,
        "comment_id": parsed.comment_id,
        "body_sha256": parsed.body_sha256,
        "manifest_sha256": parsed.manifest_sha256,
        "previous_record_sha256": previous,
    }
    record["record_sha256"] = _record_hash(record)
    return record


def _invalidation_record(projection, invalidation, *, sequence, previous):
    parsed = preflight.parse_invalidation_comment(invalidation)
    assert parsed is not None
    subject = parsed.payload["projection"]
    record = {
        "sequence": sequence,
        "kind": "invalidation",
        "record_id": parsed.invalidation_id,
        "comment_id": parsed.comment_id,
        "body_sha256": parsed.body_sha256,
        "manifest_sha256": parsed.manifest_sha256,
        "projection_comment_id": int(subject["comment_id"]),
        "projection_body_sha256": str(subject["body_sha256"]),
        "previous_record_sha256": previous,
    }
    record["record_sha256"] = _record_hash(record)
    return record


def _ledger(records):
    return {
        "contract": LEDGER_CONTRACT,
        "baseline_control_sha": LEDGER_BASE_SHA,
        "records": list(records),
    }


def _contents(value):
    raw = canonical_json(value) + "\n"
    return {
        "encoding": "base64",
        "content": base64.b64encode(raw.encode("utf-8")).decode("ascii"),
        "sha": "c" * 40,
    }


def _timeline_comment(comment):
    return {
        "__typename": "IssueComment",
        "databaseId": comment["id"],
        "body": comment["body"],
        "author": {"login": comment["user"]["login"]},
        "createdAt": comment["created_at"],
        "updatedAt": comment["updated_at"],
    }


class LedgerProductionAPI(GitHubAPI):
    """Production-provider double with stable carrier scans and explicit main history."""

    carrier_ledger_production_test_double = True

    def __init__(
        self,
        *,
        projection,
        ledger_by_ref,
        parents,
        workflow_runs,
        branch_head=TRUSTED_SHA,
    ):
        self.projection = projection
        self.ledger_by_ref = dict(ledger_by_ref)
        self.parents = dict(parents)
        self.branch_head = branch_head
        self.backing = FakeReadOnlyAPI(
            projection_comments=[projection],
            workflow_runs=workflow_runs,
        )
        self.graphql_queries = []
        self.gets = self.backing.gets
        self.posts = []

    def graphql_query(self, query, variables):
        self.graphql_queries.append((query, dict(variables)))
        if variables.get("after") is not None:
            raise AssertionError("ledger fixture uses one page per complete scan")
        if "ISSUE_COMMENT" not in query or "COMMENT_DELETED_EVENT" not in query:
            raise AssertionError("production carrier must use the combined timeline")
        node = _timeline_comment(self.projection)
        return {
            "data": {
                "repository": {
                    "issue": {
                        "locked": True,
                        "timelineItems": {
                            "totalCount": 1,
                            "filteredCount": 1,
                            "pageCount": 1,
                            "updatedAt": "2026-09-04T00:10:00Z",
                            "nodes": [node],
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
        self.gets.append(path)
        if path == f"/repos/{preflight.CONTROL_REPOSITORY}/branches/main":
            return {
                "protected": True,
                "commit": {"sha": self.branch_head},
            }
        commit_prefix = f"/repos/{preflight.CONTROL_REPOSITORY}/commits/"
        if path.startswith(commit_prefix) and "?" not in path:
            sha = path[len(commit_prefix) :]
            if sha in self.parents:
                return {
                    "sha": sha,
                    "parents": [{"sha": self.parents[sha]}],
                    "commit": {"tree": {"sha": "b" * 40}},
                }
        ledger_prefix = (
            f"/repos/{preflight.CONTROL_REPOSITORY}/contents/{LEDGER_PATH}?ref="
        )
        if path.startswith(ledger_prefix):
            ref = path[len(ledger_prefix) :]
            value = self.ledger_by_ref.get(ref)
            if value is None:
                raise GitHubAPIError(404, "not found")
            return _contents(value)
        return self.backing.get(path)

    def post(self, path, body):
        self.posts.append((path, body))
        raise AssertionError("preflight must never issue a write")


class PreflightCarrierLedgerTests(unittest.TestCase):
    def test_valid_projection_requires_exact_protected_main_ledger_binding(self):
        projection = projection_comment()
        projection_record = _projection_record(projection)
        api = LedgerProductionAPI(
            projection=projection,
            ledger_by_ref={
                LEDGER_BASE_SHA: None,
                GENESIS_SHA: _ledger([]),
                TRUSTED_SHA: _ledger([projection_record]),
            },
            parents={
                TRUSTED_SHA: GENESIS_SHA,
                GENESIS_SHA: LEDGER_BASE_SHA,
            },
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

    def test_same_surface_deleted_invalidation_cannot_outrun_durable_ledger(self):
        projection = projection_comment()
        tombstone = invalidation_comment(projection)
        projection_record = _projection_record(projection)
        invalidation_record = _invalidation_record(
            projection,
            tombstone,
            sequence=2,
            previous=projection_record["record_sha256"],
        )
        api = LedgerProductionAPI(
            projection=projection,
            ledger_by_ref={
                LEDGER_BASE_SHA: None,
                GENESIS_SHA: _ledger([]),
                PROJECTION_COMMIT_SHA: _ledger([projection_record]),
                TRUSTED_SHA: _ledger([projection_record, invalidation_record]),
            },
            parents={
                TRUSTED_SHA: PROJECTION_COMMIT_SHA,
                PROJECTION_COMMIT_SHA: GENESIS_SHA,
                GENESIS_SHA: LEDGER_BASE_SHA,
            },
            workflow_runs=[current_run(projection)],
        )

        # Both complete unified timeline scans contain only the projection and
        # no CommentDeletedEvent. The durable main ledger still remembers the
        # invalidation and must stop the candidate before projected PASS.
        with self.assertRaisesRegex(
            RuntimeError,
            "PUBLIC_CARRIER_LEDGER_INVALIDATED",
        ):
            runtime.run_preflight(
                valid_environment(projection),
                api_factory=lambda token, url: api,
                now=EVALUATED_AT,
            )

        self.assertEqual(len(api.graphql_queries), 2)
        self.assertFalse(api.posts)

    def test_removing_a_previously_admitted_ledger_record_is_permanently_detected(self):
        projection = projection_comment()
        tombstone = invalidation_comment(projection)
        projection_record = _projection_record(projection)
        invalidation_record = _invalidation_record(
            projection,
            tombstone,
            sequence=2,
            previous=projection_record["record_sha256"],
        )
        api = LedgerProductionAPI(
            projection=projection,
            ledger_by_ref={
                LEDGER_BASE_SHA: None,
                GENESIS_SHA: _ledger([]),
                PROJECTION_COMMIT_SHA: _ledger([projection_record]),
                INVALIDATION_COMMIT_SHA: _ledger(
                    [projection_record, invalidation_record]
                ),
                TRUSTED_SHA: _ledger([projection_record]),
            },
            parents={
                TRUSTED_SHA: INVALIDATION_COMMIT_SHA,
                INVALIDATION_COMMIT_SHA: PROJECTION_COMMIT_SHA,
                PROJECTION_COMMIT_SHA: GENESIS_SHA,
                GENESIS_SHA: LEDGER_BASE_SHA,
            },
            workflow_runs=[current_run(projection)],
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "PUBLIC_CARRIER_LEDGER_REWRITTEN",
        ):
            runtime.run_preflight(
                valid_environment(projection),
                api_factory=lambda token, url: api,
                now=EVALUATED_AT,
            )

        self.assertEqual(len(api.graphql_queries), 2)
        self.assertFalse(api.posts)

    def test_preflight_fails_if_dispatch_sha_is_no_longer_current_protected_main(self):
        projection = projection_comment()
        projection_record = _projection_record(projection)
        api = LedgerProductionAPI(
            projection=projection,
            ledger_by_ref={
                LEDGER_BASE_SHA: None,
                GENESIS_SHA: _ledger([]),
                TRUSTED_SHA: _ledger([projection_record]),
            },
            parents={
                TRUSTED_SHA: GENESIS_SHA,
                GENESIS_SHA: LEDGER_BASE_SHA,
            },
            workflow_runs=[current_run(projection)],
            branch_head="9" * 40,
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "PUBLIC_CARRIER_LEDGER_MAIN_MOVED",
        ):
            runtime.run_preflight(
                valid_environment(projection),
                api_factory=lambda token, url: api,
                now=EVALUATED_AT,
            )

        self.assertEqual(len(api.graphql_queries), 2)
        self.assertFalse(api.posts)


if __name__ == "__main__":
    unittest.main()
