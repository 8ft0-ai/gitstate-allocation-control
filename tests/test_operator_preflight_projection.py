from __future__ import annotations

import inspect
import unittest
from collections.abc import Mapping
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

import phase2.preflight_projection as preflight
import phase2.preflight_runtime as runtime
from phase2.governance_state import parse_guarded_execution_manifest
from phase2.operator_capsule import OperatorCapsuleError, parse_capsule_comment
from phase2.operator_manifest import (
    WorkflowHistoryRecord,
    canonical_json,
    sha256_text,
    workflow_history_baseline,
)
from test_operator_guard import make_state, parsed_records


RUN_ID = 501
TRUSTED_SHA = "a" * 40
EVALUATED_AT = datetime(2026, 9, 4, 1, 0, tzinfo=timezone.utc)


def thaw(value):
    if isinstance(value, Mapping):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw(item) for item in value]
    return value


def source_payload(record):
    source = record.source
    assert source is not None
    return {
        "comment_id": source.comment_id,
        "body": source.body,
        "owner": source.owner,
        "created_at": source.created_at,
        "updated_at": source.updated_at,
    }


def bound_observation(observation):
    owner = observation.owner_observation
    owner_payload = (
        {"required": False}
        if owner is None
        else {
            "required": True,
            "observation_id": owner.observation_id,
            "observation_sha256": owner.observation_sha256,
            "valid": owner.valid,
        }
    )
    return {
        "protocol_sha": observation.protocol_sha,
        "state_commit_sha": observation.state_commit_sha,
        "state_digest_sha256": observation.state_digest_sha256,
        "app_id": observation.app_id,
        "installation_id": observation.installation_id,
        "repository_selection": observation.repository_selection,
        "selected_repository_ids": list(observation.selected_repository_ids),
        "permission_profile_sha256": observation.permission_profile_sha256,
        "owner_observation": owner_payload,
        "environment_name": observation.environment_name,
        "environment_policy_sha256": observation.environment_policy_sha256,
        "execution_variable": observation.execution_variable,
    }


def projection_payload(*, projection_id="9" * 32, workflow_history=None):
    _, _, _, manifest, comments, observation = make_state()
    if workflow_history is not None:
        value = thaw(manifest.payload)
        value["workflow_history"] = {
            "through_id": workflow_history.through_id,
            "history_sha256": workflow_history.history_sha256,
        }
        manifest = parse_guarded_execution_manifest(canonical_json(value))
    records = parsed_records(comments)
    return manifest, {
        "contract": preflight.PROJECTION_CONTRACT,
        "projection_id": projection_id,
        "manifest_comment_id": 7001,
        "manifest_sha256": manifest.sha256,
        "manifest": thaw(manifest.payload),
        "governance_sources": [source_payload(record) for record in records],
        "observation": bound_observation(observation),
        "execution_authorised": False,
        "workstream_e_authorised": False,
    }


def projection_comment(comment_id=1001, *, payload=None, login="8ft0-ai", edited=False):
    _, value = projection_payload() if payload is None else (None, payload)
    body = preflight.PROJECTION_PREFIX + canonical_json(value)
    return {
        "id": comment_id,
        "body": body,
        "user": {"login": login},
        "created_at": "2026-09-04T00:00:00Z",
        "updated_at": "2026-09-04T00:01:00Z" if edited else "2026-09-04T00:00:00Z",
    }


def invalidation_comment(projection, *, comment_id=1002, manifest_sha=None):
    parsed = preflight.parse_projection_comment(projection)
    assert parsed is not None
    value = {
        "contract": preflight.INVALIDATION_CONTRACT,
        "invalidation_id": "8" * 32,
        "manifest_sha256": manifest_sha or parsed.manifest_sha256,
        "projection": {
            "comment_id": parsed.comment_id,
            "body_sha256": parsed.body_sha256,
        },
        "authority": {"required": False},
        "manifest_approval": {"required": False},
        "reason": "public fail-closed tombstone",
        "execution_authorised": False,
        "workstream_e_authorised": False,
    }
    body = preflight.INVALIDATION_PREFIX + canonical_json(value)
    return {
        "id": comment_id,
        "body": body,
        "user": {"login": "8ft0-ai"},
        "created_at": "2026-09-04T00:02:00Z",
        "updated_at": "2026-09-04T00:02:00Z",
    }


def workflow_run(
    run_id,
    *,
    title,
    attempt=1,
    head_sha=TRUSTED_SHA,
    run_number=1,
):
    return {
        "id": run_id,
        "run_number": run_number,
        "run_attempt": attempt,
        "head_sha": head_sha,
        "event": "workflow_dispatch",
        "display_title": title,
    }


class FakeReadOnlyAPI:
    def __init__(
        self,
        *,
        projection_comments,
        workflow_runs=None,
        attempt_payloads=None,
        deletion_pages=None,
    ):
        self.projection_comments = list(projection_comments)
        self.workflow_runs = list(workflow_runs or [])
        self.attempt_payloads = dict(attempt_payloads or {})
        self.deletion_pages = list(deletion_pages or [[]])
        self.gets = []
        self.graphql_queries = []
        self.posts = []

    @staticmethod
    def _page(path):
        return int(path.rsplit("page=", 1)[1])

    def graphql_query(self, query, variables):
        self.graphql_queries.append((query, dict(variables)))
        after = variables.get("after")
        if after is None:
            page = 0
        elif isinstance(after, str) and after.startswith("cursor-"):
            page = int(after.split("-", 1)[1])
        else:
            raise AssertionError("unexpected GraphQL cursor")
        nodes = self.deletion_pages[page] if page < len(self.deletion_pages) else []
        has_next = page + 1 < len(self.deletion_pages)
        return {
            "data": {
                "repository": {
                    "issue": {
                        "timelineItems": {
                            "nodes": nodes,
                            "pageInfo": {
                                "hasNextPage": has_next,
                                "endCursor": f"cursor-{page + 1}" if has_next else None,
                            },
                        }
                    }
                }
            }
        }

    def get(self, path):
        self.gets.append(path)
        if f"/issues/{preflight.PROJECTION_ISSUE_NUMBER}/comments" in path:
            page = self._page(path)
            if page == 1 and len(self.projection_comments) > 100:
                return self.projection_comments[:100]
            if page == 2 and len(self.projection_comments) > 100:
                return self.projection_comments[100:]
            return self.projection_comments if page == 1 else []
        if f"/issues/{preflight.OPERATOR_HISTORY_ISSUE_NUMBER}/comments" in path:
            return []
        if path == f"/repos/{preflight.CONTROL_REPOSITORY}/commits/{TRUSTED_SHA}":
            return {"commit": {"tree": {"sha": "b" * 40}}}
        if path.startswith(
            f"/repos/{preflight.CONTROL_REPOSITORY}/contents/{preflight.WORKFLOW_PATH}?ref="
        ):
            return {"sha": "c" * 40}
        if path.startswith(
            f"/repos/{preflight.CONTROL_REPOSITORY}/contents/phase2/operator_runtime.py?ref="
        ):
            return {"sha": "d" * 40}
        if path.startswith(
            f"/repos/{preflight.CONTROL_REPOSITORY}/actions/workflows/{preflight.WORKFLOW_FILENAME}/runs"
        ):
            page = self._page(path)
            return {"workflow_runs": self.workflow_runs if page == 1 else []}
        if "/actions/runs/" in path and "/attempts/" in path:
            run_id = int(path.split("/actions/runs/", 1)[1].split("/", 1)[0])
            attempt = int(path.rsplit("/", 1)[1])
            return self.attempt_payloads[(run_id, attempt)]
        raise AssertionError(path)

    def post(self, path, body):
        self.posts.append((path, body))
        raise AssertionError("preflight must never issue a write")


def valid_environment(projection):
    parsed = preflight.parse_projection_comment(projection)
    assert parsed is not None
    return {
        "GITHUB_REPOSITORY": preflight.CONTROL_REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": TRUSTED_SHA,
        "GITHUB_RUN_ID": str(RUN_ID),
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_TOKEN": "read-only-fixture-token",
        "PREFLIGHT_PROJECTION_COMMENT_ID": str(projection["id"]),
        "PREFLIGHT_PROJECTION_BODY_SHA256": sha256_text(projection["body"]),
        "PREFLIGHT_MANIFEST_SHA256": parsed.manifest_sha256,
    }


def current_run(projection, *, run_id=RUN_ID, run_number=1):
    parsed = preflight.parse_projection_comment(projection)
    assert parsed is not None
    title = runtime.expected_run_name(
        parsed.comment_id,
        parsed.body_sha256,
        parsed.manifest_sha256,
    )
    return workflow_run(run_id, title=title, run_number=run_number)


class PreflightProjectionTests(unittest.TestCase):
    def test_projection_reproduces_exact_guarded_manifest_and_is_non_authorising(self):
        manifest, payload = projection_payload()
        source = projection_comment(payload=payload)
        parsed = preflight.parse_projection_comment(
            source,
            expected_body_sha256=sha256_text(source["body"]),
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.manifest.sha256, manifest.sha256)
        self.assertEqual(parsed.manifest_sha256, manifest.sha256)
        self.assertFalse(parsed.payload["execution_authorised"])
        self.assertFalse(parsed.payload["workstream_e_authorised"])

    def test_projection_rejects_edit_wrong_owner_noncanonical_or_manifest_tamper(self):
        _, payload = projection_payload()
        cases = [
            (projection_comment(payload=payload, edited=True), "PREFLIGHT_PROJECTION_SOURCE_EDITED"),
            (projection_comment(payload=payload, login="attacker"), "PREFLIGHT_PROJECTION_WRONG_OWNER"),
        ]
        for source, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(preflight.PreflightProjectionError, reason):
                    preflight.parse_projection_comment(source)

        noncanonical = projection_comment(payload=payload)
        noncanonical["body"] = noncanonical["body"].replace(",", ", ", 1)
        with self.assertRaisesRegex(preflight.PreflightProjectionError, "NONCANONICAL_JSON"):
            preflight.parse_projection_comment(noncanonical)

        tampered = thaw(payload)
        tampered["manifest"]["state_baseline"]["digest_sha256"] = "0" * 64
        with self.assertRaisesRegex(preflight.PreflightProjectionError, "MANIFEST_IDENTITY_MISMATCH"):
            preflight.parse_projection_comment(projection_comment(payload=tampered))

    def test_projection_cannot_be_parsed_or_consumed_as_v1_execution_capsule(self):
        source = projection_comment()
        with self.assertRaisesRegex(OperatorCapsuleError, "CAPSULE_TRANSPORT_INVALID"):
            parse_capsule_comment(
                source,
                now=EVALUATED_AT,
                expected_control_sha=TRUSTED_SHA,
                expected_profile="operator-preflight/v1",
            )

    def test_matching_public_invalidation_blocks_and_unrelated_subject_does_not(self):
        projection = projection_comment()
        matching = invalidation_comment(projection)
        parsed, invalidations = preflight.parse_projection_history(
            [projection, matching],
            expected_projection_comment_id=projection["id"],
            expected_projection_body_sha256=sha256_text(projection["body"]),
        )
        self.assertIsNotNone(preflight._matching_invalidation(parsed, invalidations))

        unrelated_projection = projection_comment(2001, payload=projection_payload(projection_id="7" * 32)[1])
        unrelated = invalidation_comment(unrelated_projection, comment_id=2002)
        parsed, invalidations = preflight.parse_projection_history(
            [projection, unrelated],
            expected_projection_comment_id=projection["id"],
            expected_projection_body_sha256=sha256_text(projection["body"]),
        )
        self.assertIsNone(preflight._matching_invalidation(parsed, invalidations))

    def test_preflight_passes_with_read_only_capability_and_complete_projection_pagination(self):
        projection = projection_comment(1001)
        ordinary = [
            {
                "id": index,
                "body": f"ordinary public rationale {index}",
                "user": {"login": "8ft0-ai"},
                "created_at": "2026-09-04T00:00:00Z",
                "updated_at": "2026-09-04T00:00:00Z",
            }
            for index in range(1, 101)
        ]
        api = FakeReadOnlyAPI(
            projection_comments=ordinary + [projection],
            workflow_runs=[current_run(projection)],
        )
        output = StringIO()
        with redirect_stdout(output):
            record = runtime.run_preflight(
                valid_environment(projection),
                api_factory=lambda token, url: api,
                now=EVALUATED_AT,
            )
        self.assertTrue(record["guard_passed"])
        self.assertEqual(record["guard_code"], "PASS")
        self.assertFalse(record["execution_authorised"])
        self.assertEqual(record["control_state_tokens_minted"], 0)
        self.assertFalse(record["canonical_state_mutated"])
        self.assertEqual(record["workstream_d_scenarios_executed"], 0)
        self.assertFalse(record["workstream_e_authorised"])
        self.assertFalse(api.posts)
        self.assertEqual(len(api.graphql_queries), 2)
        self.assertTrue(any("page=2" in path for path in api.gets))
        self.assertNotIn("read-only-fixture-token", output.getvalue())

    def test_deleted_carrier_comment_cannot_restore_preflight_after_tombstone_disappears(self):
        projection = projection_comment()
        deletion = {
            "__typename": "CommentDeletedEvent",
            "id": "CDE_kwDOexample",
            "createdAt": "2026-09-04T00:03:00Z",
        }
        api = FakeReadOnlyAPI(
            projection_comments=[projection],
            workflow_runs=[current_run(projection)],
            deletion_pages=[[deletion]],
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
        self.assertFalse(api.posts)

    def test_carrier_deletion_history_paginates_before_permanent_fail_closed(self):
        projection = projection_comment()
        deletion = {
            "__typename": "CommentDeletedEvent",
            "id": "CDE_kwDOlater",
            "createdAt": "2026-09-04T00:04:00Z",
        }
        api = FakeReadOnlyAPI(
            projection_comments=[projection],
            workflow_runs=[current_run(projection)],
            deletion_pages=[[], [deletion]],
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

    def test_legacy_projection_runtime_and_suffix_validator_are_retired(self):
        projection = projection_comment()
        parsed = preflight.parse_projection_comment(projection)
        assert parsed is not None
        with self.assertRaisesRegex(
            preflight.PreflightProjectionError,
            "PREFLIGHT_RUNTIME_REQUIRED",
        ):
            preflight.run_preflight({})
        with self.assertRaisesRegex(
            preflight.PreflightProjectionError,
            "PREFLIGHT_RUNTIME_REQUIRED",
        ):
            preflight.validate_preflight_workflow_suffix(
                object(),
                parsed.manifest.workflow_history,
                run_id=RUN_ID,
                run_attempt=1,
                trusted_sha=TRUSTED_SHA,
            )

    def test_complete_workflow_prefix_must_match_manifest_baseline(self):
        baseline = workflow_history_baseline(
            [
                WorkflowHistoryRecord(
                    100,
                    1,
                    TRUSTED_SHA,
                    runtime.WORKFLOW_HISTORY_OPERATION,
                )
            ]
        )
        _, payload = projection_payload(workflow_history=baseline)
        projection = projection_comment(payload=payload)
        api = FakeReadOnlyAPI(
            projection_comments=[projection],
            workflow_runs=[
                workflow_run(100, title="historical", run_number=1),
                current_run(projection, run_number=2),
            ],
        )
        record = runtime.run_preflight(
            valid_environment(projection),
            api_factory=lambda token, url: api,
            now=EVALUATED_AT,
        )
        self.assertTrue(record["guard_passed"])

        wrong = projection_payload(
            workflow_history=type(baseline)(baseline.through_id, "0" * 64)
        )[1]
        wrong_projection = projection_comment(2001, payload=wrong)
        wrong_api = FakeReadOnlyAPI(
            projection_comments=[wrong_projection],
            workflow_runs=[
                workflow_run(100, title="historical", run_number=1),
                current_run(wrong_projection, run_number=2),
            ],
        )
        with self.assertRaisesRegex(runtime.PreflightRuntimeError, "WORKFLOW_HISTORY_CHANGED"):
            runtime.run_preflight(
                valid_environment(wrong_projection),
                api_factory=lambda token, url: wrong_api,
                now=EVALUATED_AT,
            )

    def test_multiple_bound_attempt_one_preflights_are_allowed_but_unrelated_dispatch_is_not(self):
        projection = projection_comment()
        title = current_run(projection)["display_title"]
        api = FakeReadOnlyAPI(
            projection_comments=[projection],
            workflow_runs=[
                workflow_run(500, title=title, run_number=1),
                workflow_run(RUN_ID, title=title, run_number=2),
            ],
        )
        record = runtime.run_preflight(
            valid_environment(projection),
            api_factory=lambda token, url: api,
            now=EVALUATED_AT,
        )
        self.assertTrue(record["guard_passed"])

        unrelated_api = FakeReadOnlyAPI(
            projection_comments=[projection],
            workflow_runs=[
                workflow_run(500, title="contract_check", run_number=1),
                workflow_run(RUN_ID, title=title, run_number=2),
            ],
        )
        with self.assertRaisesRegex(runtime.PreflightRuntimeError, "WORKFLOW_HISTORY_CHANGED"):
            runtime.run_preflight(
                valid_environment(projection),
                api_factory=lambda token, url: unrelated_api,
                now=EVALUATED_AT,
            )

    def test_historical_rerun_attempts_are_reconstructed_before_prefix_digest(self):
        baseline = workflow_history_baseline(
            [
                WorkflowHistoryRecord(100, 1, TRUSTED_SHA, runtime.WORKFLOW_HISTORY_OPERATION),
                WorkflowHistoryRecord(100, 2, TRUSTED_SHA, runtime.WORKFLOW_HISTORY_OPERATION),
            ]
        )
        _, payload = projection_payload(workflow_history=baseline)
        projection = projection_comment(payload=payload)
        current_attempt = workflow_run(100, title="historical", attempt=2, run_number=1)
        first_attempt = workflow_run(100, title="historical", attempt=1, run_number=1)
        api = FakeReadOnlyAPI(
            projection_comments=[projection],
            workflow_runs=[current_attempt, current_run(projection, run_number=2)],
            attempt_payloads={(100, 1): first_attempt},
        )
        record = runtime.run_preflight(
            valid_environment(projection),
            api_factory=lambda token, url: api,
            now=EVALUATED_AT,
        )
        self.assertTrue(record["guard_passed"])
        self.assertTrue(any("/attempts/1" in path for path in api.gets))

    def test_matching_invalidation_blocks_before_guard_and_never_writes(self):
        projection = projection_comment()
        tombstone = invalidation_comment(projection)
        api = FakeReadOnlyAPI(projection_comments=[projection, tombstone])
        record = runtime.run_preflight(
            valid_environment(projection),
            api_factory=lambda token, url: api,
            now=EVALUATED_AT,
        )
        self.assertFalse(record["guard_passed"])
        self.assertEqual(record["guard_code"], "GOVERNANCE_SUPERSEDED")
        self.assertFalse(record["execution_authorised"])
        self.assertFalse(api.posts)

    def test_preflight_modules_have_no_token_mint_or_mutation_provider_dependency(self):
        source = inspect.getsource(preflight) + inspect.getsource(runtime)
        for forbidden in (
            "create_app_jwt",
            "mint_token",
            "operator_inventory",
            "workstream_d_live",
            "workstream_d_revocation",
            ".post(",
            "PHASE2_ALLOCATOR_APP_PRIVATE_KEY",
        ):
            self.assertNotIn(forbidden, source)

    def test_workflow_preflight_route_is_capability_denied_and_live_v1_path_is_preserved(self):
        workflow = Path(".github/workflows/phase2-adversarial.yml").read_text(encoding="utf-8")
        preflight_job = workflow.split("\n  operator-preflight:\n", 1)[1]
        self.assertIn("needs: [contract-check]", preflight_job)
        self.assertIn("actions: read", preflight_job)
        self.assertIn("issues: read", preflight_job)
        self.assertIn("phase2.preflight_runtime preflight", preflight_job)
        self.assertIn("PREFLIGHT_MANIFEST_SHA256", preflight_job)
        for forbidden in (
            "capsule-discovery",
            "capsule-consumption",
            "issues: write",
            "environment:",
            "PHASE2_ALLOCATOR_APP_PRIVATE_KEY",
            "PHASE2_ALLOCATOR_INSTALLATION_ID",
            "PHASE2_STATE_REPOSITORY_ID",
            "phase2.operator_capsule",
            "phase2.operator_runtime preflight",
        ):
            self.assertNotIn(forbidden, preflight_job)

        self.assertIn(
            "operator_preflight projection={0} body={1} manifest={2}",
            workflow,
        )
        capsule_prefix = workflow.split("\n  live-scenario-suite:\n", 1)[0]
        self.assertEqual(
            capsule_prefix.count("if: ${{ inputs.operation == 'live_scenario_suite' }}"),
            2,
        )
        self.assertIn("PYTHONPATH=. python3 -m phase2.operator_capsule discover", capsule_prefix)
        self.assertIn("PYTHONPATH=. python3 -m phase2.operator_capsule consume", capsule_prefix)
        self.assertEqual(workflow.count("${{ secrets.PHASE2_ALLOCATOR_APP_PRIVATE_KEY }}"), 1)


if __name__ == "__main__":
    unittest.main()
