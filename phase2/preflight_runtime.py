from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence

from . import preflight_projection as projection
from .github_api import GitHubAPI, GitHubAPIError
from .operator_guard import GuardResult, evaluate_guards
from .operator_manifest import (
    SHA40,
    SHA256,
    WorkflowHistoryRecord,
    canonical_json,
    sha256_text,
    workflow_history_baseline,
)


WORKFLOW_HISTORY_OPERATION = "phase2-adversarial/workflow-dispatch/v1"
WORKSTREAM_D_EXECUTION_VARIABLE = "PHASE2_WORKSTREAM_D_EXECUTION_ENABLED"
PUBLIC_CARRIER_DELETION_QUERY = """query PublicCarrierDeletionEvents($owner:String!,$name:String!,$number:Int!,$after:String){repository(owner:$owner,name:$name){issue(number:$number){locked timelineItems(first:100,after:$after,itemTypes:[COMMENT_DELETED_EVENT]){nodes{__typename ... on CommentDeletedEvent{id createdAt}} pageInfo{hasNextPage endCursor}}}}}"""
PUBLIC_CARRIER_TIMELINE_QUERY = """query PublicCarrierTimeline($owner:String!,$name:String!,$number:Int!,$after:String){repository(owner:$owner,name:$name){issue(number:$number){locked timelineItems(first:100,after:$after,itemTypes:[ISSUE_COMMENT,COMMENT_DELETED_EVENT]){totalCount filteredCount pageCount updatedAt nodes{__typename ... on IssueComment{databaseId body author{login} createdAt updatedAt} ... on CommentDeletedEvent{id createdAt}} pageInfo{hasNextPage endCursor}}}}}"""


class PreflightRuntimeError(RuntimeError):
    pass


def expected_run_name(
    projection_comment_id: int,
    projection_body_sha256: str,
    manifest_sha256: str,
) -> str:
    return (
        "operator_preflight "
        f"projection={projection_comment_id} "
        f"body={projection_body_sha256} "
        f"manifest={manifest_sha256}"
    )


def _require_sha(value: object, pattern, reason: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise PreflightRuntimeError(reason)
    return value


def _require_positive_int(value: object, reason: str) -> int:
    if type(value) is not int or value <= 0:
        raise PreflightRuntimeError(reason)
    return value


def _public_carrier_inventory_digest(comments: Sequence[Mapping[str, Any]]) -> str:
    records: list[tuple[int, str]] = []
    seen_comment_ids: set[int] = set()
    for comment in comments:
        if not isinstance(comment, Mapping):
            raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
        comment_id = _require_positive_int(
            comment.get("id"),
            "READ_EVIDENCE_AMBIGUOUS",
        )
        if comment_id in seen_comment_ids:
            raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
        seen_comment_ids.add(comment_id)

        body = comment.get("body")
        user = comment.get("user")
        owner = user.get("login") if isinstance(user, Mapping) else None
        created_at = comment.get("created_at")
        updated_at = comment.get("updated_at")
        if (
            not isinstance(body, str)
            or not isinstance(owner, str)
            or not owner
            or not isinstance(created_at, str)
            or not created_at
            or not isinstance(updated_at, str)
            or not updated_at
        ):
            raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
        records.append(
            (
                comment_id,
                canonical_json(
                    {
                        "body_sha256": sha256_text(body),
                        "comment_id": comment_id,
                        "created_at": created_at,
                        "owner": owner,
                        "updated_at": updated_at,
                    }
                ),
            )
        )
    records.sort(key=lambda item: item[0])
    return sha256_text("".join(f"{record}\n" for _, record in records))


def _public_carrier_timeline_digest(
    comments: Sequence[Mapping[str, Any]],
    *,
    total_count: int,
    updated_at: str,
) -> str:
    return sha256_text(
        canonical_json(
            {
                "comment_inventory_sha256": _public_carrier_inventory_digest(comments),
                "timeline_total_count": total_count,
                "timeline_updated_at": updated_at,
            }
        )
    )


def _timeline_issue_comment(node: Mapping[str, Any]) -> dict[str, Any]:
    comment_id = _require_positive_int(node.get("databaseId"), "READ_EVIDENCE_AMBIGUOUS")
    body = node.get("body")
    author = node.get("author")
    owner = author.get("login") if isinstance(author, Mapping) else None
    created_at = node.get("createdAt")
    updated_at = node.get("updatedAt")
    if (
        not isinstance(body, str)
        or not isinstance(owner, str)
        or not owner
        or not isinstance(created_at, str)
        or not created_at
        or not isinstance(updated_at, str)
        or not updated_at
    ):
        raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
    return {
        "id": comment_id,
        "body": body,
        "user": {"login": owner},
        "created_at": created_at,
        "updated_at": updated_at,
    }


def _read_public_carrier_timeline_scan(
    api: GitHubAPI,
) -> tuple[list[dict[str, Any]], str]:
    owner, name = projection.CONTROL_REPOSITORY.split("/", 1)
    after: str | None = None
    seen_cursors: set[str] = set()
    comments: list[dict[str, Any]] = []
    expected_total_count: int | None = None
    expected_updated_at: str | None = None

    for _ in range(100):
        payload = api.graphql_query(
            PUBLIC_CARRIER_TIMELINE_QUERY,
            {
                "owner": owner,
                "name": name,
                "number": projection.PROJECTION_ISSUE_NUMBER,
                "after": after,
            },
        )
        if not isinstance(payload, Mapping):
            raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
        errors = payload.get("errors")
        if errors not in (None, []):
            raise PreflightRuntimeError("READ_EVIDENCE_UNAVAILABLE")
        data = payload.get("data")
        repository = data.get("repository") if isinstance(data, Mapping) else None
        issue = repository.get("issue") if isinstance(repository, Mapping) else None
        if not isinstance(issue, Mapping):
            raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
        locked = issue.get("locked")
        if locked is False:
            raise PreflightRuntimeError("PUBLIC_CARRIER_NOT_LOCKED")
        if locked is not True:
            raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")

        timeline = issue.get("timelineItems")
        if not isinstance(timeline, Mapping):
            raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
        nodes = timeline.get("nodes")
        page_info = timeline.get("pageInfo")
        total_count = timeline.get("totalCount")
        filtered_count = timeline.get("filteredCount")
        page_count = timeline.get("pageCount")
        updated_at = timeline.get("updatedAt")
        if (
            not isinstance(nodes, list)
            or any(not isinstance(node, Mapping) for node in nodes)
            or not isinstance(page_info, Mapping)
            or type(total_count) is not int
            or total_count < 0
            or type(filtered_count) is not int
            or filtered_count < 0
            or type(page_count) is not int
            or page_count < 0
            or page_count != len(nodes)
            or filtered_count < page_count
            or total_count < filtered_count
            or not isinstance(updated_at, str)
            or not updated_at
        ):
            raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")

        if expected_total_count is None:
            expected_total_count = total_count
            expected_updated_at = updated_at
        elif total_count != expected_total_count or updated_at != expected_updated_at:
            raise PreflightRuntimeError("PUBLIC_CARRIER_CHANGED")

        for node in nodes:
            typename = node.get("__typename")
            if typename == "CommentDeletedEvent":
                if (
                    not isinstance(node.get("id"), str)
                    or not node.get("id")
                    or not isinstance(node.get("createdAt"), str)
                    or not node.get("createdAt")
                ):
                    raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
                raise PreflightRuntimeError("PUBLIC_CARRIER_DELETION_DETECTED")
            if typename != "IssueComment":
                raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
            comments.append(_timeline_issue_comment(node))

        if expected_total_count is not None and len(comments) > expected_total_count:
            raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")

        has_next_page = page_info.get("hasNextPage")
        end_cursor = page_info.get("endCursor")
        if type(has_next_page) is not bool:
            raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
        if not has_next_page:
            if end_cursor is not None and not isinstance(end_cursor, str):
                raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
            if expected_total_count is None or expected_updated_at is None:
                raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
            if len(comments) != expected_total_count:
                raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
            digest = _public_carrier_timeline_digest(
                comments,
                total_count=expected_total_count,
                updated_at=expected_updated_at,
            )
            return comments, digest
        if (
            not isinstance(end_cursor, str)
            or not end_cursor
            or end_cursor in seen_cursors
        ):
            raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
        seen_cursors.add(end_cursor)
        after = end_cursor

    raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")


def validate_public_carrier_history(api: GitHubAPI) -> None:
    owner, name = projection.CONTROL_REPOSITORY.split("/", 1)
    after: str | None = None
    seen_cursors: set[str] = set()
    for _ in range(100):
        payload = api.graphql_query(
            PUBLIC_CARRIER_DELETION_QUERY,
            {
                "owner": owner,
                "name": name,
                "number": projection.PROJECTION_ISSUE_NUMBER,
                "after": after,
            },
        )
        if not isinstance(payload, Mapping):
            raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
        errors = payload.get("errors")
        if errors not in (None, []):
            raise PreflightRuntimeError("READ_EVIDENCE_UNAVAILABLE")
        data = payload.get("data")
        repository = data.get("repository") if isinstance(data, Mapping) else None
        issue = repository.get("issue") if isinstance(repository, Mapping) else None
        if not isinstance(issue, Mapping):
            raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
        locked = issue.get("locked")
        if locked is False:
            raise PreflightRuntimeError("PUBLIC_CARRIER_NOT_LOCKED")
        if locked is not True and isinstance(api, GitHubAPI):
            raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
        timeline = issue.get("timelineItems")
        if not isinstance(timeline, Mapping):
            raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
        nodes = timeline.get("nodes")
        page_info = timeline.get("pageInfo")
        if (
            not isinstance(nodes, list)
            or any(not isinstance(node, Mapping) for node in nodes)
            or not isinstance(page_info, Mapping)
        ):
            raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
        for node in nodes:
            if (
                node.get("__typename") != "CommentDeletedEvent"
                or not isinstance(node.get("id"), str)
                or not node.get("id")
                or not isinstance(node.get("createdAt"), str)
                or not node.get("createdAt")
            ):
                raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
            raise PreflightRuntimeError("PUBLIC_CARRIER_DELETION_DETECTED")
        has_next_page = page_info.get("hasNextPage")
        end_cursor = page_info.get("endCursor")
        if type(has_next_page) is not bool:
            raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
        if not has_next_page:
            if end_cursor is not None and not isinstance(end_cursor, str):
                raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
            return
        if (
            not isinstance(end_cursor, str)
            or not end_cursor
            or end_cursor in seen_cursors
        ):
            raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")
        seen_cursors.add(end_cursor)
        after = end_cursor
    raise PreflightRuntimeError("READ_EVIDENCE_AMBIGUOUS")


def _read_public_carrier_comments(
    api: GitHubAPI,
) -> tuple[list[dict[str, Any]], str]:
    if isinstance(api, GitHubAPI):
        first, first_digest = _read_public_carrier_timeline_scan(api)
        second, second_digest = _read_public_carrier_timeline_scan(api)
        if first_digest != second_digest:
            raise PreflightRuntimeError("PUBLIC_CARRIER_CHANGED")
        return second, second_digest

    # Existing dependency-injected pure unit fakes predate the production
    # single-timeline contract. Preserve that fixture adapter without exposing
    # its split REST/GraphQL observation path to the CLI production provider.
    validate_public_carrier_history(api)
    first = projection._list_issue_comments(api, projection.PROJECTION_ISSUE_NUMBER)
    first_digest = _public_carrier_inventory_digest(first)
    second = projection._list_issue_comments(api, projection.PROJECTION_ISSUE_NUMBER)
    second_digest = _public_carrier_inventory_digest(second)
    validate_public_carrier_history(api)
    if first_digest != second_digest:
        raise PreflightRuntimeError("PUBLIC_CARRIER_CHANGED")
    return second, second_digest


def _workflow_attempt(
    api: GitHubAPI,
    run: Mapping[str, Any],
    attempt: int,
) -> Mapping[str, Any]:
    current_attempt = _require_positive_int(run.get("run_attempt"), "WORKFLOW_HISTORY_CHANGED")
    if attempt == current_attempt:
        return run
    payload = api.get(
        f"/repos/{projection.CONTROL_REPOSITORY}/actions/runs/{run['id']}/attempts/{attempt}"
    )
    if not isinstance(payload, Mapping):
        raise PreflightRuntimeError("WORKFLOW_HISTORY_CHANGED")
    return payload


def _complete_workflow_records(
    api: GitHubAPI,
    runs: Sequence[Mapping[str, Any]],
) -> tuple[WorkflowHistoryRecord, ...]:
    records: list[WorkflowHistoryRecord] = []
    seen: set[tuple[int, int]] = set()
    for run in runs:
        run_id = _require_positive_int(run.get("id"), "WORKFLOW_HISTORY_CHANGED")
        current_attempt = _require_positive_int(run.get("run_attempt"), "WORKFLOW_HISTORY_CHANGED")
        for attempt in range(1, current_attempt + 1):
            source = _workflow_attempt(api, run, attempt)
            if source.get("id") != run_id or source.get("run_attempt") != attempt:
                raise PreflightRuntimeError("WORKFLOW_HISTORY_CHANGED")
            if source.get("event") != "workflow_dispatch":
                raise PreflightRuntimeError("WORKFLOW_HISTORY_CHANGED")
            trusted_sha = _require_sha(
                source.get("head_sha"),
                SHA40,
                "WORKFLOW_HISTORY_CHANGED",
            )
            key = (run_id, attempt)
            if key in seen:
                raise PreflightRuntimeError("WORKFLOW_HISTORY_CHANGED")
            seen.add(key)
            records.append(
                WorkflowHistoryRecord(
                    run_id,
                    attempt,
                    trusted_sha,
                    WORKFLOW_HISTORY_OPERATION,
                )
            )
    return tuple(records)


def _validate_workflow_run_number_continuity(
    runs: Sequence[Mapping[str, Any]],
    *,
    baseline_through_id: int,
    current_run_id: int,
) -> None:
    run_numbers_by_id: dict[int, int] = {}
    seen_run_numbers: set[int] = set()
    for run in runs:
        run_id = _require_positive_int(run.get("id"), "WORKFLOW_HISTORY_CHANGED")
        run_number = _require_positive_int(run.get("run_number"), "WORKFLOW_HISTORY_CHANGED")
        if run_id in run_numbers_by_id or run_number in seen_run_numbers:
            raise PreflightRuntimeError("WORKFLOW_HISTORY_CHANGED")
        run_numbers_by_id[run_id] = run_number
        seen_run_numbers.add(run_number)

    current_run_number = run_numbers_by_id.get(current_run_id)
    if current_run_number is None:
        raise PreflightRuntimeError("WORKFLOW_HISTORY_CHANGED")

    if baseline_through_id == 0:
        baseline_run_number = 0
    else:
        baseline_run_number = run_numbers_by_id.get(baseline_through_id)
        if baseline_run_number is None:
            raise PreflightRuntimeError("WORKFLOW_HISTORY_CHANGED")

    if current_run_number <= baseline_run_number:
        raise PreflightRuntimeError("WORKFLOW_HISTORY_CHANGED")

    observed = {
        run_number
        for run_number in seen_run_numbers
        if baseline_run_number < run_number <= current_run_number
    }
    expected = set(range(baseline_run_number + 1, current_run_number + 1))
    if observed != expected:
        raise PreflightRuntimeError("WORKFLOW_HISTORY_CHANGED")


def validate_workflow_history(
    api: GitHubAPI,
    manifest,
    *,
    run_id: int,
    run_attempt: int,
    trusted_sha: str,
    projection_comment_id: int,
    projection_body_sha256: str,
    manifest_sha256: str,
) -> None:
    if run_attempt != 1:
        raise PreflightRuntimeError("OPERATOR_RERUN_FORBIDDEN")
    expected_title = expected_run_name(
        projection_comment_id,
        projection_body_sha256,
        manifest_sha256,
    )
    runs = projection._list_workflow_runs(api)
    records = _complete_workflow_records(api, runs)
    baseline = manifest.workflow_history
    prefix = tuple(record for record in records if record.run_id <= baseline.through_id)
    if workflow_history_baseline(prefix) != baseline:
        raise PreflightRuntimeError("WORKFLOW_HISTORY_CHANGED")
    _validate_workflow_run_number_continuity(
        runs,
        baseline_through_id=baseline.through_id,
        current_run_id=run_id,
    )

    suffix = [
        run
        for run in runs
        if type(run.get("id")) is int and int(run["id"]) > baseline.through_id
    ]
    if not suffix:
        raise PreflightRuntimeError("WORKFLOW_HISTORY_CHANGED")
    current_seen = False
    suffix_ids: set[int] = set()
    for run in suffix:
        suffix_run_id = _require_positive_int(run.get("id"), "WORKFLOW_HISTORY_CHANGED")
        if suffix_run_id in suffix_ids:
            raise PreflightRuntimeError("WORKFLOW_HISTORY_CHANGED")
        suffix_ids.add(suffix_run_id)
        if (
            run.get("run_attempt") != 1
            or run.get("event") != "workflow_dispatch"
            or run.get("head_sha") != trusted_sha
            or run.get("display_title") != expected_title
        ):
            raise PreflightRuntimeError("WORKFLOW_HISTORY_CHANGED")
        if suffix_run_id == run_id:
            current_seen = True
    if not current_seen:
        raise PreflightRuntimeError("WORKFLOW_HISTORY_CHANGED")


def _context(values: Mapping[str, str]) -> tuple[str, int, int, str, int, str, str]:
    try:
        repository = values["GITHUB_REPOSITORY"]
        ref = values["GITHUB_REF"]
        trusted_sha = values["GITHUB_SHA"]
        run_id = int(values["GITHUB_RUN_ID"])
        run_attempt = int(values["GITHUB_RUN_ATTEMPT"])
        token = values["GITHUB_TOKEN"]
        projection_comment_id = int(values["PREFLIGHT_PROJECTION_COMMENT_ID"])
        projection_body_sha256 = values["PREFLIGHT_PROJECTION_BODY_SHA256"]
        manifest_sha256 = values["PREFLIGHT_MANIFEST_SHA256"]
    except (KeyError, TypeError, ValueError) as exc:
        raise PreflightRuntimeError("PREFLIGHT_CONTEXT_INCOMPLETE") from exc
    if repository != projection.CONTROL_REPOSITORY:
        raise PreflightRuntimeError("OPERATOR_REPOSITORY_MISMATCH")
    if ref != "refs/heads/main":
        raise PreflightRuntimeError("OPERATOR_PROTECTED_MAIN_REQUIRED")
    _require_sha(trusted_sha, SHA40, "OPERATOR_TRUSTED_SHA_INVALID")
    _require_positive_int(run_id, "OPERATOR_RUN_INVALID")
    _require_positive_int(run_attempt, "OPERATOR_RUN_INVALID")
    if not token:
        raise PreflightRuntimeError("READ_EVIDENCE_UNAVAILABLE")
    _require_positive_int(projection_comment_id, "PREFLIGHT_PROJECTION_COMMENT_ID_INVALID")
    _require_sha(
        projection_body_sha256,
        SHA256,
        "PREFLIGHT_PROJECTION_EXPECTED_DIGEST_INVALID",
    )
    _require_sha(manifest_sha256, SHA256, "PREFLIGHT_MANIFEST_DIGEST_INVALID")
    return (
        trusted_sha,
        run_id,
        run_attempt,
        token,
        projection_comment_id,
        projection_body_sha256,
        manifest_sha256,
    )


def _require_execution_variable_identity(preflight_projection) -> None:
    manifest_variable = preflight_projection.manifest.payload["environment"][
        "execution_variable"
    ]
    bound_variable = preflight_projection.bound_observation["execution_variable"]
    if (
        manifest_variable != WORKSTREAM_D_EXECUTION_VARIABLE
        or bound_variable != WORKSTREAM_D_EXECUTION_VARIABLE
    ):
        raise PreflightRuntimeError("PREFLIGHT_EXECUTION_VARIABLE_IDENTITY_MISMATCH")


def _projection_evidence(
    preflight_projection,
    result: GuardResult,
    *,
    run_id: int,
    run_attempt: int,
    trusted_sha: str,
    public_carrier_snapshot_sha256: str,
) -> dict[str, object]:
    projection_valid = result.passed is True
    return {
        "status": (
            "GITSTATE_PREFLIGHT_PROJECTION_VALID"
            if projection_valid
            else "GITSTATE_PREFLIGHT_BLOCKED"
        ),
        "run_id": run_id,
        "run_attempt": run_attempt,
        "trusted_sha": trusted_sha,
        "projection_comment_id": preflight_projection.comment_id,
        "projection_body_sha256": preflight_projection.body_sha256,
        "manifest_sha256": preflight_projection.manifest_sha256,
        "public_carrier_snapshot_sha256": public_carrier_snapshot_sha256,
        "projection_valid": projection_valid,
        "private_freshness_proven": False,
        "projected_snapshot_guard_code": result.code,
        "projected_snapshot_guard_category": result.category,
        "execution_authorised": False,
        "credential_material_emitted": False,
        "control_state_tokens_minted": 0,
        "canonical_state_mutated": False,
        "workstream_d_scenarios_executed": 0,
        "workstream_e_authorised": False,
    }


def run_preflight(
    values: Mapping[str, str] | None = None,
    *,
    api_factory: Callable[[str, str], GitHubAPI] = GitHubAPI,
    now: datetime | None = None,
) -> dict[str, object]:
    env = os.environ if values is None else values
    (
        trusted_sha,
        run_id,
        run_attempt,
        token,
        projection_comment_id,
        projection_body_sha256,
        expected_manifest_sha256,
    ) = _context(env)

    api = api_factory(token, env.get("GITHUB_API_URL", "https://api.github.com"))
    comments, public_carrier_snapshot_sha256 = _read_public_carrier_comments(api)
    preflight_projection, invalidations = projection.parse_projection_history(
        comments,
        expected_projection_comment_id=projection_comment_id,
        expected_projection_body_sha256=projection_body_sha256,
    )
    if preflight_projection.manifest_sha256 != expected_manifest_sha256:
        raise PreflightRuntimeError("PREFLIGHT_MANIFEST_IDENTITY_MISMATCH")
    _require_execution_variable_identity(preflight_projection)

    if projection._matching_invalidation(preflight_projection, invalidations) is not None:
        result = GuardResult.failure("GOVERNANCE_SUPERSEDED")
        record = _projection_evidence(
            preflight_projection,
            result,
            run_id=run_id,
            run_attempt=run_attempt,
            trusted_sha=trusted_sha,
            public_carrier_snapshot_sha256=public_carrier_snapshot_sha256,
        )
        print(json.dumps(record, sort_keys=True, separators=(",", ":")))
        return record

    validate_workflow_history(
        api,
        preflight_projection.manifest,
        run_id=run_id,
        run_attempt=run_attempt,
        trusted_sha=trusted_sha,
        projection_comment_id=projection_comment_id,
        projection_body_sha256=projection_body_sha256,
        manifest_sha256=expected_manifest_sha256,
    )

    execution_variable_absent = env.get(WORKSTREAM_D_EXECUTION_VARIABLE, "") == ""
    evaluated_at = now or datetime.now(timezone.utc)
    if evaluated_at.tzinfo is None:
        raise PreflightRuntimeError("PREFLIGHT_TIME_INVALID")
    evaluated_at = evaluated_at.astimezone(timezone.utc)
    observation = projection._guard_observation(
        preflight_projection,
        api,
        trusted_sha=trusted_sha,
        evaluated_at=evaluated_at,
        execution_variable_absent=execution_variable_absent,
    )
    result = evaluate_guards(preflight_projection.manifest, observation)
    record = _projection_evidence(
        preflight_projection,
        result,
        run_id=run_id,
        run_attempt=run_attempt,
        trusted_sha=trusted_sha,
        public_carrier_snapshot_sha256=public_carrier_snapshot_sha256,
    )
    print(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return record


def _blocked_payload(exc: Exception) -> dict[str, object]:
    if isinstance(exc, GitHubAPIError):
        reason = "READ_EVIDENCE_RATE_LIMITED" if exc.rate_limited else "READ_EVIDENCE_UNAVAILABLE"
        payload: dict[str, object] = {
            "status": "GITSTATE_PREFLIGHT_BLOCKED",
            "reason_code": reason,
            "projection_valid": False,
            "private_freshness_proven": False,
            "execution_authorised": False,
            "credential_material_emitted": False,
            "control_state_tokens_minted": 0,
            "canonical_state_mutated": False,
            "workstream_d_scenarios_executed": 0,
            "workstream_e_authorised": False,
        }
        payload.update(exc.safe_diagnostic())
        return payload
    return {
        "status": "GITSTATE_PREFLIGHT_BLOCKED",
        "reason_code": str(exc).split(":", 1)[0] or type(exc).__name__,
        "projection_valid": False,
        "private_freshness_proven": False,
        "execution_authorised": False,
        "credential_material_emitted": False,
        "control_state_tokens_minted": 0,
        "canonical_state_mutated": False,
        "workstream_d_scenarios_executed": 0,
        "workstream_e_authorised": False,
    }


def main() -> int:
    try:
        if len(sys.argv) != 2 or sys.argv[1] != "preflight":
            raise PreflightRuntimeError("PREFLIGHT_COMMAND_REQUIRED")
        record = run_preflight()
        return 0 if record.get("projection_valid") is True else 1
    except Exception as exc:
        print(json.dumps(_blocked_payload(exc), sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())