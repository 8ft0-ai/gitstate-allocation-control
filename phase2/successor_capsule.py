from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Mapping

from .github_api import GitHubAPI, GitHubAPIError
from .operator_capsule import LIVE_PROFILE, OPERATOR_ISSUE_NUMBER
from .operator_manifest import (
    OPAQUE_ID,
    SHA256,
    V1_CAPSULE_CONTRACT,
    V1_CONSUMPTION_CONTRACT,
    canonical_json,
    sha256_text,
)
from .preflight_carrier_ledger import validate_carrier_ledger
from .preflight_control_anchor import validate_ledger_only_control_descendant
from . import preflight_projection as projection
from . import preflight_runtime as preflight_runtime
from .preflight_runtime_legacy import expected_run_name
from .successor_contract import (
    CONSUMPTION_CONTRACT,
    CONSUMPTION_PREFIX,
    SuccessorCapsule,
    SuccessorConsumption,
    SuccessorContractError,
    parse_capsule_comment,
    parse_consumption_comment,
    operator_history_baseline,
    parse_operator_history,
    validate_capsule_governance,
)


CONTROL_REPOSITORY = projection.CONTROL_REPOSITORY


class SuccessorCapsuleError(RuntimeError):
    pass


def _list_operator_comments(api: GitHubAPI) -> list[dict[str, Any]]:
    comments: list[dict[str, Any]] = []
    for page in range(1, 101):
        payload = api.get(
            f"/repos/{CONTROL_REPOSITORY}/issues/{OPERATOR_ISSUE_NUMBER}/comments"
            f"?per_page=100&page={page}"
        )
        if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
            raise SuccessorCapsuleError("READ_EVIDENCE_AMBIGUOUS")
        comments.extend(payload)
        if len(payload) < 100:
            return comments
    raise SuccessorCapsuleError("READ_EVIDENCE_AMBIGUOUS")


def _parse_time(value: object, reason: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise SuccessorCapsuleError(reason)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise SuccessorCapsuleError(reason) from exc
    if parsed.tzinfo is None:
        raise SuccessorCapsuleError(reason)
    return parsed.astimezone(timezone.utc)


def _validate_preflight_evidence(
    api: GitHubAPI,
    capsule: SuccessorCapsule,
    *,
    current_run_id: int,
) -> None:
    preflight = capsule.preflight_run
    run_id = int(preflight["run_id"])
    if run_id >= current_run_id:
        raise SuccessorCapsuleError("SUCCESSOR_PREFLIGHT_ORDER_INVALID")
    payload = api.get(f"/repos/{CONTROL_REPOSITORY}/actions/runs/{run_id}")
    if not isinstance(payload, Mapping):
        raise SuccessorCapsuleError("SUCCESSOR_PREFLIGHT_EVIDENCE_AMBIGUOUS")
    expected_title = expected_run_name(
        int(capsule.projection["comment_id"]),
        str(capsule.projection["body_sha256"]),
        capsule.manifest_sha256,
    )
    if (
        payload.get("id") != run_id
        or payload.get("run_attempt") != 1
        or payload.get("event") != "workflow_dispatch"
        or payload.get("head_sha") != capsule.expected_control_sha
        or payload.get("display_title") != expected_title
        or payload.get("status") != "completed"
        or payload.get("conclusion") != "success"
    ):
        raise SuccessorCapsuleError("SUCCESSOR_PREFLIGHT_EVIDENCE_INVALID")
    completed = _parse_time(
        payload.get("updated_at"), "SUCCESSOR_PREFLIGHT_EVIDENCE_INVALID"
    )
    if completed > capsule.created_at:
        raise SuccessorCapsuleError("SUCCESSOR_PREFLIGHT_ORDER_INVALID")


def validate_public_subject(
    api: GitHubAPI,
    capsule: SuccessorCapsule,
    *,
    trusted_sha: str,
    current_run_id: int,
):
    if capsule.expected_control_sha != trusted_sha:
        raise SuccessorCapsuleError("SUCCESSOR_CAPSULE_STALE_CONTROL_SHA")

    comments, _ = preflight_runtime._legacy._read_public_carrier_comments(api)
    preflight_projection, invalidations = projection.parse_projection_history(
        comments,
        expected_projection_comment_id=int(capsule.projection["comment_id"]),
        expected_projection_body_sha256=str(capsule.projection["body_sha256"]),
    )
    if preflight_projection.manifest_sha256 != capsule.manifest_sha256:
        raise SuccessorCapsuleError("SUCCESSOR_CAPSULE_MANIFEST_MISMATCH")
    if (
        capsule.authority["body_sha256"]
        != preflight_projection.manifest.payload["authority"]["body_sha256"]
    ):
        raise SuccessorCapsuleError("SUCCESSOR_CAPSULE_AUTHORITY_BINDING_MISMATCH")
    if projection._matching_invalidation(preflight_projection, invalidations) is not None:
        raise SuccessorCapsuleError("GOVERNANCE_SUPERSEDED")

    validate_carrier_ledger(
        api,
        trusted_sha=trusted_sha,
        projection_comment_id=preflight_projection.comment_id,
        projection_body_sha256=preflight_projection.body_sha256,
        manifest_sha256=preflight_projection.manifest_sha256,
    )
    projected_control_sha = str(
        preflight_projection.manifest.payload["executor"]["commit_sha"]
    )
    validate_ledger_only_control_descendant(
        api,
        projected_control_sha=projected_control_sha,
        trusted_sha=trusted_sha,
    )
    validate_capsule_governance(
        capsule,
        preflight_projection.manifest,
        preflight_projection.governance_history,
    )
    _validate_preflight_evidence(
        api,
        capsule,
        current_run_id=current_run_id,
    )
    return preflight_projection


def _open_operator_capsules(comments: list[Mapping[str, Any]]):
    try:
        records = parse_operator_history(comments, require_closed=False)
    except SuccessorContractError as exc:
        raise SuccessorCapsuleError(str(exc)) from exc
    consumption_kinds = {V1_CONSUMPTION_CONTRACT, CONSUMPTION_CONTRACT}
    capsule_kinds = {V1_CAPSULE_CONTRACT, "gitstate-operator/v2"}
    consumed = {
        record.capsule_id for record in records if record.record_kind in consumption_kinds
    }
    return tuple(
        record
        for record in records
        if record.record_kind in capsule_kinds and record.capsule_id not in consumed
    )


def _require_preconsumption_history(
    comments: list[Mapping[str, Any]],
    capsule: SuccessorCapsule,
    manifest,
) -> None:
    try:
        records = parse_operator_history(comments, require_closed=False)
    except SuccessorContractError as exc:
        raise SuccessorCapsuleError(str(exc)) from exc
    baseline = manifest.operator_history
    prefix = tuple(record for record in records if record.comment_id <= baseline.through_id)
    if operator_history_baseline(prefix) != baseline:
        raise SuccessorCapsuleError("OPERATOR_HISTORY_CHANGED")
    suffix = tuple(record for record in records if record.comment_id > baseline.through_id)
    if (
        len(suffix) != 1
        or suffix[0].record_kind != "gitstate-operator/v2"
        or suffix[0].comment_id != capsule.comment_id
        or suffix[0].capsule_id != capsule.capsule_id
        or suffix[0].body_sha256 != capsule.body_sha256
        or suffix[0].manifest_sha256 != capsule.manifest_sha256
    ):
        raise SuccessorCapsuleError("OPERATOR_HISTORY_PRECONSUMPTION_INVALID")


def _require_current_preconsumption_history(
    api: GitHubAPI, capsule: SuccessorCapsule, manifest
) -> None:
    _require_preconsumption_history(_list_operator_comments(api), capsule, manifest)


def discover_capsule(
    api: GitHubAPI,
    *,
    expected_control_sha: str,
    expected_operation: str,
    run_id: int,
    run_attempt: int,
    expected_capsule_id: str = "",
    expected_capsule_body_sha256: str = "",
    expected_manifest_sha256: str = "",
    now: datetime | None = None,
) -> SuccessorCapsule:
    if run_attempt != 1:
        raise SuccessorCapsuleError("OPERATOR_RERUN_FORBIDDEN")
    current = now or datetime.now(timezone.utc)
    comments = _list_operator_comments(api)

    # Historical operator records are immutable evidence. Validate the complete
    # mixed V1/V2 history against each record's own bound identities before
    # applying current-run eligibility to any unconsumed V2 capsule.
    open_capsules = _open_operator_capsules(comments)

    consumptions: list[SuccessorConsumption] = []
    candidates: list[SuccessorCapsule] = []
    comments_by_id: dict[int, Mapping[str, Any]] = {}
    for comment in comments:
        try:
            consumption = parse_consumption_comment(comment)
            if consumption is not None:
                consumptions.append(consumption)
                continue
            capsule = parse_capsule_comment(comment, now=None)
        except SuccessorContractError as exc:
            raise SuccessorCapsuleError(str(exc)) from exc
        if capsule is not None:
            candidates.append(capsule)
            comments_by_id[capsule.comment_id] = comment

    consumed_ids = {consumption.capsule_id for consumption in consumptions}
    live_eligible: list[SuccessorCapsule] = []
    for capsule in candidates:
        if capsule.capsule_id in consumed_ids:
            continue
        try:
            reparsed = parse_capsule_comment(
                comments_by_id[capsule.comment_id],
                now=current,
                expected_control_sha=expected_control_sha,
                expected_operation=expected_operation,
            )
        except SuccessorContractError as exc:
            if str(exc) in {
                "SUCCESSOR_CAPSULE_EXPIRED",
                "SUCCESSOR_CAPSULE_NOT_YET_VALID",
            }:
                continue
            raise SuccessorCapsuleError(str(exc)) from exc
        if reparsed is None:
            raise SuccessorCapsuleError("SUCCESSOR_CAPSULE_NOT_FOUND")
        live_eligible.append(reparsed)

    eligible = live_eligible
    if expected_capsule_id:
        eligible = [capsule for capsule in eligible if capsule.capsule_id == expected_capsule_id]
    if expected_capsule_body_sha256:
        if SHA256.fullmatch(expected_capsule_body_sha256) is None:
            raise SuccessorCapsuleError("EXPECTED_SUCCESSOR_CAPSULE_DIGEST_INVALID")
        eligible = [capsule for capsule in eligible if capsule.body_sha256 == expected_capsule_body_sha256]
    if expected_manifest_sha256:
        if SHA256.fullmatch(expected_manifest_sha256) is None:
            raise SuccessorCapsuleError("EXPECTED_SUCCESSOR_MANIFEST_DIGEST_INVALID")
        eligible = [capsule for capsule in eligible if capsule.manifest_sha256 == expected_manifest_sha256]

    if len(eligible) != 1:
        raise SuccessorCapsuleError(
            "SUCCESSOR_CAPSULE_NOT_FOUND" if not eligible else "SUCCESSOR_CAPSULE_AMBIGUOUS"
        )
    capsule = eligible[0]
    if len(open_capsules) != 1 or open_capsules[0].capsule_id != capsule.capsule_id:
        raise SuccessorCapsuleError("OPERATOR_HISTORY_OPEN_SET_INVALID")
    preflight_projection = validate_public_subject(
        api, capsule, trusted_sha=expected_control_sha, current_run_id=run_id
    )
    _require_preconsumption_history(comments, capsule, preflight_projection.manifest)
    return capsule


def consume_capsule(
    api: GitHubAPI,
    *,
    expected_control_sha: str,
    expected_operation: str,
    expected_capsule_id: str,
    expected_capsule_comment_id: int,
    expected_capsule_body_sha256: str,
    expected_manifest_sha256: str,
    run_id: int,
    run_attempt: int,
    now: datetime | None = None,
) -> tuple[SuccessorCapsule, SuccessorConsumption]:
    current = now or datetime.now(timezone.utc)
    capsule = discover_capsule(
        api,
        expected_control_sha=expected_control_sha,
        expected_operation=expected_operation,
        run_id=run_id,
        run_attempt=run_attempt,
        expected_capsule_id=expected_capsule_id,
        expected_capsule_body_sha256=expected_capsule_body_sha256,
        expected_manifest_sha256=expected_manifest_sha256,
        now=current,
    )
    if capsule.comment_id != expected_capsule_comment_id:
        raise SuccessorCapsuleError("SUCCESSOR_CAPSULE_CHANGED_BEFORE_CONSUMPTION")

    preflight_projection = validate_public_subject(
        api,
        capsule,
        trusted_sha=expected_control_sha,
        current_run_id=run_id,
    )

    _require_current_preconsumption_history(
        api, capsule, preflight_projection.manifest
    )

    payload = {
        "contract": CONSUMPTION_CONTRACT,
        "capsule_id": capsule.capsule_id,
        "capsule_comment_id": capsule.comment_id,
        "capsule_body_sha256": capsule.body_sha256,
        "manifest_sha256": capsule.manifest_sha256,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "trusted_sha": expected_control_sha,
        "operation": expected_operation,
        "consumed_at": current.astimezone(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        ),
        "workstream_e_authorised": False,
    }
    body = CONSUMPTION_PREFIX + canonical_json(payload)
    response = api.post(
        f"/repos/{CONTROL_REPOSITORY}/issues/{OPERATOR_ISSUE_NUMBER}/comments",
        {"body": body},
    )
    comment_id = response.get("id") if isinstance(response, Mapping) else None
    if type(comment_id) is not int or comment_id <= 0:
        raise SuccessorCapsuleError("SUCCESSOR_CONSUMPTION_CREATE_FAILED")
    observed = api.get(
        f"/repos/{CONTROL_REPOSITORY}/issues/comments/{comment_id}"
    )
    if not isinstance(observed, Mapping):
        raise SuccessorCapsuleError("SUCCESSOR_CONSUMPTION_REREAD_FAILED")
    try:
        consumption = parse_consumption_comment(observed)
    except SuccessorContractError as exc:
        raise SuccessorCapsuleError(str(exc)) from exc
    if consumption is None or consumption.body_sha256 != sha256_text(body):
        raise SuccessorCapsuleError("SUCCESSOR_CONSUMPTION_REREAD_MISMATCH")
    if consumption.payload != payload:
        raise SuccessorCapsuleError("SUCCESSOR_CONSUMPTION_REREAD_MISMATCH")
    return capsule, consumption


def _require_workflow_identity(
    values: Mapping[str, str],
) -> tuple[str, int, int, str]:
    if values.get("GITHUB_REPOSITORY") != CONTROL_REPOSITORY:
        raise SuccessorCapsuleError("OPERATOR_REPOSITORY_MISMATCH")
    if values.get("GITHUB_REF") != "refs/heads/main":
        raise SuccessorCapsuleError("OPERATOR_PROTECTED_MAIN_REQUIRED")
    sha = values.get("GITHUB_SHA", "")
    if len(sha) != 40 or any(ch not in "0123456789abcdef" for ch in sha):
        raise SuccessorCapsuleError("OPERATOR_TRUSTED_SHA_INVALID")
    try:
        run_id = int(values["GITHUB_RUN_ID"])
        run_attempt = int(values["GITHUB_RUN_ATTEMPT"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SuccessorCapsuleError("OPERATOR_RUN_IDENTITY_INVALID") from exc
    if run_id <= 0 or run_attempt != 1:
        raise SuccessorCapsuleError("OPERATOR_RERUN_FORBIDDEN")
    operation = values.get("INPUT_OPERATION", "")
    if operation != "live_scenario_suite":
        raise SuccessorCapsuleError("OPERATOR_LIVE_OPERATION_REQUIRED")
    return sha, run_id, run_attempt, LIVE_PROFILE


def _require_live_dispatch_bindings(
    values: Mapping[str, str],
) -> tuple[str, str, str]:
    capsule_id = values.get("EXPECTED_SUCCESSOR_CAPSULE_ID", "")
    capsule_body_sha256 = values.get("EXPECTED_SUCCESSOR_CAPSULE_BODY_SHA256", "")
    manifest_sha256 = values.get("EXPECTED_SUCCESSOR_MANIFEST_SHA256", "")
    if not capsule_id or not capsule_body_sha256 or not manifest_sha256:
        raise SuccessorCapsuleError("SUCCESSOR_DISPATCH_BINDING_REQUIRED")
    if OPAQUE_ID.fullmatch(capsule_id) is None:
        raise SuccessorCapsuleError("EXPECTED_SUCCESSOR_CAPSULE_ID_INVALID")
    if SHA256.fullmatch(capsule_body_sha256) is None:
        raise SuccessorCapsuleError("EXPECTED_SUCCESSOR_CAPSULE_DIGEST_INVALID")
    if SHA256.fullmatch(manifest_sha256) is None:
        raise SuccessorCapsuleError("EXPECTED_SUCCESSOR_MANIFEST_DIGEST_INVALID")
    return capsule_id, capsule_body_sha256, manifest_sha256


def _write_outputs(path: str, values: Mapping[str, str]) -> None:
    if not path:
        raise SuccessorCapsuleError("GITHUB_OUTPUT_MISSING")
    with open(path, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            if "\n" in key or "\n" in value:
                raise SuccessorCapsuleError("OPERATOR_OUTPUT_INVALID")
            handle.write(f"{key}={value}\n")


def _api_from_environment(values: Mapping[str, str]) -> GitHubAPI:
    token = values.get("GITHUB_TOKEN", "")
    if not token:
        raise SuccessorCapsuleError("GITHUB_TOKEN_MISSING")
    return GitHubAPI(token, values.get("GITHUB_API_URL", "https://api.github.com"))


def command_discover(values: Mapping[str, str]) -> None:
    sha, run_id, run_attempt, operation = _require_workflow_identity(values)
    capsule_id, capsule_body_sha256, manifest_sha256 = _require_live_dispatch_bindings(values)
    capsule = discover_capsule(
        _api_from_environment(values),
        expected_control_sha=sha,
        expected_operation=operation,
        run_id=run_id,
        run_attempt=run_attempt,
        expected_capsule_id=capsule_id,
        expected_capsule_body_sha256=capsule_body_sha256,
        expected_manifest_sha256=manifest_sha256,
    )
    outputs = capsule.runtime_outputs(run_id=run_id, run_attempt=run_attempt)
    _write_outputs(values.get("GITHUB_OUTPUT", ""), outputs)
    print(
        json.dumps(
            {
                "status": "SUCCESSOR_CAPSULE_VALIDATED",
                "capsule_id": capsule.capsule_id,
                "capsule_body_sha256": capsule.body_sha256,
                "manifest_sha256": capsule.manifest_sha256,
                "run_id": run_id,
                "run_attempt": run_attempt,
                "trusted_sha": sha,
                "credential_accessed": False,
                "workstream_e_authorised": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def command_consume(values: Mapping[str, str]) -> None:
    sha, run_id, run_attempt, operation = _require_workflow_identity(values)
    capsule_id, capsule_body_sha256, manifest_sha256 = _require_live_dispatch_bindings(values)
    try:
        expected_comment_id = int(values["EXPECTED_SUCCESSOR_CAPSULE_COMMENT_ID"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SuccessorCapsuleError(
            "EXPECTED_SUCCESSOR_CAPSULE_COMMENT_ID_INVALID"
        ) from exc
    capsule, consumption = consume_capsule(
        _api_from_environment(values),
        expected_control_sha=sha,
        expected_operation=operation,
        expected_capsule_id=capsule_id,
        expected_capsule_comment_id=expected_comment_id,
        expected_capsule_body_sha256=capsule_body_sha256,
        expected_manifest_sha256=manifest_sha256,
        run_id=run_id,
        run_attempt=run_attempt,
    )
    outputs = capsule.runtime_outputs(run_id=run_id, run_attempt=run_attempt)
    outputs.update(
        {
            "consumption_comment_id": str(consumption.comment_id),
            "consumption_body_sha256": consumption.body_sha256,
            "consumption_record_sha256": sha256_text(
                canonical_json(dict(consumption.payload))
            ),
        }
    )
    _write_outputs(values.get("GITHUB_OUTPUT", ""), outputs)
    print(
        json.dumps(
            {
                "status": "SUCCESSOR_CAPSULE_CONSUMED",
                "capsule_id": capsule.capsule_id,
                "capsule_body_sha256": capsule.body_sha256,
                "consumption_comment_id": consumption.comment_id,
                "consumption_body_sha256": consumption.body_sha256,
                "manifest_sha256": capsule.manifest_sha256,
                "run_id": run_id,
                "run_attempt": run_attempt,
                "trusted_sha": sha,
                "credential_accessed": False,
                "workstream_e_authorised": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def _blocked_payload(exc: Exception) -> dict[str, object]:
    payload: dict[str, object] = {
        "status": "BLOCKED",
        "reason_code": str(exc).split(":", 1)[0] or type(exc).__name__,
        "credential_accessed": False,
        "workstream_e_authorised": False,
    }
    if isinstance(exc, GitHubAPIError):
        payload.update(exc.safe_diagnostic())
        payload["reason_code"] = (
            "READ_EVIDENCE_RATE_LIMITED"
            if exc.rate_limited
            else "READ_EVIDENCE_UNAVAILABLE"
        )
    return payload


def main() -> int:
    try:
        if len(sys.argv) != 2:
            raise SuccessorCapsuleError("SUCCESSOR_CAPSULE_COMMAND_REQUIRED")
        if sys.argv[1] == "discover":
            command_discover(os.environ)
        elif sys.argv[1] == "consume":
            command_consume(os.environ)
        else:
            raise SuccessorCapsuleError("SUCCESSOR_CAPSULE_COMMAND_INVALID")
        return 0
    except Exception as exc:
        print(
            json.dumps(
                _blocked_payload(exc),
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())