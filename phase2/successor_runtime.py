from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from urllib.parse import quote
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from . import preflight_projection as projection
from . import preflight_runtime as preflight_runtime
from . import workstream_d_live as live
from . import workstream_d_revocation as revocation
from .credentials import (
    control_profile,
    create_app_jwt,
    mint_token,
    require_cross_repository_denial,
    require_public_repository_write_denial,
    require_state_repository_access,
    state_observation_profile,
    state_profile,
    token_request,
    validate_token_response,
    verify_live_installation,
)
from .github_api import GitHubAPI, GitHubAPIError
from .operator_capsule import LIVE_PROFILE
from .operator_guard import GuardObservation, GuardResult, evaluate_guards
from .operator_inventory import (
    CONTROL_REPOSITORY_ID,
    STATE_REPOSITORY_ID,
    InventoryEvidence,
    prove_installation_inventory,
)
from .operator_manifest import (
    SHA40,
    SHA256,
    canonical_json,
    sha256_text,
    workflow_history_baseline,
)
from .policy import load_policy
from .preflight_carrier_ledger import (
    _require_current_protected_main,
    validate_carrier_ledger,
)
from .preflight_control_anchor import validate_ledger_only_control_descendant
from .preflight_runtime_legacy import (
    _complete_workflow_records,
    _validate_workflow_run_number_continuity,
    expected_run_name,
)
from .successor_capsule import (
    SuccessorCapsuleError,
    _list_operator_comments,
    validate_public_subject,
)
from .successor_contract import (
    CAPSULE_CONTRACT,
    CONSUMPTION_CONTRACT,
    SuccessorCapsule,
    SuccessorConsumption,
    SuccessorContractError,
    operator_history_baseline,
    parse_capsule_comment,
    parse_consumption_comment,
    parse_operator_history,
    permission_profile_sha256,
)


CONTROL_REPOSITORY = projection.CONTROL_REPOSITORY
STATE_REPOSITORY = live.STATE_REPOSITORY
STATE_REPOSITORY_REF = live.STATE_REPOSITORY_BASELINE_REF
GUARD_PROTOCOL_AUTHORITY = live.PROTOCOL_AUTHORITY
EXECUTION_VARIABLE = "PHASE2_WORKSTREAM_D_EXECUTION_ENABLED"
FIXTURE_MODE = live.FIXTURE_MODE
EXECUTABLE_PATH = "phase2/successor_runtime.py"


class SuccessorRuntimeError(RuntimeError):
    pass


def _environment_policy_material(payload: Mapping[str, Any], expected_name: str) -> Mapping[str, Any]:
    if payload.get("name") != expected_name:
        raise SuccessorRuntimeError("ENVIRONMENT_BOUNDARY_CHANGED")
    rules = payload.get("protection_rules")
    if not isinstance(rules, list) or any(not isinstance(rule, Mapping) for rule in rules):
        raise SuccessorRuntimeError("READ_EVIDENCE_AMBIGUOUS")
    normalised_rules: list[dict[str, Any]] = []
    for rule in rules:
        rule_type = rule.get("type")
        if rule_type == "wait_timer":
            timer = rule.get("wait_timer")
            if type(timer) is not int or timer < 0:
                raise SuccessorRuntimeError("READ_EVIDENCE_AMBIGUOUS")
            normalised_rules.append({"type": "wait_timer", "wait_timer": timer})
            continue
        if rule_type == "required_reviewers":
            reviewers = rule.get("reviewers")
            prevent_self_review = rule.get("prevent_self_review")
            if not isinstance(reviewers, list) or type(prevent_self_review) is not bool:
                raise SuccessorRuntimeError("READ_EVIDENCE_AMBIGUOUS")
            normalised_reviewers: list[dict[str, Any]] = []
            for entry in reviewers:
                if not isinstance(entry, Mapping):
                    raise SuccessorRuntimeError("READ_EVIDENCE_AMBIGUOUS")
                reviewer = entry.get("reviewer")
                reviewer_type = entry.get("type")
                if not isinstance(reviewer, Mapping) or not isinstance(reviewer_type, str):
                    raise SuccessorRuntimeError("READ_EVIDENCE_AMBIGUOUS")
                reviewer_id = reviewer.get("id")
                if type(reviewer_id) is not int or reviewer_id <= 0:
                    raise SuccessorRuntimeError("READ_EVIDENCE_AMBIGUOUS")
                normalised_reviewers.append({"id": reviewer_id, "type": reviewer_type})
            normalised_reviewers.sort(key=lambda item: (item["type"], item["id"]))
            normalised_rules.append(
                {
                    "type": "required_reviewers",
                    "prevent_self_review": prevent_self_review,
                    "reviewers": normalised_reviewers,
                }
            )
            continue
        if rule_type == "branch_policy":
            normalised_rules.append({"type": "branch_policy"})
            continue
        raise SuccessorRuntimeError("READ_EVIDENCE_AMBIGUOUS")
    normalised_rules.sort(key=canonical_json)

    branch_policy = payload.get("deployment_branch_policy")
    if branch_policy is None:
        normalised_branch_policy: Mapping[str, Any] | None = None
    elif isinstance(branch_policy, Mapping):
        protected = branch_policy.get("protected_branches")
        custom = branch_policy.get("custom_branch_policies")
        if type(protected) is not bool or type(custom) is not bool:
            raise SuccessorRuntimeError("READ_EVIDENCE_AMBIGUOUS")
        normalised_branch_policy = {
            "custom_branch_policies": custom,
            "protected_branches": protected,
        }
    else:
        raise SuccessorRuntimeError("READ_EVIDENCE_AMBIGUOUS")
    return {
        "deployment_branch_policy": normalised_branch_policy,
        "name": expected_name,
        "protection_rules": normalised_rules,
    }


def environment_policy_sha256(payload: Mapping[str, Any], expected_name: str) -> str:
    return sha256_text(canonical_json(_environment_policy_material(payload, expected_name)))


def state_observation_sha256(
    *, repository_id: int, ref: str, commit_sha: str, tree_sha: str
) -> str:
    if repository_id != STATE_REPOSITORY_ID:
        raise SuccessorRuntimeError("STATE_REPOSITORY_ID_MISMATCH")
    if ref != STATE_REPOSITORY_REF:
        raise SuccessorRuntimeError("STATE_BASELINE_CHANGED")
    if SHA40.fullmatch(commit_sha) is None or SHA40.fullmatch(tree_sha) is None:
        raise SuccessorRuntimeError("READ_EVIDENCE_AMBIGUOUS")
    return sha256_text(
        canonical_json(
            {
                "commit_sha": commit_sha,
                "ref": ref,
                "repository_id": repository_id,
                "tree_sha": tree_sha,
            }
        )
    )


@dataclass(frozen=True)
class SuccessorRunContext:
    repository: str
    ref: str
    trusted_sha: str
    run_id: int
    run_attempt: int
    operation: str
    capsule_id: str
    capsule_comment_id: int
    capsule_body_sha256: str
    consumption_comment_id: int
    consumption_body_sha256: str
    manifest_sha256: str
    projection_comment_id: int
    projection_body_sha256: str
    attempt_nonce: str

    def validate(self) -> None:
        if self.repository != CONTROL_REPOSITORY:
            raise SuccessorRuntimeError("OPERATOR_REPOSITORY_MISMATCH")
        if self.ref != "refs/heads/main":
            raise SuccessorRuntimeError("OPERATOR_PROTECTED_MAIN_REQUIRED")
        if SHA40.fullmatch(self.trusted_sha) is None:
            raise SuccessorRuntimeError("OPERATOR_TRUSTED_SHA_INVALID")
        if self.run_id <= 0 or self.run_attempt != 1:
            raise SuccessorRuntimeError("OPERATOR_RERUN_FORBIDDEN")
        if self.operation != LIVE_PROFILE:
            raise SuccessorRuntimeError("OPERATOR_LIVE_OPERATION_REQUIRED")
        if not self.capsule_id or self.capsule_comment_id <= 0:
            raise SuccessorRuntimeError("SUCCESSOR_CONTEXT_CAPSULE_INVALID")
        for digest in (
            self.capsule_body_sha256,
            self.consumption_body_sha256,
            self.manifest_sha256,
            self.projection_body_sha256,
        ):
            if SHA256.fullmatch(digest) is None:
                raise SuccessorRuntimeError("SUCCESSOR_CONTEXT_DIGEST_INVALID")
        if self.consumption_comment_id <= 0 or self.projection_comment_id <= 0:
            raise SuccessorRuntimeError("SUCCESSOR_CONTEXT_COMMENT_INVALID")
        expected_nonce = sha256_text(
            f"{self.run_id}:{self.run_attempt}:{self.capsule_id}:{self.capsule_body_sha256}"
        )[:16]
        if self.attempt_nonce != expected_nonce:
            raise SuccessorRuntimeError("SUCCESSOR_CONTEXT_NONCE_INVALID")


@dataclass(frozen=True)
class SubjectState:
    capsule: SuccessorCapsule
    consumption: SuccessorConsumption
    preflight_projection: Any
    governance_history: Any


def _context(values: Mapping[str, str]) -> SuccessorRunContext:
    try:
        context = SuccessorRunContext(
            repository=values["GITHUB_REPOSITORY"],
            ref=values["GITHUB_REF"],
            trusted_sha=values["GITHUB_SHA"],
            run_id=int(values["GITHUB_RUN_ID"]),
            run_attempt=int(values["GITHUB_RUN_ATTEMPT"]),
            operation=values["OPERATION_PROFILE"],
            capsule_id=values["CAPSULE_ID"],
            capsule_comment_id=int(values["CAPSULE_COMMENT_ID"]),
            capsule_body_sha256=values["CAPSULE_BODY_SHA256"],
            consumption_comment_id=int(values["CONSUMPTION_COMMENT_ID"]),
            consumption_body_sha256=values["CONSUMPTION_BODY_SHA256"],
            manifest_sha256=values["MANIFEST_SHA256"],
            projection_comment_id=int(values["PROJECTION_COMMENT_ID"]),
            projection_body_sha256=values["PROJECTION_BODY_SHA256"],
            attempt_nonce=values["ATTEMPT_NONCE"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SuccessorRuntimeError("SUCCESSOR_CONTEXT_INCOMPLETE") from exc
    context.validate()
    return context


def expected_live_run_name(context: SuccessorRunContext) -> str:
    return (
        "live_scenario_suite "
        f"capsule={context.capsule_id} "
        f"body={context.capsule_body_sha256} "
        f"manifest={context.manifest_sha256}"
    )


def _api(values: Mapping[str, str], api_factory=GitHubAPI):
    token = values.get("GITHUB_TOKEN", "")
    if not token:
        raise SuccessorRuntimeError("READ_EVIDENCE_UNAVAILABLE")
    return api_factory(token, values.get("GITHUB_API_URL", "https://api.github.com"))


def _exact_comment(api, comment_id: int) -> Mapping[str, Any]:
    payload = api.get(f"/repos/{CONTROL_REPOSITORY}/issues/comments/{comment_id}")
    if not isinstance(payload, Mapping):
        raise SuccessorRuntimeError("READ_EVIDENCE_AMBIGUOUS")
    return payload


def _load_capsule_and_consumption(
    api,
    context: SuccessorRunContext,
    *,
    now: datetime,
) -> tuple[SuccessorCapsule, SuccessorConsumption]:
    try:
        capsule = parse_capsule_comment(
            _exact_comment(api, context.capsule_comment_id),
            now=now,
            expected_control_sha=context.trusted_sha,
            expected_operation=context.operation,
        )
        consumption = parse_consumption_comment(
            _exact_comment(api, context.consumption_comment_id)
        )
    except SuccessorContractError as exc:
        raise SuccessorRuntimeError(str(exc)) from exc
    if capsule is None or consumption is None:
        raise SuccessorRuntimeError("SUCCESSOR_CONTEXT_RECORD_MISSING")
    if (
        capsule.capsule_id != context.capsule_id
        or capsule.body_sha256 != context.capsule_body_sha256
        or capsule.manifest_sha256 != context.manifest_sha256
        or int(capsule.projection["comment_id"]) != context.projection_comment_id
        or str(capsule.projection["body_sha256"]) != context.projection_body_sha256
    ):
        raise SuccessorRuntimeError("SUCCESSOR_CAPSULE_CONTEXT_MISMATCH")
    payload = consumption.payload
    if (
        consumption.comment_id != context.consumption_comment_id
        or consumption.body_sha256 != context.consumption_body_sha256
        or payload["capsule_id"] != context.capsule_id
        or payload["capsule_comment_id"] != context.capsule_comment_id
        or payload["capsule_body_sha256"] != context.capsule_body_sha256
        or payload["manifest_sha256"] != context.manifest_sha256
        or payload["run_id"] != context.run_id
        or payload["run_attempt"] != context.run_attempt
        or payload["trusted_sha"] != context.trusted_sha
        or payload["operation"] != context.operation
    ):
        raise SuccessorRuntimeError("SUCCESSOR_CONSUMPTION_CONTEXT_MISMATCH")
    return capsule, consumption


def _validate_operator_history(
    api,
    context: SuccessorRunContext,
    manifest,
) -> None:
    comments = _list_operator_comments(api)
    try:
        records = parse_operator_history(comments, require_closed=True)
    except SuccessorContractError as exc:
        raise SuccessorRuntimeError("OPERATOR_HISTORY_CHANGED") from exc
    baseline = manifest.operator_history
    prefix = tuple(
        record for record in records if record.comment_id <= baseline.through_id
    )
    if operator_history_baseline(prefix) != baseline:
        raise SuccessorRuntimeError("OPERATOR_HISTORY_CHANGED")
    suffix = tuple(
        record for record in records if record.comment_id > baseline.through_id
    )
    if len(suffix) != 2:
        raise SuccessorRuntimeError("OPERATOR_HISTORY_CHANGED")
    capsule_record, consumption_record = suffix
    if (
        capsule_record.record_kind != CAPSULE_CONTRACT
        or consumption_record.record_kind != CONSUMPTION_CONTRACT
        or capsule_record.comment_id != context.capsule_comment_id
        or capsule_record.capsule_id != context.capsule_id
        or capsule_record.body_sha256 != context.capsule_body_sha256
        or consumption_record.comment_id != context.consumption_comment_id
        or consumption_record.capsule_id != context.capsule_id
        or consumption_record.capsule_comment_id != context.capsule_comment_id
        or consumption_record.capsule_body_sha256 != context.capsule_body_sha256
        or consumption_record.run_id != context.run_id
        or consumption_record.run_attempt != 1
        or consumption_record.trusted_sha != context.trusted_sha
        or consumption_record.operation != context.operation
    ):
        raise SuccessorRuntimeError("OPERATOR_HISTORY_CHANGED")


def _validate_workflow_history(
    api,
    context: SuccessorRunContext,
    capsule: SuccessorCapsule,
    manifest,
) -> None:
    runs = projection._list_workflow_runs(api)
    records = _complete_workflow_records(api, runs)
    baseline = manifest.workflow_history
    prefix = tuple(record for record in records if record.run_id <= baseline.through_id)
    if workflow_history_baseline(prefix) != baseline:
        raise SuccessorRuntimeError("WORKFLOW_HISTORY_CHANGED")
    _validate_workflow_run_number_continuity(
        runs,
        baseline_through_id=baseline.through_id,
        current_run_id=context.run_id,
    )

    preflight_title = expected_run_name(
        context.projection_comment_id,
        context.projection_body_sha256,
        context.manifest_sha256,
    )
    live_title = expected_live_run_name(context)
    bound_preflight_id = int(capsule.preflight_run["run_id"])
    preflight_seen = False
    current_seen = False
    suffix_ids: set[int] = set()
    for run in runs:
        run_id = run.get("id")
        if type(run_id) is not int or run_id <= baseline.through_id:
            continue
        if run_id in suffix_ids:
            raise SuccessorRuntimeError("WORKFLOW_HISTORY_CHANGED")
        suffix_ids.add(run_id)
        if (
            run.get("run_attempt") != 1
            or run.get("event") != "workflow_dispatch"
            or run.get("head_sha") != context.trusted_sha
        ):
            raise SuccessorRuntimeError("WORKFLOW_HISTORY_CHANGED")
        title = run.get("display_title")
        if title == preflight_title:
            if run_id == bound_preflight_id:
                preflight_seen = True
            continue
        if run_id == context.run_id and title == live_title:
            current_seen = True
            continue
        raise SuccessorRuntimeError("WORKFLOW_HISTORY_CHANGED")
    if not preflight_seen or not current_seen:
        raise SuccessorRuntimeError("WORKFLOW_HISTORY_CHANGED")


def _subject(
    values: Mapping[str, str],
    context: SuccessorRunContext,
    *,
    api_factory=GitHubAPI,
    now: datetime | None = None,
) -> SubjectState:
    evaluated_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    api = _api(values, api_factory)
    capsule, consumption = _load_capsule_and_consumption(
        api, context, now=evaluated_at
    )
    try:
        preflight_projection = validate_public_subject(
            api,
            capsule,
            trusted_sha=context.trusted_sha,
            current_run_id=context.run_id,
        )
        governance_history = preflight_projection.governance_history
    except (SuccessorCapsuleError, SuccessorContractError) as exc:
        raise SuccessorRuntimeError(str(exc)) from exc
    _validate_operator_history(api, context, preflight_projection.manifest)
    _validate_workflow_history(
        api,
        context,
        capsule,
        preflight_projection.manifest,
    )
    return SubjectState(
        capsule,
        consumption,
        preflight_projection,
        governance_history,
    )


def _guard_observation(
    values: Mapping[str, str],
    context: SuccessorRunContext,
    subject: SubjectState,
    *,
    stage: str,
    api,
    evaluated_at: datetime,
    actual_inventory: InventoryEvidence | None = None,
    state_observation: tuple[str, str] | None = None,
) -> GuardObservation:
    manifest = subject.preflight_projection.manifest
    projected_control_sha = str(manifest.payload["executor"]["commit_sha"])
    tree_sha, workflow_sha, module_blobs = projection._control_identity(
        api,
        manifest,
        trusted_sha=projected_control_sha,
    )
    bound = subject.preflight_projection.bound_observation
    environment_name = str(manifest.payload["environment"]["name"])
    environment_payload = api.get(
        f"/repos/{CONTROL_REPOSITORY}/environments/{quote(environment_name, safe='')}"
    )
    if not isinstance(environment_payload, Mapping):
        raise SuccessorRuntimeError("READ_EVIDENCE_AMBIGUOUS")
    environment_digest = environment_policy_sha256(environment_payload, environment_name)

    owner_requirement = manifest.payload["allocator_app"]["owner_observation"]
    if stage == "live_l2" and owner_requirement["required"] is True:
        # No conforming retained current owner-observation provider exists in B3.
        # Fail closed rather than replaying the B2 projection's validity bit.
        raise SuccessorRuntimeError("READ_EVIDENCE_UNAVAILABLE")
    owner_observation = None

    if actual_inventory is None:
        app_id = int(bound["app_id"])
        installation_id = int(bound["installation_id"])
        repository_selection = str(bound["repository_selection"])
        selected_repository_ids = tuple(
            int(item) for item in bound["selected_repository_ids"]
        )
        permission_digest = str(bound["permission_profile_sha256"])
    else:
        app_id = actual_inventory.app_id
        installation_id = actual_inventory.installation_id
        repository_selection = actual_inventory.repository_selection
        selected_repository_ids = actual_inventory.repository_ids
        permission_digest = permission_profile_sha256()

    return GuardObservation(
        stage=stage,
        read_status="complete",
        evaluated_at=evaluated_at,
        operation=manifest.operation,
        control_repository=CONTROL_REPOSITORY,
        control_commit_sha=projected_control_sha,
        control_tree_sha=tree_sha,
        workflow_blob_sha=workflow_sha,
        module_blobs=tuple(module_blobs),
        protocol_sha=GUARD_PROTOCOL_AUTHORITY,
        state_commit_sha=(
            str(state_observation[0]) if state_observation is not None else str(bound["state_commit_sha"])
        ),
        state_digest_sha256=(
            str(state_observation[1]) if state_observation is not None else str(bound["state_digest_sha256"])
        ),
        operator_history=manifest.operator_history,
        workflow_history=manifest.workflow_history,
        app_id=app_id,
        installation_id=installation_id,
        repository_selection=repository_selection,
        selected_repository_ids=selected_repository_ids,
        permission_profile_sha256=permission_digest,
        owner_observation=owner_observation,
        environment_name=environment_name,
        environment_policy_sha256=environment_digest,
        execution_variable=str(bound["execution_variable"]),
        execution_variable_absent=values.get(EXECUTION_VARIABLE, "") == "",
        governance_history=subject.governance_history,
        manifest_approval_proven=True,
        private_freshness_proven=(stage == "live_l2" and actual_inventory is not None and state_observation is not None),
    )


def _final_public_fence(
    values: Mapping[str, str],
    context: SuccessorRunContext,
    subject: SubjectState,
    *,
    api,
) -> None:
    validate_carrier_ledger(
        api,
        trusted_sha=context.trusted_sha,
        projection_comment_id=context.projection_comment_id,
        projection_body_sha256=context.projection_body_sha256,
        manifest_sha256=context.manifest_sha256,
    )
    projected_control_sha = str(
        subject.preflight_projection.manifest.payload["executor"]["commit_sha"]
    )
    validate_ledger_only_control_descendant(
        api,
        projected_control_sha=projected_control_sha,
        trusted_sha=context.trusted_sha,
    )
    _require_current_protected_main(api, context.trusted_sha)


def evaluate_stage(
    values: Mapping[str, str],
    context: SuccessorRunContext,
    *,
    stage: str,
    api_factory=GitHubAPI,
    now: datetime | None = None,
    actual_inventory: InventoryEvidence | None = None,
    state_observation: tuple[str, str] | None = None,
) -> tuple[SubjectState, GuardResult]:
    if stage not in {"live_l1", "live_l2"}:
        raise SuccessorRuntimeError("SUCCESSOR_STAGE_INVALID")
    evaluated_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    subject = _subject(
        values,
        context,
        api_factory=api_factory,
        now=evaluated_at,
    )
    api = _api(values, api_factory)
    observation = _guard_observation(
        values,
        context,
        subject,
        stage=stage,
        api=api,
        evaluated_at=evaluated_at,
        actual_inventory=actual_inventory,
        state_observation=state_observation,
    )
    result = evaluate_guards(subject.preflight_projection.manifest, observation)
    if not result.passed:
        raise SuccessorRuntimeError(result.code)
    _final_public_fence(values, context, subject, api=api)
    return subject, result


def run_l1(
    values: Mapping[str, str] | None = None,
    *,
    api_factory=GitHubAPI,
    now: datetime | None = None,
) -> dict[str, object]:
    env = os.environ if values is None else values
    context = _context(env)
    _, result = evaluate_stage(
        env,
        context,
        stage="live_l1",
        api_factory=api_factory,
        now=now,
    )
    return {
        "status": "GITSTATE_LIVE_L1_PASS",
        "guard_code": result.code,
        "guard_category": result.category,
        "run_id": context.run_id,
        "run_attempt": context.run_attempt,
        "trusted_sha": context.trusted_sha,
        "capsule_id": context.capsule_id,
        "manifest_sha256": context.manifest_sha256,
        "allocator_key_accessed": False,
        "inventory_tokens_minted": 0,
        "control_state_tokens_minted": 0,
        "canonical_state_mutated": False,
        "workstream_e_authorised": False,
    }


def _observe_state_baseline(
    app_api,
    *,
    installation_id: int,
    api_url: str,
    api_factory: Callable[[str, str], GitHubAPI] = GitHubAPI,
) -> tuple[str, str]:
    profile = state_observation_profile(STATE_REPOSITORY_ID)
    response = app_api.post(
        f"/app/installations/{installation_id}/access_tokens",
        token_request(profile),
    )
    if not isinstance(response, dict):
        raise SuccessorRuntimeError("STATE_OBSERVATION_TOKEN_RESPONSE_INVALID")
    token = response.get("token")
    if not isinstance(token, str) or not token:
        raise SuccessorRuntimeError("STATE_OBSERVATION_TOKEN_MISSING")

    primary_error: Exception | None = None
    state_api = None
    result: tuple[str, str] | None = None
    try:
        validate_token_response(response, profile)
        state_api = api_factory(token, api_url)
        require_state_repository_access(
            token,
            "8ft0-ai",
            "gitstate-allocation-state",
            STATE_REPOSITORY_ID,
            api_url,
            api_factory=api_factory,
        )
        ref_payload = state_api.get(
            f"/repos/{STATE_REPOSITORY}/git/ref/heads/main"
        )
        obj = ref_payload.get("object") if isinstance(ref_payload, Mapping) else None
        commit_sha = obj.get("sha") if isinstance(obj, Mapping) else None
        if not isinstance(commit_sha, str) or SHA40.fullmatch(commit_sha) is None:
            raise SuccessorRuntimeError("READ_EVIDENCE_AMBIGUOUS")
        commit_payload = state_api.get(
            f"/repos/{STATE_REPOSITORY}/git/commits/{commit_sha}"
        )
        tree = commit_payload.get("tree") if isinstance(commit_payload, Mapping) else None
        tree_sha = tree.get("sha") if isinstance(tree, Mapping) else None
        if not isinstance(tree_sha, str) or SHA40.fullmatch(tree_sha) is None:
            raise SuccessorRuntimeError("READ_EVIDENCE_AMBIGUOUS")
        result = (
            commit_sha,
            state_observation_sha256(
                repository_id=STATE_REPOSITORY_ID,
                ref=STATE_REPOSITORY_REF,
                commit_sha=commit_sha,
                tree_sha=tree_sha,
            ),
        )
    except Exception as exc:
        primary_error = exc

    try:
        revocation_api = state_api if state_api is not None else api_factory(token, api_url)
        _, _, status = revocation_api.request_with_status(
            "DELETE", "/installation/token"
        )
        if status != 204:
            raise SuccessorRuntimeError("STATE_OBSERVATION_TOKEN_REVOCATION_FAILED")
    except Exception as revoke_exc:
        raise SuccessorRuntimeError("STATE_OBSERVATION_TOKEN_REVOCATION_FAILED") from (
            primary_error or revoke_exc
        )
    finally:
        token = ""

    if primary_error is not None:
        raise primary_error
    if result is None:
        raise SuccessorRuntimeError("STATE_OBSERVATION_EVIDENCE_MISSING")
    return result


def _mutation_credentials(
    guard_values: Mapping[str, str],
    context: SuccessorRunContext,
    legacy_context: live.LiveRunContext,
    *,
    private_key: str,
    api_factory: Callable[[str, str], GitHubAPI] = GitHubAPI,
    jwt_factory: Callable[[int, str], str] = create_app_jwt,
):
    pre_l2_subject, _ = evaluate_stage(
        guard_values,
        context,
        stage="live_l1",
        api_factory=api_factory,
    )
    legacy_context.validate()

    policy = load_policy(guard_values.get("PHASE2_POLICY", "policy/actors.json"))
    if policy.get("control_repository") != CONTROL_REPOSITORY:
        raise SuccessorRuntimeError("CONTROL_REPOSITORY_POLICY_MISMATCH")
    if int(policy.get("control_repository_id", 0)) != CONTROL_REPOSITORY_ID:
        raise SuccessorRuntimeError("CONTROL_REPOSITORY_ID_MISMATCH")
    app_id = int(guard_values[policy["allocator"]["app_id_env"]])
    installation_id = int(guard_values[policy["allocator"]["installation_id_env"]])
    if int(guard_values[policy["state_repository_id_env"]]) != STATE_REPOSITORY_ID:
        raise SuccessorRuntimeError("STATE_REPOSITORY_ID_MISMATCH")
    if guard_values.get(EXECUTION_VARIABLE, "") != "":
        raise SuccessorRuntimeError("EXECUTION_ENABLEMENT_CHANGED")

    if not private_key:
        raise SuccessorRuntimeError("ALLOCATOR_PRIVATE_KEY_MISSING")
    api_url = guard_values.get("GITHUB_API_URL", "https://api.github.com")
    jwt = jwt_factory(app_id, private_key)
    private_key = ""
    app_api = api_factory(jwt, api_url)
    installation = verify_live_installation(
        app_api,
        "8ft0-ai",
        "gitstate-allocation-control",
        {
            "app_id": app_id,
            "installation_id": installation_id,
            "app_slug": policy["allocator"]["app_slug"],
            "owner": policy["allocator"]["owner"],
        },
    )
    inventory = prove_installation_inventory(
        app_api,
        installation_id=installation_id,
        app_id=app_id,
        repository_selection=str(installation["repository_selection"]),
        run_id=context.run_id,
        run_attempt=context.run_attempt,
        trusted_sha=context.trusted_sha,
        capsule_id=context.capsule_id,
        capsule_body_sha256=context.capsule_body_sha256,
        api_url=api_url,
        api_factory=api_factory,
    )
    state_observation = _observe_state_baseline(
        app_api,
        installation_id=installation_id,
        api_url=api_url,
        api_factory=api_factory,
    )
    jwt = ""

    subject, _ = evaluate_stage(
        guard_values,
        context,
        stage="live_l2",
        api_factory=api_factory,
        actual_inventory=inventory,
        state_observation=state_observation,
    )
    if (
        subject.preflight_projection.manifest.sha256
        != pre_l2_subject.preflight_projection.manifest.sha256
    ):
        raise SuccessorRuntimeError("SUCCESSOR_MANIFEST_CHANGED_DURING_L2")

    control_token = ""
    state_token = ""
    try:
        control = control_profile(CONTROL_REPOSITORY_ID)
        control_token = mint_token(app_api, installation_id, control)
        require_cross_repository_denial(
            control_token, STATE_REPOSITORY_ID, api_url
        )
        state = state_profile(STATE_REPOSITORY_ID)
        state_token = mint_token(app_api, installation_id, state)
        require_public_repository_write_denial(
            state_token,
            "8ft0-ai",
            "gitstate-allocation-control",
            api_url,
        )
        return (
            live.CredentialLease(
                control_token,
                state_token,
                (live._scope_evidence(control), live._scope_evidence(state)),
                api_url,
                api_factory,
            ),
            inventory,
        )
    except Exception:
        lease = live.CredentialLease(
            control_token,
            state_token,
            (
                live._scope_evidence(control_profile(CONTROL_REPOSITORY_ID)),
                live._scope_evidence(state_profile(STATE_REPOSITORY_ID)),
            ),
            api_url,
            api_factory,
        )
        try:
            lease.close()
        except Exception:
            pass
        raise


def execute_live(
    values: Mapping[str, str] | None = None,
) -> live.LiveSuiteResult:
    env = os.environ if values is None else values
    context = _context(env)

    key_name = "PHASE2_ALLOCATOR_APP_PRIVATE_KEY"
    guard_values = dict(env)
    guard_values.pop(key_name, None)
    subject, _ = evaluate_stage(guard_values, context, stage="live_l1")
    manifest = subject.preflight_projection.manifest
    protocol_sha = str(manifest.payload["protocol_sha"])
    legacy_context = live.LiveRunContext(
        repository=context.repository,
        ref=context.ref,
        trusted_sha=context.trusted_sha,
        expected_control_sha=context.trusted_sha,
        protocol_sha=protocol_sha,
        expected_protocol_sha=protocol_sha,
        run_id=context.run_id,
        run_attempt=context.run_attempt,
        attempt_nonce=context.attempt_nonce,
        enabled=True,
        fixture_mode=FIXTURE_MODE,
    )

    try:
        private_key = env[key_name]
    except KeyError as exc:
        raise SuccessorRuntimeError("ALLOCATOR_PRIVATE_KEY_MISSING") from exc
    if not private_key:
        raise SuccessorRuntimeError("ALLOCATOR_PRIVATE_KEY_MISSING")
    if env is os.environ:
        os.environ.pop(key_name, None)
    elif hasattr(env, "pop"):
        env.pop(key_name, None)  # type: ignore[attr-defined]

    legacy_values = dict(guard_values)
    legacy_values[EXECUTION_VARIABLE] = "true"

    previous_context = live.context_from_environment
    previous_acquire = live.acquire_credentials
    previous_protocol = live.PROTOCOL_AUTHORITY
    previous_paths = tuple(live.LIVE_EXECUTABLE_PATHS)

    def context_provider(_: Mapping[str, str]) -> live.LiveRunContext:
        return legacy_context

    def acquire_provider(
        _values: Mapping[str, str],
        _legacy_context: live.LiveRunContext,
        *,
        api_factory=GitHubAPI,
        jwt_factory=create_app_jwt,
    ):
        return _mutation_credentials(
            guard_values,
            context,
            legacy_context,
            private_key=private_key,
            api_factory=api_factory,
            jwt_factory=jwt_factory,
        )

    live.context_from_environment = context_provider
    live.acquire_credentials = acquire_provider
    live.PROTOCOL_AUTHORITY = protocol_sha
    if EXECUTABLE_PATH not in live.LIVE_EXECUTABLE_PATHS:
        live.LIVE_EXECUTABLE_PATHS = (*live.LIVE_EXECUTABLE_PATHS, EXECUTABLE_PATH)
    try:
        result = revocation.execute_live_suite(legacy_values)
    finally:
        live.context_from_environment = previous_context
        live.acquire_credentials = previous_acquire
        live.PROTOCOL_AUTHORITY = previous_protocol
        live.LIVE_EXECUTABLE_PATHS = previous_paths
        private_key = ""

    return live.LiveSuiteResult(
        result.run_id,
        result.run_attempt,
        result.attempt_namespace,
        result.trusted_sha,
        result.protocol_sha,
        result.scenario_count,
        result.evidence_sha256,
        result.inventory_attestation_sha256,
        result.credential_revocation_required,
        False,
    )


def _blocked_payload(exc: Exception) -> dict[str, object]:
    payload: dict[str, object] = {
        "status": "BLOCKED",
        "reason_code": str(exc).split(":", 1)[0] or type(exc).__name__,
        "credential_material_emitted": False,
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
            raise SuccessorRuntimeError("SUCCESSOR_RUNTIME_COMMAND_REQUIRED")
        if sys.argv[1] == "l1":
            record = run_l1()
            print(json.dumps(record, sort_keys=True, separators=(",", ":")))
            return 0
        if sys.argv[1] == "live":
            result = execute_live()
            payload = result.payload()
            payload["credential_revoked"] = True
            payload["status"] = "WORKSTREAM_D_SYNTHETIC_SUITE_PASSED"
            print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
            return 0
        raise SuccessorRuntimeError("SUCCESSOR_RUNTIME_COMMAND_INVALID")
    except Exception as exc:
        print(json.dumps(_blocked_payload(exc), sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
