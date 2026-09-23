from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping

from . import operator_manifest_v1 as _manifest


READINESS_CONTRACT = "gitstate-current-observation-runtime-subject-readiness-reconciliation/v2"
READINESS_STATUS_READY = "READY_FOR_GITSTATE_LAB_FRESH_SUCCESSOR_OBSERVATION_GOVERNANCE"
READINESS_PREFIX = READINESS_CONTRACT + "\n"
CONTROL_REPOSITORY = "8ft0-ai/gitstate-allocation-control"
NEXT_BOUNDARY = "GITSTATE_LAB_CREATE_AND_GOVERN_FRESH_SUCCESSOR"
IMMUTABLE_TAG_RULESET_NAME = "gitstate-current-observation-immutable-tags-v1"
IMMUTABLE_TAG_INCLUDE = "refs/tags/gitstate-current-observation/*"

READINESS_FIELDS = frozenset(
    {
        "all_5_current_observation_governed_blobs_identical",
        "authorises_gitstate_successor",
        "authorises_observation_request",
        "current_main",
        "fresh_runtime_subject",
        "fresh_runtime_subject_differs_from_previous",
        "fresh_runtime_tree",
        "functional_current_observation_semantics_changed",
        "future_same_run_identity_gate",
        "gitstate_lab_accessed",
        "handoff_role",
        "immutable_tag_ruleset",
        "matching_observation_consumption_count",
        "matching_observation_execution_count",
        "matching_observation_request_count",
        "matching_observation_rerun_count",
        "merge_method",
        "next_boundary",
        "observation_consumption_created",
        "observation_executed",
        "observation_request_created",
        "pr",
        "previous_runtime_subject",
        "protected_execution_tag",
        "protected_tag_compare_status",
        "protected_tag_object_type",
        "protected_tag_target",
        "readiness_status",
        "readme_blob_identical_to_reviewed_candidate",
        "repository",
        "reviewed_head",
        "workflow_rerun",
        "workstream_d_executed",
        "workstream_e_authorised",
    }
)

SAME_RUN_GATE_FIELDS = frozenset(
    {"github_run_attempt", "github_sha", "github_workflow_sha", "requested_tag_sha"}
)
RULESET_FIELDS = frozenset(
    {
        "bypass_actors",
        "deletion_prohibited",
        "enforcement",
        "id",
        "include",
        "name",
        "target",
        "update_prohibited",
    }
)


class ReadinessHandoffError(RuntimeError):
    pass


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ReadinessHandoffError(code)


def _require_sha(value: object, code: str) -> str:
    _require(isinstance(value, str) and _manifest.SHA40.fullmatch(value) is not None, code)
    return str(value)


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def validate_readiness_payload(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    _require(isinstance(payload, dict), "READINESS_PAYLOAD_INVALID")
    _require(frozenset(payload) == READINESS_FIELDS, "READINESS_SCHEMA_MISMATCH")

    subject = _require_sha(payload.get("fresh_runtime_subject"), "READINESS_SUBJECT_INVALID")
    previous = _require_sha(payload.get("previous_runtime_subject"), "READINESS_PREVIOUS_SUBJECT_INVALID")
    _require_sha(payload.get("fresh_runtime_tree"), "READINESS_TREE_INVALID")
    _require_sha(payload.get("reviewed_head"), "READINESS_REVIEWED_HEAD_INVALID")

    _require(payload.get("repository") == CONTROL_REPOSITORY, "READINESS_REPOSITORY_MISMATCH")
    _require(payload.get("readiness_status") == READINESS_STATUS_READY, "READINESS_STATUS_INVALID")
    _require(payload.get("current_main") == subject, "READINESS_MAIN_MISMATCH")
    _require(subject != previous, "READINESS_SUBJECT_REUSED")
    _require(payload.get("fresh_runtime_subject_differs_from_previous") is True, "READINESS_SUBJECT_FRESHNESS_INVALID")
    _require(payload.get("all_5_current_observation_governed_blobs_identical") is True, "READINESS_GOVERNED_BLOBS_CHANGED")
    _require(payload.get("functional_current_observation_semantics_changed") is False, "READINESS_OBSERVATION_SEMANTICS_CHANGED")
    _require(payload.get("authorises_gitstate_successor") is False, "READINESS_SUCCESSOR_AUTHORITY_WIDENED")
    _require(payload.get("authorises_observation_request") is False, "READINESS_OBSERVATION_AUTHORITY_WIDENED")
    _require(payload.get("gitstate_lab_accessed") is False, "READINESS_CROSS_PROJECT_ACCESS_INVALID")
    _require(payload.get("handoff_role") == "implementation/readiness only", "READINESS_ROLE_INVALID")
    _require(payload.get("merge_method") == "squash", "READINESS_MERGE_METHOD_INVALID")
    _require(payload.get("next_boundary") == NEXT_BOUNDARY, "READINESS_NEXT_BOUNDARY_INVALID")
    _require(type(payload.get("pr")) is int and int(payload["pr"]) > 0, "READINESS_PR_INVALID")
    _require(payload.get("readme_blob_identical_to_reviewed_candidate") is True, "READINESS_REVIEWED_DOC_DRIFT")

    for key in (
        "matching_observation_consumption_count",
        "matching_observation_execution_count",
        "matching_observation_request_count",
        "matching_observation_rerun_count",
    ):
        _require(type(payload.get(key)) is int and payload[key] == 0, "READINESS_PRIOR_ATTEMPT_EXISTS")
    for key in (
        "observation_consumption_created",
        "observation_executed",
        "observation_request_created",
        "workflow_rerun",
        "workstream_d_executed",
        "workstream_e_authorised",
    ):
        _require(payload.get(key) is False, "READINESS_CONSEQUENCE_ALREADY_EXISTS")

    expected_tag = f"refs/tags/gitstate-current-observation/{subject}"
    _require(payload.get("protected_execution_tag") == expected_tag, "READINESS_TAG_INVALID")
    _require(payload.get("protected_tag_target") == subject, "READINESS_TAG_TARGET_INVALID")
    _require(payload.get("protected_tag_compare_status") == "identical", "READINESS_TAG_COMPARE_INVALID")
    _require(payload.get("protected_tag_object_type") == "commit", "READINESS_TAG_OBJECT_INVALID")

    gate = payload.get("future_same_run_identity_gate")
    _require(isinstance(gate, dict) and frozenset(gate) == SAME_RUN_GATE_FIELDS, "READINESS_SAME_RUN_GATE_INVALID")
    _require(gate.get("github_run_attempt") == 1, "READINESS_SAME_RUN_ATTEMPT_INVALID")
    for key in ("github_sha", "github_workflow_sha", "requested_tag_sha"):
        _require(gate.get(key) == subject, "READINESS_SAME_RUN_IDENTITY_INVALID")

    ruleset = payload.get("immutable_tag_ruleset")
    _require(isinstance(ruleset, dict) and frozenset(ruleset) == RULESET_FIELDS, "READINESS_RULESET_INVALID")
    _require(ruleset.get("bypass_actors") == [], "READINESS_RULESET_BYPASS_INVALID")
    _require(ruleset.get("deletion_prohibited") is True, "READINESS_RULESET_DELETE_INVALID")
    _require(ruleset.get("update_prohibited") is True, "READINESS_RULESET_UPDATE_INVALID")
    _require(ruleset.get("enforcement") == "active", "READINESS_RULESET_ENFORCEMENT_INVALID")
    _require(type(ruleset.get("id")) is int and int(ruleset["id"]) > 0, "READINESS_RULESET_ID_INVALID")
    _require(ruleset.get("include") == [IMMUTABLE_TAG_INCLUDE], "READINESS_RULESET_SCOPE_INVALID")
    _require(ruleset.get("name") == IMMUTABLE_TAG_RULESET_NAME, "READINESS_RULESET_NAME_INVALID")
    _require(ruleset.get("target") == "tag", "READINESS_RULESET_TARGET_INVALID")
    return _freeze(dict(payload))


def parse_readiness_handoff(body: str) -> Mapping[str, Any]:
    _require(isinstance(body, str) and body.startswith(READINESS_PREFIX), "READINESS_BODY_INVALID")
    raw = body[len(READINESS_PREFIX) :]
    try:
        payload = _manifest._strict_json(raw, "READINESS_JSON_INVALID")
    except _manifest.OperatorContractError as exc:
        raise ReadinessHandoffError(str(exc)) from exc
    return validate_readiness_payload(payload)


def render_readiness_handoff(payload: Mapping[str, Any]) -> str:
    validated = validate_readiness_payload(dict(payload))
    return READINESS_PREFIX + _manifest.canonical_json(_thaw(validated))


def readiness_body_sha256(body: str) -> str:
    parse_readiness_handoff(body)
    return _manifest.sha256_text(body)


def readiness_payload_sha256(body: str) -> str:
    parse_readiness_handoff(body)
    return _manifest.sha256_text(body[len(READINESS_PREFIX) :])
