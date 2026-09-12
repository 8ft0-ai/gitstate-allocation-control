from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from . import operator_manifest_v1 as _v1


MANIFEST_V2_CONTRACT = "gitstate-live-execution-manifest/v2"
MANIFEST_V2_FIELDS = frozenset(
    {
        "contract",
        "operation",
        "governing_issue",
        "executor",
        "protocol_sha",
        "proposal",
        "readiness",
        "state_baseline",
        "operator_history",
        "workflow_history",
        "allocator_app",
        "environment",
        "single_use",
        "workstream_e_authorised",
    }
)


@dataclass(frozen=True)
class ExecutionManifestV2(_v1.ExecutionManifest):
    """Additive pre-authority manifest. Historical v1 remains unchanged."""

    @property
    def authority(self):
        raise _v1.OperatorContractError("V2_MANIFEST_HAS_NO_LIVE_AUTHORITY")


def _validate_common(value: Mapping[str, Any]) -> None:
    _v1._require_string(value.get("operation"), "MANIFEST_OPERATION_INVALID")
    _v1._require_int(value.get("governing_issue"), "MANIFEST_GOVERNING_ISSUE_INVALID")

    executor = value.get("executor")
    if not isinstance(executor, dict):
        raise _v1.OperatorContractError("MANIFEST_EXECUTOR_INVALID")
    _v1._require_exact_keys(executor, _v1.EXECUTOR_FIELDS, "MANIFEST_EXECUTOR_INVALID")
    repository = _v1._require_string(executor.get("repository"), "MANIFEST_EXECUTOR_INVALID")
    if _v1.REPOSITORY.fullmatch(repository) is None:
        raise _v1.OperatorContractError("MANIFEST_EXECUTOR_INVALID")
    for key in ("commit_sha", "tree_sha", "workflow_blob_sha"):
        _v1._require_hex(executor.get(key), _v1.SHA40, "MANIFEST_EXECUTOR_INVALID")
    _v1._require_module_blobs(executor.get("module_blobs"))

    _v1._require_hex(value.get("protocol_sha"), _v1.SHA40, "MANIFEST_PROTOCOL_INVALID")
    for key in ("proposal", "readiness"):
        _v1._require_comment_binding(value.get(key), f"MANIFEST_{key.upper()}_INVALID")

    state = value.get("state_baseline")
    if not isinstance(state, dict):
        raise _v1.OperatorContractError("MANIFEST_STATE_BASELINE_INVALID")
    _v1._require_exact_keys(state, _v1.STATE_BASELINE_FIELDS, "MANIFEST_STATE_BASELINE_INVALID")
    _v1._require_hex(state.get("commit_sha"), _v1.SHA40, "MANIFEST_STATE_BASELINE_INVALID")
    _v1._require_hex(state.get("digest_sha256"), _v1.SHA256, "MANIFEST_STATE_BASELINE_INVALID")

    _v1._require_history_baseline(value.get("operator_history"), "MANIFEST_OPERATOR_HISTORY_INVALID")
    _v1._require_history_baseline(value.get("workflow_history"), "MANIFEST_WORKFLOW_HISTORY_INVALID")

    app = value.get("allocator_app")
    if not isinstance(app, dict):
        raise _v1.OperatorContractError("MANIFEST_APP_BOUNDARY_INVALID")
    _v1._require_exact_keys(app, _v1.ALLOCATOR_APP_FIELDS, "MANIFEST_APP_BOUNDARY_INVALID")
    _v1._require_int(app.get("app_id"), "MANIFEST_APP_BOUNDARY_INVALID")
    _v1._require_int(app.get("installation_id"), "MANIFEST_APP_BOUNDARY_INVALID")
    if app.get("repository_selection") != "selected":
        raise _v1.OperatorContractError("MANIFEST_APP_BOUNDARY_INVALID")
    repository_ids = app.get("selected_repository_ids")
    if (
        not isinstance(repository_ids, list)
        or not repository_ids
        or any(type(item) is not int or item <= 0 for item in repository_ids)
        or repository_ids != sorted(repository_ids)
        or len(repository_ids) != len(set(repository_ids))
    ):
        raise _v1.OperatorContractError("MANIFEST_APP_BOUNDARY_INVALID")
    _v1._require_hex(
        app.get("permission_profile_sha256"),
        _v1.SHA256,
        "MANIFEST_APP_BOUNDARY_INVALID",
    )
    _v1._require_owner_observation(app.get("owner_observation"))

    environment = value.get("environment")
    if not isinstance(environment, dict):
        raise _v1.OperatorContractError("MANIFEST_ENVIRONMENT_INVALID")
    _v1._require_exact_keys(
        environment, _v1.ENVIRONMENT_FIELDS, "MANIFEST_ENVIRONMENT_INVALID"
    )
    _v1._require_string(environment.get("name"), "MANIFEST_ENVIRONMENT_INVALID")
    _v1._require_hex(
        environment.get("policy_sha256"), _v1.SHA256, "MANIFEST_ENVIRONMENT_INVALID"
    )
    _v1._require_string(
        environment.get("execution_variable"), "MANIFEST_ENVIRONMENT_INVALID"
    )
    _v1._require_bool(
        environment.get("execution_variable_expected_absent"),
        True,
        "MANIFEST_ENVIRONMENT_INVALID",
    )

    _v1._require_bool(value.get("single_use"), True, "MANIFEST_SINGLE_USE_REQUIRED")
    _v1._require_bool(
        value.get("workstream_e_authorised"),
        False,
        "WORKSTREAM_E_NOT_AUTHORISED",
    )


def parse_execution_manifest_v2(
    raw: str, *, expected_sha256: str | None = None
) -> ExecutionManifestV2:
    value = _v1._strict_json(raw, "MANIFEST_JSON_INVALID")
    _v1._require_exact_keys(value, MANIFEST_V2_FIELDS, "MANIFEST_SCHEMA_MISMATCH")
    if value.get("contract") != MANIFEST_V2_CONTRACT:
        raise _v1.OperatorContractError("MANIFEST_CONTRACT_MISMATCH")
    _validate_common(value)

    digest = _v1.sha256_text(raw)
    if expected_sha256 is not None:
        _v1._require_hex(
            expected_sha256, _v1.SHA256, "MANIFEST_EXPECTED_DIGEST_INVALID"
        )
        if digest != expected_sha256:
            raise _v1.OperatorContractError("MANIFEST_IDENTITY_MISMATCH")
    return ExecutionManifestV2(_v1._freeze(value), digest)
