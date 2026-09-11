from __future__ import annotations

from . import operator_guard_v1 as _v1

globals().update(
    {name: getattr(_v1, name) for name in dir(_v1) if not name.startswith("__")}
)

from .governance_state_v2 import (
    GuardedExecutionManifestV2,
    reduce_governance_history_v2,
)


def _evaluate_v2_governance(
    manifest: GuardedExecutionManifestV2,
    observation: GuardObservation,
):
    try:
        reduce_governance_history_v2(
            manifest,
            observation.governance_history,
            require_live_authority=False,
        )
    except GovernanceStateError as exc:
        return GuardResult.failure(exc.code)
    except Exception:
        return GuardResult.failure("GUARD_EVALUATOR_DEFECT")

    if observation.stage != "preflight":
        # For V2, this observation bit is set only after successor-contract
        # validation has proven one exact manifest approval and one exact
        # manifest-bound one-use live authority through the owner-authenticated
        # public-safe attestation. Preflight never sets or consumes this proof.
        if not observation.manifest_approval_proven:
            return GuardResult.failure("AUTHORITY_NOT_GRANTED")
        if (
            type(manifest.manifest_comment_id) is not int
            or manifest.manifest_comment_id <= 0
        ):
            return GuardResult.failure("GOVERNANCE_RECORD_INVALID")
    return None


def evaluate_guards(manifest: ExecutionManifest, observation: GuardObservation) -> GuardResult:
    if not isinstance(manifest, GuardedExecutionManifestV2):
        return _v1.evaluate_guards(manifest, observation)

    if not isinstance(observation, _v1.GuardObservation):
        return GuardResult.failure("OBSERVATION_SHAPE_UNSUPPORTED")
    if observation.stage not in STAGES or observation.read_status not in READ_STATUSES:
        return GuardResult.failure("OBSERVATION_SHAPE_UNSUPPORTED")
    if observation.read_status == "unavailable":
        return GuardResult.failure("READ_EVIDENCE_UNAVAILABLE")
    if observation.read_status == "rate_limited":
        return GuardResult.failure("READ_EVIDENCE_RATE_LIMITED")
    if observation.read_status == "ambiguous":
        return GuardResult.failure("READ_EVIDENCE_AMBIGUOUS")
    if not _v1._valid_complete_observation(observation):
        return GuardResult.failure("OBSERVATION_SHAPE_UNSUPPORTED")
    if manifest.payload.get("workstream_e_authorised") is not False:
        return GuardResult.failure("WORKSTREAM_E_NOT_AUTHORISED")

    governance = _evaluate_v2_governance(manifest, observation)
    if governance is not None:
        return governance

    control = _v1._compare_control(manifest, observation)
    if control is not None:
        return control
    if observation.protocol_sha != manifest.payload["protocol_sha"]:
        return GuardResult.failure("PROTOCOL_IDENTITY_CHANGED")

    if observation.stage == "live_l2" and not observation.private_freshness_proven:
        return GuardResult.failure("READ_EVIDENCE_UNAVAILABLE")

    if observation.stage != "live_l1":
        state = manifest.payload["state_baseline"]
        if (
            observation.state_commit_sha != state["commit_sha"]
            or observation.state_digest_sha256 != state["digest_sha256"]
        ):
            return GuardResult.failure("STATE_BASELINE_CHANGED")

    if observation.operator_history != manifest.operator_history:
        return GuardResult.failure("OPERATOR_HISTORY_CHANGED")
    if observation.workflow_history != manifest.workflow_history:
        return GuardResult.failure("WORKFLOW_HISTORY_CHANGED")

    if observation.stage != "live_l1":
        app = _v1._compare_app(manifest, observation)
        if app is not None:
            return app

    environment = manifest.payload["environment"]
    if (
        observation.environment_name != environment["name"]
        or observation.environment_policy_sha256 != environment["policy_sha256"]
        or observation.execution_variable != environment["execution_variable"]
    ):
        return GuardResult.failure("ENVIRONMENT_BOUNDARY_CHANGED")
    if (
        environment["execution_variable_expected_absent"]
        and not observation.execution_variable_absent
    ):
        return GuardResult.failure("EXECUTION_ENABLEMENT_CHANGED")
    return GuardResult.pass_result()
