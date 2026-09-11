from __future__ import annotations

from . import successor_capsule_v1 as _v1

_V1_EXPORTS = {
    name: getattr(_v1, name) for name in dir(_v1) if not name.startswith("__")
}
_ORIGINAL_DISCOVER = _v1.discover_capsule
_ORIGINAL_CONSUME = _v1.consume_capsule
_ORIGINAL_REQUIRE_APPROVAL = _v1.require_current_manifest_approval_attestation
globals().update(_V1_EXPORTS)

from .governance_state_v2 import GuardedExecutionManifestV2
from .successor_contract import APPROVAL_ATTESTATION_V2_CONTRACT


def _sync_v1_globals() -> None:
    # Existing tests and callers patch the public successor_capsule module.
    # Reflect those seams into the byte-for-byte historical implementation
    # before delegating so additive v2 support cannot change v1 observability.
    for name in _V1_EXPORTS:
        if name in {"discover_capsule", "consume_capsule"}:
            continue
        if name in globals():
            setattr(_v1, name, globals()[name])


def require_current_manifest_approval_attestation(
    api: GitHubAPI, capsule: SuccessorCapsule
):
    # Preserve the complete historical selection and v1 ambiguity contract.
    selected = _ORIGINAL_REQUIRE_APPROVAL(api, capsule)
    if selected.payload.get("contract") != APPROVAL_ATTESTATION_V2_CONTRACT:
        return selected

    # V2 authority belongs to the exact immutable manifest object, not to the
    # authority record already selected by a downstream capsule. Re-read the
    # public evidence so the selected attestation must still exist unchanged
    # and any newly competing authority for the same manifest fails closed.
    attestations = []
    for comment in _list_operator_comments(api):
        try:
            attestation = parse_manifest_approval_attestation(comment)
        except SuccessorContractError as exc:
            raise SuccessorCapsuleError(str(exc)) from exc
        if attestation is not None:
            attestations.append(attestation)

    current_selected = [
        item
        for item in attestations
        if item.attestation_id == selected.attestation_id
        and item.body_sha256 == selected.body_sha256
    ]
    if len(current_selected) != 1:
        raise SuccessorCapsuleError(
            "SUCCESSOR_APPROVAL_ATTESTATION_NOT_FOUND"
            if not current_selected
            else "SUCCESSOR_APPROVAL_ATTESTATION_AMBIGUOUS"
        )
    selected = current_selected[0]

    manifest_comment_id = selected.payload.get("manifest_comment_id")
    competing = [
        item
        for item in attestations
        if item.payload.get("contract") == APPROVAL_ATTESTATION_V2_CONTRACT
        and item.payload.get("manifest_comment_id") == manifest_comment_id
        and item.payload.get("manifest_sha256") == capsule.manifest_sha256
        and item.attestation_id != selected.attestation_id
    ]
    if competing:
        raise SuccessorCapsuleError("SUCCESSOR_APPROVAL_ATTESTATION_AMBIGUOUS")
    return selected


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

    if isinstance(preflight_projection.manifest, GuardedExecutionManifestV2):
        if (
            preflight_projection.manifest.manifest_comment_id
            != int(preflight_projection.payload["manifest_comment_id"])
        ):
            raise SuccessorCapsuleError(
                "SUCCESSOR_CAPSULE_MANIFEST_IDENTITY_MISMATCH"
            )
    elif (
        capsule.authority["body_sha256"]
        != preflight_projection.manifest.payload["authority"]["body_sha256"]
    ):
        raise SuccessorCapsuleError(
            "SUCCESSOR_CAPSULE_AUTHORITY_BINDING_MISMATCH"
        )

    if projection._matching_invalidation(
        preflight_projection, invalidations
    ) is not None:
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
    attestation = require_current_manifest_approval_attestation(api, capsule)
    validate_capsule_governance(
        capsule,
        preflight_projection.manifest,
        preflight_projection.governance_history,
        attestation,
    )
    _validate_preflight_evidence(
        api,
        capsule,
        current_run_id=current_run_id,
    )
    return preflight_projection


def discover_capsule(*args, **kwargs):
    _sync_v1_globals()
    return _ORIGINAL_DISCOVER(*args, **kwargs)


_PUBLIC_DISCOVER = discover_capsule


def consume_capsule(*args, **kwargs):
    _sync_v1_globals()
    # If a caller/test replaced the public discovery seam, propagate that exact
    # replacement. Otherwise use the historical implementation directly.
    current_discover = globals().get("discover_capsule")
    _v1.discover_capsule = (
        _ORIGINAL_DISCOVER
        if current_discover is _PUBLIC_DISCOVER
        else current_discover
    )
    return _ORIGINAL_CONSUME(*args, **kwargs)
