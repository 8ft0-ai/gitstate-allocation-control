from __future__ import annotations

from . import successor_capsule_v1 as _v1

globals().update(
    {name: getattr(_v1, name) for name in dir(_v1) if not name.startswith("__")}
)

from .governance_state_v2 import GuardedExecutionManifestV2


_validate_public_subject_v1 = _v1.validate_public_subject


def validate_public_subject(
    api: GitHubAPI,
    capsule: SuccessorCapsule,
    *,
    trusted_sha: str,
    current_run_id: int,
):
    comments, _ = preflight_runtime._legacy._read_public_carrier_comments(api)
    preflight_projection, invalidations = projection.parse_projection_history(
        comments,
        expected_projection_comment_id=int(capsule.projection["comment_id"]),
        expected_projection_body_sha256=str(capsule.projection["body_sha256"]),
    )
    if not isinstance(
        preflight_projection.manifest, GuardedExecutionManifestV2
    ):
        return _validate_public_subject_v1(
            api,
            capsule,
            trusted_sha=trusted_sha,
            current_run_id=current_run_id,
        )

    if preflight_projection.manifest_sha256 != capsule.manifest_sha256:
        raise SuccessorCapsuleError("SUCCESSOR_CAPSULE_MANIFEST_MISMATCH")
    if (
        preflight_projection.manifest.manifest_comment_id
        != int(preflight_projection.payload["manifest_comment_id"])
    ):
        raise SuccessorCapsuleError(
            "SUCCESSOR_CAPSULE_MANIFEST_IDENTITY_MISMATCH"
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
    _v1._validate_preflight_evidence(
        api,
        capsule,
        current_run_id=current_run_id,
    )
    return preflight_projection


# Discovery, consumption and successor-runtime import the name from the
# historical module globals. Redirect only that semantic seam.
_v1.validate_public_subject = validate_public_subject
