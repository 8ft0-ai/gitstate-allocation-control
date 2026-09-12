from __future__ import annotations

from . import successor_contract_v1 as _v1

globals().update(
    {name: getattr(_v1, name) for name in dir(_v1) if not name.startswith("__")}
)

from .governance_state_v2 import (
    GuardedExecutionManifestV2,
    reduce_governance_history_v2,
)


APPROVAL_ATTESTATION_V2_CONTRACT = "gitstate-manifest-approval-attestation/v2"
APPROVAL_ATTESTATION_V2_RESERVED_PREFIX = "/gitstate-manifest-approval-attestation-v2"
APPROVAL_ATTESTATION_V2_PREFIX = APPROVAL_ATTESTATION_V2_RESERVED_PREFIX + " "
EXACT_RECORD_BINDING_FIELDS = frozenset(
    {
        "record_id",
        "body_sha256",
        "manifest_comment_id",
        "manifest_sha256",
    }
)
APPROVAL_ATTESTATION_V2_FIELDS = frozenset(
    {
        "contract",
        "attestation_id",
        "manifest_comment_id",
        "manifest_sha256",
        "authority",
        "approval",
        "disposition",
        "execution_authorised",
        "single_use",
        "workstream_e_authorised",
    }
)


def _parse_exact_record_binding(value, reason: str):
    if not isinstance(value, dict):
        raise SuccessorContractError(reason)
    _v1._require_exact_keys(value, EXACT_RECORD_BINDING_FIELDS, reason)
    _v1._require_hex(value.get("record_id"), OPAQUE_ID, reason)
    _v1._require_hex(value.get("body_sha256"), SHA256, reason)
    _v1._require_int(value.get("manifest_comment_id"), reason)
    _v1._require_hex(value.get("manifest_sha256"), SHA256, reason)
    return _v1._freeze(value)


def _parse_manifest_approval_attestation_v2(comment):
    body = comment.get("body")
    if not isinstance(body, str):
        raise SuccessorContractError(
            "SUCCESSOR_APPROVAL_ATTESTATION_COMMENT_INVALID"
        )
    if not body.startswith(APPROVAL_ATTESTATION_V2_RESERVED_PREFIX):
        return None
    if (
        not body.startswith(APPROVAL_ATTESTATION_V2_PREFIX)
        or "\n" in body
    ):
        raise SuccessorContractError(
            "SUCCESSOR_APPROVAL_ATTESTATION_RESERVED_RECORD_INVALID"
        )
    comment_id, body, body_sha256, created_at = _v1._comment_identity(
        comment,
        owner=GOVERNANCE_OWNER,
        reason="SUCCESSOR_APPROVAL_ATTESTATION",
    )
    value = _v1._strict_json(
        body[len(APPROVAL_ATTESTATION_V2_PREFIX) :],
        "SUCCESSOR_APPROVAL_ATTESTATION_JSON_INVALID",
    )
    _v1._require_exact_keys(
        value,
        APPROVAL_ATTESTATION_V2_FIELDS,
        "SUCCESSOR_APPROVAL_ATTESTATION_SCHEMA_MISMATCH",
    )
    if value.get("contract") != APPROVAL_ATTESTATION_V2_CONTRACT:
        raise SuccessorContractError(
            "SUCCESSOR_APPROVAL_ATTESTATION_CONTRACT_MISMATCH"
        )
    _v1._require_hex(
        value.get("attestation_id"),
        OPAQUE_ID,
        "SUCCESSOR_APPROVAL_ATTESTATION_ID_INVALID",
    )
    manifest_comment_id = _v1._require_int(
        value.get("manifest_comment_id"),
        "SUCCESSOR_APPROVAL_ATTESTATION_MANIFEST_INVALID",
    )
    manifest_sha256 = _v1._require_hex(
        value.get("manifest_sha256"),
        SHA256,
        "SUCCESSOR_APPROVAL_ATTESTATION_MANIFEST_INVALID",
    )
    authority = _parse_exact_record_binding(
        value.get("authority"),
        "SUCCESSOR_APPROVAL_ATTESTATION_AUTHORITY_INVALID",
    )
    approval = _parse_exact_record_binding(
        value.get("approval"),
        "SUCCESSOR_APPROVAL_ATTESTATION_APPROVAL_INVALID",
    )
    for binding in (authority, approval):
        if (
            binding["manifest_comment_id"] != manifest_comment_id
            or binding["manifest_sha256"] != manifest_sha256
        ):
            raise SuccessorContractError(
                "SUCCESSOR_APPROVAL_ATTESTATION_MANIFEST_BINDING_MISMATCH"
            )
    if value.get("disposition") != "approved":
        raise SuccessorContractError(
            "SUCCESSOR_APPROVAL_ATTESTATION_NOT_APPROVED"
        )
    if value.get("execution_authorised") is not True:
        raise SuccessorContractError(
            "SUCCESSOR_APPROVAL_ATTESTATION_AUTHORITY_INVALID"
        )
    if value.get("single_use") is not True:
        raise SuccessorContractError(
            "SUCCESSOR_APPROVAL_ATTESTATION_AUTHORITY_INVALID"
        )
    if value.get("workstream_e_authorised") is not False:
        raise SuccessorContractError("WORKSTREAM_E_NOT_AUTHORISED")
    return ManifestApprovalAttestation(
        _v1._freeze(value), comment_id, body_sha256, created_at
    )


_parse_manifest_approval_attestation_v1 = _v1.parse_manifest_approval_attestation


def parse_manifest_approval_attestation(comment):
    body = comment.get("body")
    if isinstance(body, str) and body.startswith(
        APPROVAL_ATTESTATION_V2_RESERVED_PREFIX
    ):
        return _parse_manifest_approval_attestation_v2(comment)
    return _parse_manifest_approval_attestation_v1(comment)


_validate_capsule_governance_v1 = _v1.validate_capsule_governance


def validate_capsule_governance(
    capsule: SuccessorCapsule,
    manifest,
    base_history: GovernanceHistory,
    attestation: ManifestApprovalAttestation,
) -> GovernanceHistory:
    if not isinstance(manifest, GuardedExecutionManifestV2):
        return _validate_capsule_governance_v1(
            capsule, manifest, base_history, attestation
        )

    if capsule.manifest_sha256 != manifest.sha256:
        raise SuccessorContractError("SUCCESSOR_CAPSULE_MANIFEST_MISMATCH")
    if not isinstance(base_history, GovernanceHistory):
        raise SuccessorContractError("SUCCESSOR_CAPSULE_GOVERNANCE_INVALID")
    if not isinstance(attestation, ManifestApprovalAttestation):
        raise SuccessorContractError(
            "SUCCESSOR_APPROVAL_ATTESTATION_INVALID"
        )

    try:
        reduce_governance_history_v2(
            manifest,
            base_history,
            require_live_authority=False,
        )
    except (GovernanceStateError, TypeError, ValueError) as exc:
        raise SuccessorContractError(
            "SUCCESSOR_CAPSULE_GOVERNANCE_INVALID"
        ) from exc

    manifest_comment_id = manifest.manifest_comment_id
    if type(manifest_comment_id) is not int or manifest_comment_id <= 0:
        raise SuccessorContractError(
            "SUCCESSOR_CAPSULE_MANIFEST_IDENTITY_MISSING"
        )
    if attestation.created_at >= capsule.created_at:
        raise SuccessorContractError(
            "SUCCESSOR_APPROVAL_ATTESTATION_ORDER_INVALID"
        )

    attested = attestation.payload
    if attested.get("contract") != APPROVAL_ATTESTATION_V2_CONTRACT:
        raise SuccessorContractError(
            "SUCCESSOR_APPROVAL_ATTESTATION_CONTRACT_MISMATCH"
        )
    if (
        attested.get("manifest_comment_id") != manifest_comment_id
        or attested.get("manifest_sha256") != manifest.sha256
    ):
        raise SuccessorContractError(
            "SUCCESSOR_APPROVAL_ATTESTATION_MANIFEST_BINDING_MISMATCH"
        )

    approval = capsule.manifest_approval
    authority = capsule.authority
    attested_authority = attested["authority"]
    attested_approval = attested["approval"]
    if (
        attestation.attestation_id != approval["attestation_id"]
        or attestation.body_sha256 != approval["attestation_body_sha256"]
        or attested_authority["record_id"] != authority["record_id"]
        or attested_authority["body_sha256"] != authority["body_sha256"]
        or attested_approval["record_id"] != approval["record_id"]
        or attested_approval["body_sha256"] != approval["body_sha256"]
        or attested_authority["manifest_comment_id"] != manifest_comment_id
        or attested_approval["manifest_comment_id"] != manifest_comment_id
        or attested_authority["manifest_sha256"] != manifest.sha256
        or attested_approval["manifest_sha256"] != manifest.sha256
        or attested.get("disposition") != "approved"
        or attested.get("execution_authorised") is not True
        or attested.get("single_use") is not True
        or attested.get("workstream_e_authorised") is not False
    ):
        raise SuccessorContractError(
            "SUCCESSOR_CAPSULE_APPROVAL_BINDING_MISMATCH"
        )
    return base_history
