from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

from .credentials import control_profile, state_observation_profile, state_profile
from .governance_state import (
    GovernanceHistory,
    GovernanceStateError,
    GuardedExecutionManifest,
    reduce_governance_history,
)
from .operator_inventory import (
    CONTROL_REPOSITORY_ID,
    INVENTORY_PERMISSIONS,
    STATE_REPOSITORY_ID,
)
from .operator_manifest import (
    GOVERNANCE_OWNER,
    OPAQUE_ID,
    SHA40,
    SHA256,
    HistoryBaseline,
    OperatorHistoryRecord,
    V1_CAPSULE_CONTRACT,
    V1_CONSUMPTION_CONTRACT,
    canonical_json,
    parse_v1_operator_history_comment,
    sha256_text,
)


CAPSULE_CONTRACT = "gitstate-operator/v2"
CONSUMPTION_CONTRACT = "gitstate-consumption/v2"
CAPSULE_PREFIX = "/gitstate-operator-v2 "
CONSUMPTION_PREFIX = "/gitstate-consumption-v2 "
MAX_CAPSULE_LIFETIME = timedelta(hours=1)
CLOCK_SKEW = timedelta(minutes=1)

BINDING_FIELDS = frozenset({"comment_id", "body_sha256"})
RECORD_BINDING_FIELDS = frozenset({"record_id", "body_sha256"})
PREFLIGHT_RUN_FIELDS = frozenset({"run_id", "run_attempt", "trusted_sha"})
APPROVAL_FIELDS = frozenset({"record_id", "body_sha256", "attestation_id", "attestation_body_sha256"})
APPROVAL_ATTESTATION_CONTRACT = "gitstate-manifest-approval-attestation/v1"
APPROVAL_ATTESTATION_PREFIX = "/gitstate-manifest-approval-attestation-v1 "
APPROVAL_ATTESTATION_FIELDS = frozenset(
    {
        "contract",
        "attestation_id",
        "manifest_sha256",
        "authority",
        "approval",
        "disposition",
        "workstream_e_authorised",
    }
)

CAPSULE_FIELDS = frozenset(
    {
        "contract",
        "capsule_id",
        "operation",
        "projection",
        "manifest_sha256",
        "authority",
        "manifest_approval",
        "expected_control_sha",
        "preflight_run",
        "created_at",
        "expires_at",
        "execution_authorised",
        "single_use",
        "workstream_e_authorised",
    }
)
CONSUMPTION_FIELDS = frozenset(
    {
        "contract",
        "capsule_id",
        "capsule_comment_id",
        "capsule_body_sha256",
        "manifest_sha256",
        "run_id",
        "run_attempt",
        "trusted_sha",
        "operation",
        "consumed_at",
        "workstream_e_authorised",
    }
)


class SuccessorContractError(RuntimeError):
    pass


def _duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SuccessorContractError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_float(_: str) -> float:
    raise SuccessorContractError("FLOAT_NOT_SUPPORTED")


def _reject_constant(_: str) -> float:
    raise SuccessorContractError("NONFINITE_NUMBER_NOT_SUPPORTED")


def _require_supported_json(value: Any) -> None:
    if value is None or isinstance(value, float):
        raise SuccessorContractError("UNSUPPORTED_JSON_VALUE")
    if isinstance(value, (str, bool)) or type(value) is int:
        return
    if isinstance(value, list):
        for item in value:
            _require_supported_json(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise SuccessorContractError("UNSUPPORTED_JSON_VALUE")
            _require_supported_json(item)
        return
    raise SuccessorContractError("UNSUPPORTED_JSON_VALUE")


def _strict_json(raw: str, reason: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_duplicate_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except SuccessorContractError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise SuccessorContractError(reason) from exc
    if not isinstance(value, dict):
        raise SuccessorContractError(reason)
    _require_supported_json(value)
    if raw != canonical_json(value):
        raise SuccessorContractError("NONCANONICAL_JSON")
    return value


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _require_exact_keys(
    value: Mapping[str, Any], expected: frozenset[str], reason: str
) -> None:
    if frozenset(value) != expected:
        raise SuccessorContractError(reason)


def _require_int(value: Any, reason: str, *, minimum: int = 1) -> int:
    if type(value) is not int or value < minimum:
        raise SuccessorContractError(reason)
    return value


def _require_string(value: Any, reason: str) -> str:
    if not isinstance(value, str) or not value:
        raise SuccessorContractError(reason)
    return value


def _require_hex(value: Any, pattern, reason: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise SuccessorContractError(reason)
    return value


def _parse_time(value: Any, reason: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise SuccessorContractError(reason)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise SuccessorContractError(reason) from exc
    if parsed.tzinfo is None:
        raise SuccessorContractError(reason)
    return parsed.astimezone(timezone.utc)


def _comment_identity(
    comment: Mapping[str, Any], *, owner: str, reason: str
) -> tuple[int, str, str, datetime]:
    comment_id = _require_int(comment.get("id"), reason)
    body = comment.get("body")
    if not isinstance(body, str):
        raise SuccessorContractError(reason)
    user = comment.get("user")
    if not isinstance(user, Mapping) or user.get("login") != owner:
        raise SuccessorContractError(f"{reason}_WRONG_OWNER")
    created = _parse_time(comment.get("created_at"), f"{reason}_TIME_INVALID")
    updated = _parse_time(comment.get("updated_at"), f"{reason}_TIME_INVALID")
    if created != updated:
        raise SuccessorContractError(f"{reason}_SOURCE_EDITED")
    return comment_id, body, sha256_text(body), created


def _parse_comment_binding(value: Any, reason: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise SuccessorContractError(reason)
    _require_exact_keys(value, BINDING_FIELDS, reason)
    _require_int(value.get("comment_id"), reason)
    _require_hex(value.get("body_sha256"), SHA256, reason)
    return _freeze(value)


def _parse_record_binding(value: Any, reason: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise SuccessorContractError(reason)
    _require_exact_keys(value, RECORD_BINDING_FIELDS, reason)
    _require_hex(value.get("record_id"), OPAQUE_ID, reason)
    _require_hex(value.get("body_sha256"), SHA256, reason)
    return _freeze(value)


@dataclass(frozen=True)
class ManifestApprovalAttestation:
    payload: Mapping[str, Any]
    comment_id: int
    body_sha256: str
    created_at: datetime

    @property
    def attestation_id(self) -> str:
        return str(self.payload["attestation_id"])


def parse_manifest_approval_attestation(
    comment: Mapping[str, Any],
) -> ManifestApprovalAttestation | None:
    body = comment.get("body")
    if not isinstance(body, str):
        raise SuccessorContractError("SUCCESSOR_APPROVAL_ATTESTATION_COMMENT_INVALID")
    reserved_like = body.startswith("/gitstate-manifest-approval-attestation-v1")
    if not reserved_like:
        return None
    if not body.startswith(APPROVAL_ATTESTATION_PREFIX) or "\n" in body:
        raise SuccessorContractError("SUCCESSOR_APPROVAL_ATTESTATION_RESERVED_RECORD_INVALID")

    comment_id, body, body_sha256, created_at = _comment_identity(
        comment, owner=GOVERNANCE_OWNER, reason="SUCCESSOR_APPROVAL_ATTESTATION"
    )
    value = _strict_json(
        body[len(APPROVAL_ATTESTATION_PREFIX):],
        "SUCCESSOR_APPROVAL_ATTESTATION_JSON_INVALID",
    )
    _require_exact_keys(
        value, APPROVAL_ATTESTATION_FIELDS, "SUCCESSOR_APPROVAL_ATTESTATION_SCHEMA_MISMATCH"
    )
    if value.get("contract") != APPROVAL_ATTESTATION_CONTRACT:
        raise SuccessorContractError("SUCCESSOR_APPROVAL_ATTESTATION_CONTRACT_MISMATCH")
    _require_hex(value.get("attestation_id"), OPAQUE_ID, "SUCCESSOR_APPROVAL_ATTESTATION_ID_INVALID")
    _require_hex(value.get("manifest_sha256"), SHA256, "SUCCESSOR_APPROVAL_ATTESTATION_MANIFEST_INVALID")
    _parse_record_binding(value.get("authority"), "SUCCESSOR_APPROVAL_ATTESTATION_AUTHORITY_INVALID")
    _parse_record_binding(value.get("approval"), "SUCCESSOR_APPROVAL_ATTESTATION_APPROVAL_INVALID")
    if value.get("disposition") != "approved":
        raise SuccessorContractError("SUCCESSOR_APPROVAL_ATTESTATION_NOT_APPROVED")
    if value.get("workstream_e_authorised") is not False:
        raise SuccessorContractError("WORKSTREAM_E_NOT_AUTHORISED")
    return ManifestApprovalAttestation(_freeze(value), comment_id, body_sha256, created_at)


@dataclass(frozen=True)
class SuccessorCapsule:
    payload: Mapping[str, Any]
    comment_id: int
    body_sha256: str
    canonical_payload_sha256: str
    created_at: datetime

    @property
    def capsule_id(self) -> str:
        return str(self.payload["capsule_id"])

    @property
    def operation(self) -> str:
        return str(self.payload["operation"])

    @property
    def expected_control_sha(self) -> str:
        return str(self.payload["expected_control_sha"])

    @property
    def manifest_sha256(self) -> str:
        return str(self.payload["manifest_sha256"])

    @property
    def projection(self) -> Mapping[str, Any]:
        return self.payload["projection"]

    @property
    def authority(self) -> Mapping[str, Any]:
        return self.payload["authority"]

    @property
    def manifest_approval(self) -> Mapping[str, Any]:
        return self.payload["manifest_approval"]

    @property
    def preflight_run(self) -> Mapping[str, Any]:
        return self.payload["preflight_run"]

    def runtime_outputs(self, *, run_id: int, run_attempt: int) -> dict[str, str]:
        nonce = sha256_text(
            f"{run_id}:{run_attempt}:{self.capsule_id}:{self.body_sha256}"
        )[:16]
        approval = self.manifest_approval
        authority = self.authority
        projection = self.projection
        return {
            "capsule_id": self.capsule_id,
            "capsule_comment_id": str(self.comment_id),
            "capsule_body_sha256": self.body_sha256,
            "capsule_payload_sha256": self.canonical_payload_sha256,
            "manifest_sha256": self.manifest_sha256,
            "projection_comment_id": str(projection["comment_id"]),
            "projection_body_sha256": str(projection["body_sha256"]),
            "authority_record_id": str(authority["record_id"]),
            "authority_body_sha256": str(authority["body_sha256"]),
            "manifest_approval_record_id": str(approval["record_id"]),
            "manifest_approval_body_sha256": str(approval["body_sha256"]),
            "expected_control_sha": self.expected_control_sha,
            "operation_profile": self.operation,
            "attempt_nonce": nonce,
        }


@dataclass(frozen=True)
class SuccessorConsumption:
    payload: Mapping[str, Any]
    comment_id: int
    body_sha256: str

    @property
    def capsule_id(self) -> str:
        return str(self.payload["capsule_id"])


def parse_capsule_comment(
    comment: Mapping[str, Any],
    *,
    now: datetime | None,
    expected_control_sha: str | None = None,
    expected_operation: str | None = None,
) -> SuccessorCapsule | None:
    body = comment.get("body")
    if not isinstance(body, str):
        raise SuccessorContractError("SUCCESSOR_CAPSULE_COMMENT_INVALID")
    reserved_like = body.startswith("/gitstate-operator-v2")
    if not reserved_like:
        return None
    if not body.startswith(CAPSULE_PREFIX) or "\n" in body:
        raise SuccessorContractError("SUCCESSOR_CAPSULE_RESERVED_RECORD_INVALID")

    comment_id, body, body_sha256, comment_created = _comment_identity(
        comment,
        owner=GOVERNANCE_OWNER,
        reason="SUCCESSOR_CAPSULE",
    )
    value = _strict_json(
        body[len(CAPSULE_PREFIX) :],
        "SUCCESSOR_CAPSULE_JSON_INVALID",
    )
    _require_exact_keys(value, CAPSULE_FIELDS, "SUCCESSOR_CAPSULE_SCHEMA_MISMATCH")
    if value.get("contract") != CAPSULE_CONTRACT:
        raise SuccessorContractError("SUCCESSOR_CAPSULE_CONTRACT_MISMATCH")
    _require_hex(value.get("capsule_id"), OPAQUE_ID, "SUCCESSOR_CAPSULE_ID_INVALID")
    operation = _require_string(
        value.get("operation"), "SUCCESSOR_CAPSULE_OPERATION_INVALID"
    )
    projection = _parse_comment_binding(
        value.get("projection"), "SUCCESSOR_CAPSULE_PROJECTION_INVALID"
    )
    del projection
    _require_hex(
        value.get("manifest_sha256"),
        SHA256,
        "SUCCESSOR_CAPSULE_MANIFEST_INVALID",
    )
    _parse_record_binding(
        value.get("authority"), "SUCCESSOR_CAPSULE_AUTHORITY_INVALID"
    )

    approval = value.get("manifest_approval")
    if not isinstance(approval, dict):
        raise SuccessorContractError("SUCCESSOR_CAPSULE_APPROVAL_INVALID")
    _require_exact_keys(approval, APPROVAL_FIELDS, "SUCCESSOR_CAPSULE_APPROVAL_INVALID")
    _require_hex(approval.get("record_id"), OPAQUE_ID, "SUCCESSOR_CAPSULE_APPROVAL_INVALID")
    _require_hex(approval.get("body_sha256"), SHA256, "SUCCESSOR_CAPSULE_APPROVAL_INVALID")
    _require_hex(approval.get("attestation_id"), OPAQUE_ID, "SUCCESSOR_CAPSULE_APPROVAL_INVALID")
    _require_hex(approval.get("attestation_body_sha256"), SHA256, "SUCCESSOR_CAPSULE_APPROVAL_INVALID")

    expected_control = _require_hex(
        value.get("expected_control_sha"),
        SHA40,
        "SUCCESSOR_CAPSULE_CONTROL_SHA_INVALID",
    )
    preflight = value.get("preflight_run")
    if not isinstance(preflight, dict):
        raise SuccessorContractError("SUCCESSOR_CAPSULE_PREFLIGHT_INVALID")
    _require_exact_keys(
        preflight, PREFLIGHT_RUN_FIELDS, "SUCCESSOR_CAPSULE_PREFLIGHT_INVALID"
    )
    _require_int(preflight.get("run_id"), "SUCCESSOR_CAPSULE_PREFLIGHT_INVALID")
    if preflight.get("run_attempt") != 1:
        raise SuccessorContractError("SUCCESSOR_CAPSULE_PREFLIGHT_INVALID")
    preflight_sha = _require_hex(
        preflight.get("trusted_sha"), SHA40, "SUCCESSOR_CAPSULE_PREFLIGHT_INVALID"
    )
    if preflight_sha != expected_control:
        raise SuccessorContractError("SUCCESSOR_CAPSULE_PREFLIGHT_CONTROL_MISMATCH")

    created = _parse_time(value.get("created_at"), "SUCCESSOR_CAPSULE_TIME_INVALID")
    expires = _parse_time(value.get("expires_at"), "SUCCESSOR_CAPSULE_TIME_INVALID")
    if expires <= created or expires - created > MAX_CAPSULE_LIFETIME:
        raise SuccessorContractError("SUCCESSOR_CAPSULE_TIME_INVALID")
    if comment_created + CLOCK_SKEW < created or comment_created > expires:
        raise SuccessorContractError("SUCCESSOR_CAPSULE_TIME_INVALID")
    if now is not None:
        current = now.astimezone(timezone.utc)
        if current + CLOCK_SKEW < created:
            raise SuccessorContractError("SUCCESSOR_CAPSULE_NOT_YET_VALID")
        if current >= expires:
            raise SuccessorContractError("SUCCESSOR_CAPSULE_EXPIRED")

    if value.get("execution_authorised") is not True:
        raise SuccessorContractError("SUCCESSOR_CAPSULE_EXECUTION_AUTHORITY_REQUIRED")
    if value.get("single_use") is not True:
        raise SuccessorContractError("SUCCESSOR_CAPSULE_SINGLE_USE_REQUIRED")
    if value.get("workstream_e_authorised") is not False:
        raise SuccessorContractError("WORKSTREAM_E_NOT_AUTHORISED")
    if expected_control_sha is not None and expected_control != expected_control_sha:
        raise SuccessorContractError("SUCCESSOR_CAPSULE_STALE_CONTROL_SHA")
    if expected_operation is not None and operation != expected_operation:
        raise SuccessorContractError("SUCCESSOR_CAPSULE_OPERATION_MISMATCH")

    canonical_payload = canonical_json(value)
    return SuccessorCapsule(
        _freeze(value),
        comment_id,
        body_sha256,
        sha256_text(canonical_payload),
        comment_created,
    )


def parse_consumption_comment(
    comment: Mapping[str, Any],
) -> SuccessorConsumption | None:
    body = comment.get("body")
    if not isinstance(body, str):
        raise SuccessorContractError("SUCCESSOR_CONSUMPTION_COMMENT_INVALID")
    reserved_like = body.startswith("/gitstate-consumption-v2")
    if not reserved_like:
        return None
    if not body.startswith(CONSUMPTION_PREFIX) or "\n" in body:
        raise SuccessorContractError("SUCCESSOR_CONSUMPTION_RESERVED_RECORD_INVALID")

    comment_id, body, body_sha256, _ = _comment_identity(
        comment,
        owner="github-actions[bot]",
        reason="SUCCESSOR_CONSUMPTION",
    )
    value = _strict_json(
        body[len(CONSUMPTION_PREFIX) :],
        "SUCCESSOR_CONSUMPTION_JSON_INVALID",
    )
    _require_exact_keys(
        value, CONSUMPTION_FIELDS, "SUCCESSOR_CONSUMPTION_SCHEMA_MISMATCH"
    )
    if value.get("contract") != CONSUMPTION_CONTRACT:
        raise SuccessorContractError("SUCCESSOR_CONSUMPTION_CONTRACT_MISMATCH")
    _require_hex(
        value.get("capsule_id"), OPAQUE_ID, "SUCCESSOR_CONSUMPTION_CAPSULE_INVALID"
    )
    _require_int(
        value.get("capsule_comment_id"),
        "SUCCESSOR_CONSUMPTION_CAPSULE_INVALID",
    )
    _require_hex(
        value.get("capsule_body_sha256"),
        SHA256,
        "SUCCESSOR_CONSUMPTION_CAPSULE_INVALID",
    )
    _require_hex(
        value.get("manifest_sha256"),
        SHA256,
        "SUCCESSOR_CONSUMPTION_MANIFEST_INVALID",
    )
    _require_int(value.get("run_id"), "SUCCESSOR_CONSUMPTION_RUN_INVALID")
    if value.get("run_attempt") != 1:
        raise SuccessorContractError("SUCCESSOR_CONSUMPTION_RUN_INVALID")
    _require_hex(
        value.get("trusted_sha"), SHA40, "SUCCESSOR_CONSUMPTION_CONTROL_SHA_INVALID"
    )
    _require_string(
        value.get("operation"), "SUCCESSOR_CONSUMPTION_OPERATION_INVALID"
    )
    _parse_time(value.get("consumed_at"), "SUCCESSOR_CONSUMPTION_TIME_INVALID")
    if value.get("workstream_e_authorised") is not False:
        raise SuccessorContractError("WORKSTREAM_E_NOT_AUTHORISED")
    return SuccessorConsumption(_freeze(value), comment_id, body_sha256)


def validate_capsule_governance(
    capsule: SuccessorCapsule,
    manifest: GuardedExecutionManifest,
    base_history: GovernanceHistory,
    attestation: ManifestApprovalAttestation,
) -> GovernanceHistory:
    if capsule.manifest_sha256 != manifest.sha256:
        raise SuccessorContractError("SUCCESSOR_CAPSULE_MANIFEST_MISMATCH")
    if not isinstance(base_history, GovernanceHistory):
        raise SuccessorContractError("SUCCESSOR_CAPSULE_GOVERNANCE_INVALID")
    if not isinstance(attestation, ManifestApprovalAttestation):
        raise SuccessorContractError("SUCCESSOR_APPROVAL_ATTESTATION_INVALID")

    try:
        state = reduce_governance_history(manifest, base_history)
    except (GovernanceStateError, TypeError, ValueError) as exc:
        raise SuccessorContractError("SUCCESSOR_CAPSULE_GOVERNANCE_INVALID") from exc

    authority_matches = [
        source for source in base_history.sources
        if source.comment_id == manifest.authority.comment_id
        and sha256_text(source.body) == capsule.authority["body_sha256"]
    ]
    approval = capsule.manifest_approval
    attested = attestation.payload
    if attestation.created_at > capsule.created_at:
        raise SuccessorContractError("SUCCESSOR_APPROVAL_ATTESTATION_ORDER_INVALID")
    if state.approval_status in {"ambiguous", "rejected"}:
        raise SuccessorContractError("SUCCESSOR_CAPSULE_APPROVAL_NOT_ACTIVE")
    if state.approval_status == "approved" and (
        state.active_approval is None
        or state.active_approval.record_id != approval["record_id"]
        or state.active_approval.body_sha256 != approval["body_sha256"]
    ):
        raise SuccessorContractError("SUCCESSOR_CAPSULE_APPROVAL_BINDING_MISMATCH")
    if len(authority_matches) != 1:
        raise SuccessorContractError("SUCCESSOR_CAPSULE_GOVERNANCE_BINDING_MISMATCH")
    if state.authority_status != "active":
        raise SuccessorContractError("SUCCESSOR_CAPSULE_AUTHORITY_NOT_ACTIVE")
    if state.authority.record_id != capsule.authority["record_id"]:
        raise SuccessorContractError("SUCCESSOR_CAPSULE_AUTHORITY_BINDING_MISMATCH")
    if (
        attestation.attestation_id != approval["attestation_id"]
        or attestation.body_sha256 != approval["attestation_body_sha256"]
        or attested["manifest_sha256"] != capsule.manifest_sha256
        or attested["authority"]["record_id"] != capsule.authority["record_id"]
        or attested["authority"]["body_sha256"] != capsule.authority["body_sha256"]
        or attested["approval"]["record_id"] != approval["record_id"]
        or attested["approval"]["body_sha256"] != approval["body_sha256"]
        or attested["disposition"] != "approved"
        or attested["workstream_e_authorised"] is not False
    ):
        raise SuccessorContractError("SUCCESSOR_CAPSULE_APPROVAL_BINDING_MISMATCH")
    return base_history


def _v2_history_record(comment: Mapping[str, Any]) -> OperatorHistoryRecord | None:
    body = comment.get("body")
    if not isinstance(body, str):
        raise SuccessorContractError("OPERATOR_HISTORY_COMMENT_INVALID")
    if body.startswith("/gitstate-operator-v2"):
        capsule = parse_capsule_comment(comment, now=None)
        if capsule is None:
            raise SuccessorContractError("OPERATOR_HISTORY_RESERVED_RECORD_INVALID")
        return OperatorHistoryRecord(
            comment_id=capsule.comment_id,
            record_kind=CAPSULE_CONTRACT,
            body_sha256=capsule.body_sha256,
            capsule_id=capsule.capsule_id,
            trusted_sha=capsule.expected_control_sha,
            operation=capsule.operation,
            manifest_sha256=capsule.manifest_sha256,
        )
    if body.startswith("/gitstate-consumption-v2"):
        consumption = parse_consumption_comment(comment)
        if consumption is None:
            raise SuccessorContractError("OPERATOR_HISTORY_RESERVED_RECORD_INVALID")
        payload = consumption.payload
        return OperatorHistoryRecord(
            comment_id=consumption.comment_id,
            record_kind=CONSUMPTION_CONTRACT,
            body_sha256=consumption.body_sha256,
            capsule_id=str(payload["capsule_id"]),
            trusted_sha=str(payload["trusted_sha"]),
            operation=str(payload["operation"]),
            capsule_comment_id=int(payload["capsule_comment_id"]),
            capsule_body_sha256=str(payload["capsule_body_sha256"]),
            run_id=int(payload["run_id"]),
            run_attempt=int(payload["run_attempt"]),
            manifest_sha256=str(payload["manifest_sha256"]),
        )
    return None


def parse_operator_history(
    comments: Iterable[Mapping[str, Any]],
    *,
    require_closed: bool = True,
) -> tuple[OperatorHistoryRecord, ...]:
    records: list[OperatorHistoryRecord] = []
    for comment in comments:
        try:
            v1 = parse_v1_operator_history_comment(comment)
        except OperatorContractError as exc:
            raise SuccessorContractError(str(exc)) from exc
        if v1 is not None:
            records.append(v1)
            continue
        v2 = _v2_history_record(comment)
        if v2 is not None:
            records.append(v2)

    ordered = tuple(sorted(records, key=lambda item: item.comment_id))
    validate_operator_history(ordered, require_closed=require_closed)
    return ordered


def validate_operator_history(
    records: Sequence[OperatorHistoryRecord],
    *,
    require_closed: bool = True,
) -> None:
    capsule_kinds = {V1_CAPSULE_CONTRACT, CAPSULE_CONTRACT}
    consumption_for = {
        V1_CAPSULE_CONTRACT: V1_CONSUMPTION_CONTRACT,
        CAPSULE_CONTRACT: CONSUMPTION_CONTRACT,
    }
    comment_ids: set[int] = set()
    capsules: dict[str, OperatorHistoryRecord] = {}
    consumed: set[str] = set()
    run_attempts: set[tuple[int, int]] = set()

    for record in sorted(records, key=lambda item: item.comment_id):
        if record.comment_id <= 0 or record.comment_id in comment_ids:
            raise SuccessorContractError("OPERATOR_HISTORY_DUPLICATE_COMMENT")
        comment_ids.add(record.comment_id)
        if record.record_kind in capsule_kinds:
            if record.capsule_id in capsules:
                raise SuccessorContractError("OPERATOR_HISTORY_DUPLICATE_CAPSULE")
            capsules[record.capsule_id] = record
            continue

        capsule = capsules.get(record.capsule_id)
        if capsule is None:
            raise SuccessorContractError("OPERATOR_HISTORY_ORPHAN_CONSUMPTION")
        if record.record_kind != consumption_for[capsule.record_kind]:
            raise SuccessorContractError("OPERATOR_HISTORY_CONSUMPTION_VERSION_MISMATCH")
        if record.capsule_id in consumed:
            raise SuccessorContractError("OPERATOR_HISTORY_DUPLICATE_CONSUMPTION")
        if (
            record.capsule_comment_id != capsule.comment_id
            or record.capsule_body_sha256 != capsule.body_sha256
            or record.trusted_sha != capsule.trusted_sha
            or record.operation != capsule.operation
            or (
                capsule.record_kind == CAPSULE_CONTRACT
                and (
                    capsule.manifest_sha256 is None
                    or record.manifest_sha256 is None
                    or record.manifest_sha256 != capsule.manifest_sha256
                )
            )
            or record.run_attempt != 1
            or record.run_id is None
        ):
            raise SuccessorContractError("OPERATOR_HISTORY_CONSUMPTION_MISMATCH")
        run_key = (record.run_id, record.run_attempt)
        if run_key in run_attempts:
            raise SuccessorContractError("OPERATOR_HISTORY_DUPLICATE_RUN_ATTEMPT")
        run_attempts.add(run_key)
        consumed.add(record.capsule_id)

    if require_closed and set(capsules) - consumed:
        raise SuccessorContractError("OPERATOR_HISTORY_UNCONSUMED_CAPSULE")


def canonical_operator_history(
    records: Sequence[OperatorHistoryRecord],
    *,
    through_comment_id: int | None = None,
) -> str:
    selected = tuple(
        record
        for record in sorted(records, key=lambda item: item.comment_id)
        if through_comment_id is None or record.comment_id <= through_comment_id
    )
    validate_operator_history(selected, require_closed=True)
    return "".join(
        f"{record.comment_id}\t{record.record_kind}\t{record.body_sha256}\n"
        for record in selected
    )


def operator_history_baseline(
    records: Sequence[OperatorHistoryRecord],
    *,
    through_comment_id: int | None = None,
) -> HistoryBaseline:
    selected = tuple(
        record
        for record in sorted(records, key=lambda item: item.comment_id)
        if through_comment_id is None or record.comment_id <= through_comment_id
    )
    canonical = canonical_operator_history(
        selected,
        through_comment_id=None,
    )
    through = max((record.comment_id for record in selected), default=0)
    return HistoryBaseline(through, sha256_text(canonical))


def permission_profile_sha256() -> str:
    control = control_profile(CONTROL_REPOSITORY_ID)
    state = state_profile(STATE_REPOSITORY_ID)
    value = {
        "contract": "gitstate-live-permission-profile/v1",
        "inventory": {
            "repository_scope": "installation-selected-set",
            "permissions": dict(INVENTORY_PERMISSIONS),
        },
        "control": {
            "repository_id": CONTROL_REPOSITORY_ID,
            "permissions": dict(control.permissions),
        },
        "state_observation": {
            "repository_id": STATE_REPOSITORY_ID,
            "permissions": dict(state_observation_profile(STATE_REPOSITORY_ID).permissions),
        },
        "state": {
            "repository_id": STATE_REPOSITORY_ID,
            "permissions": dict(state.permissions),
        },
    }
    return sha256_text(canonical_json(value))
