from __future__ import annotations

from dataclasses import dataclass

from . import operator_manifest_v1 as _v1
from . import operator_manifest_v2 as _v2


MANIFEST_V3_CONTRACT = "gitstate-live-execution-manifest/v3"
MANIFEST_V3_FIELDS = frozenset(
    field for field in _v2.MANIFEST_V2_FIELDS if field != "readiness"
)


@dataclass(frozen=True)
class ExecutionManifestV3(_v2.ExecutionManifestV2):
    """Additive pre-readiness manifest. Historical v1/v2 remain unchanged."""

    @property
    def readiness(self):
        raise _v1.OperatorContractError("V3_MANIFEST_HAS_NO_READINESS")

    @property
    def authority(self):
        raise _v1.OperatorContractError("V3_MANIFEST_HAS_NO_LIVE_AUTHORITY")


def parse_execution_manifest_v3(
    raw: str, *, expected_sha256: str | None = None
) -> ExecutionManifestV3:
    value = _v1._strict_json(raw, "MANIFEST_JSON_INVALID")
    _v1._require_exact_keys(value, MANIFEST_V3_FIELDS, "MANIFEST_SCHEMA_MISMATCH")
    if value.get("contract") != MANIFEST_V3_CONTRACT:
        raise _v1.OperatorContractError("MANIFEST_CONTRACT_MISMATCH")

    # Reuse the reviewed v2 validation body without changing v2. V3 differs
    # only in sequencing: readiness does not exist at manifest construction.
    synthetic = dict(value)
    synthetic["readiness"] = value.get("proposal")
    _v2._validate_common(synthetic)

    digest = _v1.sha256_text(raw)
    if expected_sha256 is not None:
        _v1._require_hex(
            expected_sha256, _v1.SHA256, "MANIFEST_EXPECTED_DIGEST_INVALID"
        )
        if digest != expected_sha256:
            raise _v1.OperatorContractError("MANIFEST_IDENTITY_MISMATCH")
    return ExecutionManifestV3(_v1._freeze(value), digest)
