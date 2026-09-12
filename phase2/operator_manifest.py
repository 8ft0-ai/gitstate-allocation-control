from __future__ import annotations

from . import operator_manifest_v1 as _v1

globals().update(
    {name: getattr(_v1, name) for name in dir(_v1) if not name.startswith("__")}
)

from .operator_manifest_v2 import (
    MANIFEST_V2_CONTRACT,
    MANIFEST_V2_FIELDS,
    ExecutionManifestV2,
    parse_execution_manifest_v2,
)
from .operator_manifest_v3 import (
    MANIFEST_V3_CONTRACT,
    MANIFEST_V3_FIELDS,
    ExecutionManifestV3,
    parse_execution_manifest_v3,
)


def parse_execution_manifest(raw: str, *, expected_sha256: str | None = None):
    value = _v1._strict_json(raw, "MANIFEST_JSON_INVALID")
    if value.get("contract") == MANIFEST_V3_CONTRACT:
        return parse_execution_manifest_v3(raw, expected_sha256=expected_sha256)
    if value.get("contract") == MANIFEST_V2_CONTRACT:
        return parse_execution_manifest_v2(raw, expected_sha256=expected_sha256)
    return _v1.parse_execution_manifest(raw, expected_sha256=expected_sha256)
