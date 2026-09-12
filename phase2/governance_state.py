from __future__ import annotations

from . import governance_state_v1 as _v1

globals().update(
    {name: getattr(_v1, name) for name in dir(_v1) if not name.startswith("__")}
)

from .governance_state_v2 import (
    GuardedExecutionManifestV2,
    GovernanceStateV2,
    attach_manifest_comment_id,
    parse_governance_comment_v2,
    parse_governance_comments_v2,
    parse_guarded_execution_manifest_v2,
    reduce_governance_history_v2,
    validate_governance_history_v2,
)
from .operator_manifest_v2 import MANIFEST_V2_CONTRACT


def parse_guarded_execution_manifest(
    raw: str,
    *,
    expected_sha256: str | None = None,
):
    value = _v1._strict_guarded_json(raw)
    if value.get("contract") == MANIFEST_V2_CONTRACT:
        return parse_guarded_execution_manifest_v2(
            raw, expected_sha256=expected_sha256
        )
    return _v1.parse_guarded_execution_manifest(
        raw, expected_sha256=expected_sha256
    )
