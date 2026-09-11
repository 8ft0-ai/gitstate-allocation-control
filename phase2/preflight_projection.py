from __future__ import annotations

from dataclasses import replace

from . import preflight_projection_v1 as _v1

globals().update(
    {name: getattr(_v1, name) for name in dir(_v1) if not name.startswith("__")}
)

from .governance_state_v2 import (
    GuardedExecutionManifestV2,
    attach_manifest_comment_id,
)


_parse_projection_comment_v1 = _v1.parse_projection_comment


def parse_projection_comment(
    comment,
    *,
    expected_body_sha256: str | None = None,
):
    projection = _parse_projection_comment_v1(
        comment, expected_body_sha256=expected_body_sha256
    )
    if projection is None or not isinstance(
        projection.manifest, GuardedExecutionManifestV2
    ):
        return projection
    manifest_comment_id = int(projection.payload["manifest_comment_id"])
    manifest = attach_manifest_comment_id(
        projection.manifest, manifest_comment_id
    )
    return replace(projection, manifest=manifest)


# The historical projection-history implementation resolves this name in its
# own module globals. Point it at the additive dispatcher without altering its
# V1 record/history semantics.
_v1.parse_projection_comment = parse_projection_comment
