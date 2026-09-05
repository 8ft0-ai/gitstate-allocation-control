from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Callable, Mapping

from . import preflight_runtime_legacy as _legacy
from .preflight_carrier_ledger import validate_carrier_ledger

# Re-export the exact reviewed implementation surface so existing callers and
# regressions retain their established imports while this wrapper adds only the
# protected-main carrier-history fence.
for _name in dir(_legacy):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_legacy, _name)


def _carrier_ledger_required(api: object) -> bool:
    return type(api) is GitHubAPI or getattr(
        api, "carrier_ledger_production_test_double", False
    ) is True


def run_preflight(
    values: Mapping[str, str] | None = None,
    *,
    api_factory: Callable[[str, str], GitHubAPI] = GitHubAPI,
    now: datetime | None = None,
) -> dict[str, object]:
    env = os.environ if values is None else values
    (
        trusted_sha,
        run_id,
        run_attempt,
        token,
        projection_comment_id,
        projection_body_sha256,
        expected_manifest_sha256,
    ) = _legacy._context(env)

    api = api_factory(token, env.get("GITHUB_API_URL", "https://api.github.com"))
    comments, public_carrier_snapshot_sha256 = _legacy._read_public_carrier_comments(api)
    preflight_projection, invalidations = projection.parse_projection_history(
        comments,
        expected_projection_comment_id=projection_comment_id,
        expected_projection_body_sha256=projection_body_sha256,
    )
    if preflight_projection.manifest_sha256 != expected_manifest_sha256:
        raise PreflightRuntimeError("PREFLIGHT_MANIFEST_IDENTITY_MISMATCH")
    _legacy._require_execution_variable_identity(preflight_projection)

    # The workflow CLI constructs the exact GitHubAPI provider and therefore
    # always enforces the protected-main ledger. Historical dependency-injected
    # fixtures keep their pre-ledger compatibility path; security regressions
    # opt in explicitly with carrier_ledger_production_test_double = True.
    if _carrier_ledger_required(api):
        validate_carrier_ledger(
            api,
            trusted_sha=trusted_sha,
            projection_comment_id=projection_comment_id,
            projection_body_sha256=projection_body_sha256,
            manifest_sha256=expected_manifest_sha256,
        )

    if projection._matching_invalidation(preflight_projection, invalidations) is not None:
        result = GuardResult.failure("GOVERNANCE_SUPERSEDED")
        record = _legacy._projection_evidence(
            preflight_projection,
            result,
            run_id=run_id,
            run_attempt=run_attempt,
            trusted_sha=trusted_sha,
            public_carrier_snapshot_sha256=public_carrier_snapshot_sha256,
        )
        print(json.dumps(record, sort_keys=True, separators=(",", ":")))
        return record

    validate_workflow_history(
        api,
        preflight_projection.manifest,
        run_id=run_id,
        run_attempt=run_attempt,
        trusted_sha=trusted_sha,
        projection_comment_id=projection_comment_id,
        projection_body_sha256=projection_body_sha256,
        manifest_sha256=expected_manifest_sha256,
    )

    execution_variable_absent = env.get(WORKSTREAM_D_EXECUTION_VARIABLE, "") == ""
    evaluated_at = now or datetime.now(timezone.utc)
    if evaluated_at.tzinfo is None:
        raise PreflightRuntimeError("PREFLIGHT_TIME_INVALID")
    evaluated_at = evaluated_at.astimezone(timezone.utc)
    observation = projection._guard_observation(
        preflight_projection,
        api,
        trusted_sha=trusted_sha,
        evaluated_at=evaluated_at,
        execution_variable_absent=execution_variable_absent,
    )
    result = evaluate_guards(preflight_projection.manifest, observation)
    record = _legacy._projection_evidence(
        preflight_projection,
        result,
        run_id=run_id,
        run_attempt=run_attempt,
        trusted_sha=trusted_sha,
        public_carrier_snapshot_sha256=public_carrier_snapshot_sha256,
    )
    print(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return record


def main() -> int:
    try:
        if len(sys.argv) != 2 or sys.argv[1] != "preflight":
            raise PreflightRuntimeError("PREFLIGHT_COMMAND_REQUIRED")
        record = run_preflight()
        return 0 if record.get("projection_valid") is True else 1
    except Exception as exc:
        print(json.dumps(_legacy._blocked_payload(exc), sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
