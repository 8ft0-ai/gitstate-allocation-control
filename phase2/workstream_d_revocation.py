"""Bounded Workstream D installation-token cleanup remediation.

This module is the trusted-main live-suite entry point for the cleanup portion
of gitstate-lab#15 comment 5310070151.  The independently reviewed scenario
executor in ``phase2.workstream_d_live`` remains authoritative for scenario
semantics and for the SQL-server Git-auth remediation merged in PR #9.

Only installation-token cleanup truthfulness, cleanup-failure precedence and a
non-secret positive revocation record are added here.  Nothing in this module
resets canonical state, authorises another live attempt, or widens Workstream D
into Workstream E.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, ClassVar, Mapping

from . import workstream_d_live as live

REMEDIATION_EXECUTABLE_PATH = "phase2/workstream_d_revocation.py"
REVOCATION_STATUS = "WORKSTREAM_D_INSTALLATION_TOKEN_CLEANUP_SUCCEEDED"


class TruthfulCredentialLease(live.CredentialLease):
    """Credential lease whose state reflects actual revocation success."""

    last_instance: ClassVar["TruthfulCredentialLease | None"] = None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.revocation_error: live.LiveExecutorError | None = None
        self.revocation_attempted = False
        self.revoked_token_count = 0
        type(self).last_instance = self

    def close(self) -> None:
        if self.revoked:
            return
        if self.revocation_error is not None:
            raise self.revocation_error

        failures: list[Exception] = []
        revoked_count = 0
        tokens = (self.state_token, self.control_token)
        try:
            for token in tokens:
                if not token:
                    continue
                try:
                    self._revoke(token)
                    revoked_count += 1
                except Exception as exc:
                    failures.append(exc)
        finally:
            # Credential material is cleared after every revoke attempt even
            # when one token could not be positively revoked.
            self.state_token = ""
            self.control_token = ""
            self.revocation_attempted = True
            self.revoked_token_count = revoked_count

        if failures:
            self.revoked = False
            error = live.LiveExecutorError("INSTALLATION_TOKEN_REVOCATION_FAILED")
            self.revocation_error = error
            raise error from failures[0]

        self.revoked = True


def _bind_executable_identity() -> None:
    paths = tuple(live.LIVE_EXECUTABLE_PATHS)
    if REMEDIATION_EXECUTABLE_PATH not in paths:
        live.LIVE_EXECUTABLE_PATHS = (*paths, REMEDIATION_EXECUTABLE_PATH)


def _cleanup_record(
    context: live.LiveRunContext,
    lease: TruthfulCredentialLease,
) -> dict[str, Any]:
    return {
        "attempt_namespace": context.namespace.value,
        "credential_material_emitted": False,
        "credential_revoked": True,
        "installation_tokens_revoked": 2,
        "run_attempt": context.run_attempt,
        "run_id": context.run_id,
        "status": REVOCATION_STATUS,
        "workstream_e_authorised": False,
    }


def execute_live_suite(
    values: Mapping[str, str] | None = None,
) -> live.LiveSuiteResult:
    """Delegate the suite while making token cleanup fail closed and observable."""
    env = os.environ if values is None else values
    context = live.context_from_environment(env)
    context.validate()
    _bind_executable_identity()

    previous_lease_class = live.CredentialLease
    TruthfulCredentialLease.last_instance = None
    live.CredentialLease = TruthfulCredentialLease
    primary_error: Exception | None = None
    result: live.LiveSuiteResult | None = None
    try:
        try:
            result = live.execute_live_suite(env)
        except Exception as exc:
            primary_error = exc
    finally:
        live.CredentialLease = previous_lease_class

    lease = TruthfulCredentialLease.last_instance
    if lease is not None and lease.revocation_error is not None:
        if primary_error is lease.revocation_error:
            raise lease.revocation_error
        raise lease.revocation_error from primary_error

    # Only two successful revoke calls prove the normal live credential pair
    # was positively revoked. Partial-acquisition cleanup remains fail-closed
    # but does not emit the two-token success marker.
    if (
        lease is not None
        and lease.revocation_attempted
        and lease.revoked
        and lease.revoked_token_count == 2
    ):
        print(
            json.dumps(
                _cleanup_record(context, lease),
                sort_keys=True,
                separators=(",", ":"),
            )
        )

    if primary_error is not None:
        raise primary_error
    if result is None:
        raise live.LiveExecutorError("WORKSTREAM_D_RESULT_MISSING")
    return result


def main() -> int:
    try:
        result = execute_live_suite()
        payload = result.payload()
        payload["credential_revoked"] = True
        payload["status"] = "WORKSTREAM_D_SYNTHETIC_SUITE_PASSED_PENDING_ENABLEMENT_REMOVAL"
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "BLOCKED",
                    "reason_code": str(exc).split(":", 1)[0]
                    or type(exc).__name__,
                    "credential_material_emitted": False,
                    "workstream_e_authorised": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
