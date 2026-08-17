"""Bounded Workstream D live-suite remediation wrapper.

This module is the trusted-main live-suite entry point for the cleanup portion
of gitstate-lab#15 comment 5310070151 and the canonical-anchor recovery
remediation authorised in gitstate-lab#27.

The independently reviewed scenario executor in ``phase2.workstream_d_live``
remains authoritative for scenario semantics.  This wrapper adds only:
- truthful installation-token cleanup and positive revocation evidence; and
- a bounded adapter for recoverable metadata-only canonical-anchor contention.

The first successful request/allocation CAS remains the ownership commit point.
A failed subsequent anchor write never rolls ownership back.  Recovery verifies
the original request-creation identity from accepted first-parent Git/Dolt
history, then delegates the repair to the existing Workstream C reconciliation
anchor path.  Nothing here resets canonical state, authorises another live
attempt, changes token profiles, or widens Workstream D into Workstream E.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, ClassVar, Mapping, Sequence

from . import workstream_d_live as live
from .canonical import CanonicalIdentity
from .reconciliation import ReconciliationError, ReconciliationService

REMEDIATION_EXECUTABLE_PATH = "phase2/workstream_d_revocation.py"
REVOCATION_STATUS = "WORKSTREAM_D_INSTALLATION_TOKEN_CLEANUP_SUCCEEDED"
ANCHOR_MAX_STALE_RETRIES = 3
ANCHOR_FAILURE_CODES = frozenset(
    {"CANONICAL_PUSH_FAILED", "STALE_ALLOCATOR_RETRY_EXHAUSTED"}
)


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


def _credential_free_history_env() -> dict[str, str]:
    env = live._credential_free_git_env()
    for key in (
        "PHASE2_ALLOCATOR_APP_PRIVATE_KEY",
        "PHASE2_OWNER_INVENTORY_ATTESTATION_B64",
    ):
        env.pop(key, None)
    return env


def _history_run(
    command: Sequence[str], cwd: Path
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=cwd,
        env=_credential_free_history_env(),
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _history_snapshot(
    backend: live.LiveFixtureBackend,
    remote: Path,
    target_sha: str,
    *,
    root: Path,
):
    updated = _history_run(
        ["git", "--git-dir", str(remote), "update-ref", "refs/dolt/data", target_sha],
        root,
    )
    if updated.returncode != 0:
        raise ReconciliationError("CANONICAL_HISTORY_REF_PIN_FAILED")

    workspace_root = root / "history-workspaces"
    workspace_root.mkdir(exist_ok=True)
    repository = live.DoltCanonicalRepository(
        "git+file://" + str(remote),
        lambda database: live.ManagedDoltConnection(
            database, backend.repository.dolt_bin
        ),
        dolt_bin=backend.repository.dolt_bin,
        run_command=_history_run,
        workspace_root=workspace_root,
    )
    return repository, repository.bootstrap()


def _verified_creation_identity(
    backend: live.LiveFixtureBackend,
    request_id: str,
    expected_git_sha: str,
    expected_dolt_commit: str,
) -> CanonicalIdentity:
    """Prove the request's first accepted Git/Dolt revision from a read-only mirror."""

    if backend.read_only_remote_factory is None:
        raise ReconciliationError("CANONICAL_HISTORY_TRANSPORT_MISSING")

    with tempfile.TemporaryDirectory(prefix="wd-anchor-history-") as directory:
        root = Path(directory)
        mirror, current_sha = backend.read_only_remote_factory(root)
        try:
            env = _credential_free_history_env()
            first_parent_output = live._run(
                [
                    "git",
                    "--git-dir",
                    str(mirror),
                    "rev-list",
                    "--first-parent",
                    current_sha,
                ],
                cwd=root,
                env=env,
            )
            first_parent = tuple(
                line.strip() for line in first_parent_output.splitlines() if line.strip()
            )
            if expected_git_sha not in first_parent:
                raise ReconciliationError(
                    "CANONICAL_HISTORY_CREATION_NOT_FIRST_PARENT"
                )

            creation_index = first_parent.index(expected_git_sha)
            if creation_index + 1 >= len(first_parent):
                raise ReconciliationError("CANONICAL_HISTORY_CREATION_PARENT_MISSING")
            parent_sha = first_parent[creation_index + 1]

            writable_remote = root / "history.git"
            cloned = _history_run(
                ["git", "clone", "--mirror", str(mirror), str(writable_remote)],
                root,
            )
            if cloned.returncode != 0:
                raise ReconciliationError("CANONICAL_HISTORY_MIRROR_CLONE_FAILED")

            creation_repository, creation = _history_snapshot(
                backend,
                writable_remote,
                expected_git_sha,
                root=root,
            )
            try:
                if (
                    creation.identity.git_ref_sha != expected_git_sha
                    or creation.identity.dolt_commit != expected_dolt_commit
                ):
                    raise ReconciliationError(
                        "CANONICAL_HISTORY_CREATION_IDENTITY_MISMATCH"
                    )
                creation_row = creation_repository.store(creation).get_request(request_id)
                if creation_row is None:
                    raise ReconciliationError(
                        "CANONICAL_HISTORY_CREATION_REQUEST_MISSING"
                    )
            finally:
                creation.close()

            parent_repository, parent = _history_snapshot(
                backend,
                writable_remote,
                parent_sha,
                root=root,
            )
            try:
                if parent_repository.store(parent).get_request(request_id) is not None:
                    raise ReconciliationError(
                        "CANONICAL_HISTORY_REQUEST_PREDATES_CREATION"
                    )
            finally:
                parent.close()

            return CanonicalIdentity(
                "refs/dolt/data",
                expected_git_sha,
                expected_dolt_commit,
            )
        finally:
            live._set_tree_read_only(mirror, read_only=False)


class _TargetedAnchorReconciler(ReconciliationService):
    """Use the accepted Workstream C repair path with a Git/Dolt-proved identity."""

    def __init__(
        self,
        backend: live.LiveFixtureBackend,
        request_id: str,
        creation_git_sha: str,
        creation_dolt_commit: str,
    ) -> None:
        super().__init__(
            backend.repository,
            backend.gateway,
            control_repository=live.CONTROL_REPOSITORY,
            issue_number=backend.issue_number,
            task_summary_lookup=lambda task_id: f"synthetic fixture {task_id}",
            canonical_history=live._HistoryStub(),
            clock=lambda: live.NOW,
            max_stale_retries=ANCHOR_MAX_STALE_RETRIES,
        )
        self._backend = backend
        self._target_request_id = request_id
        self._creation_git_sha = creation_git_sha
        self._creation_dolt_commit = creation_dolt_commit

    def _allocation_creation_anchor(self, request_id: str) -> CanonicalIdentity | None:
        if request_id != self._target_request_id:
            raise ReconciliationError("CANONICAL_HISTORY_REQUEST_MISMATCH")
        return _verified_creation_identity(
            self._backend,
            request_id,
            self._creation_git_sha,
            self._creation_dolt_commit,
        )


def _require_recorded_anchor(
    backend: live.LiveFixtureBackend,
    request_id: str,
    creation_git_sha: str,
    creation_dolt_commit: str,
) -> None:
    row = backend._request_row(request_id)
    if row is None:
        raise live.LiveExecutorError("CANONICAL_ANCHOR_REQUEST_MISSING")
    if row.get("anchor_status") != "RECORDED":
        raise live.LiveExecutorError("CANONICAL_ANCHOR_RECONCILIATION_INCOMPLETE")
    if (
        row.get("canonical_git_ref_sha") != creation_git_sha
        or row.get("canonical_dolt_commit") != creation_dolt_commit
    ):
        raise live.LiveExecutorError("CANONICAL_ANCHOR_RECONCILIATION_MISMATCH")


def _repair_pending_anchor(
    backend: live.LiveFixtureBackend,
    request_id: str,
    creation_git_sha: str,
    creation_dolt_commit: str,
) -> None:
    reconciler = _TargetedAnchorReconciler(
        backend,
        request_id,
        creation_git_sha,
        creation_dolt_commit,
    )
    try:
        repaired = reconciler._repair_anchor(request_id)
    except ReconciliationError as exc:
        raise live.LiveExecutorError(
            "CANONICAL_ANCHOR_RECONCILIATION_FAILED"
        ) from exc
    if not repaired:
        raise live.LiveExecutorError("CANONICAL_ANCHOR_RECONCILIATION_MISSING")
    _require_recorded_anchor(
        backend,
        request_id,
        creation_git_sha,
        creation_dolt_commit,
    )


def _process_with_anchor_recovery(
    self: live.LiveFixtureBackend,
    scenario: int,
    index: int,
    *,
    request_type: str,
    task_id: str | None = None,
    allocation_id: str | None = None,
    request_id: str | None = None,
    payload_variant: str = "",
    reason: str | None = None,
    project: bool = True,
    source_override: tuple[int, str] | None = None,
) -> live._ResultRecord:
    """Preserve the accepted process→anchor→projection contract under contention."""

    if payload_variant:
        raise live.LiveExecutorError("UNSUPPORTED_PROTOCOL_PAYLOAD_VARIANT")
    rid, body, payload_hash = live._protocol_request_contract(
        self.namespace,
        scenario,
        index,
        request_type=request_type,
        task_id=task_id,
        allocation_id=allocation_id,
        request_id=request_id,
        reason=reason,
    )
    source_id, source_url = source_override or self._post_body(body)
    command = live.AllocationCommand(
        request_id=rid,
        request_type=request_type,
        payload_hash=payload_hash,
        agent_id=self.agent_id,
        task_id=task_id,
        allocation_id=allocation_id,
        reason=reason,
        task_types=("task",) if request_type == "ALLOCATE_NEXT" else (),
    )
    context = live.RequestContext(
        live.CONTROL_REPOSITORY,
        self.issue_number,
        source_id,
        "fixture:gitstate-phase-2-allocator",
        self.agent_id,
    )
    service = live.AllocationService(
        self.repository,
        clock=lambda: live.NOW,
        max_stale_retries=ANCHOR_MAX_STALE_RETRIES,
    )
    result = service.process(command, context)
    if not result.canonical_git_ref_sha or not result.canonical_dolt_commit:
        raise live.LiveExecutorError("CANONICAL_RESULT_IDENTITY_MISSING")

    if result.ref_advanced:
        anchor = service.record_anchor(
            rid,
            result.canonical_git_ref_sha,
            result.canonical_dolt_commit,
        )
        if anchor.reason_code in ANCHOR_FAILURE_CODES:
            _repair_pending_anchor(
                self,
                rid,
                result.canonical_git_ref_sha,
                result.canonical_dolt_commit,
            )
        else:
            _require_recorded_anchor(
                self,
                rid,
                result.canonical_git_ref_sha,
                result.canonical_dolt_commit,
            )

    record = live._ResultRecord(
        source_id=source_id,
        source_url=source_url,
        request_id=rid,
        status=result.status,
        reason=result.reason_code,
        allocation_id=result.allocation_id,
        task_id=result.task_id,
        accepted_ref=result.canonical_git_ref_sha,
        dolt_commit=result.canonical_dolt_commit,
        canonical_row=self._request_row_identity(rid),
        payload_hash=payload_hash,
    )
    if project:
        projection = self.reconciler._canonical_projection(
            rid, source_comment_id=source_id
        )
        projection_body = live.render_projection(projection)
        posted = self.gateway.post_projection(self.issue_number, projection_body)
        self.reconciler._record_projection_posted(rid, posted)
        record.projection_url = posted.html_url
        record.projection_body = projection_body
    self.memory[f"s{scenario}:{index}"] = record
    return record


def execute_live_suite(
    values: Mapping[str, str] | None = None,
) -> live.LiveSuiteResult:
    """Delegate the suite while making cleanup and anchor recovery fail closed."""

    env = os.environ if values is None else values
    context = live.context_from_environment(env)
    context.validate()
    _bind_executable_identity()

    previous_lease_class = live.CredentialLease
    previous_process = live.LiveFixtureBackend._process
    TruthfulCredentialLease.last_instance = None
    live.CredentialLease = TruthfulCredentialLease
    live.LiveFixtureBackend._process = _process_with_anchor_recovery

    primary_error: Exception | None = None
    result: live.LiveSuiteResult | None = None
    try:
        try:
            result = live.execute_live_suite(env)
        except Exception as exc:
            primary_error = exc
    finally:
        live.CredentialLease = previous_lease_class
        live.LiveFixtureBackend._process = previous_process

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
