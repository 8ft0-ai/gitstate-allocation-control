"""Bounded Workstream D canonical-anchor reconciliation remediation.

This module remediates gitstate-lab#27 without changing accepted Workstream B/C
semantics.  The first successful canonical allocation/release CAS remains the
ownership commit point.  Anchor metadata is attempted with the accepted default
retry budget; if it remains pending, repair is delegated to the existing
Workstream C reconciliation path using credential-free reconstruction of the
accepted Git/Dolt history.

The module is reachable only through the already protected trusted-main
Workstream D live entrypoint.  It adds no repository, App, token-profile,
workflow, production, or Workstream E authority.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable, ClassVar, Mapping, Sequence

from . import workstream_d_live as live
from .allocation_store import AllocationStore
from .canonical import CanonicalPushFailed
from .dolt_repository import DoltCanonicalRepository
from .reconciliation import (
    CanonicalHistoryRevision,
    ReconciliationError,
    ReconciliationService,
)

REMEDIATION_EXECUTABLE_PATH = "phase2/workstream_d_anchor_repair.py"
_ANCHOR_FAILURES = frozenset(
    {"CANONICAL_PUSH_FAILED", "STALE_ALLOCATOR_RETRY_EXHAUSTED"}
)


def _repository_store(repository: Any, snapshot: Any) -> Any:
    factory = getattr(repository, "store", None)
    if callable(factory):
        return factory(snapshot)
    return AllocationStore(snapshot.connection)


def _request_row(repository: Any, request_id: str) -> dict[str, Any] | None:
    snapshot = repository.bootstrap()
    try:
        row = _repository_store(repository, snapshot).get_request(request_id)
        return None if row is None else dict(row)
    finally:
        snapshot.close()


class DurableAcceptedHistory:
    """Complete Phase 2 first-parent history from one exact read-only mirror.

    The owner-authorised state token is used only by the existing broker to make
    one exact Git mirror. All traversal and historical Dolt reconstruction below
    uses local file transport with the credential-free environment. GitBlobstore
    transport commits that do not change the NBS manifest are not Dolt snapshots.
    Pre-Phase-2 manifest history may also predate a cloneable database/schema;
    that prefix is accepted only when the first readable Phase 2 snapshot is
    request-empty. Once Phase 2 history begins every manifest revision must be
    readable and retain the Phase 2 schema.
    """

    def __init__(
        self,
        read_only_remote_factory: Callable[[Path], tuple[Path, str]],
        *,
        dolt_bin: str,
    ) -> None:
        self.read_only_remote_factory = read_only_remote_factory
        self.dolt_bin = dolt_bin
        self._cache: tuple[CanonicalHistoryRevision, ...] | None = None

    @property
    def complete(self) -> bool:
        # accepted_revisions either proves the bounded Phase 2 history or raises;
        # no partial post-schema history is represented as complete evidence.
        return True

    @staticmethod
    def _read_only_run(
        command: Sequence[str], cwd: Path
    ) -> subprocess.CompletedProcess[str]:
        executable = Path(command[0]).name
        lowered = tuple(str(item).lower() for item in command[1:])
        if (
            executable == "git"
            and any(item in {"push", "receive-pack"} for item in lowered)
        ) or (executable == "dolt" and "push" in lowered):
            raise live.LiveExecutorError("CANONICAL_HISTORY_REMOTE_WRITE_FORBIDDEN")
        return subprocess.run(
            list(command),
            cwd=cwd,
            env=live._credential_free_git_env(),
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    @staticmethod
    def _request_ids(
        repository: DoltCanonicalRepository, snapshot: Any
    ) -> frozenset[str] | None:
        cursor = snapshot.connection.cursor()
        try:
            cursor.execute("SHOW TABLES LIKE 'allocation_requests'")
            if cursor.fetchone() is None:
                return None
        finally:
            cursor.close()
        reconstructed = repository.store(snapshot).reconstruct()
        return frozenset(
            str(row["request_id"]) for row in reconstructed.get("requests", [])
        )

    @staticmethod
    def _is_manifest_revision(mirror: Path, git_sha: str, *, root: Path) -> bool:
        changed = live._run(
            [
                "git",
                "--git-dir",
                str(mirror),
                "diff-tree",
                "--root",
                "--no-commit-id",
                "--name-only",
                "-r",
                git_sha,
            ],
            cwd=root,
            env=live._credential_free_git_env(),
        )
        paths = tuple(line.strip() for line in changed.splitlines() if line.strip())
        return "manifest" in paths

    def _revision(
        self,
        mirror: Path,
        git_sha: str,
        *,
        root: Path,
        index: int,
    ) -> CanonicalHistoryRevision | None:
        historical_remote = root / f"history-{index}.git"
        live._run(
            [
                "git",
                "clone",
                "--mirror",
                "--no-hardlinks",
                str(mirror),
                str(historical_remote),
            ],
            cwd=root,
            env=live._credential_free_git_env(),
        )
        live._run(
            [
                "git",
                "--git-dir",
                str(historical_remote),
                "update-ref",
                "refs/dolt/data",
                git_sha,
            ],
            cwd=root,
            env=live._credential_free_git_env(),
        )
        client_root = root / f"client-{index}"
        client_root.mkdir()
        repository = DoltCanonicalRepository(
            "git+file://" + str(historical_remote),
            lambda database: live.ManagedDoltConnection(database, self.dolt_bin),
            dolt_bin=self.dolt_bin,
            run_command=self._read_only_run,
            workspace_root=client_root,
        )
        snapshot = repository.bootstrap()
        try:
            if snapshot.identity.git_ref_sha != git_sha:
                raise live.LiveExecutorError(
                    "CANONICAL_HISTORY_REVISION_IDENTITY_MISMATCH"
                )
            request_ids = self._request_ids(repository, snapshot)
            if request_ids is None:
                return None
            return CanonicalHistoryRevision(snapshot.identity, request_ids)
        finally:
            snapshot.close()

    def accepted_revisions(self) -> tuple[CanonicalHistoryRevision, ...]:
        if self._cache is not None:
            return self._cache
        with tempfile.TemporaryDirectory(prefix="wd-anchor-history-") as directory:
            root = Path(directory)
            mirror, source_sha = self.read_only_remote_factory(root)
            try:
                output = live._run(
                    [
                        "git",
                        "--git-dir",
                        str(mirror),
                        "rev-list",
                        "--first-parent",
                        "--reverse",
                        "refs/dolt/data",
                    ],
                    cwd=root,
                    env=live._credential_free_git_env(),
                )
                git_shas = tuple(line.strip() for line in output.splitlines() if line.strip())
                if not git_shas or git_shas[-1] != source_sha:
                    raise live.LiveExecutorError(
                        "CANONICAL_HISTORY_CURRENT_REF_MISMATCH"
                    )

                # GitBlobstore may advance refs/dolt/data while staging immutable
                # table files as part of one Dolt push. Only a commit that changes
                # the NBS manifest represents a complete accepted Dolt snapshot.
                manifest_shas = tuple(
                    git_sha
                    for git_sha in git_shas
                    if self._is_manifest_revision(mirror, git_sha, root=root)
                )
                if not manifest_shas:
                    raise live.LiveExecutorError("CANONICAL_HISTORY_EMPTY")
                if manifest_shas[-1] != source_sha:
                    raise live.LiveExecutorError(
                        "CANONICAL_HISTORY_CURRENT_REF_NOT_MANIFEST"
                    )

                revisions: list[CanonicalHistoryRevision] = []
                for index, git_sha in enumerate(manifest_shas, 1):
                    try:
                        revision = self._revision(
                            mirror, git_sha, root=root, index=index
                        )
                    except CanonicalPushFailed as exc:
                        if revisions:
                            raise live.LiveExecutorError(
                                "CANONICAL_HISTORY_UNREADABLE_AFTER_PHASE2"
                            ) from exc
                        # Initial GitBlobstore manifests may predate a cloneable
                        # Dolt database. They cannot be treated as Phase 2 state.
                        continue
                    if revision is None:
                        if revisions:
                            raise live.LiveExecutorError(
                                "CANONICAL_HISTORY_PHASE2_SCHEMA_REGRESSION"
                            )
                        continue
                    if not revisions and revision.request_ids:
                        # An unreadable/pre-schema prefix is safe to exclude only
                        # when the first proven Phase 2 snapshot predates requests.
                        raise live.LiveExecutorError(
                            "CANONICAL_HISTORY_PHASE2_PREFIX_AMBIGUOUS"
                        )
                    revisions.append(revision)

                if not revisions:
                    raise live.LiveExecutorError("CANONICAL_HISTORY_PHASE2_EMPTY")
                if revisions[-1].identity.git_ref_sha != source_sha:
                    raise live.LiveExecutorError(
                        "CANONICAL_HISTORY_CURRENT_PHASE2_REVISION_MISSING"
                    )
                self._cache = tuple(revisions)
                return self._cache
            finally:
                # The broker intentionally makes the mirror read-only. Restore
                # only local temp permissions so TemporaryDirectory can remove it.
                live._set_tree_read_only(mirror, read_only=False)


def repair_pending_anchor(
    repository: Any,
    request_id: str,
    canonical_history: Any,
    *,
    control_repository: str = live.CONTROL_REPOSITORY,
    issue_number: int = live.CONTROL_ISSUE_NUMBER,
    clock: Callable[[], str] = lambda: live.NOW,
) -> dict[str, Any]:
    """Repair one pending anchor through the accepted Workstream C semantics."""
    reconciler = ReconciliationService(
        repository,
        object(),  # _repair_anchor performs no GitHub I/O.
        control_repository=control_repository,
        issue_number=issue_number,
        task_summary_lookup=lambda task_id: f"synthetic fixture {task_id}",
        canonical_history=canonical_history,
        clock=clock,
        # Deliberately omit max_stale_retries: use the accepted/default budget.
    )
    try:
        repaired = reconciler._repair_anchor(request_id)
    except ReconciliationError as exc:
        raise live.LiveExecutorError(
            f"CANONICAL_ANCHOR_RECONCILIATION_FAILED:{exc}"
        ) from exc
    if not repaired:
        raise live.LiveExecutorError("CANONICAL_ANCHOR_HISTORY_NOT_FOUND")
    row = _request_row(repository, request_id)
    if (
        row is None
        or row.get("anchor_status") != "RECORDED"
        or not row.get("canonical_git_ref_sha")
        or not row.get("canonical_dolt_commit")
    ):
        raise live.LiveExecutorError("CANONICAL_ANCHOR_REPAIR_INCOMPLETE")
    return row


def _durable_history_for_backend(backend: "AnchorRepairLiveFixtureBackend") -> DurableAcceptedHistory:
    if backend.read_only_remote_factory is None:
        raise live.LiveExecutorError("CANONICAL_HISTORY_MIRROR_BROKER_MISSING")
    dolt_bin = getattr(backend.repository, "dolt_bin", "")
    if not isinstance(dolt_bin, str) or not dolt_bin:
        raise live.LiveExecutorError("CANONICAL_HISTORY_DOLT_BINARY_MISSING")
    return DurableAcceptedHistory(
        backend.read_only_remote_factory,
        dolt_bin=dolt_bin,
    )


class AnchorRepairLiveFixtureBackend(live.LiveFixtureBackend):
    """Live fixture backend with protocol-correct pending-anchor recovery."""

    history_factory: ClassVar[Callable[[Any], Any]] = _durable_history_for_backend

    def _repair_request_anchor(self, request_id: str) -> dict[str, Any]:
        return repair_pending_anchor(
            self.repository,
            request_id,
            type(self).history_factory(self),
            control_repository=live.CONTROL_REPOSITORY,
            issue_number=self.issue_number,
            clock=lambda: live.NOW,
        )

    def _process(
        self,
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

        # Use Workstream B's accepted/default bounded retry budget. The previous
        # Workstream-D-only max_stale_retries=1 override is deliberately removed.
        service = live.AllocationService(self.repository, clock=lambda: live.NOW)
        result = service.process(command, context)
        if not result.canonical_git_ref_sha or not result.canonical_dolt_commit:
            raise live.LiveExecutorError("CANONICAL_RESULT_IDENTITY_MISSING")

        creation_identity = (
            (result.canonical_git_ref_sha, result.canonical_dolt_commit)
            if result.ref_advanced
            else None
        )
        if result.ref_advanced:
            anchor = service.record_anchor(
                rid,
                result.canonical_git_ref_sha,
                result.canonical_dolt_commit,
            )
            if anchor.reason_code in _ANCHOR_FAILURES:
                row = self._repair_request_anchor(rid)
            else:
                row = _request_row(self.repository, rid)
        else:
            row = _request_row(self.repository, rid)

        # A replay may encounter an earlier accepted request whose anchor is
        # still pending. Never manufacture a current identity from runner memory:
        # reconstruct the original creation identity through accepted history and
        # use Workstream C's repair path.
        if row is not None and row.get("anchor_status") != "RECORDED":
            row = self._repair_request_anchor(rid)

        if (
            row is None
            or row.get("anchor_status") != "RECORDED"
            or not row.get("canonical_git_ref_sha")
            or not row.get("canonical_dolt_commit")
        ):
            raise live.LiveExecutorError("CANONICAL_ANCHOR_REPAIR_INCOMPLETE")

        accepted_ref = str(row["canonical_git_ref_sha"])
        dolt_commit = str(row["canonical_dolt_commit"])
        if creation_identity is not None and creation_identity != (
            accepted_ref,
            dolt_commit,
        ):
            raise live.LiveExecutorError("CANONICAL_ANCHOR_IDENTITY_DRIFT")

        record = live._ResultRecord(
            source_id=source_id,
            source_url=source_url,
            request_id=rid,
            status=result.status,
            reason=result.reason_code,
            allocation_id=result.allocation_id,
            task_id=result.task_id,
            accepted_ref=accepted_ref,
            dolt_commit=dolt_commit,
            canonical_row=self._request_row_identity(rid),
            payload_hash=payload_hash,
        )
        if project:
            # Existing Workstream C projection logic refuses PENDING anchors;
            # therefore ALLOCATED can become execution-authorising only after
            # exact canonical request/allocation/anchor correlation is repaired.
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


def _bind_executable_identity() -> None:
    paths = tuple(live.LIVE_EXECUTABLE_PATHS)
    if REMEDIATION_EXECUTABLE_PATH not in paths:
        live.LIVE_EXECUTABLE_PATHS = (*paths, REMEDIATION_EXECUTABLE_PATH)


def execute_live_suite(
    values: Mapping[str, str] | None = None,
) -> live.LiveSuiteResult:
    """Delegate to trusted main while substituting only the reviewed D backend."""
    _bind_executable_identity()
    previous_backend = live.LiveFixtureBackend
    live.LiveFixtureBackend = AnchorRepairLiveFixtureBackend
    try:
        return live.execute_live_suite(values)
    finally:
        live.LiveFixtureBackend = previous_backend