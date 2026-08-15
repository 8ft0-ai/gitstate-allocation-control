"""Concrete isolated Git/Dolt canonical repository implementation.

This module intentionally has no default live credentials or repository URL.
Callers must inject the already-authorised state-repository URL and a PEP-249
connection factory for the isolated checkout.  Publication is always a normal
fast-forward push to ``refs/dolt/data`` guarded by an explicit expected-old SHA;
there is no force option.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

from .canonical import (
    CANONICAL_REF,
    CanonicalIdentity,
    CanonicalIdentityMismatch,
    CanonicalPushFailed,
    StaleCanonicalBase,
    verify_canonical_identity,
)
from .dolt_store import DoltAllocationStore


RunCommand = Callable[[Sequence[str], Path], subprocess.CompletedProcess[str]]
ConnectionFactory = Callable[[Path], Any]


def _run(command: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _scalar(connection: Any, sql: str) -> str:
    cursor = connection.cursor()
    try:
        cursor.execute(sql)
        row = cursor.fetchone()
        if row is None:
            raise CanonicalIdentityMismatch("MISSING_CANONICAL_DOLT_COMMIT")
        if isinstance(row, dict):
            value = next(iter(row.values()))
        else:
            value = row[0]
        text = str(value)
        if not text or any(char.isspace() for char in text):
            raise CanonicalIdentityMismatch("INVALID_CANONICAL_DOLT_COMMIT")
        return text
    finally:
        cursor.close()


def _call(connection: Any, sql: str) -> None:
    cursor = connection.cursor()
    try:
        cursor.execute(sql)
    finally:
        cursor.close()


@dataclass
class DoltCanonicalSnapshot:
    identity: CanonicalIdentity
    connection: Any
    workspace: Path

    def close(self) -> None:
        try:
            self.connection.close()
        finally:
            shutil.rmtree(self.workspace, ignore_errors=True)


class DoltCanonicalRepository:
    """Isolated canonical checkout plus no-force expected-old-SHA publication."""

    def __init__(
        self,
        remote_url: str,
        connection_factory: ConnectionFactory,
        *,
        git_bin: str = "git",
        state_ref: str = CANONICAL_REF,
        run_command: RunCommand = _run,
        workspace_root: str | Path | None = None,
    ) -> None:
        if state_ref != CANONICAL_REF:
            raise CanonicalIdentityMismatch("CANONICAL_REF_MISMATCH")
        if not remote_url:
            raise ValueError("remote_url is required")
        self.remote_url = remote_url
        self.connection_factory = connection_factory
        self.git_bin = git_bin
        self.state_ref = state_ref
        self.run_command = run_command
        self.workspace_root = None if workspace_root is None else Path(workspace_root)

    def _command(self, command: Sequence[str], cwd: Path, failure: str) -> str:
        completed = self.run_command(command, cwd)
        if completed.returncode != 0:
            raise CanonicalPushFailed(failure)
        return completed.stdout.strip()

    def bootstrap(self) -> DoltCanonicalSnapshot:
        workspace = Path(
            tempfile.mkdtemp(
                prefix="phase2-canonical-",
                dir=None if self.workspace_root is None else str(self.workspace_root),
            )
        )
        try:
            self._command((self.git_bin, "init", "-q"), workspace, "CANONICAL_GIT_INIT_FAILED")
            self._command(
                (self.git_bin, "remote", "add", "origin", self.remote_url),
                workspace,
                "CANONICAL_REMOTE_SETUP_FAILED",
            )
            self._command(
                (self.git_bin, "fetch", "--no-tags", "origin", f"+{self.state_ref}:{self.state_ref}"),
                workspace,
                "CANONICAL_FETCH_FAILED",
            )
            git_sha = self._command(
                (self.git_bin, "rev-parse", self.state_ref), workspace, "CANONICAL_REF_RESOLVE_FAILED"
            )
            self._command(
                (self.git_bin, "checkout", "--detach", "-q", git_sha),
                workspace,
                "CANONICAL_CHECKOUT_FAILED",
            )
            connection = self.connection_factory(workspace)
            dolt_commit = _scalar(connection, "SELECT DOLT_HASHOF('HEAD')")
            identity = CanonicalIdentity(self.state_ref, git_sha, dolt_commit)
            verify_canonical_identity(identity)
            return DoltCanonicalSnapshot(identity, connection, workspace)
        except Exception:
            shutil.rmtree(workspace, ignore_errors=True)
            raise

    def store(self, snapshot: DoltCanonicalSnapshot) -> DoltAllocationStore:
        return DoltAllocationStore(snapshot.connection)

    def _remote_sha(self, workspace: Path) -> str:
        output = self._command(
            (self.git_bin, "ls-remote", "--refs", "origin", self.state_ref),
            workspace,
            "CANONICAL_REMOTE_REF_LOOKUP_FAILED",
        )
        fields = output.split()
        if len(fields) != 2 or fields[1] != self.state_ref:
            raise CanonicalIdentityMismatch("CANONICAL_REMOTE_REF_MISSING")
        return fields[0]

    def publish(self, expected_old_sha: str, snapshot: DoltCanonicalSnapshot) -> CanonicalIdentity:
        verify_canonical_identity(snapshot.identity, expected_git_sha=expected_old_sha)
        if self._remote_sha(snapshot.workspace) != expected_old_sha:
            raise StaleCanonicalBase("STALE_EXPECTED_OLD_SHA")

        # Version the SQL transaction in Dolt before wrapping the resulting
        # database files in the Git commit that advances refs/dolt/data.
        _call(snapshot.connection, "CALL DOLT_ADD('-A')")
        _call(snapshot.connection, "CALL DOLT_COMMIT('-am', 'phase2 canonical allocation')")
        snapshot.connection.commit()
        dolt_commit = _scalar(snapshot.connection, "SELECT DOLT_HASHOF('HEAD')")

        self._command((self.git_bin, "add", "-A"), snapshot.workspace, "CANONICAL_GIT_ADD_FAILED")
        self._command(
            (
                self.git_bin,
                "-c",
                "user.name=phase2-allocator",
                "-c",
                "user.email=phase2-allocator@invalid",
                "commit",
                "-q",
                "-m",
                "Phase 2 canonical allocation",
            ),
            snapshot.workspace,
            "CANONICAL_GIT_COMMIT_FAILED",
        )
        candidate_sha = self._command(
            (self.git_bin, "rev-parse", "HEAD"), snapshot.workspace, "CANONICAL_GIT_COMMIT_RESOLVE_FAILED"
        )

        # Re-check immediately before the normal push. A race after this check
        # is still safe: the non-force push is rejected because the candidate is
        # a child of expected_old_sha, never of a newer writer.
        if self._remote_sha(snapshot.workspace) != expected_old_sha:
            raise StaleCanonicalBase("STALE_EXPECTED_OLD_SHA")
        pushed = self.run_command(
            (self.git_bin, "push", "origin", f"{candidate_sha}:{self.state_ref}"),
            snapshot.workspace,
        )
        if pushed.returncode != 0:
            try:
                current = self._remote_sha(snapshot.workspace)
            except Exception as exc:
                raise CanonicalPushFailed("CANONICAL_PUSH_FAILED") from exc
            if current != expected_old_sha:
                raise StaleCanonicalBase("STALE_EXPECTED_OLD_SHA")
            raise CanonicalPushFailed("CANONICAL_PUSH_FAILED")

        accepted = CanonicalIdentity(self.state_ref, candidate_sha, dolt_commit)
        verify_canonical_identity(accepted)
        return accepted
