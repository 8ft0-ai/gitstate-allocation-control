"""Concrete isolated Git-backed Dolt canonical repository implementation.

This module intentionally has no default live credentials or repository URL.
Callers inject the already-authorised state-repository URL and a PEP-249
connection factory for the isolated Dolt clone. The factory is bound to that
clone by comparing the connection's Dolt ``HEAD`` and active branch with an
independent Dolt-CLI identity read taken before the connection is opened.

``refs/dolt/data`` is a Dolt Git-remote storage ref, not an ordinary checkout.
Bootstrap therefore clones through Dolt's Git-remote transport and publication
uses Dolt's normal ``DOLT_PUSH`` procedure through the bound connection. The Git
ref SHA is used only as the explicit expected-old compare-and-swap token. No
force option is exposed or used.
"""

from __future__ import annotations

import csv
import io
import re
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
_SAFE_BRANCH = re.compile(r"^[A-Za-z0-9._/-]+$")


def _run(command: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _normalise_dolt_remote(remote_url: str) -> str:
    """Mirror the pinned Beads v1.1.0 Git-to-Dolt remote conversion."""
    native = (
        "dolthub://",
        "file://",
        "aws://",
        "gs://",
        "git+https://",
        "git+http://",
        "git+ssh://",
        "git+file://",
    )
    if remote_url.startswith(native):
        return remote_url
    if remote_url.startswith(("https://", "http://", "ssh://")):
        return "git+" + remote_url
    if "@" in remote_url:
        colon = remote_url.find(":")
        if colon > 0 and "/" not in remote_url[:colon]:
            return "git+ssh://" + remote_url[:colon] + "/" + remote_url[colon + 1 :]
    return remote_url


def _git_probe_url(dolt_remote_url: str) -> str:
    """Return the ordinary Git URL backing a Dolt ``git+`` remote.

    Workstream B is specifically bound to a Git repository ref
    (``refs/dolt/data``), so Dolt-native object-store and filesystem remotes are
    not valid canonical targets even though Dolt itself can use them.
    """
    if dolt_remote_url.startswith("git+"):
        return dolt_remote_url[4:]
    raise CanonicalIdentityMismatch("CANONICAL_GIT_BACKED_REMOTE_REQUIRED")


def _scalar(connection: Any, sql: str) -> str:
    cursor = connection.cursor()
    try:
        cursor.execute(sql)
        row = cursor.fetchone()
        if row is None:
            raise CanonicalIdentityMismatch("MISSING_CANONICAL_DOLT_IDENTITY")
        if isinstance(row, dict):
            value = next(iter(row.values()))
        else:
            value = row[0]
        text = str(value)
        if not text or any(char.isspace() for char in text):
            raise CanonicalIdentityMismatch("INVALID_CANONICAL_DOLT_IDENTITY")
        return text
    finally:
        cursor.close()


def _call(connection: Any, sql: str, params: Sequence[object] = ()) -> None:
    cursor = connection.cursor()
    try:
        cursor.execute(sql, tuple(params))
    finally:
        cursor.close()


@dataclass
class DoltCanonicalSnapshot:
    identity: CanonicalIdentity
    connection: Any
    workspace: Path
    database: Path

    def close(self) -> None:
        try:
            self.connection.close()
        finally:
            shutil.rmtree(self.workspace, ignore_errors=True)


class DoltCanonicalRepository:
    """Fresh Dolt clone plus expected-old-SHA, non-force publication."""

    def __init__(
        self,
        remote_url: str,
        connection_factory: ConnectionFactory,
        *,
        git_bin: str = "git",
        dolt_bin: str = "dolt",
        dolt_branch: str = "main",
        state_ref: str = CANONICAL_REF,
        run_command: RunCommand = _run,
        workspace_root: str | Path | None = None,
    ) -> None:
        if state_ref != CANONICAL_REF:
            raise CanonicalIdentityMismatch("CANONICAL_REF_MISMATCH")
        if not remote_url:
            raise ValueError("remote_url is required")
        if not dolt_branch or not _SAFE_BRANCH.fullmatch(dolt_branch):
            raise ValueError("invalid dolt_branch")
        self.remote_url = remote_url
        self.dolt_remote_url = _normalise_dolt_remote(remote_url)
        self.git_remote_url = _git_probe_url(self.dolt_remote_url)
        self.connection_factory = connection_factory
        self.git_bin = git_bin
        self.dolt_bin = dolt_bin
        self.dolt_branch = dolt_branch
        self.state_ref = state_ref
        self.run_command = run_command
        self.workspace_root = None if workspace_root is None else Path(workspace_root)

    def _command(self, command: Sequence[str], cwd: Path, failure: str) -> str:
        completed = self.run_command(command, cwd)
        if completed.returncode != 0:
            raise CanonicalPushFailed(failure)
        return completed.stdout.strip()

    def _remote_sha(self, workspace: Path) -> str:
        output = self._command(
            (self.git_bin, "ls-remote", "--refs", self.git_remote_url, self.state_ref),
            workspace,
            "CANONICAL_REMOTE_REF_LOOKUP_FAILED",
        )
        fields = output.split()
        if len(fields) != 2 or fields[1] != self.state_ref:
            raise CanonicalIdentityMismatch("CANONICAL_REMOTE_REF_MISSING")
        git_sha = fields[0]
        verify_canonical_identity(CanonicalIdentity(self.state_ref, git_sha, "probe"))
        return git_sha

    def _cli_scalar(self, database: Path, sql: str, failure: str) -> str:
        output = self._command(
            (self.dolt_bin, "sql", "-q", sql, "-r", "csv"),
            database,
            failure,
        )
        try:
            rows = list(csv.reader(io.StringIO(output)))
        except csv.Error as exc:
            raise CanonicalIdentityMismatch("INVALID_CANONICAL_DOLT_CLI_OUTPUT") from exc
        if len(rows) != 2 or len(rows[1]) != 1:
            raise CanonicalIdentityMismatch("INVALID_CANONICAL_DOLT_CLI_OUTPUT")
        value = rows[1][0].strip()
        if not value or any(char.isspace() for char in value):
            raise CanonicalIdentityMismatch("INVALID_CANONICAL_DOLT_CLI_OUTPUT")
        return value

    def _verify_connection_binding(self, connection: Any, cloned_head: str) -> str:
        connection_head = _scalar(connection, "SELECT DOLT_HASHOF('HEAD')")
        if connection_head != cloned_head:
            raise CanonicalIdentityMismatch("CANONICAL_DOLT_CONNECTION_MISMATCH")
        active_branch = _scalar(connection, "SELECT ACTIVE_BRANCH()")
        if active_branch != self.dolt_branch:
            raise CanonicalIdentityMismatch("CANONICAL_DOLT_BRANCH_MISMATCH")
        return connection_head

    def bootstrap(self) -> DoltCanonicalSnapshot:
        workspace = Path(
            tempfile.mkdtemp(
                prefix="phase2-canonical-",
                dir=None if self.workspace_root is None else str(self.workspace_root),
            )
        )
        connection = None
        try:
            expected_git_sha = self._remote_sha(workspace)
            database = workspace / "canonical"
            self._command(
                (self.dolt_bin, "clone", self.dolt_remote_url, database.name),
                workspace,
                "CANONICAL_DOLT_CLONE_FAILED",
            )

            # Read the clone identity before any SQL server/embedded connection
            # is opened, avoiding a second process touching an open Dolt store.
            cloned_head = self._cli_scalar(
                database,
                "SELECT DOLT_HASHOF('HEAD') AS commit_hash",
                "CANONICAL_DOLT_HEAD_LOOKUP_FAILED",
            )

            # A ref movement while clone was in flight invalidates this snapshot.
            if self._remote_sha(workspace) != expected_git_sha:
                raise StaleCanonicalBase("STALE_EXPECTED_OLD_SHA")

            connection = self.connection_factory(database)
            dolt_commit = self._verify_connection_binding(connection, cloned_head)
            identity = CanonicalIdentity(self.state_ref, expected_git_sha, dolt_commit)
            verify_canonical_identity(identity)
            return DoltCanonicalSnapshot(identity, connection, workspace, database)
        except Exception:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
            shutil.rmtree(workspace, ignore_errors=True)
            raise

    def store(self, snapshot: DoltCanonicalSnapshot) -> DoltAllocationStore:
        return DoltAllocationStore(snapshot.connection)

    def publish(self, expected_old_sha: str, snapshot: DoltCanonicalSnapshot) -> CanonicalIdentity:
        verify_canonical_identity(snapshot.identity, expected_git_sha=expected_old_sha)
        if self._remote_sha(snapshot.workspace) != expected_old_sha:
            raise StaleCanonicalBase("STALE_EXPECTED_OLD_SHA")

        # Version the accepted SQL transaction in the already-bound clone.
        _call(snapshot.connection, "CALL DOLT_ADD('-A')")
        _call(snapshot.connection, "CALL DOLT_COMMIT('-am', 'phase2 canonical allocation')")
        snapshot.connection.commit()
        dolt_commit = _scalar(snapshot.connection, "SELECT DOLT_HASHOF('HEAD')")

        # Re-check immediately before the normal Dolt push. DOLT_PUSH without
        # '--force' is the same non-force path used by pinned Beads v1.1.0.
        if self._remote_sha(snapshot.workspace) != expected_old_sha:
            raise StaleCanonicalBase("STALE_EXPECTED_OLD_SHA")
        try:
            _call(snapshot.connection, "CALL DOLT_PUSH(%s, %s)", ("origin", self.dolt_branch))
            snapshot.connection.commit()
        except Exception as exc:
            try:
                current = self._remote_sha(snapshot.workspace)
            except Exception as lookup_exc:
                raise CanonicalPushFailed("CANONICAL_PUSH_FAILED") from lookup_exc
            if current != expected_old_sha:
                raise StaleCanonicalBase("STALE_EXPECTED_OLD_SHA") from exc
            raise CanonicalPushFailed("CANONICAL_PUSH_FAILED") from exc

        accepted_git_sha = self._remote_sha(snapshot.workspace)
        if accepted_git_sha == expected_old_sha:
            raise CanonicalPushFailed("CANONICAL_REF_NOT_ADVANCED")
        accepted = CanonicalIdentity(self.state_ref, accepted_git_sha, dolt_commit)
        verify_canonical_identity(accepted)
        return accepted
