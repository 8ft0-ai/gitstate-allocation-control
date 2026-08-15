"""Credential-free canonical bootstrap and compare-and-swap abstractions."""

from __future__ import annotations

import hashlib
import re
import sqlite3
import threading
from dataclasses import dataclass
from typing import Callable, Protocol

from .allocation_schema import initialise_sqlite_fixture

CANONICAL_REF = "refs/dolt/data"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


class CanonicalError(RuntimeError):
    """Base class for canonical-state failures."""


class CanonicalIdentityMismatch(CanonicalError):
    pass


class StaleCanonicalBase(CanonicalError):
    pass


class CanonicalPushFailed(CanonicalError):
    pass


@dataclass(frozen=True)
class CanonicalIdentity:
    ref_name: str
    git_ref_sha: str
    dolt_commit: str


@dataclass
class CanonicalSnapshot:
    identity: CanonicalIdentity
    connection: sqlite3.Connection

    def close(self) -> None:
        self.connection.close()


def verify_canonical_identity(
    identity: CanonicalIdentity,
    *,
    expected_ref_name: str = CANONICAL_REF,
    expected_git_sha: str | None = None,
    expected_dolt_commit: str | None = None,
) -> None:
    """Fail closed when bootstrap returned a different Git or Dolt identity."""
    if identity.ref_name != expected_ref_name:
        raise CanonicalIdentityMismatch("CANONICAL_REF_MISMATCH")
    if not FULL_SHA.fullmatch(identity.git_ref_sha):
        raise CanonicalIdentityMismatch("INVALID_CANONICAL_GIT_SHA")
    if not identity.dolt_commit or any(char.isspace() for char in identity.dolt_commit):
        raise CanonicalIdentityMismatch("INVALID_CANONICAL_DOLT_COMMIT")
    if expected_git_sha is not None and identity.git_ref_sha != expected_git_sha:
        raise CanonicalIdentityMismatch("CANONICAL_GIT_BASE_MISMATCH")
    if expected_dolt_commit is not None and identity.dolt_commit != expected_dolt_commit:
        raise CanonicalIdentityMismatch("CANONICAL_DOLT_BASE_MISMATCH")


class CanonicalRepository(Protocol):
    """Repository boundary used by the mutation engine."""

    def bootstrap(self) -> CanonicalSnapshot: ...

    def publish(self, expected_old_sha: str, snapshot: CanonicalSnapshot) -> CanonicalIdentity: ...


class NoForceCASPublisher:
    """Expected-old-SHA publisher that can only request fast-forward pushes.

    ``resolve_sha`` and ``push_fast_forward`` are injected so this class remains
    testable without a remote or credentials. The push callback has no force
    argument by design and must implement a normal non-force ref update.
    """

    def __init__(
        self,
        resolve_sha: Callable[[str], str],
        push_fast_forward: Callable[[str, str], None],
    ) -> None:
        self._resolve_sha = resolve_sha
        self._push_fast_forward = push_fast_forward

    def publish(self, ref_name: str, expected_old_sha: str, candidate_sha: str) -> None:
        if ref_name != CANONICAL_REF:
            raise CanonicalIdentityMismatch("CANONICAL_REF_MISMATCH")
        if not FULL_SHA.fullmatch(expected_old_sha) or not FULL_SHA.fullmatch(candidate_sha):
            raise CanonicalIdentityMismatch("INVALID_CANONICAL_GIT_SHA")
        if self._resolve_sha(ref_name) != expected_old_sha:
            raise StaleCanonicalBase("STALE_EXPECTED_OLD_SHA")
        try:
            self._push_fast_forward(ref_name, candidate_sha)
        except StaleCanonicalBase:
            raise
        except Exception as exc:
            raise CanonicalPushFailed("CANONICAL_PUSH_FAILED") from exc


class LocalCanonicalRepository:
    """Thread-safe isolated canonical fixture with atomic CAS publication.

    It never invokes Git, Dolt, GitHub, a workflow, or a credential. Each
    bootstrap is a private SQLite copy; only a successful expected-old-SHA CAS
    swaps the committed bytes into authority.
    """

    def __init__(self, *, initial_git_sha: str = "1" * 40, initial_dolt_commit: str = "fixture-0") -> None:
        identity = CanonicalIdentity(CANONICAL_REF, initial_git_sha, initial_dolt_commit)
        verify_canonical_identity(identity)
        connection = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
        initialise_sqlite_fixture(connection)
        self._state = connection.serialize()
        connection.close()
        self._identity = identity
        self._lock = threading.Lock()
        self._publish_count = 0
        self._fail_pushes = 0
        self._force_attempted = False

    @property
    def identity(self) -> CanonicalIdentity:
        with self._lock:
            return self._identity

    @property
    def publish_count(self) -> int:
        with self._lock:
            return self._publish_count

    @property
    def force_attempted(self) -> bool:
        return self._force_attempted

    def fail_next_pushes(self, count: int = 1) -> None:
        if count < 0:
            raise ValueError("count must be non-negative")
        with self._lock:
            self._fail_pushes = count

    def bootstrap(self) -> CanonicalSnapshot:
        with self._lock:
            state = self._state
            identity = self._identity
        verify_canonical_identity(identity)
        connection = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
        connection.deserialize(state)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return CanonicalSnapshot(identity, connection)

    def publish(self, expected_old_sha: str, snapshot: CanonicalSnapshot) -> CanonicalIdentity:
        verify_canonical_identity(snapshot.identity, expected_git_sha=expected_old_sha)
        candidate = snapshot.connection.serialize()
        with self._lock:
            if self._identity.git_ref_sha != expected_old_sha:
                raise StaleCanonicalBase("STALE_EXPECTED_OLD_SHA")
            if self._fail_pushes:
                self._fail_pushes -= 1
                raise CanonicalPushFailed("CANONICAL_PUSH_FAILED")
            sequence = self._publish_count + 1
            git_sha = hashlib.sha1(
                expected_old_sha.encode("ascii") + sequence.to_bytes(8, "big") + candidate,
                usedforsecurity=False,
            ).hexdigest()
            dolt_commit = hashlib.sha256(candidate + sequence.to_bytes(8, "big")).hexdigest()[:32]
            self._state = candidate
            self._identity = CanonicalIdentity(CANONICAL_REF, git_sha, dolt_commit)
            self._publish_count = sequence
            return self._identity

    def inspect(self) -> sqlite3.Connection:
        """Return a read-only-by-convention isolated copy for assertions."""
        return self.bootstrap().connection
