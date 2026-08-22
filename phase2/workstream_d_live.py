"""Trusted-main synthetic fixture executor for Workstream D scenarios 1-14.

This module is not normal Phase 2 intake.  It is entered only by the manual
protected-main ``live_scenario_suite`` operation after the credential-free
contract job and the existing Workstream D authority gate succeed.  The live
executor reuses the accepted Workstream B/C services and the existing
``phase2.adversarial`` evidence contract.  Synthetic GitHub comments are
attempt-qualified transport/evidence only and never create a runtime actor.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import inspect
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .adversarial import (
    AssertionEvidence,
    AttemptNamespace,
    CanonicalAllocationEvidence,
    ClientTranscript,
    CONTROL_REPOSITORY_ID,
    EXPECTED_FAULT_OUTCOMES,
    ExecutableIdentity,
    FaultEvidence,
    FinalOwnerEvidence,
    REQUIRED_DEPENDENCY_IDENTITIES,
    SCENARIO_13_FAULT_CONTROLS,
    SCENARIO_IDS,
    STATE_REPOSITORY_ID,
    RepeatedResultEvidence,
    ScenarioDriver,
    ScenarioEvidence,
    ScenarioSpec,
    TerminalRequestEvidence,
    TokenScopeEvidence,
    evidence_summary,
    validate_live_gate,
)
from .allocation_engine import AllocationService
from .allocation_schema import dolt_schema
from .allocation_store import CanonicalOwnershipMismatch
from .allocation_types import AllocationCommand, RequestContext, Task, stable_ulid
from .canonical import CanonicalPushFailed, StaleCanonicalBase
from .credentials import (
    CredentialPolicyError,
    TokenProfile,
    control_profile,
    create_app_jwt,
    mint_token,
    require_cross_repository_denial,
    require_public_repository_write_denial,
    state_profile,
    token_request,
    validate_token_response,
    verify_live_installation,
)
from .dolt_repository import DoltCanonicalRepository
from .discovery import classify
from .github_api import GitHubAPI, GitHubAPIError
from .inventory import InventoryAttestation, InventoryError
from .parser import parse_request
from .policy import AuthorisationError, authorise, load_policy
from .projection import CanonicalProjection, parse_projection, render_projection
from .projection_github import GitHubIssueGateway
from .reconciliation import DurableComment, ReconciliationService, ReconciliationSummary

CONTROL_REPOSITORY = "8ft0-ai/gitstate-allocation-control"
STATE_REPOSITORY = "8ft0-ai/gitstate-allocation-state"
STATE_REPOSITORY_BASELINE_REF = "refs/heads/main"
STATE_REPOSITORY_BASELINE_SHA = "fb872aeb52863ce3597ff8337d545cae13292696"
CONTROL_ISSUE_NUMBER = 1
PROTOCOL_AUTHORITY = "4ad2cebf6c37d21f44e5652a70f5fb4e77da74ae"
FIXTURE_MODE = "workstream-d-synthetic-fixture-v1"
INVENTORY_MAX_AGE_SECONDS = 15 * 60
CLOSE_TIMED_MAX_SECONDS = 30.0
POST_ALLOCATION_READ_MAX_STALE_RETRIES = 3
SCENARIO_3_FIXTURE_PAGE_SIZE = 2
SCENARIO_3_FILLER_COUNT = 2
LIVE_EXECUTABLE_PATHS = (
    ".github/workflows/phase2-adversarial.yml",
    "phase2/adversarial.py",
    "phase2/workstream_d_live.py",
)
NETWORK_DESTINATIONS = (
    "api.github.com",
    "github.com",
    "release-assets.githubusercontent.com",
    "pypi.org",
    "files.pythonhosted.org",
)
DURABILITY = ("github_issue", "github_repository", "github_ref", "github_actions")
NOW = "2026-08-16T00:00:00Z"

_COMMAND_FAILURE_PHASES = frozenset(
    {
        "state-baseline-probe",
        "fixture-git-init",
        "fixture-git-config-name",
        "fixture-git-config-email",
        "fixture-git-add",
        "fixture-git-commit",
        "fixture-beads-init",
        "fixture-dolt-remote-add",
        "fixture-dolt-commit",
        "fixture-dolt-push",
    }
)
_FIXTURE_BOOTSTRAP_FAILURE_PHASES = frozenset(
    {
        "fixture-canonical-bootstrap",
        "fixture-canonical-schema",
        "fixture-canonical-publish",
    }
)


class LiveExecutorError(RuntimeError):
    pass


class CommandFailure(LiveExecutorError):
    reason_code = "COMMAND_FAILED"

    def __init__(
        self,
        failure_phase: str,
        executable: str,
        return_code: int,
        stderr_sha256: str,
    ) -> None:
        if failure_phase not in _COMMAND_FAILURE_PHASES:
            raise ValueError("invalid command failure phase")
        if executable not in {"git", "bd"}:
            raise ValueError("invalid command executable")
        if not isinstance(return_code, int):
            raise ValueError("invalid command return code")
        if len(stderr_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in stderr_sha256
        ):
            raise ValueError("invalid stderr digest")
        super().__init__(self.reason_code)
        self.failure_phase = failure_phase
        self.executable = executable
        self.return_code = return_code
        self.stderr_sha256 = stderr_sha256

    def safe_diagnostic(self) -> dict[str, object]:
        return {
            "failure_phase": self.failure_phase,
            "executable": self.executable,
            "return_code": self.return_code,
            "stderr_sha256": self.stderr_sha256,
        }


class FixtureBootstrapFailure(LiveExecutorError):
    reason_code = "FIXTURE_BOOTSTRAP_FAILED"

    def __init__(self, failure_phase: str) -> None:
        if failure_phase not in _FIXTURE_BOOTSTRAP_FAILURE_PHASES:
            raise ValueError("invalid fixture bootstrap failure phase")
        super().__init__(self.reason_code)
        self.failure_phase = failure_phase

    def safe_diagnostic(self) -> dict[str, object]:
        return {"failure_phase": self.failure_phase}


@dataclass(frozen=True)
class LiveRunContext:
    repository: str
    ref: str
    trusted_sha: str
    expected_control_sha: str
    protocol_sha: str
    expected_protocol_sha: str
    run_id: int
    run_attempt: int
    attempt_nonce: str
    enabled: bool
    fixture_mode: str

    @property
    def namespace(self) -> AttemptNamespace:
        return AttemptNamespace.parse(
            f"wd-{self.run_id}-{self.run_attempt}-{self.attempt_nonce}",
            run_id=self.run_id,
            run_attempt=self.run_attempt,
        )

    def validate(self) -> AttemptNamespace:
        if self.fixture_mode != FIXTURE_MODE:
            raise LiveExecutorError("FIXTURE_MODE_REQUIRED")
        validate_live_gate(
            repository=self.repository,
            ref=self.ref,
            trusted_sha=self.trusted_sha,
            protocol_sha=self.protocol_sha,
            expected_trusted_sha=self.expected_control_sha,
            expected_protocol_sha=self.expected_protocol_sha,
            run_attempt=self.run_attempt,
            enabled=self.enabled,
        )
        return self.namespace


@dataclass
class CredentialLease:
    control_token: str
    state_token: str
    token_scope_records: tuple[TokenScopeEvidence, TokenScopeEvidence]
    api_url: str
    api_factory: Callable[[str, str], GitHubAPI] = GitHubAPI
    revoked: bool = False

    def _revoke(self, token: str) -> None:
        if not token:
            return
        try:
            self.api_factory(token, self.api_url).request("DELETE", "/installation/token")
        except Exception as exc:
            raise LiveExecutorError("INSTALLATION_TOKEN_REVOCATION_FAILED") from exc

    def close(self) -> None:
        if self.revoked:
            return
        failures: list[Exception] = []
        for token in (self.state_token, self.control_token):
            try:
                self._revoke(token)
            except Exception as exc:
                failures.append(exc)
        self.state_token = ""
        self.control_token = ""
        self.revoked = True
        if failures:
            raise LiveExecutorError("INSTALLATION_TOKEN_REVOCATION_FAILED") from failures[0]


@dataclass(frozen=True)
class ValidatedInventory:
    attestation: InventoryAttestation
    digest: str


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode()


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _decode_inventory(
    encoded: str,
    *,
    app_id: int,
    installation_id: int,
    now: datetime | None = None,
) -> ValidatedInventory:
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        value = json.loads(raw)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise LiveExecutorError("INVALID_INVENTORY_ATTESTATION_ENCODING") from exc
    if not isinstance(value, dict):
        raise LiveExecutorError("INVALID_INVENTORY_ATTESTATION_ENCODING")
    attestation = InventoryAttestation.from_dict(value)
    attestation.validate(
        app_id=app_id,
        installation_id=installation_id,
        expected_repository_ids={CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID},
        now=now or datetime.now(timezone.utc),
        max_age_seconds=INVENTORY_MAX_AGE_SECONDS,
    )
    return ValidatedInventory(attestation, _sha256(value))


def _scope_evidence(profile: TokenProfile) -> TokenScopeEvidence:
    permissions = tuple(f"{name}:{level}" for name, level in profile.permissions.items())
    return TokenScopeEvidence(
        profile=profile.name,
        requested_repository_ids=(profile.repository_id,),
        returned_repository_ids=(profile.repository_id,),
        requested_permissions=permissions,
        returned_permissions=permissions,
        restrictions_explicit=True,
        returned_scope_validated=True,
        cross_repository_denied=True,
    )


def acquire_credentials(
    values: Mapping[str, str],
    context: LiveRunContext,
    *,
    api_factory: Callable[[str, str], GitHubAPI] = GitHubAPI,
    jwt_factory: Callable[[int, str], str] = create_app_jwt,
) -> tuple[CredentialLease, ValidatedInventory]:
    # This is deliberately the first operation.  No private-key lookup may move
    # above this exact trusted-main/first-attempt/enablement gate.
    context.validate()
    policy = load_policy(values.get("PHASE2_POLICY", "policy/actors.json"))
    if policy.get("control_repository") != CONTROL_REPOSITORY:
        raise LiveExecutorError("CONTROL_REPOSITORY_POLICY_MISMATCH")
    if int(policy.get("control_repository_id", 0)) != CONTROL_REPOSITORY_ID:
        raise LiveExecutorError("CONTROL_REPOSITORY_ID_MISMATCH")
    api_url = values.get("GITHUB_API_URL", "https://api.github.com")
    app_id = int(values[policy["allocator"]["app_id_env"]])
    installation_id = int(values[policy["allocator"]["installation_id_env"]])
    if int(values[policy["state_repository_id_env"]]) != STATE_REPOSITORY_ID:
        raise LiveExecutorError("STATE_REPOSITORY_ID_MISMATCH")
    inventory = _decode_inventory(
        values["PHASE2_OWNER_INVENTORY_ATTESTATION_B64"],
        app_id=app_id,
        installation_id=installation_id,
    )

    key_name = "PHASE2_ALLOCATOR_APP_PRIVATE_KEY"
    private_key = values[key_name]
    if values is os.environ:
        os.environ.pop(key_name, None)
    jwt = jwt_factory(app_id, private_key)
    private_key = ""
    app_api = api_factory(jwt, api_url)
    verify_live_installation(
        app_api,
        "8ft0-ai",
        "gitstate-allocation-control",
        {
            "app_id": app_id,
            "installation_id": installation_id,
            "app_slug": policy["allocator"]["app_slug"],
            "owner": policy["allocator"]["owner"],
        },
    )

    control_token = ""
    state_token = ""
    try:
        control = control_profile(CONTROL_REPOSITORY_ID)
        control_token = mint_token(app_api, installation_id, control)
        require_cross_repository_denial(control_token, STATE_REPOSITORY_ID, api_url)
        state = state_profile(STATE_REPOSITORY_ID)
        state_token = mint_token(app_api, installation_id, state)
        require_public_repository_write_denial(
            state_token, "8ft0-ai", "gitstate-allocation-control", api_url
        )
        jwt = ""
        return (
            CredentialLease(
                control_token,
                state_token,
                (_scope_evidence(control), _scope_evidence(state)),
                api_url,
                api_factory,
            ),
            inventory,
        )
    except Exception:
        jwt = ""
        lease = CredentialLease(
            control_token,
            state_token,
            (
                _scope_evidence(control_profile(CONTROL_REPOSITORY_ID)),
                _scope_evidence(state_profile(STATE_REPOSITORY_ID)),
            ),
            api_url,
            api_factory,
        )
        try:
            lease.close()
        except Exception:
            pass
        raise


def _run(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    phase: str | None = None,
) -> str:
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        env=None if env is None else dict(env),
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        if phase is None:
            raise LiveExecutorError(f"COMMAND_FAILED:{command[0]}:{completed.returncode}")
        executable = Path(str(command[0])).name
        stderr_text = completed.stderr or ""
        failure = CommandFailure(
            phase,
            executable,
            int(completed.returncode),
            hashlib.sha256(stderr_text.encode("utf-8", errors="replace")).hexdigest(),
        )
        stderr_text = ""
        completed = None  # type: ignore[assignment]
        command = ()
        env = None
        cwd = Path(".")
        raise failure
    return completed.stdout.strip()


def _remote_url() -> str:
    return f"https://github.com/{STATE_REPOSITORY}.git"


def _state_git_env(root: Path, token: str) -> dict[str, str]:
    askpass = root / "state-askpass.sh"
    askpass.write_text(
        "#!/bin/sh\ncase \"$1\" in *Username*) printf '%s\\n' x-access-token ;; *) printf '%s\\n' \"$PHASE2_STATE_TOKEN\" ;; esac\n",
        encoding="utf-8",
    )
    askpass.chmod(0o700)
    env = dict(os.environ)
    env.update(
        {
            "GIT_ASKPASS": str(askpass),
            "GIT_TERMINAL_PROMPT": "0",
            "PHASE2_STATE_TOKEN": token,
        }
    )
    return env


def _credential_free_git_env() -> dict[str, str]:
    env = dict(os.environ)
    for key in (
        "PHASE2_STATE_TOKEN",
        "GIT_ASKPASS",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GITHUB_PAT",
    ):
        env.pop(key, None)
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _canonical_creation_ref_order(
    mirror: Path, current_sha: str, creation_refs: Sequence[str]
) -> tuple[str, str]:
    refs = tuple(creation_refs)
    if len(refs) != 2:
        raise LiveExecutorError("SCENARIO_1_CREATION_REF_COUNT_INVALID")
    if refs[0] == refs[1]:
        raise LiveExecutorError("SCENARIO_1_CREATION_REFS_EQUAL")

    env = _credential_free_git_env()
    try:
        observed_current = _run(
            ["git", "--git-dir", str(mirror), "rev-parse", "refs/dolt/data"],
            cwd=mirror.parent,
            env=env,
        )
    except LiveExecutorError as exc:
        raise LiveExecutorError("SCENARIO_1_CANONICAL_CURRENT_REF_MISSING") from exc
    if observed_current != current_sha:
        raise LiveExecutorError("SCENARIO_1_CANONICAL_CURRENT_REF_MISMATCH")

    def git_status(*arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "--git-dir", str(mirror), *arguments],
            cwd=mirror.parent,
            env=env,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    for ref in refs:
        if git_status("cat-file", "-e", f"{ref}^{{commit}}").returncode != 0:
            raise LiveExecutorError("SCENARIO_1_CREATION_REF_MISSING")

    def is_ancestor(older: str, newer: str) -> bool:
        completed = git_status("merge-base", "--is-ancestor", older, newer)
        if completed.returncode == 0:
            return True
        if completed.returncode == 1:
            return False
        raise LiveExecutorError("SCENARIO_1_CREATION_ANCESTRY_CHECK_FAILED")

    left_before_right = is_ancestor(refs[0], refs[1])
    right_before_left = is_ancestor(refs[1], refs[0])
    if left_before_right == right_before_left:
        raise LiveExecutorError("SCENARIO_1_CREATION_REFS_INCOMPARABLE")
    ordered = refs if left_before_right else (refs[1], refs[0])
    if not is_ancestor(ordered[1], current_sha):
        raise LiveExecutorError("SCENARIO_1_CREATION_REF_NOT_CURRENT")
    return ordered


def assert_uninitialised_state(token: str, *, root: Path) -> None:
    output = _run(
        ["git", "ls-remote", "--refs", _remote_url()],
        cwd=root,
        env=_state_git_env(root, token),
        phase="state-baseline-probe",
    )
    expected = (
        f"{STATE_REPOSITORY_BASELINE_SHA}\t{STATE_REPOSITORY_BASELINE_REF}"
    )
    if output.strip() != expected:
        raise LiveExecutorError("UNEXPECTED_CANONICAL_STATE")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


class ManagedDoltConnection:
    def __init__(
        self,
        database: Path,
        dolt_bin: str,
        git_env: Mapping[str, str] | None = None,
    ) -> None:
        try:
            import pymysql  # type: ignore
        except ImportError as exc:
            raise LiveExecutorError("PINNED_PYMYSQL_UNAVAILABLE") from exc
        self._pymysql = pymysql
        self.database = database
        self.port = _free_port()
        self.log = (database.parent / "dolt-sql.log").open("w+")
        self.process = subprocess.Popen(
            [
                dolt_bin,
                "sql-server",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--loglevel",
                "warning",
            ],
            cwd=database,
            env=None if git_env is None else dict(git_env),
            text=True,
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        self.inner = self._connect()

    def _connect(self):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            try:
                return self._pymysql.connect(
                    host="127.0.0.1",
                    port=self.port,
                    user="root",
                    password="",
                    database=self.database.name,
                    autocommit=False,
                    connect_timeout=1,
                )
            except self._pymysql.MySQLError:
                time.sleep(0.1)
        self._stop()
        raise LiveExecutorError("DOLT_SQL_SERVER_UNAVAILABLE")

    def cursor(self):
        return self.inner.cursor()

    def commit(self) -> None:
        self.inner.commit()

    def rollback(self) -> None:
        self.inner.rollback()

    def close(self) -> None:
        try:
            self.inner.close()
        finally:
            self._stop()

    def _stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if not self.log.closed:
            self.log.close()


def _execute_ddl(connection: Any, ddl: str) -> None:
    delimiter = ";"
    buffered: list[str] = []
    cursor = connection.cursor()
    try:
        for line in ddl.splitlines():
            stripped = line.strip()
            if not buffered and (not stripped or stripped.startswith("--")):
                continue
            if stripped.upper().startswith("DELIMITER "):
                if "\n".join(buffered).strip():
                    raise LiveExecutorError("UNEXPECTED_DDL_BUFFER")
                delimiter = stripped.split(None, 1)[1]
                continue
            buffered.append(line)
            statement = "\n".join(buffered).rstrip()
            if statement.endswith(delimiter):
                statement = statement[: -len(delimiter)].strip()
                buffered.clear()
                if statement:
                    cursor.execute(statement)
        if "\n".join(buffered).strip():
            raise LiveExecutorError("UNTERMINATED_DDL")
        connection.commit()
    finally:
        cursor.close()


def _set_tree_read_only(root: Path, *, read_only: bool) -> None:
    mode_file = 0o444 if read_only else 0o600
    mode_dir = 0o555 if read_only else 0o700
    paths = sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=not read_only)
    if not read_only:
        root.chmod(mode_dir)
    for path in paths:
        try:
            path.chmod(mode_dir if path.is_dir() else mode_file)
        except FileNotFoundError:
            continue
    if read_only:
        root.chmod(mode_dir)


@dataclass
class FixtureRepositoryLease:
    repository: DoltCanonicalRepository
    credential_env: dict[str, str]
    askpass: Path
    closed: bool = False

    def make_read_only_remote(self, root: Path) -> tuple[Path, str]:
        """Broker one exact GitHub snapshot, then expose no credential to the client."""
        if self.closed or "PHASE2_STATE_TOKEN" not in self.credential_env:
            raise LiveExecutorError("READ_ONLY_MIRROR_BROKER_CLOSED")
        mirror = root / "state-read-only.git"
        _run(
            ["git", "clone", "--mirror", _remote_url(), str(mirror)],
            cwd=root,
            env=self.credential_env,
        )
        live_line = _run(
            ["git", "ls-remote", "--refs", _remote_url(), "refs/dolt/data"],
            cwd=root,
            env=self.credential_env,
        )
        fields = live_line.split()
        if len(fields) != 2 or fields[1] != "refs/dolt/data":
            raise LiveExecutorError("READ_ONLY_MIRROR_LIVE_REF_MISSING")
        mirror_sha = _run(
            ["git", "--git-dir", str(mirror), "rev-parse", "refs/dolt/data"],
            cwd=root,
            env=_credential_free_git_env(),
        )
        if mirror_sha != fields[0]:
            raise LiveExecutorError("READ_ONLY_MIRROR_REF_MISMATCH")
        _set_tree_read_only(mirror, read_only=True)
        return mirror, mirror_sha

    def close(self) -> None:
        if self.closed:
            return
        self.credential_env.pop("PHASE2_STATE_TOKEN", None)
        self.credential_env.pop("GIT_ASKPASS", None)
        try:
            self.askpass.unlink()
        except FileNotFoundError:
            pass
        self.closed = True


def bootstrap_fixture_repository(
    state_token: str, *, root: Path, bd_bin: str, dolt_bin: str
) -> FixtureRepositoryLease:
    assert_uninitialised_state(state_token, root=root)
    source = root / "fixture-source"
    source.mkdir()
    env = _state_git_env(root, state_token)
    env.update({"BD_NON_INTERACTIVE": "1", "CI": "true", "HOME": str(root / "home")})
    Path(env["HOME"]).mkdir()
    _run(
        ["git", "init", "--initial-branch=main"],
        cwd=source,
        phase="fixture-git-init",
    )
    _run(
        ["git", "config", "user.name", "Workstream D Fixture"],
        cwd=source,
        phase="fixture-git-config-name",
    )
    _run(
        ["git", "config", "user.email", "workstream-d@example.invalid"],
        cwd=source,
        phase="fixture-git-config-email",
    )
    (source / "README.md").write_text("Workstream D synthetic fixture state\n")
    _run(["git", "add", "README.md"], cwd=source, phase="fixture-git-add")
    _run(
        ["git", "commit", "-m", "Initial Workstream D fixture state"],
        cwd=source,
        phase="fixture-git-commit",
    )
    _run(
        [bd_bin, "init", "--prefix", "wd", "--quiet", "--skip-hooks", "--skip-agents", "--non-interactive"],
        cwd=source,
        env=env,
        phase="fixture-beads-init",
    )
    remote = _remote_url()
    # GitHub requires a default branch.  The exact remote main ref is a pinned
    # synthetic transport sentinel, not canonical allocator state, and must
    # never be advanced or replaced by the fixture executor.
    _run(
        [bd_bin, "dolt", "remote", "add", "origin", "git+" + remote],
        cwd=source,
        env=env,
        phase="fixture-dolt-remote-add",
    )
    _run(
        [bd_bin, "dolt", "commit", "-m", "Workstream D pinned Beads baseline"],
        cwd=source,
        env=env,
        phase="fixture-dolt-commit",
    )
    _run(
        [bd_bin, "dolt", "push"],
        cwd=source,
        env=env,
        phase="fixture-dolt-push",
    )

    def credentialled_run(
        command: Sequence[str], cwd: Path
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(command),
            cwd=cwd,
            env=env,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    repository = DoltCanonicalRepository(
        "git+" + remote,
        lambda database: ManagedDoltConnection(database, dolt_bin, env),
        dolt_bin=dolt_bin,
        run_command=credentialled_run,
        workspace_root=root,
    )
    snapshot: Any | None = None
    bootstrap_failed = False
    try:
        snapshot = repository.bootstrap()
    except Exception:
        bootstrap_failed = True
    if bootstrap_failed:
        raise FixtureBootstrapFailure("fixture-canonical-bootstrap")
    if snapshot is None:
        raise FixtureBootstrapFailure("fixture-canonical-bootstrap")
    try:
        schema_failed = False
        try:
            _execute_ddl(snapshot.connection, dolt_schema())
        except Exception:
            schema_failed = True
        if schema_failed:
            raise FixtureBootstrapFailure("fixture-canonical-schema")

        publish_failed = False
        try:
            repository.publish(snapshot.identity.git_ref_sha, snapshot)
        except Exception:
            publish_failed = True
        if publish_failed:
            raise FixtureBootstrapFailure("fixture-canonical-publish")
    finally:
        snapshot.close()
    return FixtureRepositoryLease(repository, env, root / "state-askpass.sh")


class _HistoryStub:
    complete = True

    def accepted_revisions(self) -> tuple[object, ...]:
        return ()


@dataclass
class ScenarioProof:
    """Fail-closed binding from executed checks to the existing evidence schema."""

    spec: ScenarioSpec
    namespace: AttemptNamespace
    assertion_records: dict[str, AssertionEvidence] = field(default_factory=dict)
    fault_records: dict[str, FaultEvidence] = field(default_factory=dict)

    def assertion(self, index: int, condition: bool, actual: str) -> None:
        try:
            name = self.spec.assertions[index]
        except IndexError as exc:
            raise LiveExecutorError("UNAPPROVED_ASSERTION_WITNESS") from exc
        if name in self.assertion_records:
            raise LiveExecutorError("DUPLICATE_ASSERTION_WITNESS")
        if not condition:
            raise LiveExecutorError(
                f"SCENARIO_{self.spec.scenario_id}_ASSERTION_FAILED:{index + 1}"
            )
        self.assertion_records[name] = AssertionEvidence(
            name=name,
            passed=True,
            expected=name,
            actual=actual,
        )

    def fault(self, control: str, condition: bool, actual: str) -> None:
        if control not in self.spec.fault_controls:
            raise LiveExecutorError(f"UNAPPROVED_FAULT_WITNESS:{control}")
        if control in self.fault_records:
            raise LiveExecutorError(f"DUPLICATE_FAULT_WITNESS:{control}")
        expected = EXPECTED_FAULT_OUTCOMES[control]
        if not condition or actual != expected:
            raise LiveExecutorError(f"FAULT_WITNESS_FAILED:{control}")
        self.fault_records[control] = FaultEvidence(
            control=control,
            identity=f"{self.namespace.value}:{self.spec.scenario_id}:{control}",
            passed=True,
            expected_outcome=expected,
            actual_outcome=actual,
        )

    def finalise(
        self,
    ) -> tuple[tuple[AssertionEvidence, ...], tuple[FaultEvidence, ...]]:
        assertions = tuple(self.assertion_records.get(name) for name in self.spec.assertions)
        faults = tuple(self.fault_records.get(control) for control in self.spec.fault_controls)
        if any(item is None for item in assertions):
            raise LiveExecutorError("INCOMPLETE_ASSERTION_WITNESSES")
        if any(item is None for item in faults):
            raise LiveExecutorError("INCOMPLETE_FAULT_WITNESSES")
        return (
            tuple(item for item in assertions if item is not None),
            tuple(item for item in faults if item is not None),
        )


@dataclass
class _ResultRecord:
    source_id: int
    source_url: str
    request_id: str
    status: str
    reason: str
    allocation_id: str | None
    task_id: str | None
    accepted_ref: str
    dolt_commit: str
    canonical_row: str
    payload_hash: str
    projection_url: str = ""
    projection_body: str = ""


@dataclass
class _FailFirstProjectionGateway:
    delegate: GitHubIssueGateway
    attempted: bool = False

    def post_projection(self, issue_number: int, body: str):
        self.attempted = True
        raise RuntimeError("INJECTED_FIXTURE_PROJECTION_POST_FAILURE")


FIXTURE_APP = {
    "actor_login": "fixture-bot[bot]",
    "actor_id": 900001,
    "app_id": 900002,
    "app_slug": "fixture-bot",
    "installation_id": 900003,
    "agent_prefix": "agent://github-app/fixture-bot/900003/session/",
}


def _fixture_app_policy(base_policy: Mapping[str, Any]) -> dict[str, Any]:
    policy = copy.deepcopy(dict(base_policy))
    policy["github_apps"] = [dict(FIXTURE_APP)]
    return policy


def _scenario13_parsed_request(namespace: AttemptNamespace):
    payload = {
        "protocol": "beads-allocation/v0.2",
        "type": "ALLOCATE_TASK",
        "request_id": stable_ulid(f"{namespace.value}:s13:auth"),
        "agent_id": FIXTURE_APP["agent_prefix"] + "s13",
        "task_id": "synthetic-task",
    }
    return parse_request(
        ("/beads-v0.2 " + json.dumps(payload, sort_keys=True, separators=(",", ":"))).encode()
    )


def _exercise_authorisation_negative(
    control: str,
    *,
    namespace: AttemptNamespace,
    base_policy: Mapping[str, Any],
) -> str:
    """Exercise one identity negative with exactly one targeted invalid fact."""
    policy = _fixture_app_policy(base_policy)
    parsed = _scenario13_parsed_request(namespace)
    valid = {
        "user": {
            "login": FIXTURE_APP["actor_login"],
            "id": FIXTURE_APP["actor_id"],
            "type": "Bot",
        },
        "performed_via_github_app": {
            "id": FIXTURE_APP["app_id"],
            "slug": FIXTURE_APP["app_slug"],
        },
    }
    expected_detail = ""
    comment = copy.deepcopy(valid)
    if control == "missing_comment_app_attribution":
        comment.pop("performed_via_github_app")
        expected_detail = "missing App attribution"
    elif control == "wrong_comment_app_id":
        comment["performed_via_github_app"]["id"] = int(FIXTURE_APP["app_id"]) + 1
        expected_detail = "App attribution mismatch"
    elif control == "wrong_comment_app_slug":
        comment["performed_via_github_app"]["slug"] = "wrong-fixture-app"
        expected_detail = "App attribution mismatch"
    elif control == "wrong_bot_id":
        comment["user"]["id"] = int(FIXTURE_APP["actor_id"]) + 1
        expected_detail = "unknown bot"
    elif control == "wrong_bot_login":
        comment["user"]["login"] = "wrong-fixture-bot[bot]"
        expected_detail = "unknown bot"
    elif control == "misleading_event_installation":
        comment.pop("performed_via_github_app")
        comment["installation"] = {"id": FIXTURE_APP["installation_id"]}
        expected_detail = "missing App attribution"
    elif control == "human_namespace_impersonation":
        comment = {"user": {"login": "8ft0-ai", "id": 130460431, "type": "User"}}
        expected_detail = "human namespace mismatch"
    else:
        raise LiveExecutorError(f"UNSUPPORTED_AUTHORISATION_NEGATIVE:{control}")
    try:
        authorise(comment, parsed, policy)
    except AuthorisationError as exc:
        if exc.code != "AGENT_NOT_AUTHORISED" or exc.detail != expected_detail:
            raise LiveExecutorError(f"WRONG_AUTHORISATION_REJECTION:{control}") from exc
        return exc.detail
    raise LiveExecutorError(f"AUTHORISATION_NEGATIVE_ACCEPTED:{control}")


def _exercise_installation_negative(control: str) -> tuple[str, int, int]:
    """Return rejection plus explicit zero state-token/canonical-access counters."""
    mint_calls = 0
    canonical_calls = 0

    class WrongMappingAPI:
        def get(self, path: str):
            return {
                "id": 2,
                "app_id": 1,
                "app_slug": "gitstate-phase-2-allocator",
                "repository_selection": "selected",
                "account": {"login": "8ft0-ai"},
            }

    class LostAccessAPI:
        def get(self, path: str):
            raise GitHubAPIError(404, "fixture repository installation not found")

    expected = {
        "installation_id": 1,
        "app_id": 1,
        "app_slug": "gitstate-phase-2-allocator",
        "owner": "8ft0-ai",
    }
    api: Any
    if control == "wrong_installation_mapping":
        api = WrongMappingAPI()
    elif control == "lost_control_repository_access":
        api = LostAccessAPI()
    else:
        raise LiveExecutorError(f"UNSUPPORTED_INSTALLATION_NEGATIVE:{control}")
    try:
        verify_live_installation(api, "8ft0-ai", "gitstate-allocation-control", expected)
    except (CredentialPolicyError, GitHubAPIError) as exc:
        return type(exc).__name__, mint_calls, canonical_calls
    raise LiveExecutorError(f"INSTALLATION_NEGATIVE_ACCEPTED:{control}")


def _run_close_timed_calls(
    calls: Sequence[Callable[[], Any]],
) -> tuple[tuple[Any, ...], float]:
    # Release all fixture calls through one barrier and report actual start spread.
    if len(calls) < 2:
        raise LiveExecutorError("CLOSE_TIMED_CALL_COUNT_INVALID")
    barrier = threading.Barrier(len(calls))
    lock = threading.Lock()
    started: list[float] = []

    def run(call: Callable[[], Any]) -> Any:
        try:
            barrier.wait(timeout=10)
        except threading.BrokenBarrierError as exc:
            raise LiveExecutorError("CLOSE_TIMED_BARRIER_FAILED") from exc
        timestamp = time.monotonic()
        with lock:
            started.append(timestamp)
        return call()

    with ThreadPoolExecutor(max_workers=len(calls), thread_name_prefix="wd-close") as pool:
        futures = [pool.submit(run, call) for call in calls]
        values = tuple(future.result(timeout=240) for future in futures)
    if len(started) != len(calls):
        raise LiveExecutorError("CLOSE_TIMED_START_EVIDENCE_INCOMPLETE")
    return values, max(started) - min(started)


def _cancel_queued_call(call: Callable[[], Any]) -> bool:
    # Occupy a one-worker executor, queue exactly one fixture call, then cancel it.
    blocker_started = threading.Event()
    release_blocker = threading.Event()

    def blocker() -> None:
        blocker_started.set()
        if not release_blocker.wait(timeout=10):
            raise LiveExecutorError("QUEUED_CANCEL_BLOCKER_TIMEOUT")

    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="wd-cancel") as pool:
        blocker_future = pool.submit(blocker)
        if not blocker_started.wait(timeout=10):
            raise LiveExecutorError("QUEUED_CANCEL_BLOCKER_NOT_STARTED")
        queued_future = pool.submit(call)
        cancelled = queued_future.cancel()
        release_blocker.set()
        blocker_future.result(timeout=30)
    return cancelled and queued_future.cancelled()


def _classify_edited_pre_ingress(
    comment: Mapping[str, Any],
    *,
    original_body: str,
    policy: Mapping[str, Any],
) -> str:
    # The live fixture App remains intentionally outside runtime actor policy.
    # Prove the edited payload itself is syntactically valid and positively
    # authorisable by the accepted owner/operator policy, then apply the real
    # discovery edit boundary to the actual edited GitHub comment.
    body = comment.get("body")
    if not isinstance(body, str) or body == original_body:
        raise LiveExecutorError("PRE_INGRESS_EDIT_NOT_OBSERVED")
    parsed = parse_request(body.encode("utf-8"))
    authorisation_probe = {
        "user": {"login": "8ft0-ai", "id": 130460431, "type": "User"}
    }
    try:
        principal = authorise(authorisation_probe, parsed, dict(policy))
    except AuthorisationError as exc:
        raise LiveExecutorError("PRE_INGRESS_EDIT_VALID_PAYLOAD_NOT_AUTHORISABLE") from exc
    if principal.actor_login != "8ft0-ai" or principal.actor_type != "User":
        raise LiveExecutorError("PRE_INGRESS_EDIT_WRONG_ACCEPTED_PRINCIPAL")

    candidate = classify(dict(comment), CONTROL_REPOSITORY, dict(policy))
    if (
        candidate is None
        or candidate.disposition != "REJECTED"
        or candidate.reason_code != "SOURCE_COMMENT_EDITED_BEFORE_INGRESS"
    ):
        raise LiveExecutorError("PRE_INGRESS_EDIT_DISCOVERY_NOT_REJECTED")
    return candidate.reason_code


def _protocol_request_contract(
    namespace: AttemptNamespace,
    scenario: int,
    index: int,
    *,
    request_type: str,
    task_id: str | None = None,
    allocation_id: str | None = None,
    request_id: str | None = None,
    reason: str | None = None,
) -> tuple[str, str, str]:
    rid = request_id or stable_ulid(f"{namespace.value}:s{scenario}:request:{index}")
    payload: dict[str, Any] = {
        "protocol": "beads-allocation/v0.2",
        "type": request_type,
        "request_id": rid,
        "agent_id": f"agent://operator/8ft0-ai/session/{namespace.value}",
    }
    if request_type == "ALLOCATE_NEXT":
        payload["capabilities"] = []
        payload["task_types"] = ["task"]
    elif request_type == "ALLOCATE_TASK":
        if not task_id:
            raise LiveExecutorError("PROTOCOL_FIXTURE_TASK_ID_REQUIRED")
        payload["task_id"] = task_id
    elif request_type == "RELEASE":
        if not allocation_id or not reason:
            raise LiveExecutorError("PROTOCOL_FIXTURE_RELEASE_FIELDS_REQUIRED")
        payload["allocation_id"] = allocation_id
        payload["reason"] = reason
    else:
        raise LiveExecutorError("PROTOCOL_FIXTURE_REQUEST_TYPE_INVALID")
    body = "/beads-v0.2 " + json.dumps(payload, sort_keys=True, separators=(",", ":"))
    parsed = parse_request(body.encode("utf-8"))
    return rid, body, parsed.payload_hash


@dataclass
class LiveFixtureBackend:
    repository: Any
    control_api: GitHubAPI
    issue_number: int
    trusted_sha: str
    protocol_sha: str
    token_scope_records: tuple[TokenScopeEvidence, TokenScopeEvidence]
    inventory: ValidatedInventory
    namespace: AttemptNamespace
    read_only_remote_factory: Callable[[Path], tuple[Path, str]] | None = None
    comment_page_size: int = 100
    memory: dict[str, _ResultRecord] = field(default_factory=dict)
    executed_records: dict[int, ScenarioEvidence] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.gateway = GitHubIssueGateway(
            self.control_api,
            CONTROL_REPOSITORY,
            page_size=self.comment_page_size,
        )
        self.reconciler = ReconciliationService(
            self.repository,
            self.gateway,
            control_repository=CONTROL_REPOSITORY,
            issue_number=self.issue_number,
            task_summary_lookup=lambda task_id: f"synthetic fixture {task_id}",
            canonical_history=_HistoryStub(),
            clock=lambda: NOW,
        )

    @property
    def agent_id(self) -> str:
        return f"agent://operator/8ft0-ai/session/{self.namespace.value}"

    def _fresh_backend(
        self,
        repository: Any | None = None,
        *,
        comment_page_size: int | None = None,
    ) -> "LiveFixtureBackend":
        return LiveFixtureBackend(
            repository or self.repository,
            self.control_api,
            self.issue_number,
            self.trusted_sha,
            self.protocol_sha,
            self.token_scope_records,
            self.inventory,
            self.namespace,
            self.read_only_remote_factory,
            self.comment_page_size if comment_page_size is None else comment_page_size,
        )

    def _fixture_body(self, scenario: int, index: int, operation: str) -> str:
        return json.dumps(
            {
                "fixture_mode": FIXTURE_MODE,
                "operation": operation,
                "attempt_namespace": self.namespace.value,
                "scenario_id": scenario,
                "sequence": index,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def _post_body(self, body: str) -> tuple[int, str]:
        value = self.control_api.post(
            f"/repos/{CONTROL_REPOSITORY}/issues/{self.issue_number}/comments",
            {"body": body},
        )
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("id"), int)
            or not isinstance(value.get("html_url"), str)
        ):
            raise LiveExecutorError("SOURCE_COMMENT_CREATE_FAILED")
        return int(value["id"]), str(value["html_url"])

    def _post_source(self, scenario: int, index: int, operation: str) -> tuple[int, str]:
        return self._post_body(self._fixture_body(scenario, index, operation))

    def _post_close_timed(
        self, scenario: int, operations: Sequence[str]
    ) -> tuple[tuple[tuple[int, str], ...], float, bool]:
        started = time.monotonic()
        sources = tuple(
            self._post_source(scenario, index, operation)
            for index, operation in enumerate(operations, 1)
        )
        elapsed = time.monotonic() - started
        listed = {item.comment_id for item in self.gateway.list_comments(self.issue_number)}
        visible = all(source_id in listed for source_id, _ in sources)
        return sources, elapsed, visible

    def _post_protocol_sources(
        self,
        scenario: int,
        request_types: Sequence[str],
        *,
        task_ids: Sequence[str | None] | None = None,
    ) -> tuple[tuple[tuple[int, str], ...], tuple[str, ...], float, bool]:
        started = time.monotonic()
        sources: list[tuple[int, str]] = []
        request_ids: list[str] = []
        task_values = tuple(task_ids or (None for _ in request_types))
        if len(task_values) != len(request_types):
            raise LiveExecutorError("PROTOCOL_FIXTURE_SOURCE_SHAPE_MISMATCH")
        for index, (request_type, task_id) in enumerate(
            zip(request_types, task_values), 1
        ):
            rid, body, _ = _protocol_request_contract(
                self.namespace,
                scenario,
                index,
                request_type=request_type,
                task_id=task_id,
            )
            request_ids.append(rid)
            sources.append(self._post_body(body))
        elapsed = time.monotonic() - started
        listed = {item.comment_id for item in self.gateway.list_comments(self.issue_number)}
        visible = all(source_id in listed for source_id, _ in sources)
        return tuple(sources), tuple(request_ids), elapsed, visible

    def _edit_comment(self, comment_id: int, body: str) -> None:
        self.control_api.request(
            "PATCH",
            f"/repos/{CONTROL_REPOSITORY}/issues/comments/{comment_id}",
            {"body": body},
        )

    def _delete_comment(self, comment_id: int) -> None:
        self.control_api.request(
            "DELETE", f"/repos/{CONTROL_REPOSITORY}/issues/comments/{comment_id}"
        )

    @staticmethod
    def _post_allocation_read(read: Callable[[], Any]) -> Any:
        stale_retries = 0
        while True:
            try:
                return read()
            except StaleCanonicalBase as exc:
                if stale_retries >= POST_ALLOCATION_READ_MAX_STALE_RETRIES:
                    raise LiveExecutorError("STALE_ALLOCATOR_RETRY_EXHAUSTED") from exc
                stale_retries += 1

    def _identity(self):
        snapshot = self.repository.bootstrap()
        try:
            return snapshot.identity
        finally:
            snapshot.close()

    def _seed(self, scenario: int, count: int) -> tuple[str, ...]:
        snapshot = self.repository.bootstrap()
        store = self.repository.store(snapshot)
        ids = tuple(
            f"{self.namespace.value}:s{scenario}:task:{index}" for index in range(1, count + 1)
        )
        store.begin()
        try:
            for index, task_id in enumerate(ids, 1):
                store.seed_task(
                    Task(
                        task_id,
                        "task",
                        "open",
                        None,
                        1,
                        f"2026-08-16T00:00:{index:02d}Z",
                        True,
                        False,
                    )
                )
            store.commit()
            self.repository.publish(snapshot.identity.git_ref_sha, snapshot)
        except Exception:
            store.rollback()
            raise
        finally:
            snapshot.close()
        return ids

    def _ordered_task_ids(self, task_ids: Sequence[str]) -> tuple[str, ...]:
        wanted = set(task_ids)
        snapshot = self.repository.bootstrap()
        try:
            ordered = tuple(
                task.task_id
                for task in self.repository.store(snapshot).tasks()
                if task.task_id in wanted
            )
            if set(ordered) != wanted or len(ordered) != len(wanted):
                raise LiveExecutorError("DETERMINISTIC_TASK_ORDER_INCOMPLETE")
            return ordered
        finally:
            snapshot.close()

    def _request_row(self, request_id: str) -> dict[str, Any] | None:
        def read() -> dict[str, Any] | None:
            snapshot = self.repository.bootstrap()
            try:
                row = self.repository.store(snapshot).get_request(request_id)
                return None if row is None else dict(row)
            finally:
                snapshot.close()

        return self._post_allocation_read(read)

    def _canonical_projection(self, request_id: str, **kwargs: Any) -> CanonicalProjection:
        return self._post_allocation_read(
            lambda: self.reconciler._canonical_projection(request_id, **kwargs)
        )

    def _request_row_identity(self, request_id: str) -> str:
        row = self._request_row(request_id)
        if row is None:
            raise LiveExecutorError("CANONICAL_REQUEST_ROW_MISSING")
        return _sha256(row)

    def _audit_exists(self, request_id: str, reason_code: str) -> bool:
        snapshot = self.repository.bootstrap()
        try:
            row = self.repository.store(snapshot).connection.execute(
                """SELECT event_id FROM allocation_events WHERE request_id = ?
                   AND event_type = 'AUDIT_FINDING' AND reason_code = ? LIMIT 1""",
                (request_id, reason_code),
            ).fetchone()
            return row is not None
        finally:
            snapshot.close()

    def _counts(self) -> tuple[int, int]:
        snapshot = self.repository.bootstrap()
        try:
            store = self.repository.store(snapshot)
            requests = store.connection.execute(
                "SELECT COUNT(*) AS n FROM allocation_requests"
            ).fetchone()
            allocations = store.connection.execute(
                "SELECT COUNT(*) AS n FROM allocations"
            ).fetchone()
            return int(requests["n"]), int(allocations["n"])
        finally:
            snapshot.close()

    def _allocation(self, allocation_id: str) -> dict[str, Any]:
        snapshot = self.repository.bootstrap()
        try:
            row = self.repository.store(snapshot).connection.execute(
                "SELECT * FROM allocations WHERE allocation_id = ?", (allocation_id,)
            ).fetchone()
            if row is None:
                raise LiveExecutorError("ALLOCATION_ROW_MISSING")
            return dict(row)
        finally:
            snapshot.close()

    def _allocation_optional(self, allocation_id: str) -> dict[str, Any] | None:
        try:
            return self._allocation(allocation_id)
        except LiveExecutorError as exc:
            if str(exc) == "ALLOCATION_ROW_MISSING":
                return None
            raise

    def _allocations_for_tasks(self, task_ids: Sequence[str]) -> tuple[dict[str, Any], ...]:
        snapshot = self.repository.bootstrap()
        try:
            store = self.repository.store(snapshot)
            rows: list[dict[str, Any]] = []
            for task_id in task_ids:
                for row in store.connection.execute(
                    "SELECT * FROM allocations WHERE task_id = ? ORDER BY allocation_id",
                    (task_id,),
                ).fetchall():
                    rows.append(dict(row))
            return tuple(rows)
        finally:
            snapshot.close()

    def _mirrors_valid(self, task_ids: Sequence[str]) -> bool:
        snapshot = self.repository.bootstrap()
        try:
            store = self.repository.store(snapshot)
            for task_id in task_ids:
                task = store.task(task_id)
                if task is None:
                    return False
                try:
                    store.assert_ownership_invariant(task)
                except CanonicalOwnershipMismatch:
                    return False
            return True
        finally:
            snapshot.close()

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
    ) -> _ResultRecord:
        if payload_variant:
            raise LiveExecutorError("UNSUPPORTED_PROTOCOL_PAYLOAD_VARIANT")
        rid, body, payload_hash = _protocol_request_contract(
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
        command = AllocationCommand(
            request_id=rid,
            request_type=request_type,
            payload_hash=payload_hash,
            agent_id=self.agent_id,
            task_id=task_id,
            allocation_id=allocation_id,
            reason=reason,
            task_types=("task",) if request_type == "ALLOCATE_NEXT" else (),
        )
        context = RequestContext(
            CONTROL_REPOSITORY,
            self.issue_number,
            source_id,
            "fixture:gitstate-phase-2-allocator",
            self.agent_id,
        )
        service = AllocationService(self.repository, clock=lambda: NOW)
        result = service.process(command, context)
        if not result.canonical_git_ref_sha or not result.canonical_dolt_commit:
            raise LiveExecutorError("CANONICAL_RESULT_IDENTITY_MISSING")
        if result.ref_advanced:
            anchor = service.record_anchor(rid, result.canonical_git_ref_sha, result.canonical_dolt_commit)
            if anchor.reason_code in {"CANONICAL_PUSH_FAILED", "STALE_ALLOCATOR_RETRY_EXHAUSTED"}:
                raise LiveExecutorError("CANONICAL_ANCHOR_RECORD_FAILED")
        record = _ResultRecord(
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
            projection = self._canonical_projection(
                rid, source_comment_id=source_id
            )
            body = render_projection(projection)
            posted = self.gateway.post_projection(self.issue_number, body)
            self.reconciler._record_projection_posted(rid, posted)
            record.projection_url = posted.html_url
            record.projection_body = body
        self.memory[f"s{scenario}:{index}"] = record
        return record

    def _executable_identities(self) -> tuple[ExecutableIdentity, ...]:
        identities = []
        for path in LIVE_EXECUTABLE_PATHS:
            entry = _run(
                ["git", "ls-tree", self.trusted_sha, "--", path], cwd=Path.cwd()
            )
            blob = _run(
                ["git", "rev-parse", "--verify", f"{self.trusted_sha}:{path}"],
                cwd=Path.cwd(),
            )
            identities.append(
                ExecutableIdentity(
                    path,
                    blob,
                    self.trusted_sha,
                    entry,
                    f"{self.trusted_sha}:{path}",
                )
            )
        return tuple(identities)

    @staticmethod
    def _terminal(record: _ResultRecord) -> TerminalRequestEvidence:
        return TerminalRequestEvidence(
            record.source_id,
            record.request_id,
            record.status,
            record.reason,
            record.accepted_ref,
            record.dolt_commit,
            record.canonical_row,
            record.projection_url,
        )

    @staticmethod
    def _consume_projection_api_only(
        gateway: GitHubIssueGateway, issue_number: int, projection_url: str
    ) -> tuple[dict[str, Any], ClientTranscript]:
        comments = gateway.list_comments(issue_number)
        matching = tuple(item for item in comments if item.html_url == projection_url)
        if len(matching) != 1:
            raise LiveExecutorError("API_ONLY_PROJECTION_NOT_UNIQUE")
        payload = parse_projection(matching[0].body)
        if payload is None:
            raise LiveExecutorError("API_ONLY_PROJECTION_INVALID")
        transcript = ClientTranscript(
            "github-api-only",
            _sha256(
                {
                    "comment_id": matching[0].comment_id,
                    "projection_url": projection_url,
                    "body_sha256": hashlib.sha256(matching[0].body.encode()).hexdigest(),
                    "capabilities": ["github_issue_api"],
                }
            ),
            True,
        )
        return payload, transcript

    def _fresh_git_reconstruction(
        self, request_ids: Sequence[str]
    ) -> tuple[dict[str, Any], ClientTranscript]:
        if self.read_only_remote_factory is None:
            raise LiveExecutorError("READ_ONLY_RECONSTRUCTION_TRANSPORT_MISSING")
        with tempfile.TemporaryDirectory(prefix="wd-read-only-client-") as directory:
            root = Path(directory)
            mirror, source_sha = self.read_only_remote_factory(root)
            client_root = root / "client"
            client_root.mkdir()

            def read_only_run(
                command: Sequence[str], cwd: Path
            ) -> subprocess.CompletedProcess[str]:
                executable = Path(command[0]).name
                lowered = tuple(str(item).lower() for item in command[1:])
                if (
                    (executable == "git" and any(item in {"push", "receive-pack"} for item in lowered))
                    or (executable == Path(self.repository.dolt_bin).name and "push" in lowered)
                ):
                    raise LiveExecutorError("READ_ONLY_CLIENT_REMOTE_WRITE_FORBIDDEN")
                return subprocess.run(
                    list(command),
                    cwd=cwd,
                    env=_credential_free_git_env(),
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

            read_only_repository = DoltCanonicalRepository(
                "git+file://" + str(mirror),
                lambda database: ManagedDoltConnection(database, self.repository.dolt_bin),
                dolt_bin=self.repository.dolt_bin,
                run_command=read_only_run,
                workspace_root=client_root,
            )
            snapshot = read_only_repository.bootstrap()
            try:
                if snapshot.identity.git_ref_sha != source_sha:
                    raise LiveExecutorError("READ_ONLY_CLIENT_SOURCE_REF_MISMATCH")
                if any(path.name == ".beads" for path in snapshot.workspace.rglob(".beads")):
                    raise LiveExecutorError("FRESH_CLIENT_CONTAINS_BEADS_WORKSPACE")
                reconstructed = read_only_repository.store(snapshot).reconstruct()
                seen = {str(row.get("request_id")) for row in reconstructed.get("requests", [])}
                if any(request_id not in seen for request_id in request_ids):
                    raise LiveExecutorError("FRESH_CLIENT_REQUEST_MISSING")
                credential_keys = {
                    "PHASE2_STATE_TOKEN",
                    "GIT_ASKPASS",
                    "GH_TOKEN",
                    "GITHUB_TOKEN",
                    "GITHUB_PAT",
                }
                clean = not any(key in _credential_free_git_env() for key in credential_keys)
                transcript = ClientTranscript(
                    "git-capable",
                    _sha256(
                        {
                            "canonical_git_ref_sha": snapshot.identity.git_ref_sha,
                            "canonical_dolt_commit": snapshot.identity.dolt_commit,
                            "requested_ids": list(request_ids),
                            "reconstruction_sha256": _sha256(reconstructed),
                            "fresh_workspace": True,
                            "beads_workspace_present": False,
                            "client_credentials_present": False,
                            "remote": "credential-free-read-only-mirror-of-exact-github-ref",
                            "source_github_ref_sha": source_sha,
                        }
                    ),
                    clean,
                )
                return reconstructed, transcript
            finally:
                snapshot.close()
                _set_tree_read_only(mirror, read_only=False)

    def _evidence(
        self,
        spec: ScenarioSpec,
        proof: ScenarioProof,
        *,
        source_ids: tuple[int, ...] = (),
        request_ids: tuple[str, ...] = (),
        base_refs: tuple[str, ...] = (),
        accepted_refs: tuple[str, ...] = (),
        dolt_commits: tuple[str, ...] = (),
        canonical_rows: tuple[str, ...] = (),
        projection_urls: tuple[str, ...] = (),
        terminals: tuple[TerminalRequestEvidence, ...] = (),
        repeated_result: RepeatedResultEvidence | None = None,
        final_owner: FinalOwnerEvidence | None = None,
        allocation_rows: tuple[CanonicalAllocationEvidence, ...] = (),
        clients: tuple[ClientTranscript, ...] = (),
        cleanup: str = "retain",
        network: tuple[str, ...] = (),
        scenario13: bool = False,
    ) -> ScenarioEvidence:
        assertions, faults = proof.finalise()
        return ScenarioEvidence(
            scenario_id=spec.scenario_id,
            attempt_namespace=self.namespace.value,
            trusted_sha=self.trusted_sha,
            protocol_sha=self.protocol_sha,
            workflow_run_id=self.namespace.run_id,
            workflow_run_attempt=self.namespace.run_attempt,
            control_repository_id=CONTROL_REPOSITORY_ID,
            state_repository_id=STATE_REPOSITORY_ID,
            exit_status=0,
            source_comment_ids=source_ids,
            request_ids=request_ids,
            base_ref_shas=base_refs,
            accepted_ref_shas=accepted_refs,
            dolt_commits=dolt_commits,
            canonical_rows=canonical_rows,
            projection_urls=projection_urls,
            terminal_requests=terminals,
            allocation_rows=allocation_rows,
            fault_ids=faults,
            assertions=assertions,
            client_transcripts=clients,
            executable_identities=self._executable_identities(),
            dependency_identities=REQUIRED_DEPENDENCY_IDENTITIES,
            durability_records=DURABILITY,
            repeated_result=repeated_result,
            final_owner=final_owner,
            installation_inventory_repository_ids=(
                (CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID) if scenario13 else ()
            ),
            installation_inventory_current=scenario13,
            installation_inventory_attestation=self.inventory.digest if scenario13 else "",
            token_scope_records=self.token_scope_records if scenario13 else (),
            network_destinations=network,
            cleanup_decision=cleanup,
            limitations=(
                "synthetic fixture only",
                "no production approval",
                "Workstream E not authorised",
            ),
        )

    def execute(self, spec: ScenarioSpec, namespace: AttemptNamespace) -> ScenarioEvidence:
        if namespace != self.namespace:
            raise LiveExecutorError("BACKEND_ATTEMPT_MISMATCH")
        handler = getattr(self, f"_scenario_{spec.scenario_id}", None)
        if not callable(handler) or spec.scenario_id not in SCENARIO_IDS:
            raise LiveExecutorError("UNAPPROVED_SCENARIO")
        result = handler(spec)
        self.executed_records[spec.scenario_id] = result
        return result

    def _scenario_1(self, spec: ScenarioSpec) -> ScenarioEvidence:
        proof = ScenarioProof(spec, self.namespace)
        tasks = self._seed(1, 2)
        expected_order = self._ordered_task_ids(tasks)
        base = self._identity()
        sources, request_ids, source_elapsed, visible = self._post_protocol_sources(
            1, ("ALLOCATE_NEXT", "ALLOCATE_NEXT")
        )
        workers = (self._fresh_backend(), self._fresh_backend())
        values, process_start_spread = _run_close_timed_calls(
            (
                lambda: workers[0]._process(
                    1,
                    1,
                    request_type="ALLOCATE_NEXT",
                    request_id=request_ids[0],
                    source_override=sources[0],
                ),
                lambda: workers[1]._process(
                    1,
                    2,
                    request_type="ALLOCATE_NEXT",
                    request_id=request_ids[1],
                    source_override=sources[1],
                ),
            )
        )
        first, second = values
        rows = self._allocations_for_tasks(tasks)
        active = tuple(row for row in rows if row.get("state") == "ACTIVE")
        proof.fault(
            "close_timed_requests",
            visible
            and source_elapsed <= CLOSE_TIMED_MAX_SECONDS
            and process_start_spread <= CLOSE_TIMED_MAX_SECONDS,
            EXPECTED_FAULT_OUTCOMES["close_timed_requests"],
        )
        proof.assertion(0, len(active) == 2, f"active_rows={len(active)}")
        proof.assertion(
            1,
            len({row.get("task_id") for row in active}) == 2
            and len({row.get("allocation_id") for row in active}) == 2,
            "task_ids and allocation_ids are pairwise distinct",
        )
        proof.assertion(
            2,
            self._mirrors_valid(tasks),
            "both task mirrors satisfy ownership invariant",
        )
        selected = {first.task_id, second.task_id}
        if self.read_only_remote_factory is None:
            raise LiveExecutorError("SCENARIO_1_READ_ONLY_MIRROR_BROKER_MISSING")
        records_by_ref = {
            first.accepted_ref: first,
            second.accepted_ref: second,
        }
        if len(records_by_ref) != 2:
            raise LiveExecutorError("SCENARIO_1_CREATION_REFS_EQUAL")
        with tempfile.TemporaryDirectory(prefix="wd-scenario-1-order-") as directory:
            mirror, current_ref = self.read_only_remote_factory(Path(directory))
            try:
                creation_refs = _canonical_creation_ref_order(
                    mirror,
                    current_ref,
                    tuple(records_by_ref),
                )
            finally:
                _set_tree_read_only(mirror, read_only=False)
        creation_order = tuple(records_by_ref[ref].task_id for ref in creation_refs)
        proof.assertion(
            3,
            selected == set(tasks)
            and expected_order == tasks
            and creation_order == expected_order,
            (
                f"expected_priority_created_id_order={expected_order} "
                f"canonical_creation_order={creation_order} "
                f"creation_refs={creation_refs} current_ref={current_ref} "
                f"start_spread={process_start_spread:.6f}"
            ),
        )
        return self._evidence(
            spec,
            proof,
            source_ids=(first.source_id, second.source_id),
            request_ids=(first.request_id, second.request_id),
            base_refs=(base.git_ref_sha, base.git_ref_sha),
            accepted_refs=(first.accepted_ref, second.accepted_ref),
            dolt_commits=(first.dolt_commit, second.dolt_commit),
            canonical_rows=(first.canonical_row, second.canonical_row),
            projection_urls=(first.projection_url, second.projection_url),
            terminals=(self._terminal(first), self._terminal(second)),
        )

    def _scenario_2(self, spec: ScenarioSpec) -> ScenarioEvidence:
        proof = ScenarioProof(spec, self.namespace)
        task_id = self._seed(2, 1)[0]
        base = self._identity()
        sources, request_ids, source_elapsed, visible = self._post_protocol_sources(
            2,
            ("ALLOCATE_TASK", "ALLOCATE_TASK"),
            task_ids=(task_id, task_id),
        )
        workers = (self._fresh_backend(), self._fresh_backend())
        values, process_start_spread = _run_close_timed_calls(
            (
                lambda: workers[0]._process(
                    2,
                    1,
                    request_type="ALLOCATE_TASK",
                    task_id=task_id,
                    request_id=request_ids[0],
                    source_override=sources[0],
                ),
                lambda: workers[1]._process(
                    2,
                    2,
                    request_type="ALLOCATE_TASK",
                    task_id=task_id,
                    request_id=request_ids[1],
                    source_override=sources[1],
                ),
            )
        )
        first, second = values
        rows = self._allocations_for_tasks((task_id,))
        active = tuple(row for row in rows if row.get("state") == "ACTIVE")
        proof.fault(
            "close_timed_requests",
            visible
            and source_elapsed <= CLOSE_TIMED_MAX_SECONDS
            and process_start_spread <= CLOSE_TIMED_MAX_SECONDS,
            EXPECTED_FAULT_OUTCOMES["close_timed_requests"],
        )
        proof.assertion(0, len(active) == 1, f"active_rows={len(active)}")
        proof.assertion(
            1,
            self._mirrors_valid((task_id,)),
            "task mirror agrees with single active allocation",
        )
        proof.assertion(
            2,
            len(rows) == 1
            and sorted((first.reason, second.reason))
            == ["ALLOCATED", "TASK_ALREADY_ALLOCATED"],
            f"allocation_rows={len(rows)} results={first.reason},{second.reason} start_spread={process_start_spread:.6f}",
        )
        return self._evidence(
            spec,
            proof,
            source_ids=(first.source_id, second.source_id),
            request_ids=(first.request_id, second.request_id),
            base_refs=(base.git_ref_sha, base.git_ref_sha),
            accepted_refs=(first.accepted_ref, second.accepted_ref),
            dolt_commits=(first.dolt_commit, second.dolt_commit),
            canonical_rows=(first.canonical_row, second.canonical_row),
            projection_urls=(first.projection_url, second.projection_url),
            terminals=(self._terminal(first), self._terminal(second)),
        )

    def _scenario_3(self, spec: ScenarioSpec) -> ScenarioEvidence:
        proof = ScenarioProof(spec, self.namespace)
        self._seed(3, 3)
        base = self._identity()
        sources, request_ids, source_elapsed, initial_visible = self._post_protocol_sources(
            3, ("ALLOCATE_NEXT", "ALLOCATE_NEXT", "ALLOCATE_NEXT")
        )
        third_rid = request_ids[2]
        queued_executed = {"value": False}

        def queued_third() -> _ResultRecord:
            queued_executed["value"] = True
            return self._fresh_backend()._process(
                3,
                3,
                request_type="ALLOCATE_NEXT",
                request_id=third_rid,
                source_override=sources[2],
            )

        queued_cancelled = _cancel_queued_call(queued_third)
        cancelled_before_canonical = (
            queued_cancelled
            and not queued_executed["value"]
            and self._request_row(third_rid) is None
        )

        workers = (self._fresh_backend(), self._fresh_backend())
        first_two, process_start_spread = _run_close_timed_calls(
            (
                lambda: workers[0]._process(
                    3,
                    1,
                    request_type="ALLOCATE_NEXT",
                    request_id=request_ids[0],
                    source_override=sources[0],
                ),
                lambda: workers[1]._process(
                    3,
                    2,
                    request_type="ALLOCATE_NEXT",
                    request_id=request_ids[1],
                    source_override=sources[1],
                ),
            )
        )
        first, second = first_two

        filler_ids = tuple(
            self._post_source(3, 1000 + index, "pagination-fixture")[0]
            for index in range(SCENARIO_3_FILLER_COUNT)
        )
        recovery = self._fresh_backend(
            comment_page_size=SCENARIO_3_FIXTURE_PAGE_SIZE
        )
        listed_comments = recovery.gateway.list_comments(self.issue_number)
        listed = {item.comment_id for item in listed_comments}
        retained_after_cancel = sources[2][0] in listed
        recovered: dict[str, _ResultRecord] = {}

        def recover_unprocessed(comment: DurableComment) -> None:
            if comment.comment_id != sources[2][0]:
                raise LiveExecutorError("SCENARIO_3_UNEXPECTED_UNPROCESSED_PROTOCOL_COMMENT")
            parsed = parse_request(comment.body.encode("utf-8"))
            if parsed.payload.get("request_id") != third_rid:
                raise LiveExecutorError("SCENARIO_3_RECOVERY_REQUEST_BINDING_MISMATCH")
            recovered["third"] = recovery._process(
                3,
                3,
                request_type="ALLOCATE_NEXT",
                request_id=third_rid,
                source_override=(comment.comment_id, comment.html_url),
            )

        recovery_reconciler = ReconciliationService(
            recovery.repository,
            recovery.gateway,
            control_repository=CONTROL_REPOSITORY,
            issue_number=self.issue_number,
            task_summary_lookup=lambda task_id: f"synthetic fixture {task_id}",
            canonical_history=_HistoryStub(),
            unprocessed_handler=recover_unprocessed,
            clock=lambda: NOW,
        )
        recovery_summary = recovery_reconciler.reconcile(
            f"{self.namespace.value}:scenario-3-recovery"
        )
        third = recovered.get("third")
        if third is None:
            raise LiveExecutorError("SCENARIO_3_RECONCILIATION_DID_NOT_RECOVER_SOURCE")
        records = (first, second, third)
        pagination_complete = (
            len(listed_comments) > SCENARIO_3_FIXTURE_PAGE_SIZE
            and all(item in listed for item in filler_ids)
            and all(source[0] in listed for source in sources)
        )
        accepted_recovery = (
            sources[2][0] in recovery_summary.unprocessed_comments
            and third.status == "ALLOCATED"
            and self._request_row(third_rid) is not None
            and not recovery_summary.errors
        )
        proof.fault(
            "cancel_queued_attempt",
            initial_visible
            and source_elapsed <= CLOSE_TIMED_MAX_SECONDS
            and process_start_spread <= CLOSE_TIMED_MAX_SECONDS
            and queued_cancelled
            and cancelled_before_canonical
            and retained_after_cancel
            and accepted_recovery,
            EXPECTED_FAULT_OUTCOMES["cancel_queued_attempt"],
        )
        proof.fault(
            "multi_page_comment_fixture",
            pagination_complete,
            EXPECTED_FAULT_OUTCOMES["multi_page_comment_fixture"],
        )
        proof.assertion(
            0,
            pagination_complete,
            (
                f"fixture_page_size={SCENARIO_3_FIXTURE_PAGE_SIZE} "
                f"listed_filler_count={sum(item in listed for item in filler_ids)}"
            ),
        )
        proof.assertion(
            1,
            queued_cancelled
            and cancelled_before_canonical
            and retained_after_cancel
            and accepted_recovery,
            "queued third worker was cancelled before execution; accepted full-pagination reconciliation rediscovered and terminated the retained source",
        )
        proof.assertion(
            2,
            all(item.status == "ALLOCATED" for item in records)
            and all(self._request_row(item.request_id) is not None for item in records),
            "all three retained fixture requests are terminal canonical requests",
        )
        return self._evidence(
            spec,
            proof,
            source_ids=tuple(item.source_id for item in records),
            request_ids=tuple(item.request_id for item in records),
            base_refs=(base.git_ref_sha, base.git_ref_sha, second.accepted_ref),
            accepted_refs=tuple(item.accepted_ref for item in records),
            dolt_commits=tuple(item.dolt_commit for item in records),
            canonical_rows=tuple(item.canonical_row for item in records),
            projection_urls=tuple(item.projection_url for item in records),
            terminals=tuple(self._terminal(item) for item in records),
        )

    def _scenario_4(self, spec: ScenarioSpec) -> ScenarioEvidence:
        proof_recorder = ScenarioProof(spec, self.namespace)
        task_id = self._seed(4, 1)[0]
        base = self._identity()
        first = self._process(4, 1, request_type="ALLOCATE_TASK", task_id=task_id)
        before_ref = self._identity().git_ref_sha
        before_counts = self._counts()
        command = AllocationCommand(
            first.request_id,
            "ALLOCATE_TASK",
            first.payload_hash,
            self.agent_id,
            task_id=task_id,
        )
        context = RequestContext(
            CONTROL_REPOSITORY,
            self.issue_number,
            first.source_id,
            "fixture:gitstate-phase-2-allocator",
            self.agent_id,
        )
        repeated = AllocationService(self.repository, clock=lambda: NOW).process(command, context)
        after_ref = self._identity().git_ref_sha
        after_counts = self._counts()
        projection = self.reconciler._canonical_projection(first.request_id, source_comment_id=first.source_id)
        body = render_projection(projection)
        posted = self.gateway.post_projection(self.issue_number, body)
        original_digest = hashlib.sha256(first.projection_body.encode()).hexdigest()
        repeated_digest = hashlib.sha256(body.encode()).hexdigest()
        repeated_proof = RepeatedResultEvidence(
            first.request_id,
            first.canonical_row,
            first.projection_url,
            posted.html_url,
            original_digest,
            repeated_digest,
            before_ref,
            after_ref,
            before_counts[0],
            after_counts[0],
            before_counts[1],
            after_counts[1],
        )
        proof_recorder.assertion(
            0,
            not repeated.ref_advanced and before_ref == after_ref,
            f"canonical_ref={after_ref}",
        )
        proof_recorder.assertion(1, before_counts == after_counts, f"counts={after_counts}")
        proof_recorder.assertion(
            2,
            first.projection_body == body,
            f"projection_sha256={repeated_digest}",
        )
        identity = self._identity()
        return self._evidence(
            spec,
            proof_recorder,
            request_ids=(first.request_id,),
            base_refs=(base.git_ref_sha,),
            accepted_refs=(after_ref,),
            dolt_commits=(identity.dolt_commit,),
            canonical_rows=(first.canonical_row,),
            projection_urls=(first.projection_url, posted.html_url),
            repeated_result=repeated_proof,
        )

    def _scenario_5(self, spec: ScenarioSpec) -> ScenarioEvidence:
        proof = ScenarioProof(spec, self.namespace)
        task_id = self._seed(5, 1)[0]
        base = self._identity()
        first = self._process(5, 1, request_type="ALLOCATE_TASK", task_id=task_id, project=False)
        before = self._identity()
        before_counts = self._counts()
        before_allocation = None if not first.allocation_id else self._allocation(first.allocation_id)
        changed_payload = "f" * 64
        command = AllocationCommand(
            first.request_id, "ALLOCATE_TASK", changed_payload, self.agent_id, task_id=task_id
        )
        context = RequestContext(
            CONTROL_REPOSITORY,
            self.issue_number,
            first.source_id,
            "fixture:gitstate-phase-2-allocator",
            self.agent_id,
        )
        mismatch = AllocationService(self.repository, clock=lambda: NOW).process(command, context)
        after = self._identity()
        after_counts = self._counts()
        after_allocation = None if not first.allocation_id else self._allocation(first.allocation_id)
        projection = CanonicalProjection(
            request_id=first.request_id,
            result_status="REJECTED",
            reason_code=mismatch.reason_code,
            source_repository=CONTROL_REPOSITORY,
            source_issue_number=self.issue_number,
            source_comment_id=first.source_id,
            canonical_git_ref_sha=first.accepted_ref,
            canonical_dolt_commit=first.dolt_commit,
        )
        posted = self.gateway.post_projection(self.issue_number, render_projection(projection))
        proof.assertion(0, first.payload_hash != changed_payload, "original and replay payload hashes differ")
        proof.assertion(
            1,
            mismatch.reason_code == "REQUEST_ID_PAYLOAD_MISMATCH" and before.git_ref_sha == after.git_ref_sha,
            f"reason={mismatch.reason_code} ref={after.git_ref_sha}",
        )
        proof.assertion(
            2,
            before_counts == after_counts and _sha256(before_allocation) == _sha256(after_allocation),
            "request/allocation counts and ownership row are unchanged",
        )
        return self._evidence(
            spec,
            proof,
            base_refs=(base.git_ref_sha,),
            accepted_refs=(after.git_ref_sha,),
            dolt_commits=(after.dolt_commit,),
            canonical_rows=(first.canonical_row,),
            projection_urls=(posted.html_url,),
        )

    def _scenario_6(self, spec: ScenarioSpec) -> ScenarioEvidence:
        proof_recorder = ScenarioProof(spec, self.namespace)
        task_id = self._seed(6, 1)[0]
        left = self.repository.bootstrap()
        right = self.repository.bootstrap()
        left_base = left.identity.git_ref_sha
        left_store = self.repository.store(left)
        right_store = self.repository.store(right)
        rid1 = stable_ulid(f"{self.namespace.value}:s6:winner")
        rid2 = stable_ulid(f"{self.namespace.value}:s6:stale")
        _, body1, hash1 = _protocol_request_contract(
            self.namespace, 6, 1, request_type="ALLOCATE_TASK", task_id=task_id, request_id=rid1
        )
        _, body2, hash2 = _protocol_request_contract(
            self.namespace, 6, 2, request_type="ALLOCATE_TASK", task_id=task_id, request_id=rid2
        )
        source1, _ = self._post_body(body1)
        source2, _ = self._post_body(body2)
        c1 = AllocationCommand(rid1, "ALLOCATE_TASK", hash1, self.agent_id, task_id=task_id)
        c2 = AllocationCommand(rid2, "ALLOCATE_TASK", hash2, self.agent_id, task_id=task_id)
        ctx1 = RequestContext(CONTROL_REPOSITORY, self.issue_number, source1, "fixture", self.agent_id)
        ctx2 = RequestContext(CONTROL_REPOSITORY, self.issue_number, source2, "fixture", self.agent_id)
        stale_rejected = False
        try:
            left_store.begin()
            winner = AllocationService(self.repository, clock=lambda: NOW)._apply(left_store, c1, ctx1, NOW)
            left_store.commit()
            right_store.begin()
            stale = AllocationService(self.repository, clock=lambda: NOW)._apply(right_store, c2, ctx2, NOW)
            right_store.commit()
            accepted = self.repository.publish(left.identity.git_ref_sha, left)
            try:
                self.repository.publish(right.identity.git_ref_sha, right)
            except StaleCanonicalBase:
                stale_rejected = True
            else:
                raise LiveExecutorError("SCENARIO_6_STALE_WRITER_ACCEPTED")
        finally:
            left.close()
            right.close()
        if not winner.allocation_id or not stale.allocation_id:
            raise LiveExecutorError("SCENARIO_6_ALLOCATION_ID_MISSING")
        anchor = AllocationService(self.repository, clock=lambda: NOW).record_anchor(
            rid1, accepted.git_ref_sha, accepted.dolt_commit
        )
        if anchor.reason_code in {"CANONICAL_PUSH_FAILED", "STALE_ALLOCATOR_RETRY_EXHAUSTED"}:
            raise LiveExecutorError("SCENARIO_6_WINNER_ANCHOR_FAILED")
        row = self._allocation(winner.allocation_id)
        stale_row = self._allocation_optional(stale.allocation_id)
        final = self._identity()
        row_identity = _sha256(row)
        allocation = CanonicalAllocationEvidence(
            winner.allocation_id, row_identity, final.git_ref_sha, "ACTIVE", self.agent_id
        )
        final_owner = FinalOwnerEvidence(
            winner.allocation_id,
            winner.allocation_id,
            stale.allocation_id,
            final.git_ref_sha,
            final.git_ref_sha,
        )
        publish_params = tuple(inspect.signature(DoltCanonicalRepository.publish).parameters)
        proof_recorder.fault(
            "delay_publication",
            stale_rejected,
            EXPECTED_FAULT_OUTCOMES["delay_publication"],
        )
        proof_recorder.assertion(0, stale_rejected, "second publish raised StaleCanonicalBase")
        proof_recorder.assertion(1, stale_row is None, "stale allocation ID is absent from accepted canonical rows")
        proof_recorder.assertion(2, "force" not in publish_params, f"publish_parameters={publish_params}")
        proof_recorder.assertion(
            3,
            row.get("allocation_id") == winner.allocation_id
            and self._request_row(rid1) is not None
            and self._request_row(rid1).get("anchor_status") == "RECORDED",
            f"final_ref={final.git_ref_sha} creation_ref={accepted.git_ref_sha} winner={winner.allocation_id}",
        )
        return self._evidence(
            spec,
            proof_recorder,
            base_refs=(left_base,),
            accepted_refs=(final.git_ref_sha,),
            dolt_commits=(final.dolt_commit,),
            canonical_rows=(row_identity,),
            allocation_rows=(allocation,),
            final_owner=final_owner,
        )

    def _scenario_7(self, spec: ScenarioSpec) -> ScenarioEvidence:
        proof = ScenarioProof(spec, self.namespace)
        task_id = self._seed(7, 1)[0]
        base = self._identity()
        before_counts = self._counts()
        source, _ = self._post_source(7, 1, "ALLOCATE_TASK")
        rid = stable_ulid(f"{self.namespace.value}:s7")
        command = AllocationCommand(rid, "ALLOCATE_TASK", hashlib.sha256(b"s7").hexdigest(), self.agent_id, task_id=task_id)
        context = RequestContext(CONTROL_REPOSITORY, self.issue_number, source, "fixture", self.agent_id)
        repository = self.repository
        injected = {"called": False}

        class FailPublish:
            def bootstrap(self_inner):
                return repository.bootstrap()

            def store(self_inner, snapshot):
                return repository.store(snapshot)

            def publish(self_inner, expected, snapshot):
                injected["called"] = True
                raise CanonicalPushFailed("INJECTED_FIXTURE_PUSH_FAILURE")

        result = AllocationService(FailPublish(), clock=lambda: NOW, max_stale_retries=0).process(command, context)
        after = self._identity()
        after_counts = self._counts()
        proof.fault(
            "fail_canonical_push",
            injected["called"] and result.reason_code == "CANONICAL_PUSH_FAILED",
            EXPECTED_FAULT_OUTCOMES["fail_canonical_push"],
        )
        proof.assertion(
            0,
            after.git_ref_sha == base.git_ref_sha and after_counts == before_counts,
            f"ref={after.git_ref_sha} counts={after_counts}",
        )
        proof.assertion(1, result.reason_code == "CANONICAL_PUSH_FAILED", f"reason={result.reason_code}")
        return self._evidence(
            spec,
            proof,
            base_refs=(base.git_ref_sha,),
            accepted_refs=(base.git_ref_sha,),
            dolt_commits=(base.dolt_commit,),
            canonical_rows=(_sha256({"ref": base.git_ref_sha, "counts": before_counts}),),
        )

    def _scenario_8(self, spec: ScenarioSpec) -> ScenarioEvidence:
        proof = ScenarioProof(spec, self.namespace)
        task_id = self._seed(8, 1)[0]
        base = self._identity()
        result = self._process(8, 1, request_type="ALLOCATE_TASK", task_id=task_id, project=False)
        projection = self.reconciler._canonical_projection(result.request_id, source_comment_id=result.source_id)
        body = render_projection(projection)
        failing = _FailFirstProjectionGateway(self.gateway)
        failed = False
        try:
            failing.post_projection(self.issue_number, body)
        except RuntimeError as exc:
            failed = str(exc) == "INJECTED_FIXTURE_PROJECTION_POST_FAILURE"
        if not failed:
            raise LiveExecutorError("SCENARIO_8_PROJECTION_FAILURE_NOT_INJECTED")
        self.reconciler._record_projection_missing(result.request_id)
        recovery = self._fresh_backend()
        repaired_projection = recovery.reconciler._canonical_projection(
            result.request_id, source_comment_id=result.source_id
        )
        repaired_body = render_projection(repaired_projection)
        repaired = recovery.gateway.post_projection(self.issue_number, repaired_body)
        if not recovery.reconciler._record_projection_posted(result.request_id, repaired):
            raise LiveExecutorError("SCENARIO_8_REPAIR_NOT_RECORDED")
        before_orphan_counts = self._counts()
        orphan_request_id = stable_ulid(f"{self.namespace.value}:s8:orphan")
        orphan_body = render_projection(
            {
                **repaired_projection.envelope(),
                "request_id": orphan_request_id,
                "source_comment_id": result.source_id + 1000000000,
            }
        )
        orphan = self.gateway.post_projection(self.issue_number, orphan_body)
        orphan_comment = DurableComment(orphan.comment_id, orphan_body, orphan.html_url)
        summary = ReconciliationSummary(self.namespace.value)
        self.reconciler._invalidate_orphan(orphan_comment, summary)
        after_orphan_counts = self._counts()
        orphan_subject = self.reconciler._orphan_subject(orphan_comment)
        result.projection_url = repaired.html_url
        result.projection_body = repaired_body
        proof.fault(
            "fail_projection_post",
            failing.attempted and failed and repaired.html_url != "",
            EXPECTED_FAULT_OUTCOMES["fail_projection_post"],
        )
        proof.fault(
            "inject_orphan_projection",
            orphan.comment_id in summary.orphan_projections_invalidated,
            EXPECTED_FAULT_OUTCOMES["inject_orphan_projection"],
        )
        proof.assertion(
            0,
            repaired_projection.canonical_git_ref_sha == result.accepted_ref
            and repaired_projection.canonical_dolt_commit == result.dolt_commit,
            f"git={result.accepted_ref} dolt={result.dolt_commit}",
        )
        expected_subject = f"{CONTROL_REPOSITORY}:issue:{self.issue_number}:projection_comment:{orphan.comment_id}"
        proof.assertion(1, orphan_subject == expected_subject, f"orphan_subject={orphan_subject}")
        proof.assertion(
            2,
            before_orphan_counts == after_orphan_counts and self._request_row(orphan_request_id) is None,
            "orphan invalidation changed no request/allocation row",
        )
        return self._evidence(
            spec,
            proof,
            source_ids=(result.source_id,),
            base_refs=(base.git_ref_sha,),
            accepted_refs=(result.accepted_ref,),
            dolt_commits=(result.dolt_commit,),
            canonical_rows=(result.canonical_row,),
            projection_urls=(repaired.html_url,),
        )

    def _scenario_9(self, spec: ScenarioSpec) -> ScenarioEvidence:
        proof = ScenarioProof(spec, self.namespace)
        task_ids = self._seed(9, 2)
        base = self._identity()
        pre_counts = self._counts()
        policy = load_policy("policy/actors.json")

        pre_edit_request = stable_ulid(f"{self.namespace.value}:s9:pre-edit")
        original_payload = {
            "protocol": "beads-allocation/v0.2",
            "type": "ALLOCATE_TASK",
            "request_id": pre_edit_request,
            "agent_id": self.agent_id,
            "task_id": task_ids[0],
        }
        original_body = "/beads-v0.2 " + json.dumps(
            original_payload, sort_keys=True, separators=(",", ":")
        )
        created = self.control_api.post(
            f"/repos/{CONTROL_REPOSITORY}/issues/{self.issue_number}/comments",
            {"body": original_body},
        )
        if not isinstance(created, dict) or not isinstance(created.get("id"), int):
            raise LiveExecutorError("SCENARIO_9_PRE_EDIT_CREATE_FAILED")
        pre_edit = int(created["id"])

        edited_payload = dict(original_payload)
        edited_payload["task_id"] = task_ids[1]
        edited_body = "/beads-v0.2 " + json.dumps(
            edited_payload, sort_keys=True, separators=(",", ":")
        )
        self._edit_comment(pre_edit, edited_body)
        current_pre_edit = self.control_api.get(
            f"/repos/{CONTROL_REPOSITORY}/issues/comments/{pre_edit}"
        )
        if not isinstance(current_pre_edit, dict):
            raise LiveExecutorError("SCENARIO_9_PRE_EDIT_READ_FAILED")
        pre_edit_reason = _classify_edited_pre_ingress(
            current_pre_edit,
            original_body=original_body,
            policy=policy,
        )
        pre_edit_rejected = pre_edit_reason == "SOURCE_COMMENT_EDITED_BEFORE_INGRESS"

        pre_delete_request = stable_ulid(f"{self.namespace.value}:s9:pre-delete")
        pre_delete_payload = dict(original_payload)
        pre_delete_payload["request_id"] = pre_delete_request
        pre_delete_body = "/beads-v0.2 " + json.dumps(
            pre_delete_payload, sort_keys=True, separators=(",", ":")
        )
        pre_delete_created = self.control_api.post(
            f"/repos/{CONTROL_REPOSITORY}/issues/{self.issue_number}/comments",
            {"body": pre_delete_body},
        )
        if (
            not isinstance(pre_delete_created, dict)
            or not isinstance(pre_delete_created.get("id"), int)
        ):
            raise LiveExecutorError("SCENARIO_9_PRE_DELETE_CREATE_FAILED")
        pre_delete = int(pre_delete_created["id"])
        self._delete_comment(pre_delete)
        deleted_view = {item.comment_id for item in self.gateway.list_comments(self.issue_number)}
        pre_delete_absent = pre_delete not in deleted_view
        after_pre_counts = self._counts()

        post_edit = self._process(9, 3, request_type="ALLOCATE_TASK", task_id=task_ids[0])
        before_edit = self._allocation(post_edit.allocation_id or "")
        self._edit_comment(
            post_edit.source_id,
            json.dumps({"fixture_mode": FIXTURE_MODE, "post_ingress_edit": True}),
        )
        after_edit = self._allocation(post_edit.allocation_id or "")
        post_delete = self._process(9, 4, request_type="ALLOCATE_TASK", task_id=task_ids[1])
        before_delete = self._allocation(post_delete.allocation_id or "")
        self._delete_comment(post_delete.source_id)
        after_delete = self._allocation(post_delete.allocation_id or "")

        fresh = self._fresh_backend()
        mutation_summary = fresh.reconciler.reconcile(
            f"{self.namespace.value}:scenario-9-source-mutations"
        )
        edit_marker = f"{post_edit.request_id}:SOURCE_COMMENT_EDITED"
        delete_marker = f"{post_delete.request_id}:SOURCE_COMMENT_DELETED"
        edit_reported = (
            edit_marker in mutation_summary.source_mutations
            and fresh._audit_exists(post_edit.request_id, "SOURCE_COMMENT_EDITED")
        )
        delete_reported = (
            delete_marker in mutation_summary.source_mutations
            and fresh._audit_exists(post_delete.request_id, "SOURCE_COMMENT_DELETED")
        )
        fresh_comments = fresh.gateway.list_comments(self.issue_number)
        durable_urls = {item.html_url for item in fresh_comments}
        fresh_recovery = (
            post_edit.projection_url in durable_urls
            and post_delete.projection_url in durable_urls
            and not mutation_summary.errors
        )

        proof.fault(
            "edit_before_ingress",
            pre_edit_rejected and pre_counts == after_pre_counts,
            EXPECTED_FAULT_OUTCOMES["edit_before_ingress"],
        )
        proof.fault(
            "delete_before_ingress",
            pre_delete_absent and pre_counts == after_pre_counts,
            EXPECTED_FAULT_OUTCOMES["delete_before_ingress"],
        )
        proof.fault(
            "edit_after_ingress",
            _sha256(before_edit) == _sha256(after_edit) and edit_reported,
            EXPECTED_FAULT_OUTCOMES["edit_after_ingress"],
        )
        proof.fault(
            "delete_after_ingress",
            _sha256(before_delete) == _sha256(after_delete) and delete_reported,
            EXPECTED_FAULT_OUTCOMES["delete_after_ingress"],
        )
        proof.assertion(
            0,
            pre_edit_rejected and pre_counts == after_pre_counts,
            "edited protocol payload parsed and proved authorisable under accepted owner/operator policy; actual edited GitHub source was rejected by the accepted discovery edit boundary",
        )
        proof.assertion(
            1,
            pre_delete_absent and pre_counts == after_pre_counts,
            "valid protocol request deleted before discovery is absent and no durable original body is claimed",
        )
        proof.assertion(
            2,
            _sha256(before_edit) == _sha256(after_edit)
            and _sha256(before_delete) == _sha256(after_delete)
            and edit_reported
            and delete_reported,
            "post-ingress source mutations left ownership rows byte-identical and accepted reconciliation retained edit/delete audit findings",
        )
        proof.assertion(
            3,
            fresh_recovery and fresh.memory == {},
            "fresh backend executed accepted reconciliation and recovered retained projections from GitHub/canonical durability without the original backend memory",
        )
        return self._evidence(
            spec,
            proof,
            source_ids=(pre_edit, pre_delete, post_edit.source_id, post_delete.source_id),
            base_refs=(base.git_ref_sha,),
            accepted_refs=(post_edit.accepted_ref, post_delete.accepted_ref),
            dolt_commits=(post_edit.dolt_commit, post_delete.dolt_commit),
            canonical_rows=(post_edit.canonical_row, post_delete.canonical_row),
            projection_urls=(post_edit.projection_url, post_delete.projection_url),
        )

    def _scenario_10(self, spec: ScenarioSpec) -> ScenarioEvidence:
        proof = ScenarioProof(spec, self.namespace)
        task_ids = self._seed(10, 2)
        base = self._identity()
        active = self._process(10, 1, request_type="ALLOCATE_TASK", task_id=task_ids[0], project=False)
        grant_release = self._process(10, 2, request_type="ALLOCATE_TASK", task_id=task_ids[1], project=False)
        if not grant_release.allocation_id:
            raise LiveExecutorError("SCENARIO_10_RELEASE_FIXTURE_GRANT_FAILED")
        released = self._process(
            10,
            3,
            request_type="RELEASE",
            allocation_id=grant_release.allocation_id,
            reason="Workstream D scenario 10 reconstruction release",
            project=False,
        )
        reconstructed, transcript = self._fresh_git_reconstruction(
            (active.request_id, grant_release.request_id, released.request_id)
        )
        requests = {str(row.get("request_id")): row for row in reconstructed.get("requests", [])}
        allocations = {
            str(row.get("allocation_id")): row for row in reconstructed.get("allocations", [])
        }
        history_ok = (
            active.request_id in requests
            and released.request_id in requests
            and active.allocation_id in allocations
            and grant_release.allocation_id in allocations
            and allocations[str(active.allocation_id)].get("state") == "ACTIVE"
            and allocations[str(grant_release.allocation_id)].get("state") == "RELEASED"
            and transcript.clean_environment
            and not transcript.prohibited_capabilities_used
        )

        mismatch = self.repository.bootstrap()
        try:
            store = self.repository.store(mismatch)
            store.begin()
            try:
                store.connection.execute(
                    "UPDATE issues SET assignee = NULL WHERE id = ?", (task_ids[0],)
                )
                store.commit()
                self.repository.publish(mismatch.identity.git_ref_sha, mismatch)
            except Exception:
                store.rollback()
                raise
        finally:
            mismatch.close()
        mismatch_detected = not self._mirrors_valid((task_ids[0],))
        mismatch_recovery = self._fresh_backend()
        mismatch_summary = mismatch_recovery.reconciler.reconcile(
            f"{self.namespace.value}:scenario-10-mismatch"
        )
        audit_retained = mismatch_recovery._audit_exists(
            active.request_id, "CANONICAL_OWNERSHIP_MISMATCH"
        )
        active_rows = self._allocations_for_tasks((task_ids[0],))
        retained_fail_closed = (
            active.request_id in mismatch_summary.ownership_mismatches
            and audit_retained
            and not mismatch_summary.errors
            and not self._mirrors_valid((task_ids[0],))
        )
        proof.fault(
            "inject_mirror_mismatch",
            mismatch_detected and retained_fail_closed,
            EXPECTED_FAULT_OUTCOMES["inject_mirror_mismatch"],
        )
        proof.assertion(
            0,
            history_ok,
            "credential-free fresh Git-capable client reconstructs active ownership plus released allocation/request history through an exact read-only mirror of the GitHub canonical ref",
        )
        proof.assertion(
            1,
            mismatch_detected and retained_fail_closed,
            "durable mirror mismatch was detected by accepted reconciliation and retained CANONICAL_OWNERSHIP_MISMATCH audit evidence without automatic repair",
        )
        proof.assertion(
            2,
            len(active_rows) == 1 and active_rows[0].get("allocation_id") == active.allocation_id,
            "singular active allocation row remains authority while the mismatched mirror stays fail-closed",
        )
        final = self._identity()
        return self._evidence(
            spec,
            proof,
            base_refs=(base.git_ref_sha,),
            accepted_refs=(final.git_ref_sha,),
            dolt_commits=(final.dolt_commit,),
            canonical_rows=(_sha256(reconstructed),),
            clients=(transcript,),
        )

    def _scenario_11(self, spec: ScenarioSpec) -> ScenarioEvidence:
        proof = ScenarioProof(spec, self.namespace)
        task_id = self._seed(11, 1)[0]
        result = self._process(11, 1, request_type="ALLOCATE_TASK", task_id=task_id)
        projection, transcript = self._consume_projection_api_only(
            self.gateway, self.issue_number, result.projection_url
        )
        proof.assertion(0, transcript.prohibited_capabilities_used == (), "API-only helper receives only issue gateway and URL")
        proof.assertion(1, projection.get("execution_may_begin") is True, "execution_may_begin=true")
        proof.assertion(
            2,
            bool(projection.get("release_instruction")) and bool(projection.get("allocation_id")),
            "release_instruction and allocation_id are present",
        )
        return self._evidence(
            spec,
            proof,
            source_ids=(result.source_id,),
            projection_urls=(result.projection_url,),
            clients=(transcript,),
        )

    def _scenario_12(self, spec: ScenarioSpec) -> ScenarioEvidence:
        proof = ScenarioProof(spec, self.namespace)
        task_id = self._seed(12, 1)[0]
        base = self._identity()
        granted = self._process(12, 1, request_type="ALLOCATE_TASK", task_id=task_id, project=False)
        if not granted.allocation_id:
            raise LiveExecutorError("SCENARIO_12_GRANT_FAILED")
        released = self._process(
            12,
            2,
            request_type="RELEASE",
            allocation_id=granted.allocation_id,
            reason="Workstream D synthetic fixture release",
        )
        allocation = self._allocation(granted.allocation_id)
        release_request = self._request_row(released.request_id)
        mirror_ok = self._mirrors_valid((task_id,))
        rows = self._allocations_for_tasks((task_id,))
        proof.assertion(
            0,
            release_request is not None
            and allocation.get("release_request_id") == released.request_id
            and released.reason == "RELEASED",
            f"release_request={released.request_id} reason={released.reason}",
        )
        proof.assertion(
            1,
            len(rows) == 1 and allocation.get("state") == "RELEASED",
            "grant allocation row remains retained in RELEASED state",
        )
        proof.assertion(
            2,
            mirror_ok and allocation.get("state") == "RELEASED",
            "released state and Beads ownership mirror agree after atomic release",
        )
        return self._evidence(
            spec,
            proof,
            source_ids=(released.source_id,),
            base_refs=(base.git_ref_sha,),
            accepted_refs=(released.accepted_ref,),
            dolt_commits=(released.dolt_commit,),
            canonical_rows=(released.canonical_row,),
            projection_urls=(released.projection_url,),
            cleanup="released",
        )

    def _scenario_13(self, spec: ScenarioSpec) -> ScenarioEvidence:
        proof = ScenarioProof(spec, self.namespace)
        source, _ = self._post_source(13, 1, "authorisation-and-token-scope")
        base_policy = load_policy("policy/actors.json")
        auth_controls = {
            "missing_comment_app_attribution",
            "wrong_comment_app_id",
            "wrong_comment_app_slug",
            "wrong_bot_id",
            "wrong_bot_login",
            "misleading_event_installation",
            "human_namespace_impersonation",
        }
        installation_controls = {"wrong_installation_mapping", "lost_control_repository_access"}
        inventory_controls = {
            "inventory_additional_repository",
            "inventory_missing_repository",
            "inventory_stale_after_settings_change",
        }
        token_controls = {
            "token_repository_restriction_omitted",
            "token_permission_restriction_omitted",
            "default_token_request",
            "multi_repository_token_request",
            "unapproved_permission_request",
        }
        seen_auth: set[str] = set()
        no_state_access: dict[str, bool] = {}
        inventory_rejected: set[str] = set()
        token_rejected: set[str] = set()
        unauthorised_release_no_mutation = False

        for control in SCENARIO_13_FAULT_CONTROLS:
            condition = False
            if control in auth_controls:
                detail = _exercise_authorisation_negative(
                    control, namespace=self.namespace, base_policy=base_policy
                )
                seen_auth.add(control)
                condition = bool(detail)
            elif control in installation_controls:
                rejection, mint_calls, canonical_calls = _exercise_installation_negative(control)
                no_state_access[control] = mint_calls == 0 and canonical_calls == 0
                condition = bool(rejection) and no_state_access[control]
            elif control in inventory_controls:
                att = self.inventory.attestation
                ids: Sequence[int]
                audited_at = att.audited_at
                if control == "inventory_additional_repository":
                    ids = (*att.repository_ids, 999999)
                elif control == "inventory_missing_repository":
                    ids = (CONTROL_REPOSITORY_ID,)
                else:
                    ids = att.repository_ids
                    audited_at = datetime(2000, 1, 1, tzinfo=timezone.utc)
                bad = InventoryAttestation(
                    att.app_id,
                    att.installation_id,
                    "selected",
                    tuple(ids),
                    audited_at,
                )
                try:
                    bad.validate(
                        app_id=att.app_id,
                        installation_id=att.installation_id,
                        expected_repository_ids={CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID},
                        now=datetime.now(timezone.utc),
                        max_age_seconds=INVENTORY_MAX_AGE_SECONDS,
                    )
                except InventoryError:
                    inventory_rejected.add(control)
                    condition = True
            elif control in token_controls:
                permissions = dict(control_profile(CONTROL_REPOSITORY_ID).permissions)
                if control == "token_repository_restriction_omitted":
                    bad = TokenProfile("control", 0, permissions)
                elif control == "token_permission_restriction_omitted":
                    bad = TokenProfile("control", CONTROL_REPOSITORY_ID, {})
                elif control == "default_token_request":
                    bad = TokenProfile("default", CONTROL_REPOSITORY_ID, permissions)
                elif control == "multi_repository_token_request":
                    bad = TokenProfile("control", (CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID), permissions)  # type: ignore[arg-type]
                else:
                    bad = TokenProfile("control", CONTROL_REPOSITORY_ID, {"contents": "write"})
                try:
                    token_request(bad)
                except CredentialPolicyError:
                    token_rejected.add(control)
                    condition = True
            elif control == "returned_scope_mismatch":
                profile = control_profile(CONTROL_REPOSITORY_ID)
                try:
                    validate_token_response(
                        {
                            "repositories": [{"id": STATE_REPOSITORY_ID}],
                            "permissions": profile.permissions,
                            "token": "fixture",
                        },
                        profile,
                    )
                except CredentialPolicyError:
                    condition = True
            elif control == "control_token_cross_repository_access":
                condition = self.token_scope_records[0].cross_repository_denied
            elif control == "state_token_cross_repository_access":
                condition = self.token_scope_records[1].cross_repository_denied
            elif control == "unauthorised_release":
                snapshot = self.repository.bootstrap()
                store = self.repository.store(snapshot)
                before = _sha256(store.reconstruct())
                command = AllocationCommand(
                    stable_ulid(f"{self.namespace.value}:s13:unauthorised-release"),
                    "RELEASE",
                    hashlib.sha256(b"s13-unauthorised-release").hexdigest(),
                    "agent://human/not-authorised/session/s13",
                    allocation_id=stable_ulid(f"{self.namespace.value}:s13:missing-allocation"),
                    reason="synthetic unauthorised release",
                )
                context = RequestContext(
                    CONTROL_REPOSITORY,
                    self.issue_number,
                    source,
                    "fixture",
                    self.agent_id,
                )
                try:
                    store.begin()
                    result = AllocationService(self.repository, clock=lambda: NOW)._apply(
                        store, command, context, NOW
                    )
                    store.rollback()
                    after = _sha256(store.reconstruct())
                    unauthorised_release_no_mutation = (
                        result.reason_code == "AGENT_NOT_AUTHORISED" and before == after
                    )
                    condition = unauthorised_release_no_mutation
                finally:
                    snapshot.close()
            else:
                raise LiveExecutorError(f"UNHANDLED_SCENARIO_13_CONTROL:{control}")
            proof.fault(control, condition, EXPECTED_FAULT_OUTCOMES[control])

        control_profile_record, state_profile_record = self.token_scope_records
        proof.assertion(
            0,
            len(proof.fault_records) == len(SCENARIO_13_FAULT_CONTROLS)
            and tuple(proof.fault_records) == SCENARIO_13_FAULT_CONTROLS,
            f"typed_fault_count={len(proof.fault_records)}",
        )
        proof.assertion(
            1,
            seen_auth == auth_controls,
            "all static identity negatives executed through pure authorise fixtures with no credential callback",
        )
        proof.assertion(
            2,
            all(no_state_access.get(control, False) for control in installation_controls),
            "wrong-installation and lost-access fixtures made zero token-mint and canonical-access calls",
        )
        proof.assertion(
            3,
            set(self.inventory.attestation.repository_ids)
            == {CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID}
            and len(self.inventory.attestation.repository_ids) == 2,
            f"repository_ids={self.inventory.attestation.repository_ids}",
        )
        proof.assertion(
            4,
            control_profile_record.requested_repository_ids == (CONTROL_REPOSITORY_ID,)
            and state_profile_record.requested_repository_ids == (STATE_REPOSITORY_ID,)
            and control_profile_record.returned_scope_validated
            and state_profile_record.returned_scope_validated,
            "control/state scope records are exact, single-repository and validated",
        )
        proof.assertion(
            5,
            control_profile_record.cross_repository_denied
            and state_profile_record.cross_repository_denied,
            "both live token probes denied cross-repository capability",
        )
        proof.assertion(
            6,
            token_rejected == token_controls,
            f"rejected_token_controls={sorted(token_rejected)}",
        )
        proof.assertion(
            7,
            unauthorised_release_no_mutation
            and "human_namespace_impersonation" in seen_auth,
            "unauthorised release and human namespace fixtures produced no ownership mutation",
        )
        return self._evidence(spec, proof, source_ids=(source,), scenario13=True)

    def _scenario_14(self, spec: ScenarioSpec) -> ScenarioEvidence:
        proof = ScenarioProof(spec, self.namespace)
        prior_complete = tuple(sorted(self.executed_records)) == tuple(range(1, 14))
        task_id = self._seed(14, 1)[0]
        base = self._identity()
        result = self._process(14, 1, request_type="ALLOCATE_TASK", task_id=task_id)
        reconstructed, git_transcript = self._fresh_git_reconstruction((result.request_id,))
        projection, api_transcript = self._consume_projection_api_only(
            self.gateway, self.issue_number, result.projection_url
        )
        final = self._identity()
        github_durability = (
            self._request_row(result.request_id) is not None
            and projection.get("request_id") == result.request_id
            and final.git_ref_sha != ""
        )
        proof.assertion(
            0,
            frozenset(DURABILITY)
            == frozenset({"github_issue", "github_repository", "github_ref", "github_actions"}),
            f"durability_records={DURABILITY}",
        )
        proof.assertion(
            1,
            prior_complete and github_durability,
            "scenarios 1-13 already returned validated evidence and scenario 14 retained evidence is GitHub-readable",
        )
        proof.assertion(
            2,
            git_transcript.clean_environment
            and api_transcript.clean_environment
            and not git_transcript.prohibited_capabilities_used
            and not api_transcript.prohibited_capabilities_used,
            "only canonical GitHub durability is referenced; runner workspace/cache/artifacts are absent from authority records",
        )
        return self._evidence(
            spec,
            proof,
            base_refs=(base.git_ref_sha,),
            accepted_refs=(result.accepted_ref,),
            dolt_commits=(result.dolt_commit,),
            canonical_rows=(_sha256(reconstructed),),
            projection_urls=(result.projection_url,),
            clients=(git_transcript, api_transcript),
            network=NETWORK_DESTINATIONS,
        )


@dataclass(frozen=True)
class LiveSuiteResult:
    run_id: int
    run_attempt: int
    attempt_namespace: str
    trusted_sha: str
    protocol_sha: str
    scenario_count: int
    evidence_sha256: tuple[str, ...]
    inventory_attestation_sha256: str
    credential_revocation_required: bool
    enablement_removal_required: bool

    def payload(self) -> dict[str, Any]:
        return {
            "attempt_namespace": self.attempt_namespace,
            "credential_revocation_required": self.credential_revocation_required,
            "enablement_removal_required": self.enablement_removal_required,
            "evidence_sha256": list(self.evidence_sha256),
            "inventory_attestation_sha256": self.inventory_attestation_sha256,
            "production_approval": False,
            "protocol": "beads-allocation/v0.2",
            "protocol_sha": self.protocol_sha,
            "run_attempt": self.run_attempt,
            "run_id": self.run_id,
            "scenario_count": self.scenario_count,
            "trusted_sha": self.trusted_sha,
            "workstream": "D",
            "workstream_e_authorised": False,
        }


def context_from_environment(values: Mapping[str, str]) -> LiveRunContext:
    return LiveRunContext(
        repository=values["GITHUB_REPOSITORY"],
        ref=values["GITHUB_REF"],
        trusted_sha=values["GITHUB_SHA"],
        expected_control_sha=values["EXPECTED_CONTROL_SHA"],
        protocol_sha=values["EXPECTED_PROTOCOL_SHA"],
        expected_protocol_sha=PROTOCOL_AUTHORITY,
        run_id=int(values["GITHUB_RUN_ID"]),
        run_attempt=int(values["GITHUB_RUN_ATTEMPT"]),
        attempt_nonce=values["ATTEMPT_NONCE"],
        enabled=values.get("PHASE2_WORKSTREAM_D_EXECUTION_ENABLED") == "true",
        fixture_mode=values.get("PHASE2_WORKSTREAM_D_FIXTURE_MODE", ""),
    )


def execute_live_suite(values: Mapping[str, str] | None = None) -> LiveSuiteResult:
    env = os.environ if values is None else values
    context = context_from_environment(env)
    namespace = context.validate()
    lease: CredentialLease | None = None
    fixture: FixtureRepositoryLease | None = None
    primary_error: Exception | None = None
    try:
        lease, inventory = acquire_credentials(env, context)
        with tempfile.TemporaryDirectory(prefix=f"{namespace.value}-") as directory:
            root = Path(directory)
            fixture = bootstrap_fixture_repository(
                lease.state_token,
                root=root,
                bd_bin=env["BD_BIN"],
                dolt_bin=env["DOLT_BIN"],
            )
            backend = LiveFixtureBackend(
                fixture.repository,
                GitHubAPI(lease.control_token, lease.api_url),
                int(env.get("PHASE2_CONTROL_ISSUE_NUMBER", str(CONTROL_ISSUE_NUMBER))),
                context.trusted_sha,
                context.protocol_sha,
                lease.token_scope_records,
                inventory,
                namespace,
                fixture.make_read_only_remote,
            )
            records = ScenarioDriver(backend).run(
                SCENARIO_IDS,
                namespace,
                expected_trusted_sha=context.trusted_sha,
                expected_protocol_sha=context.protocol_sha,
            )
            summary = evidence_summary(
                records,
                attempt_namespace=namespace,
                expected_trusted_sha=context.trusted_sha,
                expected_protocol_sha=context.protocol_sha,
            )
            if summary["scenarios"] != 14 or summary["workstream_e_authorised"]:
                raise LiveExecutorError("UNEXPECTED_WORKSTREAM_D_SUMMARY")
            result = LiveSuiteResult(
                context.run_id,
                context.run_attempt,
                namespace.value,
                context.trusted_sha,
                context.protocol_sha,
                len(records),
                tuple(
                    hashlib.sha256(record.to_json().encode()).hexdigest()
                    for record in records
                ),
                inventory.digest,
                True,
                True,
            )
            backend.gateway.post_summary(
                backend.issue_number,
                json.dumps(
                    {
                        "type": "WORKSTREAM_D_SYNTHETIC_LIVE_RESULT",
                        "status": "PENDING_CREDENTIAL_REVOCATION_AND_ENABLEMENT_REMOVAL",
                        **result.payload(),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
            return result
    except Exception as exc:
        primary_error = exc
        raise
    finally:
        if fixture is not None:
            try:
                fixture.close()
            except Exception:
                if primary_error is None:
                    primary_error = LiveExecutorError("FIXTURE_CREDENTIAL_CLEANUP_FAILED")
        if lease is not None:
            try:
                lease.close()
            except Exception:
                if primary_error is None:
                    raise
        if primary_error is not None and sys.exc_info()[0] is None:
            raise primary_error


def _safe_live_failure(exc: Exception) -> dict[str, object]:
    payload: dict[str, object] = {
        "status": "BLOCKED",
        "credential_material_emitted": False,
        "workstream_e_authorised": False,
    }
    if isinstance(exc, GitHubAPIError):
        payload.update(exc.safe_diagnostic())
        if exc.rate_limited:
            payload["reason_code"] = "GITHUB_RATE_LIMITED"
        elif exc.status == 403:
            payload["reason_code"] = "GITHUB_API_FORBIDDEN"
        else:
            payload["reason_code"] = f"GITHUB_API_HTTP_{exc.status}"
        return payload
    payload["reason_code"] = str(exc).split(":", 1)[0] or type(exc).__name__
    return payload


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
                _safe_live_failure(exc),
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
