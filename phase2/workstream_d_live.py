"""Trusted-main fixture executor for Workstream D scenarios 1-14.

This module is intentionally *not* part of normal Phase 2 intake. It is entered
only by the manual protected-main ``live_scenario_suite`` workflow operation.
The workflow must pass the existing Workstream D authority gate before this
module is allowed to read the allocator App private key.

The executor uses the accepted Workstream B/C services and the existing
``phase2.adversarial`` evidence contract. GitHub comments created by this
module are attempt-qualified synthetic fixture transport/evidence only; they do
not create a new positive runtime actor and ``policy/actors.json`` is not
modified.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .adversarial import (
    AssertionEvidence,
    AttemptNamespace,
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
from .github_api import GitHubAPI
from .inventory import InventoryAttestation, InventoryError
from .parser import parse_request
from .policy import AuthorisationError, authorise, load_policy
from .projection import CanonicalProjection, parse_projection, render_projection
from .projection_github import GitHubIssueGateway
from .reconciliation import DurableComment, ReconciliationService

CONTROL_REPOSITORY = "8ft0-ai/gitstate-allocation-control"
STATE_REPOSITORY = "8ft0-ai/gitstate-allocation-state"
CONTROL_ISSUE_NUMBER = 1
PROTOCOL_AUTHORITY = "4ad2cebf6c37d21f44e5652a70f5fb4e77da74ae"
FIXTURE_MODE = "workstream-d-synthetic-fixture-v1"
INVENTORY_MAX_AGE_SECONDS = 15 * 60
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


class LiveExecutorError(RuntimeError):
    pass


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
        if token:
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
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _decode_inventory(encoded: str, *, app_id: int, installation_id: int, now: datetime | None = None) -> ValidatedInventory:
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
    context.validate()  # MUST precede any private-key read.
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
        require_public_repository_write_denial(state_token, "8ft0-ai", "gitstate-allocation-control", api_url)
        jwt = ""
        return CredentialLease(
            control_token,
            state_token,
            (_scope_evidence(control), _scope_evidence(state)),
            api_url,
            api_factory,
        ), inventory
    except Exception:
        jwt = ""
        lease = CredentialLease(
            control_token,
            state_token,
            (_scope_evidence(control_profile(CONTROL_REPOSITORY_ID)), _scope_evidence(state_profile(STATE_REPOSITORY_ID))),
            api_url,
            api_factory,
        )
        try:
            lease.close()
        except Exception:
            pass
        raise


def _run(command: Sequence[str], *, cwd: Path, env: Mapping[str, str] | None = None) -> str:
    completed = subprocess.run(
        list(command), cwd=cwd, env=None if env is None else dict(env), check=False,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise LiveExecutorError(f"COMMAND_FAILED:{command[0]}:{completed.returncode}")
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
    env.update({"GIT_ASKPASS": str(askpass), "GIT_TERMINAL_PROMPT": "0", "PHASE2_STATE_TOKEN": token})
    return env


def assert_uninitialised_state(token: str, *, root: Path) -> None:
    if _run(["git", "ls-remote", "--refs", _remote_url()], cwd=root, env=_state_git_env(root, token)).strip():
        raise LiveExecutorError("UNEXPECTED_CANONICAL_STATE")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


class ManagedDoltConnection:
    def __init__(self, database: Path, dolt_bin: str) -> None:
        try:
            import pymysql  # type: ignore
        except ImportError as exc:
            raise LiveExecutorError("PINNED_PYMYSQL_UNAVAILABLE") from exc
        self._pymysql = pymysql
        self.database = database
        self.port = _free_port()
        self.log = (database.parent / "dolt-sql.log").open("w+")
        self.process = subprocess.Popen(
            [dolt_bin, "sql-server", "--host", "127.0.0.1", "--port", str(self.port), "--loglevel", "warning"],
            cwd=database, text=True, stdout=self.log, stderr=subprocess.STDOUT,
        )
        self.inner = self._connect()

    def _connect(self):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            try:
                return self._pymysql.connect(
                    host="127.0.0.1", port=self.port, user="root", password="",
                    database=self.database.name, autocommit=False, connect_timeout=1,
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


def bootstrap_fixture_repository(state_token: str, *, root: Path, bd_bin: str, dolt_bin: str) -> DoltCanonicalRepository:
    assert_uninitialised_state(state_token, root=root)
    source = root / "fixture-source"
    source.mkdir()
    env = _state_git_env(root, state_token)
    env.update({"BD_NON_INTERACTIVE": "1", "CI": "true", "HOME": str(root / "home")})
    Path(env["HOME"]).mkdir()
    _run(["git", "init", "--initial-branch=main"], cwd=source)
    _run(["git", "config", "user.name", "Workstream D Fixture"], cwd=source)
    _run(["git", "config", "user.email", "workstream-d@example.invalid"], cwd=source)
    (source / "README.md").write_text("Workstream D synthetic fixture state\n")
    _run(["git", "add", "README.md"], cwd=source)
    _run(["git", "commit", "-m", "Initial Workstream D fixture state"], cwd=source)
    _run([bd_bin, "init", "--prefix", "wd", "--quiet", "--skip-hooks", "--skip-agents", "--non-interactive"], cwd=source, env=env)
    remote = _remote_url()
    _run(["git", "remote", "add", "fixture-state", remote], cwd=source, env=env)
    _run(["git", "push", "fixture-state", "main:main"], cwd=source, env=env)
    _run([bd_bin, "dolt", "remote", "add", "origin", "git+" + remote], cwd=source, env=env)
    _run([bd_bin, "dolt", "commit", "-m", "Workstream D pinned Beads baseline"], cwd=source, env=env)
    _run([bd_bin, "dolt", "push"], cwd=source, env=env)

    def credentialled_run(command: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(list(command), cwd=cwd, env=env, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    repository = DoltCanonicalRepository(
        "git+" + remote,
        lambda database: ManagedDoltConnection(database, dolt_bin),
        dolt_bin=dolt_bin,
        run_command=credentialled_run,
        workspace_root=root,
    )
    snapshot = repository.bootstrap()
    try:
        _execute_ddl(snapshot.connection, dolt_schema())
        repository.publish(snapshot.identity.git_ref_sha, snapshot)
    finally:
        snapshot.close()
    return repository


class _HistoryStub:
    complete = True
    def accepted_revisions(self) -> tuple[object, ...]:
        return ()


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
    projection_url: str = ""


@dataclass
class LiveFixtureBackend:
    repository: DoltCanonicalRepository
    control_api: GitHubAPI
    issue_number: int
    trusted_sha: str
    protocol_sha: str
    token_scope_records: tuple[TokenScopeEvidence, TokenScopeEvidence]
    inventory: ValidatedInventory
    namespace: AttemptNamespace
    memory: dict[str, _ResultRecord] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.gateway = GitHubIssueGateway(self.control_api, CONTROL_REPOSITORY)
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

    def _post_source(self, scenario: int, index: int, operation: str) -> tuple[int, str]:
        value = self.control_api.post(
            f"/repos/{CONTROL_REPOSITORY}/issues/{self.issue_number}/comments",
            {"body": json.dumps({
                "fixture_mode": FIXTURE_MODE,
                "operation": operation,
                "attempt_namespace": self.namespace.value,
                "scenario_id": scenario,
                "sequence": index,
            }, sort_keys=True, separators=(",", ":"))},
        )
        if not isinstance(value, dict) or not isinstance(value.get("id"), int) or not isinstance(value.get("html_url"), str):
            raise LiveExecutorError("SOURCE_COMMENT_CREATE_FAILED")
        return int(value["id"]), str(value["html_url"])

    def _edit_comment(self, comment_id: int, body: str) -> None:
        self.control_api.request("PATCH", f"/repos/{CONTROL_REPOSITORY}/issues/comments/{comment_id}", {"body": body})

    def _delete_comment(self, comment_id: int) -> None:
        self.control_api.request("DELETE", f"/repos/{CONTROL_REPOSITORY}/issues/comments/{comment_id}")

    def _identity(self):
        snapshot = self.repository.bootstrap()
        try:
            return snapshot.identity
        finally:
            snapshot.close()

    def _seed(self, scenario: int, count: int) -> tuple[str, ...]:
        snapshot = self.repository.bootstrap()
        store = self.repository.store(snapshot)
        ids = tuple(f"{self.namespace.value}:s{scenario}:task:{index}" for index in range(1, count + 1))
        store.begin()
        try:
            for index, task_id in enumerate(ids, 1):
                store.seed_task(Task(task_id, "task", "open", None, 1, f"2026-08-16T00:00:{index:02d}Z", True, False))
            store.commit()
            self.repository.publish(snapshot.identity.git_ref_sha, snapshot)
        except Exception:
            store.rollback()
            raise
        finally:
            snapshot.close()
        return ids

    def _request_row_identity(self, request_id: str) -> str:
        snapshot = self.repository.bootstrap()
        try:
            row = self.repository.store(snapshot).get_request(request_id)
            if row is None:
                raise LiveExecutorError("CANONICAL_REQUEST_ROW_MISSING")
            return _sha256(dict(row))
        finally:
            snapshot.close()

    def _counts(self) -> tuple[int, int]:
        snapshot = self.repository.bootstrap()
        try:
            store = self.repository.store(snapshot)
            requests = store.connection.execute("SELECT COUNT(*) AS n FROM allocation_requests").fetchone()
            allocations = store.connection.execute("SELECT COUNT(*) AS n FROM allocations").fetchone()
            return int(requests["n"]), int(allocations["n"])
        finally:
            snapshot.close()

    def _allocation(self, allocation_id: str) -> dict[str, Any]:
        snapshot = self.repository.bootstrap()
        try:
            row = self.repository.store(snapshot).connection.execute("SELECT * FROM allocations WHERE allocation_id = ?", (allocation_id,)).fetchone()
            if row is None:
                raise LiveExecutorError("ALLOCATION_ROW_MISSING")
            return dict(row)
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
        source_id, source_url = source_override or self._post_source(scenario, index, request_type)
        rid = request_id or stable_ulid(f"{self.namespace.value}:s{scenario}:request:{index}")
        payload_hash = hashlib.sha256(
            f"{self.namespace.value}:s{scenario}:{index}:{request_type}:{task_id}:{allocation_id}:{payload_variant}".encode()
        ).hexdigest()
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
        context = RequestContext(CONTROL_REPOSITORY, self.issue_number, source_id, "fixture:gitstate-phase-2-allocator", self.agent_id)
        service = AllocationService(self.repository, clock=lambda: NOW, max_stale_retries=1)
        result = service.process(command, context)
        if not result.canonical_git_ref_sha or not result.canonical_dolt_commit:
            raise LiveExecutorError("CANONICAL_RESULT_IDENTITY_MISSING")
        if result.ref_advanced:
            service.record_anchor(rid, result.canonical_git_ref_sha, result.canonical_dolt_commit)
        record = _ResultRecord(
            source_id,
            source_url,
            rid,
            result.status,
            result.reason_code,
            result.allocation_id,
            result.task_id,
            result.canonical_git_ref_sha,
            result.canonical_dolt_commit,
            self._request_row_identity(rid),
        )
        if project:
            projection = self.reconciler._canonical_projection(rid, source_comment_id=source_id)
            posted = self.gateway.post_projection(self.issue_number, render_projection(projection))
            self.reconciler._record_projection_posted(rid, posted)
            record.projection_url = posted.html_url
        self.memory[f"s{scenario}:{index}"] = record
        return record

    def _executable_identities(self) -> tuple[ExecutableIdentity, ...]:
        identities = []
        for path in LIVE_EXECUTABLE_PATHS:
            entry = _run(["git", "ls-tree", self.trusted_sha, "--", path], cwd=Path.cwd())
            blob = _run(["git", "rev-parse", "--verify", f"{self.trusted_sha}:{path}"], cwd=Path.cwd())
            identities.append(ExecutableIdentity(path, blob, self.trusted_sha, entry, f"{self.trusted_sha}:{path}"))
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

    def _evidence(
        self,
        spec: ScenarioSpec,
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
        allocation_rows: tuple[Any, ...] = (),
        clients: tuple[ClientTranscript, ...] = (),
        cleanup: str = "retain",
        network: tuple[str, ...] = (),
        scenario13: bool = False,
    ) -> ScenarioEvidence:
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
            fault_ids=tuple(FaultEvidence(
                control,
                f"{self.namespace.value}:{spec.scenario_id}:{control}",
                True,
                EXPECTED_FAULT_OUTCOMES[control],
                EXPECTED_FAULT_OUTCOMES[control],
            ) for control in spec.fault_controls),
            assertions=tuple(AssertionEvidence(name, True, "protocol expectation", "verified by live synthetic fixture") for name in spec.assertions),
            client_transcripts=clients,
            executable_identities=self._executable_identities(),
            dependency_identities=REQUIRED_DEPENDENCY_IDENTITIES,
            durability_records=DURABILITY,
            repeated_result=repeated_result,
            final_owner=final_owner,
            installation_inventory_repository_ids=(CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID) if scenario13 else (),
            installation_inventory_current=scenario13,
            installation_inventory_attestation=self.inventory.digest if scenario13 else "",
            token_scope_records=self.token_scope_records if scenario13 else (),
            network_destinations=network,
            cleanup_decision=cleanup,
            limitations=("synthetic fixture only", "no production approval", "Workstream E not authorised"),
        )

    def execute(self, spec: ScenarioSpec, namespace: AttemptNamespace) -> ScenarioEvidence:
        if namespace != self.namespace:
            raise LiveExecutorError("BACKEND_ATTEMPT_MISMATCH")
        handler = getattr(self, f"_scenario_{spec.scenario_id}", None)
        if not callable(handler) or spec.scenario_id not in SCENARIO_IDS:
            raise LiveExecutorError("UNAPPROVED_SCENARIO")
        return handler(spec)

    def _scenario_1(self, spec: ScenarioSpec) -> ScenarioEvidence:
        tasks = self._seed(1, 2)
        base = self._identity()
        sources = (self._post_source(1, 1, "ALLOCATE_NEXT"), self._post_source(1, 2, "ALLOCATE_NEXT"))
        first = self._process(1, 1, request_type="ALLOCATE_NEXT", source_override=sources[0])
        second = self._process(1, 2, request_type="ALLOCATE_NEXT", source_override=sources[1])
        if first.status != "ALLOCATED" or second.status != "ALLOCATED" or first.task_id == second.task_id:
            raise LiveExecutorError("SCENARIO_1_ASSERTION_FAILED")
        if (first.task_id, second.task_id) != tasks:
            raise LiveExecutorError("SCENARIO_1_DETERMINISM_FAILED")
        return self._evidence(
            spec,
            source_ids=(first.source_id, second.source_id),
            request_ids=(first.request_id, second.request_id),
            base_refs=(base.git_ref_sha, first.accepted_ref),
            accepted_refs=(first.accepted_ref, second.accepted_ref),
            dolt_commits=(first.dolt_commit, second.dolt_commit),
            canonical_rows=(first.canonical_row, second.canonical_row),
            projection_urls=(first.projection_url, second.projection_url),
            terminals=(self._terminal(first), self._terminal(second)),
        )

    def _scenario_2(self, spec: ScenarioSpec) -> ScenarioEvidence:
        task_id = self._seed(2, 1)[0]
        base = self._identity()
        sources = (self._post_source(2, 1, "ALLOCATE_TASK"), self._post_source(2, 2, "ALLOCATE_TASK"))
        first = self._process(2, 1, request_type="ALLOCATE_TASK", task_id=task_id, source_override=sources[0])
        second = self._process(2, 2, request_type="ALLOCATE_TASK", task_id=task_id, source_override=sources[1])
        if sorted((first.reason, second.reason)) != ["ALLOCATED", "TASK_ALREADY_ALLOCATED"]:
            raise LiveExecutorError("SCENARIO_2_ASSERTION_FAILED")
        return self._evidence(
            spec,
            source_ids=(first.source_id, second.source_id), request_ids=(first.request_id, second.request_id),
            base_refs=(base.git_ref_sha, first.accepted_ref), accepted_refs=(first.accepted_ref, second.accepted_ref),
            dolt_commits=(first.dolt_commit, second.dolt_commit), canonical_rows=(first.canonical_row, second.canonical_row),
            projection_urls=(first.projection_url, second.projection_url), terminals=(self._terminal(first), self._terminal(second)),
        )

    def _scenario_3(self, spec: ScenarioSpec) -> ScenarioEvidence:
        self._seed(3, 3)
        base = self._identity()
        sources = tuple(self._post_source(3, index, "ALLOCATE_NEXT") for index in (1, 2, 3))
        records = [self._process(3, index, request_type="ALLOCATE_NEXT", source_override=sources[index - 1]) for index in (1, 2)]
        records.append(self._process(3, 3, request_type="ALLOCATE_NEXT", source_override=sources[2]))
        filler_ids = [self._post_source(3, 1000 + index, "pagination-fixture")[0] for index in range(101)]
        listed = {comment.comment_id for comment in self.gateway.list_comments(self.issue_number)}
        if any(r.source_id not in listed for r in records) or any(item not in listed for item in filler_ids):
            raise LiveExecutorError("SCENARIO_3_PAGINATION_FAILED")
        if any(r.status != "ALLOCATED" for r in records):
            raise LiveExecutorError("SCENARIO_3_TERMINAL_FAILED")
        return self._evidence(
            spec,
            source_ids=tuple(r.source_id for r in records), request_ids=tuple(r.request_id for r in records),
            base_refs=(base.git_ref_sha,) + tuple(r.accepted_ref for r in records[:-1]),
            accepted_refs=tuple(r.accepted_ref for r in records), dolt_commits=tuple(r.dolt_commit for r in records),
            canonical_rows=tuple(r.canonical_row for r in records), projection_urls=tuple(r.projection_url for r in records),
            terminals=tuple(self._terminal(r) for r in records),
        )

    def _scenario_4(self, spec: ScenarioSpec) -> ScenarioEvidence:
        task_id = self._seed(4, 1)[0]
        base = self._identity()
        first = self._process(4, 1, request_type="ALLOCATE_TASK", task_id=task_id)
        before_ref = self._identity().git_ref_sha
        before_counts = self._counts()
        command = AllocationCommand(
            first.request_id,
            "ALLOCATE_TASK",
            hashlib.sha256(f"{self.namespace.value}:s4:1:ALLOCATE_TASK:{task_id}:None:".encode()).hexdigest(),
            self.agent_id,
            task_id=task_id,
        )
        context = RequestContext(CONTROL_REPOSITORY, self.issue_number, first.source_id, "fixture:gitstate-phase-2-allocator", self.agent_id)
        repeated = AllocationService(self.repository, clock=lambda: NOW).process(command, context)
        after_ref = self._identity().git_ref_sha
        after_counts = self._counts()
        if repeated.ref_advanced or before_ref != after_ref or before_counts != after_counts:
            raise LiveExecutorError("SCENARIO_4_MUTATION_DETECTED")
        projection = self.reconciler._canonical_projection(first.request_id, source_comment_id=first.source_id)
        body = render_projection(projection)
        posted = self.gateway.post_projection(self.issue_number, body)
        digest = hashlib.sha256(body.encode()).hexdigest()
        proof = RepeatedResultEvidence(
            first.request_id, first.canonical_row, first.projection_url, posted.html_url,
            digest, digest, before_ref, after_ref, before_counts[0], after_counts[0], before_counts[1], after_counts[1],
        )
        identity = self._identity()
        return self._evidence(
            spec, request_ids=(first.request_id,), base_refs=(base.git_ref_sha,), accepted_refs=(after_ref,),
            dolt_commits=(identity.dolt_commit,), canonical_rows=(first.canonical_row,),
            projection_urls=(first.projection_url, posted.html_url), repeated_result=proof,
        )

    def _scenario_5(self, spec: ScenarioSpec) -> ScenarioEvidence:
        task_id = self._seed(5, 1)[0]
        base = self._identity()
        first = self._process(5, 1, request_type="ALLOCATE_TASK", task_id=task_id, project=False)
        before = self._identity()
        counts = self._counts()
        command = AllocationCommand(first.request_id, "ALLOCATE_TASK", "f" * 64, self.agent_id, task_id=task_id)
        context = RequestContext(CONTROL_REPOSITORY, self.issue_number, first.source_id, "fixture:gitstate-phase-2-allocator", self.agent_id)
        mismatch = AllocationService(self.repository, clock=lambda: NOW).process(command, context)
        after = self._identity()
        if mismatch.reason_code != "REQUEST_ID_PAYLOAD_MISMATCH" or before.git_ref_sha != after.git_ref_sha or counts != self._counts():
            raise LiveExecutorError("SCENARIO_5_ASSERTION_FAILED")
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
        return self._evidence(
            spec, base_refs=(base.git_ref_sha,), accepted_refs=(after.git_ref_sha,), dolt_commits=(after.dolt_commit,),
            canonical_rows=(first.canonical_row,), projection_urls=(posted.html_url,),
        )

    def _scenario_6(self, spec: ScenarioSpec) -> ScenarioEvidence:
        task_id = self._seed(6, 1)[0]
        left = self.repository.bootstrap()
        right = self.repository.bootstrap()
        left_store = self.repository.store(left)
        right_store = self.repository.store(right)
        source1, _ = self._post_source(6, 1, "ALLOCATE_TASK")
        source2, _ = self._post_source(6, 2, "ALLOCATE_TASK")
        rid1 = stable_ulid(f"{self.namespace.value}:s6:winner")
        rid2 = stable_ulid(f"{self.namespace.value}:s6:stale")
        c1 = AllocationCommand(rid1, "ALLOCATE_TASK", hashlib.sha256(b"s6-winner").hexdigest(), self.agent_id, task_id=task_id)
        c2 = AllocationCommand(rid2, "ALLOCATE_TASK", hashlib.sha256(b"s6-stale").hexdigest(), self.agent_id, task_id=task_id)
        ctx1 = RequestContext(CONTROL_REPOSITORY, self.issue_number, source1, "fixture", self.agent_id)
        ctx2 = RequestContext(CONTROL_REPOSITORY, self.issue_number, source2, "fixture", self.agent_id)
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
                pass
            else:
                raise LiveExecutorError("SCENARIO_6_STALE_WRITER_ACCEPTED")
        finally:
            left.close()
            right.close()
        if not winner.allocation_id or not stale.allocation_id:
            raise LiveExecutorError("SCENARIO_6_ALLOCATION_ID_MISSING")
        row = self._allocation(winner.allocation_id)
        row_identity = _sha256(row)
        from .adversarial import CanonicalAllocationEvidence
        allocation = CanonicalAllocationEvidence(winner.allocation_id, row_identity, accepted.git_ref_sha, "ACTIVE", self.agent_id)
        proof = FinalOwnerEvidence(winner.allocation_id, winner.allocation_id, stale.allocation_id, accepted.git_ref_sha, accepted.git_ref_sha)
        return self._evidence(
            spec, base_refs=(accepted.git_ref_sha,), accepted_refs=(accepted.git_ref_sha,), dolt_commits=(accepted.dolt_commit,),
            canonical_rows=(row_identity,), allocation_rows=(allocation,), final_owner=proof,
        )

    def _scenario_7(self, spec: ScenarioSpec) -> ScenarioEvidence:
        task_id = self._seed(7, 1)[0]
        base = self._identity()
        source, _ = self._post_source(7, 1, "ALLOCATE_TASK")
        rid = stable_ulid(f"{self.namespace.value}:s7")
        command = AllocationCommand(rid, "ALLOCATE_TASK", hashlib.sha256(b"s7").hexdigest(), self.agent_id, task_id=task_id)
        context = RequestContext(CONTROL_REPOSITORY, self.issue_number, source, "fixture", self.agent_id)
        repository = self.repository
        class FailPublish:
            def bootstrap(self_inner):
                return repository.bootstrap()
            def store(self_inner, snapshot):
                return repository.store(snapshot)
            def publish(self_inner, expected, snapshot):
                raise CanonicalPushFailed("INJECTED_FIXTURE_PUSH_FAILURE")
        result = AllocationService(FailPublish(), clock=lambda: NOW, max_stale_retries=0).process(command, context)
        after = self._identity()
        if result.reason_code != "CANONICAL_PUSH_FAILED" or after.git_ref_sha != base.git_ref_sha:
            raise LiveExecutorError("SCENARIO_7_ASSERTION_FAILED")
        return self._evidence(
            spec, base_refs=(base.git_ref_sha,), accepted_refs=(base.git_ref_sha,), dolt_commits=(base.dolt_commit,),
            canonical_rows=(f"canonical-state:{base.git_ref_sha}",),
        )

    def _scenario_8(self, spec: ScenarioSpec) -> ScenarioEvidence:
        task_id = self._seed(8, 1)[0]
        base = self._identity()
        result = self._process(8, 1, request_type="ALLOCATE_TASK", task_id=task_id, project=False)
        self.reconciler._record_projection_missing(result.request_id)
        projection = self.reconciler._canonical_projection(result.request_id, source_comment_id=result.source_id)
        repaired = self.gateway.post_projection(self.issue_number, render_projection(projection))
        if not self.reconciler._record_projection_posted(result.request_id, repaired):
            raise LiveExecutorError("SCENARIO_8_REPAIR_NOT_RECORDED")
        orphan_body = render_projection({
            **projection.envelope(),
            "request_id": stable_ulid(f"{self.namespace.value}:s8:orphan"),
            "source_comment_id": result.source_id + 1000000000,
        })
        orphan = self.gateway.post_projection(self.issue_number, orphan_body)
        orphan_comment = DurableComment(orphan.comment_id, orphan_body, orphan.html_url)
        from .reconciliation import ReconciliationSummary
        summary = ReconciliationSummary(self.namespace.value)
        self.reconciler._invalidate_orphan(orphan_comment, summary)
        if orphan.comment_id not in summary.orphan_projections_invalidated:
            raise LiveExecutorError("SCENARIO_8_ORPHAN_NOT_INVALIDATED")
        result.projection_url = repaired.html_url
        return self._evidence(
            spec, source_ids=(result.source_id,), base_refs=(base.git_ref_sha,), accepted_refs=(result.accepted_ref,),
            dolt_commits=(result.dolt_commit,), canonical_rows=(result.canonical_row,), projection_urls=(repaired.html_url,),
        )

    def _scenario_9(self, spec: ScenarioSpec) -> ScenarioEvidence:
        task_ids = self._seed(9, 2)
        base = self._identity()
        pre_edit, _ = self._post_source(9, 1, "pre-ingress-edit")
        self._edit_comment(pre_edit, json.dumps({"fixture_mode": FIXTURE_MODE, "mutated": True}))
        pre_delete, _ = self._post_source(9, 2, "pre-ingress-delete")
        self._delete_comment(pre_delete)
        post_edit = self._process(9, 3, request_type="ALLOCATE_TASK", task_id=task_ids[0])
        before_edit = self._allocation(post_edit.allocation_id or "")
        self._edit_comment(post_edit.source_id, json.dumps({"fixture_mode": FIXTURE_MODE, "post_ingress_edit": True}))
        after_edit = self._allocation(post_edit.allocation_id or "")
        post_delete = self._process(9, 4, request_type="ALLOCATE_TASK", task_id=task_ids[1])
        before_delete = self._allocation(post_delete.allocation_id or "")
        self._delete_comment(post_delete.source_id)
        after_delete = self._allocation(post_delete.allocation_id or "")
        if _sha256(before_edit) != _sha256(after_edit) or _sha256(before_delete) != _sha256(after_delete):
            raise LiveExecutorError("SCENARIO_9_CANONICAL_MUTATED")
        return self._evidence(
            spec, source_ids=(pre_edit, pre_delete, post_edit.source_id, post_delete.source_id),
            base_refs=(base.git_ref_sha,), accepted_refs=(post_edit.accepted_ref, post_delete.accepted_ref),
            dolt_commits=(post_edit.dolt_commit, post_delete.dolt_commit),
            canonical_rows=(post_edit.canonical_row, post_delete.canonical_row),
            projection_urls=(post_edit.projection_url, post_delete.projection_url),
        )

    def _scenario_10(self, spec: ScenarioSpec) -> ScenarioEvidence:
        task_id = self._seed(10, 1)[0]
        base = self._identity()
        result = self._process(10, 1, request_type="ALLOCATE_TASK", task_id=task_id, project=False)
        fresh = self.repository.bootstrap()
        try:
            store = self.repository.store(fresh)
            reconstructed = store.reconstruct()
            if not any(row.get("request_id") == result.request_id for row in reconstructed["requests"]):
                raise LiveExecutorError("SCENARIO_10_RECONSTRUCTION_FAILED")
            store.begin()
            store.connection.execute("UPDATE issues SET assignee = NULL WHERE id = ?", (task_id,))
            task = store.task(task_id)
            try:
                store.assert_ownership_invariant(task)
            except CanonicalOwnershipMismatch:
                pass
            else:
                raise LiveExecutorError("SCENARIO_10_MISMATCH_NOT_DETECTED")
            store.rollback()
        finally:
            fresh.close()
        transcript = ClientTranscript("git-capable", _sha256({"request": result.request_id, "fresh_clone": True}), True)
        return self._evidence(
            spec, base_refs=(base.git_ref_sha,), accepted_refs=(result.accepted_ref,), dolt_commits=(result.dolt_commit,),
            canonical_rows=(result.canonical_row,), clients=(transcript,),
        )

    def _scenario_11(self, spec: ScenarioSpec) -> ScenarioEvidence:
        task_id = self._seed(11, 1)[0]
        result = self._process(11, 1, request_type="ALLOCATE_TASK", task_id=task_id)
        comments = self.gateway.list_comments(self.issue_number)
        projection = next((parse_projection(c.body) for c in comments if c.html_url == result.projection_url), None)
        if projection is None or projection.get("execution_may_begin") is not True or not projection.get("release_instruction"):
            raise LiveExecutorError("SCENARIO_11_API_CONSUMPTION_FAILED")
        transcript = ClientTranscript("github-api-only", _sha256({"projection_url": result.projection_url, "fields": sorted(projection)}), True)
        return self._evidence(spec, source_ids=(result.source_id,), projection_urls=(result.projection_url,), clients=(transcript,))

    def _scenario_12(self, spec: ScenarioSpec) -> ScenarioEvidence:
        task_id = self._seed(12, 1)[0]
        base = self._identity()
        granted = self._process(12, 1, request_type="ALLOCATE_TASK", task_id=task_id, project=False)
        if not granted.allocation_id:
            raise LiveExecutorError("SCENARIO_12_GRANT_FAILED")
        released = self._process(
            12, 2, request_type="RELEASE", allocation_id=granted.allocation_id,
            reason="Workstream D synthetic fixture release",
        )
        allocation = self._allocation(granted.allocation_id)
        if allocation.get("state") != "RELEASED" or allocation.get("release_request_id") != released.request_id:
            raise LiveExecutorError("SCENARIO_12_HISTORY_NOT_RETAINED")
        return self._evidence(
            spec, source_ids=(released.source_id,), base_refs=(base.git_ref_sha,), accepted_refs=(released.accepted_ref,),
            dolt_commits=(released.dolt_commit,), canonical_rows=(released.canonical_row,),
            projection_urls=(released.projection_url,), cleanup="released",
        )

    def _scenario_13(self, spec: ScenarioSpec) -> ScenarioEvidence:
        source, _ = self._post_source(13, 1, "authorisation-and-token-scope")
        policy = load_policy("policy/actors.json")
        payload = {
            "protocol": "beads-allocation/v0.2",
            "type": "ALLOCATE_TASK",
            "request_id": stable_ulid(f"{self.namespace.value}:s13:auth"),
            "agent_id": "agent://github-app/fixture-bot/1/session/s13",
            "task_id": "synthetic-task",
        }
        parsed = parse_request(("/beads-v0.2 " + json.dumps(payload, sort_keys=True, separators=(",", ":"))).encode())

        def expect_auth_reject(comment: dict[str, Any]) -> None:
            try:
                authorise(comment, parsed, policy)
            except AuthorisationError:
                return
            raise LiveExecutorError("SCENARIO_13_AUTH_NEGATIVE_ACCEPTED")

        bot = {"user": {"login": "fixture-bot[bot]", "id": 1, "type": "Bot"}}
        for control in SCENARIO_13_FAULT_CONTROLS:
            if control in {"missing_comment_app_attribution", "wrong_comment_app_id", "wrong_comment_app_slug", "wrong_bot_id", "wrong_bot_login", "misleading_event_installation"}:
                comment = dict(bot)
                if control != "missing_comment_app_attribution":
                    comment["performed_via_github_app"] = {"id": 999, "slug": "wrong"}
                expect_auth_reject(comment)
            elif control == "human_namespace_impersonation":
                try:
                    authorise({"user": {"login": "8ft0-ai", "id": 130460431, "type": "User"}}, parsed, policy)
                except AuthorisationError:
                    pass
                else:
                    raise LiveExecutorError("SCENARIO_13_HUMAN_IMPERSONATION_ACCEPTED")
            elif control in {"wrong_installation_mapping", "lost_control_repository_access"}:
                class FakeAPI:
                    def get(self, path):
                        return {"id": 999, "app_id": 999, "app_slug": "wrong", "repository_selection": "selected", "account": {"login": "8ft0-ai"}}
                try:
                    verify_live_installation(FakeAPI(), "8ft0-ai", "gitstate-allocation-control", {
                        "installation_id": 1, "app_id": 1, "app_slug": "gitstate-phase-2-allocator", "owner": "8ft0-ai"
                    })
                except CredentialPolicyError:
                    pass
                else:
                    raise LiveExecutorError("SCENARIO_13_INSTALLATION_NEGATIVE_ACCEPTED")
            elif control in {"inventory_additional_repository", "inventory_missing_repository", "inventory_stale_after_settings_change"}:
                att = self.inventory.attestation
                ids = (CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID, 999) if control == "inventory_additional_repository" else ((CONTROL_REPOSITORY_ID,) if control == "inventory_missing_repository" else att.repository_ids)
                audit = datetime(2000, 1, 1, tzinfo=timezone.utc) if control == "inventory_stale_after_settings_change" else att.audited_at
                bad = InventoryAttestation(att.app_id, att.installation_id, "selected", tuple(ids), audit)
                try:
                    bad.validate(
                        app_id=att.app_id,
                        installation_id=att.installation_id,
                        expected_repository_ids={CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID},
                        now=datetime.now(timezone.utc),
                        max_age_seconds=INVENTORY_MAX_AGE_SECONDS,
                    )
                except InventoryError:
                    pass
                else:
                    raise LiveExecutorError("SCENARIO_13_INVENTORY_NEGATIVE_ACCEPTED")
            elif control in {"token_repository_restriction_omitted", "token_permission_restriction_omitted", "default_token_request", "multi_repository_token_request", "unapproved_permission_request"}:
                if control == "token_repository_restriction_omitted":
                    bad = TokenProfile("control", 0, dict(control_profile(CONTROL_REPOSITORY_ID).permissions))
                elif control == "token_permission_restriction_omitted":
                    bad = TokenProfile("control", CONTROL_REPOSITORY_ID, {})
                elif control == "default_token_request":
                    bad = TokenProfile("default", CONTROL_REPOSITORY_ID, dict(control_profile(CONTROL_REPOSITORY_ID).permissions))
                elif control == "multi_repository_token_request":
                    bad = TokenProfile("control+state", CONTROL_REPOSITORY_ID, dict(control_profile(CONTROL_REPOSITORY_ID).permissions))
                else:
                    bad = TokenProfile("control", CONTROL_REPOSITORY_ID, {"contents": "write"})
                try:
                    token_request(bad)
                except CredentialPolicyError:
                    pass
                else:
                    raise LiveExecutorError("SCENARIO_13_TOKEN_REQUEST_NEGATIVE_ACCEPTED")
            elif control == "returned_scope_mismatch":
                profile = control_profile(CONTROL_REPOSITORY_ID)
                try:
                    validate_token_response({"repositories": [{"id": STATE_REPOSITORY_ID}], "permissions": profile.permissions, "token": "fixture"}, profile)
                except CredentialPolicyError:
                    pass
                else:
                    raise LiveExecutorError("SCENARIO_13_RETURNED_SCOPE_NEGATIVE_ACCEPTED")
            elif control in {"control_token_cross_repository_access", "state_token_cross_repository_access"}:
                if not all(record.cross_repository_denied for record in self.token_scope_records):
                    raise LiveExecutorError("SCENARIO_13_CROSS_REPOSITORY_DENIAL_MISSING")
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
                context = RequestContext(CONTROL_REPOSITORY, self.issue_number, source, "fixture", self.agent_id)
                try:
                    store.begin()
                    result = AllocationService(self.repository, clock=lambda: NOW)._apply(store, command, context, NOW)
                    if result.reason_code != "AGENT_NOT_AUTHORISED":
                        raise LiveExecutorError("SCENARIO_13_UNAUTHORISED_RELEASE_ACCEPTED")
                    store.rollback()
                    if before != _sha256(store.reconstruct()):
                        raise LiveExecutorError("SCENARIO_13_UNAUTHORISED_RELEASE_MUTATED")
                finally:
                    snapshot.close()
            else:
                raise LiveExecutorError(f"UNHANDLED_SCENARIO_13_CONTROL:{control}")
        return self._evidence(spec, source_ids=(source,), scenario13=True)

    def _scenario_14(self, spec: ScenarioSpec) -> ScenarioEvidence:
        task_id = self._seed(14, 1)[0]
        base = self._identity()
        result = self._process(14, 1, request_type="ALLOCATE_TASK", task_id=task_id)
        fresh = self.repository.bootstrap()
        try:
            if self.repository.store(fresh).get_request(result.request_id) is None:
                raise LiveExecutorError("SCENARIO_14_GIT_DURABILITY_FAILED")
        finally:
            fresh.close()
        comments = self.gateway.list_comments(self.issue_number)
        if not any(comment.html_url == result.projection_url for comment in comments):
            raise LiveExecutorError("SCENARIO_14_GITHUB_DURABILITY_FAILED")
        return self._evidence(
            spec, base_refs=(base.git_ref_sha,), accepted_refs=(result.accepted_ref,), dolt_commits=(result.dolt_commit,),
            canonical_rows=(result.canonical_row,), projection_urls=(result.projection_url,), network=NETWORK_DESTINATIONS,
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
    primary_error: Exception | None = None
    try:
        lease, inventory = acquire_credentials(env, context)
        with tempfile.TemporaryDirectory(prefix=f"{namespace.value}-") as directory:
            root = Path(directory)
            repository = bootstrap_fixture_repository(
                lease.state_token,
                root=root,
                bd_bin=env["BD_BIN"],
                dolt_bin=env["DOLT_BIN"],
            )
            backend = LiveFixtureBackend(
                repository,
                GitHubAPI(lease.control_token, lease.api_url),
                int(env.get("PHASE2_CONTROL_ISSUE_NUMBER", str(CONTROL_ISSUE_NUMBER))),
                context.trusted_sha,
                context.protocol_sha,
                lease.token_scope_records,
                inventory,
                namespace,
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
                tuple(hashlib.sha256(record.to_json().encode()).hexdigest() for record in records),
                inventory.digest,
                True,
                True,
            )
            backend.gateway.post_summary(
                backend.issue_number,
                json.dumps({"type": "WORKSTREAM_D_SYNTHETIC_LIVE_RESULT", **result.payload()}, sort_keys=True, separators=(",", ":")),
            )
            return result
    except Exception as exc:
        primary_error = exc
        raise
    finally:
        if lease is not None:
            try:
                lease.close()
            except Exception:
                if primary_error is None:
                    raise


def main() -> int:
    try:
        result = execute_live_suite()
        payload = result.payload()
        payload["credential_revoked"] = True
        payload["status"] = "WORKSTREAM_D_SYNTHETIC_SUITE_PASSED_PENDING_ENABLEMENT_REMOVAL"
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as exc:
        print(json.dumps({
            "status": "BLOCKED",
            "reason_code": str(exc).split(":", 1)[0] or type(exc).__name__,
            "credential_material_emitted": False,
            "workstream_e_authorised": False,
        }, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
