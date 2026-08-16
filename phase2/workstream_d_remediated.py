"""Bounded Workstream D live-failure remediation.

This module is the trusted-main entry point for the post-run remediation
authorised by gitstate-lab#15 comment 5310070151. It deliberately delegates
scenario semantics to ``phase2.workstream_d_live`` and changes only the
credential-bearing fixture transport and cleanup observability needed after
run 31975783078 failed during canonical bootstrap.

It does not reset live state, authorise a rerun, or widen Workstream D into
Workstream E.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Mapping, Sequence

from . import workstream_d_live as live

REMEDIATION_EXECUTABLE_PATH = "phase2/workstream_d_remediated.py"
REVOCATION_STATUS = "WORKSTREAM_D_INSTALLATION_TOKENS_REVOKED"
_REQUIRED_STATE_GIT_ENV = (
    "GIT_ASKPASS",
    "GIT_TERMINAL_PROMPT",
    "PHASE2_STATE_TOKEN",
)


class CredentialLease(live.CredentialLease):
    """Truthful lease cleanup: clear material always; mark revoked only on success."""

    revocation_failed = False

    def close(self) -> None:
        if self.revoked:
            return
        if self.revocation_failed:
            raise live.LiveExecutorError("INSTALLATION_TOKEN_REVOCATION_FAILED")
        failures: list[Exception] = []
        try:
            for token in (self.state_token, self.control_token):
                try:
                    self._revoke(token)
                except Exception as exc:
                    failures.append(exc)
        finally:
            self.state_token = ""
            self.control_token = ""
        if failures:
            self.revocation_failed = True
            self.revoked = False
            raise live.LiveExecutorError("INSTALLATION_TOKEN_REVOCATION_FAILED") from failures[0]
        self.revoked = True


def _writable_dolt_server_env(values: Mapping[str, str]) -> dict[str, str]:
    """Return the existing state Git auth environment without mutating process env."""
    environment = dict(values)
    if any(not environment.get(name) for name in _REQUIRED_STATE_GIT_ENV):
        raise live.LiveExecutorError("WRITABLE_DOLT_GIT_AUTH_ENV_MISSING")
    return environment


class WritableManagedDoltConnection(live.ManagedDoltConnection):
    """Dolt SQL server whose DOLT_PUSH inherits the already-minted state Git auth."""

    def __init__(
        self,
        database: Path,
        dolt_bin: str,
        credential_env: Mapping[str, str],
    ) -> None:
        try:
            import pymysql  # type: ignore
        except ImportError as exc:
            raise live.LiveExecutorError("PINNED_PYMYSQL_UNAVAILABLE") from exc
        self._pymysql = pymysql
        self.database = database
        self.port = live._free_port()
        self.log = (database.parent / "dolt-sql.log").open("w+")
        self.server_environment = _writable_dolt_server_env(credential_env)
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
            env=self.server_environment,
            text=True,
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        self.inner = self._connect()


def acquire_credentials(
    values: Mapping[str, str],
    context: live.LiveRunContext,
    *,
    api_factory: Callable[[str, str], live.GitHubAPI] = live.GitHubAPI,
    jwt_factory: Callable[[int, str], str] = live.create_app_jwt,
) -> tuple[CredentialLease, live.ValidatedInventory]:
    """Acquire the unchanged reduced profiles with fail-closed cleanup on error."""
    context.validate()
    policy = live.load_policy(values.get("PHASE2_POLICY", "policy/actors.json"))
    if policy.get("control_repository") != live.CONTROL_REPOSITORY:
        raise live.LiveExecutorError("CONTROL_REPOSITORY_POLICY_MISMATCH")
    if int(policy.get("control_repository_id", 0)) != live.CONTROL_REPOSITORY_ID:
        raise live.LiveExecutorError("CONTROL_REPOSITORY_ID_MISMATCH")
    api_url = values.get("GITHUB_API_URL", "https://api.github.com")
    app_id = int(values[policy["allocator"]["app_id_env"]])
    installation_id = int(values[policy["allocator"]["installation_id_env"]])
    if int(values[policy["state_repository_id_env"]]) != live.STATE_REPOSITORY_ID:
        raise live.LiveExecutorError("STATE_REPOSITORY_ID_MISMATCH")
    inventory = live._decode_inventory(
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
    live.verify_live_installation(
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

    control = live.control_profile(live.CONTROL_REPOSITORY_ID)
    state = live.state_profile(live.STATE_REPOSITORY_ID)
    control_token = ""
    state_token = ""
    try:
        control_token = live.mint_token(app_api, installation_id, control)
        live.require_cross_repository_denial(
            control_token, live.STATE_REPOSITORY_ID, api_url
        )
        state_token = live.mint_token(app_api, installation_id, state)
        live.require_public_repository_write_denial(
            state_token,
            "8ft0-ai",
            "gitstate-allocation-control",
            api_url,
        )
        jwt = ""
        return (
            CredentialLease(
                control_token,
                state_token,
                (live._scope_evidence(control), live._scope_evidence(state)),
                api_url,
                api_factory,
            ),
            inventory,
        )
    except Exception as primary_error:
        jwt = ""
        lease = CredentialLease(
            control_token,
            state_token,
            (live._scope_evidence(control), live._scope_evidence(state)),
            api_url,
            api_factory,
        )
        try:
            lease.close()
        except Exception as cleanup_error:
            raise cleanup_error from primary_error
        raise


def bootstrap_fixture_repository(
    state_token: str,
    *,
    root: Path,
    bd_bin: str,
    dolt_bin: str,
) -> live.FixtureRepositoryLease:
    """Bootstrap the existing synthetic fixture with writable SQL-server Git auth."""
    live.assert_uninitialised_state(state_token, root=root)
    source = root / "fixture-source"
    source.mkdir()
    env = live._state_git_env(root, state_token)
    env.update({"BD_NON_INTERACTIVE": "1", "CI": "true", "HOME": str(root / "home")})
    Path(env["HOME"]).mkdir()
    live._run(["git", "init", "--initial-branch=main"], cwd=source)
    live._run(["git", "config", "user.name", "Workstream D Fixture"], cwd=source)
    live._run(
        ["git", "config", "user.email", "workstream-d@example.invalid"],
        cwd=source,
    )
    (source / "README.md").write_text(
        "Workstream D synthetic fixture state\n", encoding="utf-8"
    )
    live._run(["git", "add", "README.md"], cwd=source)
    live._run(["git", "commit", "-m", "Initial Workstream D fixture state"], cwd=source)
    live._run(
        [
            bd_bin,
            "init",
            "--prefix",
            "wd",
            "--quiet",
            "--skip-hooks",
            "--skip-agents",
            "--non-interactive",
        ],
        cwd=source,
        env=env,
    )
    remote = live._remote_url()
    live._run(["git", "remote", "add", "fixture-state", remote], cwd=source, env=env)
    live._run(["git", "push", "fixture-state", "main:main"], cwd=source, env=env)
    live._run(
        [bd_bin, "dolt", "remote", "add", "origin", "git+" + remote],
        cwd=source,
        env=env,
    )
    live._run(
        [bd_bin, "dolt", "commit", "-m", "Workstream D pinned Beads baseline"],
        cwd=source,
        env=env,
    )
    live._run([bd_bin, "dolt", "push"], cwd=source, env=env)

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

    repository = live.DoltCanonicalRepository(
        "git+" + remote,
        lambda database: WritableManagedDoltConnection(database, dolt_bin, env),
        dolt_bin=dolt_bin,
        run_command=credentialled_run,
        workspace_root=root,
    )
    snapshot = repository.bootstrap()
    try:
        live._execute_ddl(snapshot.connection, live.dolt_schema())
        repository.publish(snapshot.identity.git_ref_sha, snapshot)
    finally:
        snapshot.close()
    return live.FixtureRepositoryLease(repository, env, root / "state-askpass.sh")


def _bind_executable_identity() -> None:
    paths = tuple(live.LIVE_EXECUTABLE_PATHS)
    if REMEDIATION_EXECUTABLE_PATH not in paths:
        live.LIVE_EXECUTABLE_PATHS = (*paths, REMEDIATION_EXECUTABLE_PATH)


def _emit_revocation_record(context: live.LiveRunContext) -> None:
    print(
        json.dumps(
            {
                "attempt_namespace": context.namespace.value,
                "credential_material_emitted": False,
                "credential_revoked": True,
                "installation_tokens_revoked": 2,
                "run_attempt": context.run_attempt,
                "run_id": context.run_id,
                "status": REVOCATION_STATUS,
                "workstream_e_authorised": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def execute_live_suite(
    values: Mapping[str, str] | None = None,
) -> live.LiveSuiteResult:
    """Run unchanged scenarios with bounded writable transport/cleanup remediation."""
    env = os.environ if values is None else values
    context = live.context_from_environment(env)
    namespace = context.validate()
    _bind_executable_identity()
    lease: CredentialLease | None = None
    fixture: live.FixtureRepositoryLease | None = None
    primary_error: Exception | None = None
    fixture_cleanup_error: Exception | None = None
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
            backend = live.LiveFixtureBackend(
                fixture.repository,
                live.GitHubAPI(lease.control_token, lease.api_url),
                int(
                    env.get(
                        "PHASE2_CONTROL_ISSUE_NUMBER",
                        str(live.CONTROL_ISSUE_NUMBER),
                    )
                ),
                context.trusted_sha,
                context.protocol_sha,
                lease.token_scope_records,
                inventory,
                namespace,
                fixture.make_read_only_remote,
            )
            records = live.ScenarioDriver(backend).run(
                live.SCENARIO_IDS,
                namespace,
                expected_trusted_sha=context.trusted_sha,
                expected_protocol_sha=context.protocol_sha,
            )
            summary = live.evidence_summary(
                records,
                attempt_namespace=namespace,
                expected_trusted_sha=context.trusted_sha,
                expected_protocol_sha=context.protocol_sha,
            )
            if summary["scenarios"] != 14 or summary["workstream_e_authorised"]:
                raise live.LiveExecutorError("UNEXPECTED_WORKSTREAM_D_SUMMARY")
            result = live.LiveSuiteResult(
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
            except Exception as exc:
                fixture_cleanup_error = exc
        if lease is not None:
            try:
                lease.close()
            except Exception as cleanup_error:
                raise cleanup_error from primary_error
            _emit_revocation_record(context)
        if primary_error is None and fixture_cleanup_error is not None:
            raise live.LiveExecutorError("FIXTURE_CREDENTIAL_CLEANUP_FAILED") from fixture_cleanup_error


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
