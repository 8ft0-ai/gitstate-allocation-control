from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Mapping

from . import workstream_d_anchor_repair as anchor_repair
from . import workstream_d_live as live
from . import workstream_d_revocation as revocation
from .credentials import (
    control_profile,
    create_app_jwt,
    mint_token,
    require_cross_repository_denial,
    require_public_repository_write_denial,
    state_profile,
    verify_live_installation,
)
from .github_api import GitHubAPI, GitHubAPIError
from .inventory import InventoryAttestation
from .operator_capsule import (
    LIVE_PROFILE,
    PREFLIGHT_PROFILE,
    PROTOCOL_AUTHORITY_SHA,
    STATE_BASELINE_SHA,
    profile_for_dispatch,
)
from .operator_inventory import (
    CONTROL_REPOSITORY_ID,
    STATE_REPOSITORY_ID,
    InventoryEvidence,
    prove_installation_inventory,
)


OPERATOR_EXECUTABLE_PATH = "phase2/operator_runtime.py"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
OPAQUE_ID = re.compile(r"^[0-9a-f]{32,64}$")


class OperatorRuntimeError(RuntimeError):
    pass


@dataclass(frozen=True)
class OperatorRunContext:
    repository: str
    ref: str
    trusted_sha: str
    expected_control_sha: str
    expected_protocol_sha: str
    expected_state_baseline: str
    run_id: int
    run_attempt: int
    input_operation: str
    operation_profile: str
    capsule_id: str
    capsule_body_sha256: str
    consumption_record_sha256: str
    attempt_nonce: str

    def validate(self) -> None:
        if self.repository != live.CONTROL_REPOSITORY:
            raise OperatorRuntimeError("OPERATOR_REPOSITORY_MISMATCH")
        if self.ref != "refs/heads/main":
            raise OperatorRuntimeError("OPERATOR_PROTECTED_MAIN_REQUIRED")
        if SHA40.fullmatch(self.trusted_sha) is None:
            raise OperatorRuntimeError("OPERATOR_TRUSTED_SHA_INVALID")
        if self.expected_control_sha != self.trusted_sha:
            raise OperatorRuntimeError("OPERATOR_CONTROL_SHA_MISMATCH")
        if self.expected_protocol_sha != PROTOCOL_AUTHORITY_SHA:
            raise OperatorRuntimeError("OPERATOR_PROTOCOL_SHA_MISMATCH")
        if self.expected_state_baseline != STATE_BASELINE_SHA:
            raise OperatorRuntimeError("OPERATOR_STATE_BASELINE_MISMATCH")
        if self.run_id <= 0 or self.run_attempt != 1:
            raise OperatorRuntimeError("OPERATOR_RERUN_FORBIDDEN")
        if self.operation_profile != profile_for_dispatch(self.input_operation):
            raise OperatorRuntimeError("OPERATOR_PROFILE_MISMATCH")
        if OPAQUE_ID.fullmatch(self.capsule_id) is None:
            raise OperatorRuntimeError("OPERATOR_CAPSULE_ID_INVALID")
        if SHA256.fullmatch(self.capsule_body_sha256) is None:
            raise OperatorRuntimeError("OPERATOR_CAPSULE_DIGEST_INVALID")
        if SHA256.fullmatch(self.consumption_record_sha256) is None:
            raise OperatorRuntimeError("OPERATOR_CONSUMPTION_DIGEST_INVALID")
        expected_nonce = hashlib.sha256(
            f"{self.run_id}:{self.run_attempt}:{self.capsule_id}:{self.capsule_body_sha256}".encode(
                "ascii"
            )
        ).hexdigest()[:16]
        if self.attempt_nonce != expected_nonce:
            raise OperatorRuntimeError("OPERATOR_NONCE_DERIVATION_MISMATCH")
        if self.input_operation == "live_scenario_suite" and self.operation_profile != LIVE_PROFILE:
            raise OperatorRuntimeError("OPERATOR_LIVE_PROFILE_MISMATCH")
        if self.input_operation == "operator_preflight" and self.operation_profile != PREFLIGHT_PROFILE:
            raise OperatorRuntimeError("OPERATOR_PREFLIGHT_PROFILE_MISMATCH")

    def legacy_live_context(self, values: Mapping[str, str]) -> live.LiveRunContext:
        if self.input_operation != "live_scenario_suite":
            raise OperatorRuntimeError("OPERATOR_LIVE_CONTEXT_NOT_AUTHORISED")
        return live.LiveRunContext(
            repository=self.repository,
            ref=self.ref,
            trusted_sha=self.trusted_sha,
            expected_control_sha=self.expected_control_sha,
            protocol_sha=self.expected_protocol_sha,
            expected_protocol_sha=PROTOCOL_AUTHORITY_SHA,
            run_id=self.run_id,
            run_attempt=self.run_attempt,
            attempt_nonce=self.attempt_nonce,
            enabled=values.get("PHASE2_WORKSTREAM_D_EXECUTION_ENABLED") == "true",
            fixture_mode=values.get("PHASE2_WORKSTREAM_D_FIXTURE_MODE", ""),
        )


def context_from_environment(values: Mapping[str, str]) -> OperatorRunContext:
    try:
        context = OperatorRunContext(
            repository=values["GITHUB_REPOSITORY"],
            ref=values["GITHUB_REF"],
            trusted_sha=values["GITHUB_SHA"],
            expected_control_sha=values["EXPECTED_CONTROL_SHA"],
            expected_protocol_sha=values["EXPECTED_PROTOCOL_SHA"],
            expected_state_baseline=values["EXPECTED_STATE_BASELINE"],
            run_id=int(values["GITHUB_RUN_ID"]),
            run_attempt=int(values["GITHUB_RUN_ATTEMPT"]),
            input_operation=values["INPUT_OPERATION"],
            operation_profile=values["OPERATION_PROFILE"],
            capsule_id=values["CAPSULE_ID"],
            capsule_body_sha256=values["CAPSULE_BODY_SHA256"],
            consumption_record_sha256=values["CONSUMPTION_RECORD_SHA256"],
            attempt_nonce=values["ATTEMPT_NONCE"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise OperatorRuntimeError("OPERATOR_CONTEXT_INCOMPLETE") from exc
    context.validate()
    return context


def _bind_executable_identity() -> None:
    paths = tuple(live.LIVE_EXECUTABLE_PATHS)
    if OPERATOR_EXECUTABLE_PATH not in paths:
        live.LIVE_EXECUTABLE_PATHS = (*paths, OPERATOR_EXECUTABLE_PATH)


def _app_inventory_proof(
    values: Mapping[str, str],
    context: OperatorRunContext,
    *,
    api_factory: Callable[[str, str], GitHubAPI] = GitHubAPI,
    jwt_factory: Callable[[int, str], str] = create_app_jwt,
) -> tuple[GitHubAPI, int, int, str, InventoryEvidence]:
    # This validation is deliberately before the private-key lookup below.
    context.validate()
    policy = live.load_policy(values.get("PHASE2_POLICY", "policy/actors.json"))
    if policy.get("control_repository") != live.CONTROL_REPOSITORY:
        raise OperatorRuntimeError("CONTROL_REPOSITORY_POLICY_MISMATCH")
    if int(policy.get("control_repository_id", 0)) != CONTROL_REPOSITORY_ID:
        raise OperatorRuntimeError("CONTROL_REPOSITORY_ID_MISMATCH")

    api_url = values.get("GITHUB_API_URL", "https://api.github.com")
    app_id = int(values[policy["allocator"]["app_id_env"]])
    installation_id = int(values[policy["allocator"]["installation_id_env"]])
    if int(values[policy["state_repository_id_env"]]) != STATE_REPOSITORY_ID:
        raise OperatorRuntimeError("STATE_REPOSITORY_ID_MISMATCH")

    key_name = "PHASE2_ALLOCATOR_APP_PRIVATE_KEY"
    private_key = values[key_name]
    if values is os.environ:
        os.environ.pop(key_name, None)
    jwt = jwt_factory(app_id, private_key)
    private_key = ""
    app_api = api_factory(jwt, api_url)
    installation = verify_live_installation(
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
    repository_selection = installation.get("repository_selection")
    if not isinstance(repository_selection, str):
        raise OperatorRuntimeError("LIVE_INSTALLATION_SELECTION_MISSING")

    inventory = prove_installation_inventory(
        app_api,
        installation_id=installation_id,
        app_id=app_id,
        repository_selection=repository_selection,
        run_id=context.run_id,
        run_attempt=context.run_attempt,
        trusted_sha=context.trusted_sha,
        capsule_id=context.capsule_id,
        capsule_body_sha256=context.capsule_body_sha256,
        api_url=api_url,
        api_factory=api_factory,
    )
    jwt = ""
    return app_api, app_id, installation_id, api_url, inventory


def preflight(
    values: Mapping[str, str] | None = None,
    *,
    api_factory: Callable[[str, str], GitHubAPI] = GitHubAPI,
    jwt_factory: Callable[[int, str], str] = create_app_jwt,
) -> dict[str, object]:
    del values, api_factory, jwt_factory
    raise OperatorRuntimeError("OPERATOR_PREFLIGHT_PROJECTION_REQUIRED")


def _operator_acquire_credentials(
    values: Mapping[str, str],
    legacy_context: live.LiveRunContext,
    *,
    api_factory: Callable[[str, str], GitHubAPI] = GitHubAPI,
    jwt_factory: Callable[[int, str], str] = create_app_jwt,
) -> tuple[live.CredentialLease, live.ValidatedInventory]:
    operator_context = context_from_environment(values)
    if operator_context.input_operation != "live_scenario_suite":
        raise OperatorRuntimeError("OPERATOR_LIVE_OPERATION_REQUIRED")
    expected_legacy = operator_context.legacy_live_context(values)
    if legacy_context != expected_legacy:
        raise OperatorRuntimeError("OPERATOR_LEGACY_CONTEXT_MISMATCH")
    legacy_context.validate()

    app_api, app_id, installation_id, api_url, inventory_evidence = _app_inventory_proof(
        values,
        operator_context,
        api_factory=api_factory,
        jwt_factory=jwt_factory,
    )

    control_token = ""
    state_token = ""
    control = control_profile(CONTROL_REPOSITORY_ID)
    state = state_profile(STATE_REPOSITORY_ID)
    try:
        # The inventory token has already been positively revoked before either
        # mutation-capable single-repository token is minted here.
        control_token = mint_token(app_api, installation_id, control)
        require_cross_repository_denial(control_token, STATE_REPOSITORY_ID, api_url)
        state_token = mint_token(app_api, installation_id, state)
        require_public_repository_write_denial(
            state_token, "8ft0-ai", "gitstate-allocation-control", api_url
        )
        attestation = InventoryAttestation(
            app_id=app_id,
            installation_id=installation_id,
            repository_selection="selected",
            repository_ids=inventory_evidence.repository_ids,
            audited_at=datetime.fromisoformat(
                inventory_evidence.audited_at.replace("Z", "+00:00")
            ),
        )
        return (
            live.CredentialLease(
                control_token,
                state_token,
                (live._scope_evidence(control), live._scope_evidence(state)),
                api_url,
                api_factory,
            ),
            live.ValidatedInventory(attestation, inventory_evidence.digest),
        )
    except Exception:
        lease = live.CredentialLease(
            control_token,
            state_token,
            (live._scope_evidence(control), live._scope_evidence(state)),
            api_url,
            api_factory,
        )
        try:
            lease.close()
        except Exception:
            pass
        raise


def execute_live(values: Mapping[str, str] | None = None) -> live.LiveSuiteResult:
    env = os.environ if values is None else values
    operator_context = context_from_environment(env)
    if operator_context.input_operation != "live_scenario_suite":
        raise OperatorRuntimeError("OPERATOR_LIVE_OPERATION_REQUIRED")
    operator_context.legacy_live_context(env).validate()
    _bind_executable_identity()

    previous_protocol = live.PROTOCOL_AUTHORITY
    previous_acquire = live.acquire_credentials
    live.PROTOCOL_AUTHORITY = PROTOCOL_AUTHORITY_SHA
    live.acquire_credentials = _operator_acquire_credentials
    try:
        return revocation.execute_live_suite(env)
    finally:
        live.acquire_credentials = previous_acquire
        live.PROTOCOL_AUTHORITY = previous_protocol


def validate_only(values: Mapping[str, str] | None = None) -> OperatorRunContext:
    env = os.environ if values is None else values
    context = context_from_environment(env)
    if context.input_operation == "live_scenario_suite":
        context.legacy_live_context(env).validate()
    print(
        json.dumps(
            {
                "status": "OPERATOR_RUNTIME_CONTEXT_VALID",
                "run_id": context.run_id,
                "run_attempt": context.run_attempt,
                "trusted_sha": context.trusted_sha,
                "protocol_sha": context.expected_protocol_sha,
                "operation": context.operation_profile,
                "credential_accessed": False,
                "workstream_e_authorised": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return context


def _blocked_payload(exc: Exception) -> dict[str, object]:
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
    elif isinstance(exc, live.CommandFailure):
        payload["reason_code"] = exc.reason_code
        payload.update(exc.safe_diagnostic())
    elif isinstance(exc, live.FixtureBootstrapFailure):
        payload["reason_code"] = exc.reason_code
        payload.update(exc.safe_diagnostic())
    elif isinstance(exc, anchor_repair.StalePhaseFailure):
        payload["reason_code"] = exc.reason_code
        payload.update(exc.safe_diagnostic())
    else:
        payload["reason_code"] = str(exc).split(":", 1)[0] or type(exc).__name__
    return payload


def main() -> int:
    try:
        if len(sys.argv) != 2:
            raise OperatorRuntimeError("OPERATOR_RUNTIME_COMMAND_REQUIRED")
        command = sys.argv[1]
        if command == "validate":
            validate_only()
        elif command == "preflight":
            preflight()
        elif command == "live":
            result = execute_live()
            payload = result.payload()
            payload.update(
                {
                    "status": "WORKSTREAM_D_SYNTHETIC_SUITE_PASSED_PENDING_ENABLEMENT_REMOVAL",
                    "credential_revoked": True,
                    "operator_capsule_id": os.environ.get("CAPSULE_ID", ""),
                    "operator_consumption_record_sha256": os.environ.get(
                        "CONSUMPTION_RECORD_SHA256", ""
                    ),
                }
            )
            print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        else:
            raise OperatorRuntimeError("OPERATOR_RUNTIME_COMMAND_INVALID")
        return 0
    except Exception as exc:
        print(
            json.dumps(
                _blocked_payload(exc),
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
