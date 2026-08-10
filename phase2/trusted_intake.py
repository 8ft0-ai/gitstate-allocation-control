from __future__ import annotations

import json
import os
import re
import sys
from typing import Any

from .credentials import (
    CredentialPolicyError,
    control_profile,
    create_app_jwt,
    mint_token,
    require_cross_repository_denial,
    require_public_repository_write_denial,
    state_profile,
    verify_live_installation,
)
from .github_api import GitHubAPI
from .policy import load_policy

FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _post_rejection(api: GitHubAPI, repository: str, issue_number: int, source_comment_id: int, reason_code: str) -> None:
    owner, repo = repository.split("/", 1)
    body = {
        "body": (
            "Phase 2 intake rejected.\n\n"
            f"```json\n{{\"execution_may_begin\":false,\"protocol\":\"beads-allocation/v0.2\","
            f"\"reason_code\":\"{reason_code}\",\"source_comment_id\":{source_comment_id}}}\n```"
        )
    }
    api.post(f"/repos/{owner}/{repo}/issues/{issue_number}/comments", body)


def run(env: dict[str, str] | None = None) -> dict[str, Any]:
    values = os.environ if env is None else env
    policy = load_policy(values.get("PHASE2_POLICY", "policy/actors.json"))
    action = values["PHASE2_ACTION"]
    trusted_sha = values["PHASE2_TRUSTED_SHA"]
    if not FULL_SHA_RE.fullmatch(trusted_sha):
        raise CredentialPolicyError("INVALID_TRUSTED_SHA")
    if action not in {"live_check", "scope_probe"}:
        raise CredentialPolicyError("UNAPPROVED_TRUSTED_ACTION")

    source_comment_id: int | None = None
    if action == "live_check":
        try:
            source_comment_id = int(values["PHASE2_SOURCE_COMMENT_ID"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CredentialPolicyError("INVALID_COMMENT_ID") from exc
        if source_comment_id <= 0:
            raise CredentialPolicyError("INVALID_COMMENT_ID")

    api_url = values.get("GITHUB_API_URL", "https://api.github.com")
    workflow_api = GitHubAPI(values["GITHUB_TOKEN"], api_url)
    app_id = int(values[policy["allocator"]["app_id_env"]])
    installation_id = int(values[policy["allocator"]["installation_id_env"]])
    private_key_name = "PHASE2_ALLOCATOR_APP_PRIVATE_KEY"
    private_key = values[private_key_name]
    if env is None:
        os.environ.pop(private_key_name, None)
    jwt = create_app_jwt(app_id, private_key)
    private_key = ""

    app_api = GitHubAPI(jwt, api_url)
    owner, repository = policy["control_repository"].split("/", 1)
    expected = {
        "app_id": app_id,
        "installation_id": installation_id,
        "app_slug": policy["allocator"]["app_slug"],
        "owner": policy["allocator"]["owner"],
    }
    try:
        verify_live_installation(app_api, owner, repository, expected)
    except CredentialPolicyError:
        if source_comment_id is not None:
            _post_rejection(
                workflow_api,
                policy["control_repository"],
                policy["allocation_issue_number"],
                source_comment_id,
                "AGENT_NOT_AUTHORISED",
            )
        return {"status": "LIVE_CHECK_REJECTED", "state_token_requested": False, "canonical_accessed": False}

    if action == "live_check":
        return {"status": "LIVE_CHECK_PASSED", "state_token_requested": False, "canonical_accessed": False}

    control_id = int(policy["control_repository_id"])
    state_id = int(values[policy["state_repository_id_env"]])
    if state_id <= 0 or state_id == control_id:
        raise CredentialPolicyError("INVALID_REPOSITORY_SCOPE")
    control_token = mint_token(app_api, installation_id, control_profile(control_id))
    require_cross_repository_denial(control_token, state_id, api_url)
    control_token = ""
    state_token = mint_token(app_api, installation_id, state_profile(state_id))
    require_public_repository_write_denial(state_token, owner, repository, api_url)
    state_token = ""
    return {"status": "SCOPE_PROBE_PASSED", "cross_repository_access": False}


def main() -> int:
    try:
        result = run()
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "BLOCKED", "reason_code": type(exc).__name__}, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
