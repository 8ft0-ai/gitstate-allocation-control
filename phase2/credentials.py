from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Any

from .github_api import GitHubAPI, GitHubAPIError


class CredentialPolicyError(RuntimeError):
    pass


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def create_app_jwt(app_id: int, private_key: str, now: int | None = None) -> str:
    timestamp = int(time.time() if now is None else now)
    header = _b64url(b'{"alg":"RS256","typ":"JWT"}')
    payload = _b64url(json.dumps({"iat": timestamp - 60, "exp": timestamp + 540, "iss": str(app_id)}, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    key_path = ""
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            key_path = handle.name
            os.chmod(key_path, 0o600)
            handle.write(private_key)
        completed = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", key_path],
            input=signing_input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            raise CredentialPolicyError("JWT_SIGNING_FAILED")
        return f"{header}.{payload}.{_b64url(completed.stdout)}"
    finally:
        if key_path:
            try:
                os.unlink(key_path)
            except FileNotFoundError:
                pass


@dataclass(frozen=True)
class TokenProfile:
    name: str
    repository_id: int
    permissions: dict[str, str]


def control_profile(repository_id: int) -> TokenProfile:
    return TokenProfile("control", repository_id, {"contents": "read", "issues": "write", "metadata": "read"})


def state_profile(repository_id: int) -> TokenProfile:
    return TokenProfile("state", repository_id, {"contents": "write", "metadata": "read"})


def token_request(profile: TokenProfile) -> dict[str, Any]:
    if not isinstance(profile.repository_id, int) or profile.repository_id <= 0:
        raise CredentialPolicyError("INVALID_REPOSITORY_SCOPE")
    allowed = {"control", "state"}
    if profile.name not in allowed:
        raise CredentialPolicyError("UNAPPROVED_TOKEN_PROFILE")
    expected = control_profile(profile.repository_id) if profile.name == "control" else state_profile(profile.repository_id)
    if profile.permissions != expected.permissions:
        raise CredentialPolicyError("UNAPPROVED_TOKEN_PERMISSIONS")
    return {"repository_ids": [profile.repository_id], "permissions": dict(profile.permissions)}


def validate_token_response(response: dict[str, Any], profile: TokenProfile) -> str:
    repositories = response.get("repositories")
    permissions = response.get("permissions")
    token = response.get("token")
    if not isinstance(repositories, list) or [repo.get("id") for repo in repositories] != [profile.repository_id]:
        raise CredentialPolicyError("RETURNED_REPOSITORY_SCOPE_MISMATCH")
    if permissions != profile.permissions:
        raise CredentialPolicyError("RETURNED_PERMISSION_SCOPE_MISMATCH")
    if not isinstance(token, str) or not token:
        raise CredentialPolicyError("MISSING_INSTALLATION_TOKEN")
    return token


def verify_live_installation(api: GitHubAPI, owner: str, repository: str, expected: dict[str, Any]) -> dict[str, Any]:
    installation = api.get(f"/repos/{owner}/{repository}/installation")
    checks = {
        "id": expected["installation_id"],
        "app_id": expected["app_id"],
        "app_slug": expected["app_slug"],
        "repository_selection": "selected",
    }
    for key, value in checks.items():
        if installation.get(key) != value:
            raise CredentialPolicyError("LIVE_INSTALLATION_MISMATCH")
    account = installation.get("account") or {}
    if account.get("login") != expected["owner"]:
        raise CredentialPolicyError("LIVE_INSTALLATION_ACCOUNT_MISMATCH")
    return installation


def mint_token(api: GitHubAPI, installation_id: int, profile: TokenProfile) -> str:
    response = api.post(f"/app/installations/{installation_id}/access_tokens", token_request(profile))
    return validate_token_response(response, profile)


def require_cross_repository_denial(token: str, forbidden_repository_id: int, api_url: str) -> None:
    try:
        GitHubAPI(token, api_url).get(f"/repositories/{forbidden_repository_id}")
    except GitHubAPIError as exc:
        if exc.status == 404:
            return
        raise CredentialPolicyError("UNEXPECTED_CROSS_REPOSITORY_RESULT") from exc
    raise CredentialPolicyError("CROSS_REPOSITORY_ACCESS_PRESENT")


def require_public_repository_write_denial(token: str, owner: str, repository: str, api_url: str) -> None:
    """Use a deliberately impossible update to distinguish public read access from write access."""
    try:
        GitHubAPI(token, api_url).request(
            "PUT",
            f"/repos/{owner}/{repository}/contents/.phase2-cross-scope-probe",
            {"message": "scope probe", "content": "", "sha": "0" * 40},
        )
    except GitHubAPIError as exc:
        if exc.status in {403, 404}:
            return
        if exc.status == 422:
            raise CredentialPolicyError("CROSS_REPOSITORY_WRITE_ACCESS_PRESENT") from exc
        raise CredentialPolicyError("UNEXPECTED_CROSS_REPOSITORY_RESULT") from exc
    raise CredentialPolicyError("CROSS_REPOSITORY_WRITE_MUTATION_OCCURRED")
