from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .parser import ParsedRequest


class AuthorisationError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


def load_policy(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        policy = json.load(handle)
    if policy.get("version") != 1:
        raise AuthorisationError("INVALID_POLICY_VERSION")
    return policy


@dataclass(frozen=True)
class Principal:
    actor_id: int
    actor_login: str
    actor_type: str
    app_id: int | None = None
    app_slug: str | None = None
    installation_id: int | None = None

    def encode(self) -> str:
        base = f"{self.actor_type}:{self.actor_id}:{self.actor_login}"
        if self.app_id is not None:
            return f"{base}:app:{self.app_id}:{self.app_slug}:{self.installation_id}"
        return base


def authorise(comment: dict[str, Any], parsed: ParsedRequest, policy: dict[str, Any]) -> Principal:
    user = comment.get("user") or {}
    login = user.get("login")
    actor_id = user.get("id")
    actor_type = user.get("type")
    if not isinstance(login, str) or not isinstance(actor_id, int) or actor_type not in {"User", "Bot"}:
        raise AuthorisationError("AGENT_NOT_AUTHORISED", "invalid actor")
    agent_id = parsed.payload["agent_id"]
    if actor_type == "User":
        allowed = next(
            (
                entry
                for entry in policy.get("principals", [])
                if entry.get("actor_login") == login and entry.get("actor_type") == "User"
            ),
            None,
        )
        operator = login in policy.get("operators", [])
        prefixes = [] if allowed is None else list(allowed.get("agent_prefixes", []))
        if operator:
            prefixes.append(f"agent://operator/{login}/session/")
        if not any(agent_id.startswith(prefix) for prefix in prefixes):
            raise AuthorisationError("AGENT_NOT_AUTHORISED", "human namespace mismatch")
        return Principal(actor_id, login, actor_type)
    app = comment.get("performed_via_github_app")
    if not isinstance(app, dict):
        raise AuthorisationError("AGENT_NOT_AUTHORISED", "missing App attribution")
    entry = next(
        (
            item
            for item in policy.get("github_apps", [])
            if item.get("actor_login") == login and item.get("actor_id") == actor_id
        ),
        None,
    )
    if entry is None:
        raise AuthorisationError("AGENT_NOT_AUTHORISED", "unknown bot")
    if app.get("id") != entry.get("app_id") or app.get("slug") != entry.get("app_slug"):
        raise AuthorisationError("AGENT_NOT_AUTHORISED", "App attribution mismatch")
    if not agent_id.startswith(entry["agent_prefix"]):
        raise AuthorisationError("AGENT_NOT_AUTHORISED", "App namespace mismatch")
    return Principal(
        actor_id,
        login,
        actor_type,
        app_id=entry["app_id"],
        app_slug=entry["app_slug"],
        installation_id=entry["installation_id"],
    )

