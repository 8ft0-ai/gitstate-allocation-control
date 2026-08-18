from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from .github_api import GitHubAPI


CONTROL_REPOSITORY_ID = 1321106380
STATE_REPOSITORY_ID = 1317964582
EXPECTED_REPOSITORY_IDS = tuple(sorted((CONTROL_REPOSITORY_ID, STATE_REPOSITORY_ID)))
INVENTORY_PERMISSIONS = {"metadata": "read"}
MAX_INVENTORY_PAGES = 100


class InventoryProofError(RuntimeError):
    pass


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def inventory_token_request() -> dict[str, Any]:
    # The absence of repositories/repository_ids is deliberate: this one token
    # must see the complete installation selection so administrative drift
    # cannot be hidden by repository narrowing.
    return {"permissions": dict(INVENTORY_PERMISSIONS)}


def validate_inventory_token_response(response: Mapping[str, Any]) -> str:
    token = response.get("token")
    permissions = response.get("permissions")
    repository_selection = response.get("repository_selection")
    if not isinstance(token, str) or not token:
        raise InventoryProofError("INVENTORY_TOKEN_MISSING")
    if permissions != INVENTORY_PERMISSIONS:
        raise InventoryProofError("INVENTORY_TOKEN_PERMISSION_MISMATCH")
    if repository_selection != "selected":
        raise InventoryProofError("INVENTORY_TOKEN_SELECTION_MISMATCH")
    return token


def _list_complete_repository_ids(api: GitHubAPI) -> tuple[int, ...]:
    repository_ids: list[int] = []
    seen: set[int] = set()
    expected_total: int | None = None

    for page in range(1, MAX_INVENTORY_PAGES + 1):
        payload = api.get(f"/installation/repositories?per_page=100&page={page}")
        if not isinstance(payload, dict):
            raise InventoryProofError("INVENTORY_RESPONSE_INVALID")
        total_count = payload.get("total_count")
        repositories = payload.get("repositories")
        if not isinstance(total_count, int) or total_count < 0 or not isinstance(repositories, list):
            raise InventoryProofError("INVENTORY_RESPONSE_INVALID")
        if expected_total is None:
            expected_total = total_count
        elif total_count != expected_total:
            raise InventoryProofError("INVENTORY_CHANGED_DURING_PAGINATION")

        for repository in repositories:
            if not isinstance(repository, dict):
                raise InventoryProofError("INVENTORY_REPOSITORY_INVALID")
            repository_id = repository.get("id")
            if not isinstance(repository_id, int) or repository_id <= 0:
                raise InventoryProofError("INVENTORY_REPOSITORY_INVALID")
            if repository_id in seen:
                raise InventoryProofError("INVENTORY_DUPLICATE_REPOSITORY")
            seen.add(repository_id)
            repository_ids.append(repository_id)

        if len(repository_ids) > expected_total:
            raise InventoryProofError("INVENTORY_COUNT_MISMATCH")
        if len(repository_ids) == expected_total:
            break
        if len(repositories) < 100:
            raise InventoryProofError("INVENTORY_PAGINATION_INCOMPLETE")
    else:
        raise InventoryProofError("INVENTORY_PAGINATION_EXCESSIVE")

    if expected_total is None or len(repository_ids) != expected_total:
        raise InventoryProofError("INVENTORY_PAGINATION_INCOMPLETE")
    return tuple(sorted(repository_ids))


@dataclass(frozen=True)
class InventoryEvidence:
    app_id: int
    installation_id: int
    repository_selection: str
    repository_ids: tuple[int, ...]
    audited_at: str
    run_id: int
    run_attempt: int
    trusted_sha: str
    capsule_id: str
    capsule_body_sha256: str
    inventory_token_permissions: dict[str, str]
    token_revoked: bool
    digest: str

    def payload(self) -> dict[str, Any]:
        return {
            "app_id": self.app_id,
            "installation_id": self.installation_id,
            "repository_selection": self.repository_selection,
            "repository_ids": list(self.repository_ids),
            "repository_count": len(self.repository_ids),
            "audited_at": self.audited_at,
            "run_id": self.run_id,
            "run_attempt": self.run_attempt,
            "trusted_sha": self.trusted_sha,
            "capsule_id": self.capsule_id,
            "capsule_body_sha256": self.capsule_body_sha256,
            "inventory_token_permissions": dict(self.inventory_token_permissions),
            "token_revoked": self.token_revoked,
            "inventory_evidence_sha256": self.digest,
        }


def prove_installation_inventory(
    app_api: GitHubAPI,
    *,
    installation_id: int,
    app_id: int,
    repository_selection: str,
    run_id: int,
    run_attempt: int,
    trusted_sha: str,
    capsule_id: str,
    capsule_body_sha256: str,
    api_url: str,
    api_factory: Callable[[str, str], GitHubAPI] = GitHubAPI,
    now: datetime | None = None,
) -> InventoryEvidence:
    if repository_selection != "selected":
        raise InventoryProofError("INVENTORY_INSTALLATION_NOT_SELECTED")
    request = inventory_token_request()
    if set(request) != {"permissions"} or request["permissions"] != INVENTORY_PERMISSIONS:
        raise InventoryProofError("INVENTORY_TOKEN_REQUEST_WIDENED")

    response = app_api.post(
        f"/app/installations/{installation_id}/access_tokens",
        request,
    )
    if not isinstance(response, dict):
        raise InventoryProofError("INVENTORY_TOKEN_RESPONSE_INVALID")

    # Once GitHub has returned a token, every later validation/enumeration path
    # must attempt positive revocation, including a broader-than-requested
    # permission response. A malformed response with no usable token cannot be
    # revoked and therefore fails immediately.
    token = response.get("token")
    if not isinstance(token, str) or not token:
        raise InventoryProofError("INVENTORY_TOKEN_MISSING")
    inventory_api = api_factory(token, api_url)
    token = ""

    primary_error: Exception | None = None
    repository_ids: tuple[int, ...] | None = None
    try:
        validate_inventory_token_response(response)
        repository_ids = _list_complete_repository_ids(inventory_api)
        if repository_ids != EXPECTED_REPOSITORY_IDS:
            raise InventoryProofError("INVENTORY_EXACT_SET_MISMATCH")
        if len(repository_ids) != 2:
            raise InventoryProofError("INVENTORY_COUNT_MISMATCH")
    except Exception as exc:
        primary_error = exc

    try:
        _, _, status = inventory_api.request_with_status(
            "DELETE", "/installation/token"
        )
        if status != 204:
            raise InventoryProofError("INVENTORY_TOKEN_REVOCATION_STATUS_INVALID")
    except Exception as exc:
        raise InventoryProofError("INVENTORY_TOKEN_REVOCATION_FAILED") from (
            primary_error or exc
        )

    if primary_error is not None:
        raise primary_error
    if repository_ids is None:
        raise InventoryProofError("INVENTORY_EVIDENCE_MISSING")

    audited = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    base: dict[str, Any] = {
        "app_id": app_id,
        "installation_id": installation_id,
        "repository_selection": repository_selection,
        "repository_ids": list(repository_ids),
        "repository_count": len(repository_ids),
        "audited_at": audited.isoformat().replace("+00:00", "Z"),
        "run_id": run_id,
        "run_attempt": run_attempt,
        "trusted_sha": trusted_sha,
        "capsule_id": capsule_id,
        "capsule_body_sha256": capsule_body_sha256,
        "inventory_token_permissions": dict(INVENTORY_PERMISSIONS),
        "token_revoked": True,
    }
    digest = _digest(base)
    return InventoryEvidence(
        app_id=app_id,
        installation_id=installation_id,
        repository_selection=repository_selection,
        repository_ids=repository_ids,
        audited_at=str(base["audited_at"]),
        run_id=run_id,
        run_attempt=run_attempt,
        trusted_sha=trusted_sha,
        capsule_id=capsule_id,
        capsule_body_sha256=capsule_body_sha256,
        inventory_token_permissions=dict(INVENTORY_PERMISSIONS),
        token_revoked=True,
        digest=digest,
    )
