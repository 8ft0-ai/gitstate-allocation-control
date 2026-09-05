from __future__ import annotations

from typing import Mapping

from .operator_manifest import SHA40
from .preflight_carrier_ledger import (
    CONTROL_REPOSITORY,
    LEDGER_PATH,
    PublicCarrierLedgerError,
)


MAX_LEDGER_ONLY_DESCENDANT_COMMITS = 1000


def _require_sha(value: object, reason: str) -> str:
    if not isinstance(value, str) or SHA40.fullmatch(value) is None:
        raise PublicCarrierLedgerError(reason)
    return value


def validate_ledger_only_control_descendant(
    api,
    *,
    projected_control_sha: str,
    trusted_sha: str,
) -> None:
    """Prove current protected main differs from the projected control only by ledger appends.

    Projection publication necessarily precedes its durable ledger binding because
    the ledger record binds the GitHub comment ID and body digest. The ledger
    append therefore advances protected main after the projection has already
    bound its exact B1 executor commit/tree. B2 may bridge that advance only when
    every first-parent commit between the projected control SHA and the current
    dispatched SHA changes exactly the carrier-ledger file. Any other repository
    change invalidates the projection rather than weakening B1 control identity.
    """

    projected_control_sha = _require_sha(
        projected_control_sha,
        "PUBLIC_CARRIER_LEDGER_CONTROL_ANCHOR_INVALID",
    )
    trusted_sha = _require_sha(
        trusted_sha,
        "PUBLIC_CARRIER_LEDGER_TRUSTED_SHA_INVALID",
    )
    if projected_control_sha == trusted_sha:
        return

    cursor = trusted_sha
    seen: set[str] = set()
    for _ in range(MAX_LEDGER_ONLY_DESCENDANT_COMMITS):
        if cursor == projected_control_sha:
            return
        if cursor in seen:
            raise PublicCarrierLedgerError(
                "PUBLIC_CARRIER_LEDGER_CONTROL_HISTORY_AMBIGUOUS"
            )
        seen.add(cursor)

        payload = api.get(f"/repos/{CONTROL_REPOSITORY}/commits/{cursor}")
        if not isinstance(payload, Mapping) or payload.get("sha") != cursor:
            raise PublicCarrierLedgerError(
                "PUBLIC_CARRIER_LEDGER_CONTROL_HISTORY_AMBIGUOUS"
            )

        files = payload.get("files")
        if not isinstance(files, list) or len(files) != 1:
            raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_CONTROL_DRIFT")
        changed = files[0]
        if (
            not isinstance(changed, Mapping)
            or changed.get("filename") != LEDGER_PATH
            or changed.get("status") != "modified"
        ):
            raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_CONTROL_DRIFT")

        parents = payload.get("parents")
        if not isinstance(parents, list) or not parents:
            raise PublicCarrierLedgerError(
                "PUBLIC_CARRIER_LEDGER_CONTROL_ANCHOR_NOT_REACHED"
            )
        first_parent = parents[0]
        parent_sha = first_parent.get("sha") if isinstance(first_parent, Mapping) else None
        cursor = _require_sha(
            parent_sha,
            "PUBLIC_CARRIER_LEDGER_CONTROL_HISTORY_AMBIGUOUS",
        )

    raise PublicCarrierLedgerError("PUBLIC_CARRIER_LEDGER_CONTROL_HISTORY_TOO_DEEP")
