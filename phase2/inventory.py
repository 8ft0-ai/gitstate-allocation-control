from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


class InventoryError(RuntimeError):
    pass


@dataclass(frozen=True)
class InventoryAttestation:
    app_id: int
    installation_id: int
    repository_selection: str
    repository_ids: tuple[int, ...]
    audited_at: datetime
    invalidated: bool = False

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "InventoryAttestation":
        try:
            audited_at = datetime.fromisoformat(value["audited_at"].replace("Z", "+00:00"))
            return cls(
                app_id=int(value["app_id"]),
                installation_id=int(value["installation_id"]),
                repository_selection=str(value["repository_selection"]),
                repository_ids=tuple(int(item) for item in value["repository_ids"]),
                audited_at=audited_at,
                invalidated=bool(value.get("invalidated", False)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise InventoryError("INVALID_ATTESTATION") from exc

    def validate(self, *, app_id: int, installation_id: int, expected_repository_ids: set[int], now: datetime, max_age_seconds: int) -> None:
        if self.invalidated:
            raise InventoryError("INVALIDATED_ATTESTATION")
        if self.app_id != app_id or self.installation_id != installation_id:
            raise InventoryError("ATTESTATION_IDENTITY_MISMATCH")
        if self.repository_selection != "selected":
            raise InventoryError("INVALID_REPOSITORY_SELECTION")
        if set(self.repository_ids) != expected_repository_ids or len(self.repository_ids) != len(expected_repository_ids):
            raise InventoryError("REPOSITORY_INVENTORY_MISMATCH")
        if self.audited_at.tzinfo is None:
            raise InventoryError("UNZONED_AUDIT_TIME")
        age = (now.astimezone(timezone.utc) - self.audited_at.astimezone(timezone.utc)).total_seconds()
        if age < 0 or age > max_age_seconds:
            raise InventoryError("STALE_ATTESTATION")

