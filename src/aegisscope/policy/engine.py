"""Shared deterministic policy gate used on both ends."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from aegisscope.contracts.models import StageManifest


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: bool
    errors: list[str]
    warnings: list[str]
    manifest: StageManifest | None = None


class PolicyEngine:
    """Reject malformed, expired, unauthorized, or out-of-scope manifests."""

    @staticmethod
    def validate_payload(
        payload: dict[str, Any], *, now: datetime | None = None
    ) -> PolicyDecision:
        errors: list[str] = []
        warnings: list[str] = []
        try:
            manifest = StageManifest.model_validate(payload)
        except ValidationError as exc:
            for item in exc.errors(include_url=False):
                location = ".".join(str(part) for part in item["loc"])
                errors.append(f"{location}: {item['msg']}")
            return PolicyDecision(allowed=False, errors=errors, warnings=warnings)

        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None or current.utcoffset() is None:
            current = current.replace(tzinfo=timezone.utc)
        if current >= manifest.expires_at:
            errors.append("manifest has expired")
        if current >= manifest.authorization.expires_at:
            errors.append("stage authorization has expired")
        if manifest.authorization.granted_at > current:
            errors.append("authorization granted_at is in the future")
        if manifest.created_at > current:
            errors.append("manifest created_at is in the future")
        if not manifest.dry_run:
            warnings.append("network-enabled manifest; runner still requires --execute")

        return PolicyDecision(
            allowed=not errors,
            errors=errors,
            warnings=warnings,
            manifest=manifest if not errors else None,
        )
