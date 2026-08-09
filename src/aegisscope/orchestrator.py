"""Control-plane preparation service. Preparation never sends a network request."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aegisscope.config import Settings
from aegisscope.contracts.models import StageManifest
from aegisscope.policy.engine import PolicyDecision, PolicyEngine
from aegisscope.security.integrity import atomic_write_new_text, canonical_sha256
from aegisscope.storage import JobStore


class PreparationError(ValueError):
    pass


class Orchestrator:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.settings.ensure_local_directories()
        self.store = JobStore(self.settings.data_dir / "db" / "aegisscope.sqlite3")

    def validate(self, payload: dict[str, Any]) -> PolicyDecision:
        return PolicyEngine.validate_payload(payload)

    def prepare(self, payload: dict[str, Any]) -> StageManifest:
        decision = self.validate(payload)
        if not decision.allowed or decision.manifest is None:
            raise PreparationError("; ".join(decision.errors))
        manifest = decision.manifest
        job_dir = self.settings.data_dir / "jobs" / manifest.job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = job_dir / "manifest.json"
        canonical = json.dumps(
            manifest.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True
        )
        digest = canonical_sha256(manifest.model_dump(mode="json"))
        digest_path = job_dir / "manifest.sha256"
        existing_job = self.store.get_job(manifest.job_id)
        if existing_job:
            existing_digest = existing_job.get("manifest_sha256") or canonical_sha256(
                existing_job["manifest"]
            )
            if existing_digest != digest:
                raise PreparationError("job_id already exists with a different audit digest")
        if manifest_path.exists() and manifest_path.read_text(encoding="utf-8") != canonical:
            raise PreparationError("job_id already exists with a different manifest")
        if digest_path.exists() and digest_path.read_text(encoding="ascii").strip() != digest:
            raise PreparationError("job_id already exists with a different manifest digest")
        if not manifest_path.exists():
            atomic_write_new_text(manifest_path, canonical)
        if not digest_path.exists():
            atomic_write_new_text(digest_path, f"{digest}\n")
        self.store.upsert_manifest(manifest, manifest_sha256=digest)
        self.store.append_event(
            manifest.job_id,
            "manifest_prepared",
            {"manifest_sha256": digest, "dry_run": manifest.dry_run},
        )
        return manifest

    def prepare_file(self, path: Path) -> StageManifest:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise PreparationError("manifest root must be an object")
        return self.prepare(payload)
