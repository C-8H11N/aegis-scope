"""SQLite-backed control-plane audit storage."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegisscope.contracts.models import StageManifest
from aegisscope.security.integrity import canonical_sha256


class JobStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    manifest_sha256 TEXT,
                    summary_json TEXT,
                    summary_sha256 TEXT,
                    analysis_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(jobs)").fetchall()
            }
            if "manifest_sha256" not in columns:
                connection.execute("ALTER TABLE jobs ADD COLUMN manifest_sha256 TEXT")
            if "analysis_json" not in columns:
                connection.execute("ALTER TABLE jobs ADD COLUMN analysis_json TEXT")
            if "summary_sha256" not in columns:
                connection.execute("ALTER TABLE jobs ADD COLUMN summary_sha256 TEXT")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(job_id) REFERENCES jobs(job_id)
                )
                """
            )

    def upsert_manifest(
        self,
        manifest: StageManifest,
        *,
        status: str = "prepared",
        manifest_sha256: str | None = None,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        manifest_json = json.dumps(manifest.model_dump(mode="json"), ensure_ascii=False)
        digest = manifest_sha256 or canonical_sha256(manifest.model_dump(mode="json"))
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO jobs(
                    job_id, status, manifest_json, manifest_sha256,
                    summary_json, summary_sha256, analysis_json, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, NULL, NULL, NULL, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    manifest_json=excluded.manifest_json,
                    manifest_sha256=excluded.manifest_sha256,
                    updated_at=excluded.updated_at
                """,
                (manifest.job_id, status, manifest_json, digest, now, now),
            )

    def set_status(self, job_id: str, status: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE jobs SET status=?, updated_at=? WHERE job_id=?",
                (status, now, job_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"unknown job_id: {job_id}")

    def append_event(
        self, job_id: str, event_type: str, details: dict[str, Any] | None = None
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO audit_events(job_id, event_type, details_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (job_id, event_type, json.dumps(details or {}, ensure_ascii=False), now),
            )

    def set_summary(
        self,
        job_id: str,
        status: str,
        summary: dict[str, Any],
        *,
        summary_sha256: str | None = None,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        if summary_sha256 is not None and (
            len(summary_sha256) != 64
            or any(value not in "0123456789abcdef" for value in summary_sha256)
        ):
            raise ValueError("summary_sha256 must be a lowercase SHA-256 digest")
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE jobs SET status=?, summary_json=?, summary_sha256=?, updated_at=? "
                "WHERE job_id=?",
                (
                    status,
                    json.dumps(summary, ensure_ascii=False),
                    summary_sha256,
                    now,
                    job_id,
                ),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"unknown job_id: {job_id}")

    def set_analysis(self, job_id: str, analysis: dict[str, Any]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE jobs SET analysis_json=?, updated_at=? WHERE job_id=?",
                (json.dumps(analysis, ensure_ascii=False), now, job_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"unknown job_id: {job_id}")

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        return self._decode_row(row) if row else None

    def list_jobs(self, limit: int = 100) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 500))
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM jobs ORDER BY updated_at DESC LIMIT ?", (safe_limit,)
            ).fetchall()
        return [self._decode_row(row) for row in rows]

    @staticmethod
    def _decode_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["manifest"] = json.loads(result.pop("manifest_json"))
        summary_json = result.pop("summary_json")
        result["summary"] = json.loads(summary_json) if summary_json else None
        analysis_json = result.pop("analysis_json", None)
        result["analysis"] = json.loads(analysis_json) if analysis_json else None
        return result
