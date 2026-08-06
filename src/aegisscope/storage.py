"""SQLite-backed control-plane audit storage."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegisscope.contracts.models import StageManifest


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
                    summary_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    def upsert_manifest(self, manifest: StageManifest, *, status: str = "prepared") -> None:
        now = datetime.now(timezone.utc).isoformat()
        manifest_json = json.dumps(manifest.model_dump(mode="json"), ensure_ascii=False)
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO jobs(job_id, status, manifest_json, summary_json, created_at, updated_at)
                VALUES (?, ?, ?, NULL, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    status=excluded.status,
                    manifest_json=excluded.manifest_json,
                    updated_at=excluded.updated_at
                """,
                (manifest.job_id, status, manifest_json, now, now),
            )

    def set_summary(self, job_id: str, status: str, summary: dict[str, Any]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE jobs SET status=?, summary_json=?, updated_at=? WHERE job_id=?",
                (status, json.dumps(summary, ensure_ascii=False), now, job_id),
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
        return result
