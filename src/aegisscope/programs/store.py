"""SQLite persistence for immutable structured program-rule snapshots."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from aegisscope.programs.models import ProgramSpec


class ProgramStore:
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
                CREATE TABLE IF NOT EXISTS program_specs (
                    spec_id TEXT PRIMARY KEY,
                    document_json TEXT NOT NULL,
                    source_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_program_specs_source "
                "ON program_specs(source_sha256)"
            )

    def create(self, spec: ProgramSpec) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO program_specs(spec_id, document_json, source_sha256, created_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    spec.spec_id,
                    spec.model_dump_json(),
                    spec.source_sha256,
                    spec.created_at.isoformat(),
                ),
            )

    def get(self, spec_id: str) -> ProgramSpec | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT document_json FROM program_specs WHERE spec_id=?", (spec_id,)
            ).fetchone()
        return ProgramSpec.model_validate_json(row["document_json"]) if row else None

    def get_by_source_sha256(self, source_sha256: str) -> ProgramSpec | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT document_json FROM program_specs WHERE source_sha256=?",
                (source_sha256,),
            ).fetchone()
        return ProgramSpec.model_validate_json(row["document_json"]) if row else None

    def list(self, limit: int = 100) -> list[ProgramSpec]:
        safe_limit = max(1, min(limit, 500))
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT document_json FROM program_specs ORDER BY created_at DESC LIMIT ?",
                (safe_limit,),
            ).fetchall()
        return [ProgramSpec.model_validate_json(row["document_json"]) for row in rows]
