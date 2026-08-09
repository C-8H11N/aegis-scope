"""SQLite persistence for derived imports, analyses, findings, and events."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegisscope.findings.models import Finding
from aegisscope.traffic.models import TrafficAnalysis, TrafficImport


class AnalystStore:
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
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS traffic_imports (
                    import_id TEXT PRIMARY KEY,
                    document_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS traffic_analyses (
                    analysis_id TEXT PRIMARY KEY,
                    document_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    fingerprint TEXT UNIQUE NOT NULL,
                    document_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS finding_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT NOT NULL,
                    from_status TEXT,
                    to_status TEXT NOT NULL,
                    statement TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(finding_id) REFERENCES findings(finding_id)
                );
                """
            )

    def put_import(self, document: TrafficImport) -> None:
        self._insert_document(
            "traffic_imports", "import_id", document.import_id, document.model_dump(mode="json")
        )

    def put_analysis(self, document: TrafficAnalysis) -> None:
        self._insert_document(
            "traffic_analyses",
            "analysis_id",
            document.analysis_id,
            document.model_dump(mode="json"),
        )

    def _insert_document(
        self, table: str, id_column: str, identity: str, payload: dict[str, Any]
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        content = json.dumps(payload, ensure_ascii=False)
        if (table, id_column) == ("traffic_imports", "import_id"):
            select_sql = "SELECT document_json FROM traffic_imports WHERE import_id=?"
            insert_sql = (
                "INSERT INTO traffic_imports(import_id, document_json, created_at) "
                "VALUES (?, ?, ?)"
            )
        elif (table, id_column) == ("traffic_analyses", "analysis_id"):
            select_sql = "SELECT document_json FROM traffic_analyses WHERE analysis_id=?"
            insert_sql = (
                "INSERT INTO traffic_analyses(analysis_id, document_json, created_at) "
                "VALUES (?, ?, ?)"
            )
        else:
            raise ValueError("unsupported immutable document table")
        with self.connect() as connection:
            existing = connection.execute(select_sql, (identity,)).fetchone()
            if existing:
                if existing["document_json"] != content:
                    raise ValueError(f"immutable document conflict: {identity}")
                return
            connection.execute(insert_sql, (identity, content, now))

    def list_imports(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._list_documents("traffic_imports", limit)

    def list_analyses(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._list_documents("traffic_analyses", limit)

    def get_analysis(self, analysis_id: str) -> TrafficAnalysis | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT document_json FROM traffic_analyses WHERE analysis_id=?",
                (analysis_id,),
            ).fetchone()
        return TrafficAnalysis.model_validate_json(row["document_json"]) if row else None

    def _list_documents(self, table: str, limit: int) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 500))
        if table == "traffic_imports":
            query = "SELECT document_json FROM traffic_imports ORDER BY created_at DESC LIMIT ?"
        elif table == "traffic_analyses":
            query = "SELECT document_json FROM traffic_analyses ORDER BY created_at DESC LIMIT ?"
        else:
            raise ValueError("unsupported immutable document table")
        with self.connect() as connection:
            rows = connection.execute(query, (safe_limit,)).fetchall()
        return [json.loads(row["document_json"]) for row in rows]

    def put_finding(self, finding: Finding) -> bool:
        now = finding.updated_at.isoformat()
        payload = json.dumps(finding.model_dump(mode="json"), ensure_ascii=False)
        with self.connect() as connection:
            existing = connection.execute(
                "SELECT finding_id FROM findings WHERE fingerprint=?", (finding.fingerprint,)
            ).fetchone()
            if existing:
                return False
            connection.execute(
                "INSERT INTO findings(finding_id, fingerprint, document_json, updated_at) VALUES (?, ?, ?, ?)",
                (finding.finding_id, finding.fingerprint, payload, now),
            )
            connection.execute(
                "INSERT INTO finding_events(finding_id, from_status, to_status, statement, created_at) VALUES (?, NULL, ?, ?, ?)",
                (finding.finding_id, finding.status.value, "created from offline candidate", now),
            )
        return True

    def update_finding(self, finding: Finding, *, from_status: str, statement: str) -> None:
        now = finding.updated_at.isoformat()
        payload = json.dumps(finding.model_dump(mode="json"), ensure_ascii=False)
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE findings SET document_json=?, updated_at=? WHERE finding_id=?",
                (payload, now, finding.finding_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"unknown finding_id: {finding.finding_id}")
            connection.execute(
                "INSERT INTO finding_events(finding_id, from_status, to_status, statement, created_at) VALUES (?, ?, ?, ?, ?)",
                (finding.finding_id, from_status, finding.status.value, statement, now),
            )

    def get_finding(self, finding_id: str) -> Finding | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT document_json FROM findings WHERE finding_id=?", (finding_id,)
            ).fetchone()
        return Finding.model_validate_json(row["document_json"]) if row else None

    def list_findings(self, limit: int = 100) -> list[Finding]:
        safe_limit = max(1, min(limit, 500))
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT document_json FROM findings ORDER BY updated_at DESC LIMIT ?", (safe_limit,)
            ).fetchall()
        return [Finding.model_validate_json(row["document_json"]) for row in rows]

    def list_events(self, finding_id: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT from_status, to_status, statement, created_at FROM finding_events WHERE finding_id=? ORDER BY event_id",
                (finding_id,),
            ).fetchall()
        return [dict(row) for row in rows]
