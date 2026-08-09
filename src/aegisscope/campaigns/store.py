"""SQLite persistence and append-only events for research campaigns."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegisscope.campaigns.models import Campaign


class CampaignStore:
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
                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    document_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS campaign_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(campaign_id) REFERENCES campaigns(campaign_id)
                );
                """
            )

    def create(self, campaign: Campaign) -> None:
        payload = json.dumps(campaign.model_dump(mode="json"), ensure_ascii=False)
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO campaigns(campaign_id, document_json, created_at, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    campaign.campaign_id,
                    payload,
                    campaign.created_at.isoformat(),
                    campaign.updated_at.isoformat(),
                ),
            )
            self._append_event_with_connection(
                connection,
                campaign.campaign_id,
                "campaign_created",
                {"target_host": campaign.target_host},
            )

    def update(
        self,
        campaign: Campaign,
        *,
        event_type: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        payload = json.dumps(campaign.model_dump(mode="json"), ensure_ascii=False)
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE campaigns SET document_json=?, updated_at=? WHERE campaign_id=?",
                (payload, campaign.updated_at.isoformat(), campaign.campaign_id),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"unknown campaign_id: {campaign.campaign_id}")
            self._append_event_with_connection(
                connection, campaign.campaign_id, event_type, details or {}
            )

    def get(self, campaign_id: str) -> Campaign | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT document_json FROM campaigns WHERE campaign_id=?", (campaign_id,)
            ).fetchone()
        return Campaign.model_validate_json(row["document_json"]) if row else None

    def list(self, limit: int = 100) -> list[Campaign]:
        safe_limit = max(1, min(limit, 500))
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT document_json FROM campaigns ORDER BY updated_at DESC LIMIT ?",
                (safe_limit,),
            ).fetchall()
        return [Campaign.model_validate_json(row["document_json"]) for row in rows]

    def list_events(self, campaign_id: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT event_type, details_json, created_at FROM campaign_events "
                "WHERE campaign_id=? ORDER BY event_id",
                (campaign_id,),
            ).fetchall()
        return [
            {
                "event_type": row["event_type"],
                "details": json.loads(row["details_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    @staticmethod
    def _append_event_with_connection(
        connection: sqlite3.Connection,
        campaign_id: str,
        event_type: str,
        details: dict[str, Any],
    ) -> None:
        connection.execute(
            "INSERT INTO campaign_events(campaign_id, event_type, details_json, created_at) "
            "VALUES (?, ?, ?, ?)",
            (
                campaign_id,
                event_type,
                json.dumps(details, ensure_ascii=False),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
