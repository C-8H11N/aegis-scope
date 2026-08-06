"""Machine-readable runner results."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ResultModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class StageStatus(StrEnum):
    DRY_RUN = "dry_run"
    COMPLETED = "completed"
    STOPPED = "stopped"
    FAILED = "failed"


class RequestResult(ResultModel):
    index: int = Field(ge=1)
    method: str
    url: str
    status_code: int | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    response_bytes: int = Field(default=0, ge=0)
    body_sha256: str | None = None
    evidence_files: list[str] = Field(default_factory=list)
    stop_reason: str | None = None
    error: str | None = None


class StageSummary(ResultModel):
    schema_version: int = 1
    job_id: str
    target_host: str
    stage_status: StageStatus
    dry_run: bool
    started_at: datetime
    ended_at: datetime
    actual_requests: int = Field(ge=0)
    stop_reason: str | None = None
    results: list[RequestResult] = Field(default_factory=list)
