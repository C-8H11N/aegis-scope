"""Strict contracts for human-reviewed findings."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegisscope.analysis.models import Confidence, LocalizedText, SeverityHint
from aegisscope.contracts.models import normalize_exact_host


class FindingModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class FindingStatus(StrEnum):
    CANDIDATE = "candidate"
    NEEDS_VALIDATION = "needs_validation"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    ACCEPTED_RISK = "accepted_risk"
    SUBMITTED = "submitted"
    FIXED = "fixed"


REPORTABLE_STATUSES = {
    FindingStatus.CONFIRMED,
    FindingStatus.SUBMITTED,
    FindingStatus.FIXED,
}


class Finding(FindingModel):
    finding_id: str = Field(pattern=r"^finding-[a-f0-9]{16}$")
    source_candidate_id: str
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    program_name: str = Field(min_length=2, max_length=200)
    title: LocalizedText
    host: str
    endpoint_key: str = Field(min_length=5, max_length=2400)
    safe_urls: list[str] = Field(min_length=1, max_length=20)
    status: FindingStatus = FindingStatus.CANDIDATE
    severity_hint: SeverityHint
    confidence: Confidence
    reportable: bool = False
    rationale: LocalizedText
    benign_explanations: list[LocalizedText] = Field(default_factory=list)
    evidence_refs: list[str] = Field(min_length=1)
    impact: str | None = Field(default=None, max_length=4000)
    remediation: str | None = Field(default=None, max_length=4000)
    duplicate_of: str | None = None
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def reportability_matches_status(self) -> Finding:
        expected = self.status in REPORTABLE_STATUSES
        if self.reportable != expected:
            raise ValueError("reportable must be derived from human-reviewed status")
        for value in self.safe_urls:
            parsed = urlsplit(value)
            if (
                parsed.scheme not in {"http", "https"}
                or parsed.hostname is None
                or parsed.username
                or parsed.password
                or parsed.fragment
                or normalize_exact_host(parsed.hostname) != self.host
            ):
                raise ValueError("finding URLs must be safe and match the exact finding host")
        return self

    @field_validator("host")
    @classmethod
    def normalize_host(cls, value: str) -> str:
        return normalize_exact_host(value)

    @field_validator("created_at", "updated_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("finding timestamps must include a timezone")
        return value


class FindingTransition(FindingModel):
    to_status: FindingStatus
    statement: str = Field(min_length=8, max_length=1000)
    impact: str | None = Field(default=None, max_length=4000)
    remediation: str | None = Field(default=None, max_length=4000)
    duplicate_of: str | None = None
