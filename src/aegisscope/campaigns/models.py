"""Strict contracts for bounded, offline-first research campaigns.

A campaign can prioritize hypotheses and prepare an unapproved stage proposal. It cannot
authorize or dispatch target traffic. Network authorization remains a separate StageManifest.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegisscope.analysis.models import Confidence, LocalizedText
from aegisscope.contracts.models import StageProposal, normalize_exact_host


class CampaignModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class CampaignStatus(StrEnum):
    READY = "ready"
    PLANNING = "planning"
    AWAITING_STAGE_AUTHORIZATION = "awaiting_stage_authorization"
    MANUAL_REVIEW = "manual_review"
    COMPLETED = "completed"
    STOPPED = "stopped"
    BUDGET_EXHAUSTED = "budget_exhausted"


class HypothesisKind(StrEnum):
    BASELINE_COVERAGE = "baseline_coverage"
    AUTHORIZATION_BOUNDARY = "authorization_boundary"
    SENSITIVE_FIELD_EXPOSURE = "sensitive_field_exposure"
    VERBOSE_ERROR = "verbose_error"
    SECURITY_OBSERVATION = "security_observation"


class HypothesisStatus(StrEnum):
    QUEUED = "queued"
    PROPOSED = "proposed"
    MANUAL_REVIEW = "manual_review"
    SUPPORTED = "supported"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    EXHAUSTED = "exhausted"


class NextActionKind(StrEnum):
    AUTHORIZE_STAGE = "authorize_stage"
    MANUAL_REVIEW = "manual_review"
    IMPORT_TRAFFIC = "import_traffic"
    NONE = "none"


class CampaignBudget(CampaignModel):
    max_stages: int = Field(default=5, ge=1, le=10)
    max_total_requests: int = Field(default=50, ge=1, le=100)
    used_stages: int = Field(default=0, ge=0, le=10)
    used_requests: int = Field(default=0, ge=0, le=100)

    @model_validator(mode="after")
    def validate_consumption(self) -> CampaignBudget:
        if self.used_stages > self.max_stages:
            raise ValueError("used_stages cannot exceed max_stages")
        if self.used_requests > self.max_total_requests:
            raise ValueError("used_requests cannot exceed max_total_requests")
        return self


class CampaignCreateRequest(CampaignModel):
    program_name: str = Field(min_length=2, max_length=200)
    target_host: str
    allowlist: list[str] = Field(min_length=1, max_length=100)
    denylist: list[str] = Field(default_factory=list, max_length=100)
    objective: str = Field(min_length=8, max_length=2000)
    max_stages: int = Field(default=5, ge=1, le=10)
    max_total_requests: int = Field(default=50, ge=1, le=100)

    @field_validator("target_host")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        return normalize_exact_host(value)

    @field_validator("allowlist", "denylist")
    @classmethod
    def normalize_lists(cls, values: list[str]) -> list[str]:
        normalized = [normalize_exact_host(value) for value in values]
        if len(normalized) != len(set(normalized)):
            raise ValueError("campaign scope lists cannot contain duplicates")
        return normalized

    @model_validator(mode="after")
    def enforce_exact_scope(self) -> CampaignCreateRequest:
        if self.target_host not in self.allowlist:
            raise ValueError("campaign target must be explicitly allowlisted")
        if self.target_host in self.denylist:
            raise ValueError("campaign target is denied")
        return self


class CampaignPlanRequest(CampaignModel):
    analysis_ids: list[str] = Field(default_factory=list, max_length=20)


class CampaignDecisionRequest(CampaignModel):
    hypothesis_id: str = Field(pattern=r"^hyp-[a-f0-9]{16}$")
    disposition: Literal["supported", "rejected", "duplicate", "exhausted"]
    statement: str = Field(min_length=8, max_length=1000)
    consumed_requests: int = Field(default=0, ge=0, le=20)


class CampaignHypothesis(CampaignModel):
    hypothesis_id: str = Field(pattern=r"^hyp-[a-f0-9]{16}$")
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    kind: HypothesisKind
    status: HypothesisStatus
    title: LocalizedText
    host: str
    safe_urls: list[str] = Field(default_factory=list, max_length=20)
    source_refs: list[str] = Field(default_factory=list, max_length=100)
    confidence: Confidence
    risk_score: int = Field(ge=0, le=100)
    novelty_score: int = Field(ge=0, le=100)
    evidence_score: int = Field(ge=0, le=100)
    estimated_request_cost: int = Field(ge=0, le=20)
    priority_score: int = Field(ge=0, le=100)
    rationale: LocalizedText
    next_step: LocalizedText
    requires_manual_tools: bool
    proposal: StageProposal | None = None

    @field_validator("host")
    @classmethod
    def normalize_host(cls, value: str) -> str:
        return normalize_exact_host(value)

    @model_validator(mode="after")
    def validate_urls_and_action(self) -> CampaignHypothesis:
        for url in self.safe_urls:
            parsed = urlsplit(url)
            if (
                parsed.scheme not in {"http", "https"}
                or parsed.hostname is None
                or parsed.username
                or parsed.password
                or parsed.fragment
                or normalize_exact_host(parsed.hostname) != self.host
            ):
                raise ValueError("hypothesis URLs must be safe and match the exact host")
        if self.proposal and self.proposal.target_host != self.host:
            raise ValueError("proposal target must match hypothesis host")
        if self.status == HypothesisStatus.PROPOSED and self.proposal is None:
            raise ValueError("proposed hypotheses require a stage proposal")
        if self.requires_manual_tools and self.proposal is not None:
            raise ValueError("manual-only hypotheses cannot contain a network proposal")
        return self


class CampaignNextAction(CampaignModel):
    kind: NextActionKind
    hypothesis_id: str | None = Field(default=None, pattern=r"^hyp-[a-f0-9]{16}$")
    title: LocalizedText
    explanation: LocalizedText
    proposal_id: str | None = None
    network_executed: Literal[False] = False


class Campaign(CampaignModel):
    schema_version: Literal[1] = 1
    campaign_id: str = Field(pattern=r"^campaign-[a-f0-9]{16}$")
    program_name: str = Field(min_length=2, max_length=200)
    objective: str = Field(min_length=8, max_length=2000)
    status: CampaignStatus
    target_host: str
    allowlist: list[str] = Field(min_length=1, max_length=100)
    denylist: list[str] = Field(default_factory=list, max_length=100)
    budget: CampaignBudget
    source_analysis_ids: list[str] = Field(default_factory=list, max_length=20)
    hypotheses: list[CampaignHypothesis] = Field(default_factory=list, max_length=200)
    next_action: CampaignNextAction
    created_at: datetime
    updated_at: datetime
    target_execution_authorized: Literal[False] = False
    network_execution_enabled: Literal[False] = False
    automatically_verified_findings: Literal[0] = 0

    @field_validator("target_host")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        return normalize_exact_host(value)

    @field_validator("allowlist", "denylist")
    @classmethod
    def normalize_scope(cls, values: list[str]) -> list[str]:
        normalized = [normalize_exact_host(value) for value in values]
        if len(normalized) != len(set(normalized)):
            raise ValueError("campaign scope lists cannot contain duplicates")
        return normalized

    @field_validator("created_at", "updated_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("campaign timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def enforce_campaign_boundary(self) -> Campaign:
        if self.target_host not in self.allowlist or self.target_host in self.denylist:
            raise ValueError("campaign target is outside its exact scope")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot be before created_at")
        if any(item.host != self.target_host for item in self.hypotheses):
            raise ValueError("all hypotheses must match the exact campaign target")
        return self
