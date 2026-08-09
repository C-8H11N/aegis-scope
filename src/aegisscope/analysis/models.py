"""Strict contracts for offline vulnerability-candidate analysis."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class AnalysisModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CandidateKind(StrEnum):
    VULNERABILITY_CANDIDATE = "vulnerability_candidate"
    SECURITY_OBSERVATION = "security_observation"
    SAFETY_STOP = "safety_stop"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SeverityHint(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class LocalizedText(AnalysisModel):
    zh_cn: str = Field(min_length=1, max_length=1000)
    en: str = Field(min_length=1, max_length=1000)


class VerificationPlan(AnalysisModel):
    network_required: bool
    new_authorization_required: bool
    steps: list[LocalizedText] = Field(min_length=1, max_length=8)
    stop_conditions: list[LocalizedText] = Field(min_length=1, max_length=8)


class VulnerabilityCandidate(AnalysisModel):
    candidate_id: str = Field(pattern=r"^cand-[a-f0-9]{16}$")
    rule_id: str = Field(pattern=r"^[a-z0-9_]{3,80}$")
    kind: CandidateKind
    title: LocalizedText
    category: str = Field(min_length=2, max_length=100)
    severity_hint: SeverityHint
    confidence: Confidence
    risk_score: int = Field(ge=0, le=100)
    affected_url: str
    evidence_files: list[str] = Field(min_length=1, max_length=20)
    rationale: LocalizedText
    benign_explanations: list[LocalizedText] = Field(default_factory=list, max_length=8)
    verification: VerificationPlan
    reportable: bool = False


class EvidenceAnalysis(AnalysisModel):
    schema_version: int = 1
    job_id: str
    target_host: str
    generated_at: datetime
    source_summary_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    evidence_integrity: str
    automatically_verified_findings: int = 0
    candidate_count: int = Field(ge=0)
    observation_count: int = Field(ge=0)
    safety_stop_count: int = Field(ge=0)
    candidates: list[VulnerabilityCandidate] = Field(default_factory=list)
    limitations: list[LocalizedText] = Field(default_factory=list)
