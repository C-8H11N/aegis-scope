"""Strict contracts for redacted, offline traffic intelligence."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegisscope.analysis.models import Confidence, LocalizedText, SeverityHint
from aegisscope.contracts.models import normalize_exact_host
from aegisscope.security.redaction import SENSITIVE_HEADER_NAMES, redact_text


class TrafficModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class TrafficSourceKind(StrEnum):
    HAR = "har"
    BURP_XML = "burp_xml"


class TrafficRecord(TrafficModel):
    record_id: str = Field(pattern=r"^req-[a-f0-9]{16}$")
    method: str = Field(pattern=r"^[A-Z]{2,12}$")
    host: str
    safe_url: str = Field(min_length=9, max_length=2048)
    normalized_path: str = Field(min_length=1, max_length=1024)
    endpoint_key: str = Field(min_length=5, max_length=2400)
    original_url_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    role_hint: str = Field(min_length=1, max_length=40)
    authentication_markers: list[str] = Field(default_factory=list, max_length=8)
    request_parameter_names: list[str] = Field(default_factory=list, max_length=100)
    response_status: int | None = Field(default=None, ge=100, le=599)
    response_bytes: int = Field(default=0, ge=0, le=100_000_000)
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    response_json_fields: list[str] = Field(default_factory=list, max_length=200)
    response_json_shape_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    response_preview: str = Field(default="", max_length=8192)
    redaction_hits: list[str] = Field(default_factory=list, max_length=50)
    captured_at: datetime | None = None

    @field_validator("host")
    @classmethod
    def normalize_host(cls, value: str) -> str:
        return normalize_exact_host(value)

    @field_validator("captured_at")
    @classmethod
    def require_capture_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("captured_at must include a timezone")
        return value

    @model_validator(mode="after")
    def require_consistent_safe_url(self) -> TrafficRecord:
        parsed = urlsplit(self.safe_url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
            raise ValueError("safe_url must be an HTTP(S) URL")
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError("safe_url cannot contain credentials or a fragment")
        if normalize_exact_host(parsed.hostname) != self.host:
            raise ValueError("safe_url host must match record host")
        if any(value != "<REDACTED>" for _name, value in parse_qsl(parsed.query)):
            raise ValueError("safe_url query values must already be redacted")
        if redact_text(parsed.path)[0] != parsed.path:
            raise ValueError("safe_url path contains unredacted sensitive data")
        if not self.endpoint_key.startswith(f"{self.method} {self.host} "):
            raise ValueError("endpoint_key must match method and host")
        if redact_text(self.response_preview)[0] != self.response_preview:
            raise ValueError("response_preview contains unredacted sensitive data")
        for name, value in self.response_headers.items():
            if name.lower() in SENSITIVE_HEADER_NAMES and value != "<REDACTED>":
                raise ValueError("response headers contain an unredacted sensitive header")
            if redact_text(value)[0] != value:
                raise ValueError("response headers contain unredacted sensitive data")
        return self


class TrafficImport(TrafficModel):
    schema_version: Literal[1] = 1
    import_id: str = Field(pattern=r"^traffic-[a-f0-9]{16}$")
    program_name: str = Field(min_length=2, max_length=200)
    source_kind: TrafficSourceKind
    source_name: str = Field(min_length=1, max_length=255)
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    role_hint: str = Field(min_length=1, max_length=40)
    allowlist: list[str] = Field(min_length=1, max_length=100)
    denylist: list[str] = Field(default_factory=list, max_length=100)
    imported_at: datetime
    record_count: int = Field(ge=0, le=5000)
    skipped_out_of_scope: int = Field(ge=0)
    skipped_invalid: int = Field(ge=0)
    records: list[TrafficRecord] = Field(default_factory=list, max_length=5000)
    warnings: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("allowlist", "denylist")
    @classmethod
    def normalize_host_lists(cls, values: list[str]) -> list[str]:
        normalized = [normalize_exact_host(value) for value in values]
        if len(normalized) != len(set(normalized)):
            raise ValueError("scope lists cannot contain duplicates")
        return normalized

    @field_validator("imported_at")
    @classmethod
    def require_import_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("imported_at must include a timezone")
        return value

    @model_validator(mode="after")
    def require_records_in_scope(self) -> TrafficImport:
        if self.record_count != len(self.records):
            raise ValueError("record_count must match records")
        if any(
            record.host not in self.allowlist or record.host in self.denylist
            for record in self.records
        ):
            raise ValueError("derived traffic contains an out-of-scope record")
        return self


class TrafficCandidateKind(StrEnum):
    AUTHORIZATION_BOUNDARY = "authorization_boundary"
    SENSITIVE_FIELD_EXPOSURE = "sensitive_field_exposure"
    VERBOSE_ERROR = "verbose_error"
    SECURITY_OBSERVATION = "security_observation"


class TrafficCandidate(TrafficModel):
    candidate_id: str = Field(pattern=r"^tcand-[a-f0-9]{16}$")
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    kind: TrafficCandidateKind
    title: LocalizedText
    severity_hint: SeverityHint
    confidence: Confidence
    risk_score: int = Field(ge=0, le=100)
    host: str
    endpoint_key: str = Field(min_length=5, max_length=2400)
    safe_urls: list[str] = Field(min_length=1, max_length=20)
    roles: list[str] = Field(default_factory=list, max_length=20)
    evidence_refs: list[str] = Field(min_length=1, max_length=50)
    rationale: LocalizedText
    benign_explanations: list[LocalizedText] = Field(default_factory=list, max_length=8)
    next_step: LocalizedText
    new_authorization_required: Literal[True] = True
    reportable: Literal[False] = False


class EndpointDiff(TrafficModel):
    endpoint_key: str
    host: str
    roles: list[str]
    statuses: dict[str, list[int]]
    body_changed: bool
    json_shape_changed: bool
    authentication_state_changed: bool
    record_refs: list[str]


class DuplicateCluster(TrafficModel):
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    endpoint_keys: list[str] = Field(min_length=2, max_length=100)
    hosts: list[str] = Field(min_length=1, max_length=100)
    record_refs: list[str] = Field(min_length=2, max_length=200)
    rationale: LocalizedText


class TrafficAnalysis(TrafficModel):
    schema_version: Literal[1] = 1
    analysis_id: str = Field(pattern=r"^traffic-analysis-[a-f0-9]{16}$")
    program_name: str
    import_ids: list[str] = Field(min_length=1, max_length=20)
    generated_at: datetime
    endpoint_count: int = Field(ge=0)
    candidate_count: int = Field(ge=0)
    duplicate_cluster_count: int = Field(ge=0)
    diffs: list[EndpointDiff] = Field(default_factory=list)
    candidates: list[TrafficCandidate] = Field(default_factory=list)
    duplicate_clusters: list[DuplicateCluster] = Field(default_factory=list)
    automatically_verified_findings: Literal[0] = 0
    limitations: list[LocalizedText] = Field(default_factory=list)

    @field_validator("generated_at")
    @classmethod
    def require_analysis_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("generated_at must include a timezone")
        return value
