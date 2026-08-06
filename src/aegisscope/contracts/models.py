"""Strict stage contracts.

There is intentionally no generic command, headers, body, cookie, token, or credential field.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime
from enum import StrEnum
from typing import Literal
from urllib.parse import unquote_plus, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$")
UNSAFE_QUERY_RE = re.compile(
    r"(?:[<>\"'{}|\\^\r\n;]|\.\./|%2e%2e|\bunion\b|\bselect\b|\bscript\b|\bsleep\s*\()",
    re.I,
)


def normalize_exact_host(value: str) -> str:
    """Normalize and validate a single exact DNS host without wildcards or paths."""

    host = value.strip().rstrip(".").lower()
    if not host or "*" in host or "/" in host or ":" in host or not HOST_RE.fullmatch(host):
        raise ValueError("an exact DNS hostname is required")
    return host


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class HttpMethod(StrEnum):
    HEAD = "HEAD"
    GET = "GET"
    OPTIONS = "OPTIONS"


class StageType(StrEnum):
    BASIC_OBSERVATION = "basic_observation"
    PUBLIC_PARAMETER_BASELINE = "public_parameter_baseline"


class RequestSpec(StrictModel):
    method: HttpMethod
    url: str = Field(min_length=9, max_length=2048)


class StageLimits(StrictModel):
    concurrency: Literal[1] = 1
    request_interval_seconds: float = Field(default=5.0, ge=5.0, le=3600.0)
    max_requests: int = Field(default=20, ge=1, le=20)
    per_url_max: int = Field(default=2, ge=1, le=2)
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=30.0)
    max_response_bytes: int = Field(default=1_048_576, ge=1, le=1_048_576)
    max_redirects: Literal[0] = 0


class Authorization(StrictModel):
    granted: Literal[True]
    scope: Literal["stage"]
    user_statement: str = Field(min_length=4, max_length=1000)
    granted_at: datetime
    expires_at: datetime

    @field_validator("granted_at", "expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("authorization timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_window(self) -> Authorization:
        if self.expires_at <= self.granted_at:
            raise ValueError("authorization expires_at must be after granted_at")
        return self


class StageManifest(StrictModel):
    schema_version: Literal[1] = 1
    job_id: str = Field(min_length=8, max_length=80)
    program_name: str = Field(min_length=2, max_length=200)
    stage_type: StageType
    target_host: str
    allowlist: list[str] = Field(min_length=1, max_length=100)
    denylist: list[str] = Field(default_factory=list, max_length=100)
    authorization: Authorization
    dry_run: bool = True
    requests: list[RequestSpec] = Field(min_length=1, max_length=20)
    limits: StageLimits = Field(default_factory=StageLimits)
    created_at: datetime
    expires_at: datetime
    notes: str = Field(default="", max_length=2000)

    @field_validator("job_id")
    @classmethod
    def validate_job_id(cls, value: str) -> str:
        if not JOB_ID_RE.fullmatch(value):
            raise ValueError("job_id must use 8-80 safe filename characters")
        return value

    @field_validator("target_host")
    @classmethod
    def validate_target_host(cls, value: str) -> str:
        return normalize_exact_host(value)

    @field_validator("allowlist", "denylist")
    @classmethod
    def validate_host_list(cls, values: list[str]) -> list[str]:
        normalized = [normalize_exact_host(value) for value in values]
        if len(normalized) != len(set(normalized)):
            raise ValueError("host lists must not contain duplicates")
        return normalized

    @field_validator("created_at", "expires_at")
    @classmethod
    def validate_manifest_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("manifest timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def enforce_stage_boundaries(self) -> StageManifest:
        if self.expires_at <= self.created_at:
            raise ValueError("manifest expires_at must be after created_at")
        if self.expires_at > self.authorization.expires_at:
            raise ValueError("manifest cannot outlive its authorization")
        if self.target_host not in self.allowlist:
            raise ValueError("target_host is not in allowlist")
        if self.target_host in self.denylist:
            raise ValueError("target_host is present in denylist")
        if len(self.requests) > self.limits.max_requests:
            raise ValueError("request list exceeds limits.max_requests")

        counts: Counter[str] = Counter()
        for request in self.requests:
            parsed = urlsplit(request.url)
            if parsed.scheme.lower() != "https":
                raise ValueError("all requests must use HTTPS")
            if parsed.username or parsed.password:
                raise ValueError("URL credentials are forbidden")
            if parsed.hostname is None or parsed.hostname.lower().rstrip(".") != self.target_host:
                raise ValueError("every URL must use target_host exactly")
            if parsed.port not in (None, 443):
                raise ValueError("only the default HTTPS port is allowed")
            if parsed.fragment:
                raise ValueError("URL fragments are not allowed")
            if self.stage_type == StageType.BASIC_OBSERVATION and parsed.query:
                raise ValueError("basic_observation URLs cannot contain a query string")
            decoded_query = unquote_plus(parsed.query)
            if len(parsed.query) > 512 or UNSAFE_QUERY_RE.search(decoded_query):
                raise ValueError("query string exceeds the safe public-baseline grammar")
            counts[request.url] += 1

        if counts and max(counts.values()) > self.limits.per_url_max:
            raise ValueError("a URL occurs more often than limits.per_url_max")
        return self


class PlannerInput(StrictModel):
    program_name: str = Field(min_length=2, max_length=200)
    target_host: str
    allowlist: list[str] = Field(min_length=1, max_length=100)
    denylist: list[str] = Field(default_factory=list, max_length=100)
    program_rules: str = Field(min_length=20, max_length=50_000)
    objective: str = Field(min_length=5, max_length=1000)

    @field_validator("target_host")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        return normalize_exact_host(value)

    @field_validator("allowlist", "denylist")
    @classmethod
    def normalize_lists(cls, values: list[str]) -> list[str]:
        return [normalize_exact_host(value) for value in values]

    @model_validator(mode="after")
    def require_scope(self) -> PlannerInput:
        if self.target_host not in self.allowlist or self.target_host in self.denylist:
            raise ValueError("planner target must be allowed and not denied")
        return self


class StageProposal(StrictModel):
    schema_version: Literal[1] = 1
    proposal_id: str = Field(min_length=8, max_length=80)
    program_name: str = Field(min_length=2, max_length=200)
    stage_type: StageType
    target_host: str
    allowlist: list[str] = Field(min_length=1, max_length=100)
    denylist: list[str] = Field(default_factory=list, max_length=100)
    requests: list[RequestSpec] = Field(min_length=1, max_length=20)
    limits: StageLimits = Field(default_factory=StageLimits)
    rationale: str = Field(min_length=5, max_length=4000)
    authorization_required: Literal[True] = True
    dry_run: Literal[True] = True

    @field_validator("proposal_id")
    @classmethod
    def validate_proposal_id(cls, value: str) -> str:
        if not JOB_ID_RE.fullmatch(value):
            raise ValueError("proposal_id must use 8-80 safe filename characters")
        return value

    @field_validator("target_host")
    @classmethod
    def normalize_proposal_target(cls, value: str) -> str:
        return normalize_exact_host(value)

    @field_validator("allowlist", "denylist")
    @classmethod
    def normalize_proposal_lists(cls, values: list[str]) -> list[str]:
        normalized = [normalize_exact_host(value) for value in values]
        if len(normalized) != len(set(normalized)):
            raise ValueError("host lists must not contain duplicates")
        return normalized

    @model_validator(mode="after")
    def validate_proposal_scope(self) -> StageProposal:
        if self.target_host not in self.allowlist or self.target_host in self.denylist:
            raise ValueError("proposal target must be allowed and not denied")
        if len(self.requests) > self.limits.max_requests:
            raise ValueError("proposal exceeds limits.max_requests")
        counts: Counter[str] = Counter()
        for request in self.requests:
            parsed = urlsplit(request.url)
            if parsed.scheme.lower() != "https":
                raise ValueError("proposal URLs must use HTTPS")
            if parsed.username or parsed.password or parsed.fragment:
                raise ValueError("proposal URLs cannot contain credentials or fragments")
            if parsed.hostname is None or parsed.hostname.lower().rstrip(".") != self.target_host:
                raise ValueError("proposal URLs must use target_host exactly")
            if parsed.port not in (None, 443):
                raise ValueError("proposal URLs must use the default HTTPS port")
            if self.stage_type == StageType.BASIC_OBSERVATION and parsed.query:
                raise ValueError("basic_observation proposals cannot contain query strings")
            decoded_query = unquote_plus(parsed.query)
            if len(parsed.query) > 512 or UNSAFE_QUERY_RE.search(decoded_query):
                raise ValueError("proposal query exceeds the safe public-baseline grammar")
            counts[request.url] += 1
        if counts and max(counts.values()) > self.limits.per_url_max:
            raise ValueError("proposal repeats a URL too many times")
        return self
