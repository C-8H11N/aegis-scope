"""Strict, reviewable SRC program-rule snapshots.

Free-form rule text is accepted only to calculate a source digest. It is not persisted and
cannot grant authorization or change the deterministic execution policy.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegisscope.contracts.models import StageType, normalize_exact_host


class ProgramModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


RuleItem = Annotated[str, Field(min_length=2, max_length=500)]


class AuthenticationPolicy(StrEnum):
    PUBLIC_ONLY = "public_only"
    SELF_REGISTERED_TEST_ACCOUNT = "self_registered_test_account"
    PROVIDED_TEST_ACCOUNT = "provided_test_account"
    MANUAL_ONLY = "manual_only"


class ProgramSpecCreateRequest(ProgramModel):
    program_name: str = Field(min_length=2, max_length=200)
    rule_version: str = Field(min_length=1, max_length=80)
    exact_hosts: list[str] = Field(min_length=1, max_length=100)
    denied_hosts: list[str] = Field(default_factory=list, max_length=100)
    allowed_stage_types: list[StageType] = Field(
        default_factory=lambda: [
            StageType.BASIC_OBSERVATION,
            StageType.PUBLIC_PARAMETER_BASELINE,
        ],
        min_length=1,
        max_length=2,
    )
    forbidden_actions: list[RuleItem] = Field(default_factory=list, max_length=100)
    evidence_requirements: list[RuleItem] = Field(default_factory=list, max_length=50)
    report_requirements: list[RuleItem] = Field(default_factory=list, max_length=50)
    authentication_policy: AuthenticationPolicy = AuthenticationPolicy.PUBLIC_ONLY
    automation_allowed: bool = False
    api_testing_allowed: bool = False
    min_request_interval_seconds: float = Field(default=5.0, ge=5.0, le=3600.0)
    max_requests_per_stage: int = Field(default=20, ge=1, le=20)
    max_concurrency: Literal[1] = 1
    testing_window: str = Field(default="Explicitly authorized stages only", max_length=500)
    source_reference: str = Field(min_length=2, max_length=1000)
    source_text: str = Field(min_length=20, max_length=100_000, exclude=True)

    @field_validator("exact_hosts", "denied_hosts")
    @classmethod
    def normalize_hosts(cls, values: list[str]) -> list[str]:
        normalized = [normalize_exact_host(value) for value in values]
        if len(normalized) != len(set(normalized)):
            raise ValueError("program host lists cannot contain duplicates")
        return normalized

    @field_validator("allowed_stage_types")
    @classmethod
    def unique_stage_types(cls, values: list[StageType]) -> list[StageType]:
        if len(values) != len(set(values)):
            raise ValueError("allowed_stage_types cannot contain duplicates")
        return values

    @model_validator(mode="after")
    def validate_scope(self) -> ProgramSpecCreateRequest:
        overlap = set(self.exact_hosts).intersection(self.denied_hosts)
        if overlap:
            raise ValueError("a host cannot be both allowed and denied")
        return self


class ProgramSpec(ProgramModel):
    schema_version: Literal[1] = 1
    spec_id: str = Field(pattern=r"^program-[a-f0-9]{16}$")
    program_name: str = Field(min_length=2, max_length=200)
    rule_version: str = Field(min_length=1, max_length=80)
    exact_hosts: list[str] = Field(min_length=1, max_length=100)
    denied_hosts: list[str] = Field(default_factory=list, max_length=100)
    allowed_stage_types: list[StageType] = Field(min_length=1, max_length=2)
    forbidden_actions: list[RuleItem] = Field(default_factory=list, max_length=100)
    evidence_requirements: list[RuleItem] = Field(default_factory=list, max_length=50)
    report_requirements: list[RuleItem] = Field(default_factory=list, max_length=50)
    authentication_policy: AuthenticationPolicy
    automation_allowed: bool
    api_testing_allowed: bool
    min_request_interval_seconds: float = Field(ge=5.0, le=3600.0)
    max_requests_per_stage: int = Field(ge=1, le=20)
    max_concurrency: Literal[1] = 1
    testing_window: str = Field(max_length=500)
    source_reference: str = Field(min_length=2, max_length=1000)
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: datetime

    @field_validator("exact_hosts", "denied_hosts")
    @classmethod
    def normalize_hosts(cls, values: list[str]) -> list[str]:
        normalized = [normalize_exact_host(value) for value in values]
        if len(normalized) != len(set(normalized)):
            raise ValueError("program host lists cannot contain duplicates")
        return normalized

    @field_validator("allowed_stage_types")
    @classmethod
    def unique_stage_types(cls, values: list[StageType]) -> list[StageType]:
        if len(values) != len(set(values)):
            raise ValueError("allowed_stage_types cannot contain duplicates")
        return values

    @field_validator("created_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_scope(self) -> ProgramSpec:
        overlap = set(self.exact_hosts).intersection(self.denied_hosts)
        if overlap:
            raise ValueError("a host cannot be both allowed and denied")
        return self
