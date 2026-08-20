"""Create immutable ProgramSpec snapshots without persisting free-form rule text."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from aegisscope.programs.models import ProgramSpec, ProgramSpecCreateRequest
from aegisscope.programs.store import ProgramStore
from aegisscope.security.redaction import redact_text


class ProgramSpecError(ValueError):
    pass


class ProgramService:
    def __init__(self, store: ProgramStore) -> None:
        self.store = store

    def create(self, request: ProgramSpecCreateRequest) -> ProgramSpec:
        source_sha256 = hashlib.sha256(request.source_text.encode("utf-8")).hexdigest()
        safe_reference = redact_text(request.source_reference)[0]
        spec = ProgramSpec(
            spec_id=f"program-{source_sha256[:16]}",
            program_name=request.program_name,
            rule_version=request.rule_version,
            exact_hosts=request.exact_hosts,
            denied_hosts=request.denied_hosts,
            allowed_stage_types=request.allowed_stage_types,
            forbidden_actions=[redact_text(item)[0] for item in request.forbidden_actions],
            evidence_requirements=[
                redact_text(item)[0] for item in request.evidence_requirements
            ],
            report_requirements=[redact_text(item)[0] for item in request.report_requirements],
            authentication_policy=request.authentication_policy,
            automation_allowed=request.automation_allowed,
            api_testing_allowed=request.api_testing_allowed,
            min_request_interval_seconds=request.min_request_interval_seconds,
            max_requests_per_stage=request.max_requests_per_stage,
            max_concurrency=request.max_concurrency,
            testing_window=redact_text(request.testing_window)[0],
            source_reference=safe_reference,
            source_sha256=source_sha256,
            created_at=datetime.now(timezone.utc),
        )
        existing = self.store.get_by_source_sha256(source_sha256)
        if existing is not None:
            comparable_fields = set(ProgramSpec.model_fields) - {"created_at", "spec_id"}
            if any(getattr(existing, field) != getattr(spec, field) for field in comparable_fields):
                raise ProgramSpecError(
                    "the same rule source digest already has a different structured snapshot"
                )
            return existing
        self.store.create(spec)
        return spec
