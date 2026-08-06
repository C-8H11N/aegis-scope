"""OpenAI-compatible proposal adapter with no tool execution capability."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from pydantic import BaseModel, ConfigDict, Field

from aegisscope.contracts.models import (
    PlannerInput,
    RequestSpec,
    StageLimits,
    StageProposal,
    StageType,
)


class PlannerConfigurationError(ValueError):
    pass


class PlannerResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    stage_type: StageType
    requests: list[RequestSpec] = Field(min_length=1, max_length=20)
    rationale: str = Field(min_length=5, max_length=4000)


class OpenAICompatiblePlanner:
    def __init__(self, *, base_url: str, api_key: str, model: str) -> None:
        parsed = urlsplit(base_url)
        loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
            raise PlannerConfigurationError("model API must use HTTPS or loopback HTTP")
        if not api_key.strip() or not model.strip():
            raise PlannerConfigurationError("model API key and model are required")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model

    def propose(self, request: PlannerInput) -> StageProposal:
        system_prompt = (
            "You create low-impact authorized SRC stage proposals. Output strict JSON only. "
            "Never grant authorization, expand scope, add authentication, add request bodies, "
            "follow redirects, scan, crawl, fuzz, exploit, brute-force, or access a different host. "
            "Only propose HTTPS HEAD, GET, or OPTIONS requests for the exact target host."
        )
        user_payload = {
            "program_name": request.program_name,
            "target_host": request.target_host,
            "allowlist": request.allowlist,
            "denylist": request.denylist,
            "objective": request.objective,
            "program_rules": request.program_rules,
            "required_output": {
                "stage_type": "basic_observation or public_parameter_baseline",
                "requests": [{"method": "HEAD|GET|OPTIONS", "url": "https://exact-host/path"}],
                "rationale": "short explanation",
            },
        }
        response = httpx.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={
                "model": self.model,
                "temperature": 0,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
                ],
            },
            timeout=30.0,
            follow_redirects=False,
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        content = data["choices"][0]["message"]["content"]
        parsed_response = PlannerResponse.model_validate_json(content)
        return StageProposal(
            proposal_id=f"proposal-{uuid4()}",
            program_name=request.program_name,
            stage_type=parsed_response.stage_type,
            target_host=request.target_host,
            allowlist=request.allowlist,
            denylist=request.denylist,
            requests=parsed_response.requests,
            limits=StageLimits(),
            rationale=parsed_response.rationale,
        )
