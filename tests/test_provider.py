from __future__ import annotations

import json

import httpx
import pytest

from aegisscope.contracts.models import PlannerInput
from aegisscope.providers.openai_compatible import (
    OpenAICompatiblePlanner,
    PlannerResponseError,
)


def _planner_input() -> PlannerInput:
    return PlannerInput(
        program_name="Safe Demo",
        target_host="demo.invalid",
        allowlist=["demo.invalid"],
        denylist=[],
        program_rules="Only offline and low-impact public observation is allowed.",
        objective="Prepare one safe public observation proposal.",
    )


def test_planner_accepts_strict_mock_response() -> None:
    credential = "-".join(("test", "only"))
    content = json.dumps(
        {
            "stage_type": "basic_observation",
            "requests": [{"method": "HEAD", "url": "https://demo.invalid/"}],
            "rationale": "One bounded public observation.",
        }
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"choices": [{"message": {"content": content}}]}
        )

    planner = OpenAICompatiblePlanner(
        base_url="http://127.0.0.1:9999/v1",
        api_key=credential,
        model="mock",
        transport=httpx.MockTransport(handler),
    )
    proposal = planner.propose(_planner_input())
    assert proposal.target_host == "demo.invalid"
    assert proposal.authorization_required is True


def test_planner_rejects_oversized_response() -> None:
    credential = "-".join(("test", "only"))
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 2048)

    planner = OpenAICompatiblePlanner(
        base_url="http://127.0.0.1:9999/v1",
        api_key=credential,
        model="mock",
        transport=httpx.MockTransport(handler),
        max_response_bytes=1024,
    )
    with pytest.raises(PlannerResponseError, match="size limit"):
        planner.propose(_planner_input())
