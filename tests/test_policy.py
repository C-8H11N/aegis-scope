from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from aegisscope.policy.engine import PolicyEngine

NOW = datetime(2026, 8, 6, tzinfo=timezone.utc)


def test_demo_manifest_is_allowed(demo_payload: dict[str, Any]) -> None:
    decision = PolicyEngine.validate_payload(demo_payload, now=NOW)
    assert decision.allowed
    assert decision.manifest is not None
    assert decision.manifest.dry_run is True


def test_unknown_field_fails_closed(demo_payload: dict[str, Any]) -> None:
    payload = deepcopy(demo_payload)
    payload["command"] = "whoami"
    decision = PolicyEngine.validate_payload(payload, now=NOW)
    assert not decision.allowed
    assert any("Extra inputs are not permitted" in error for error in decision.errors)


def test_cross_host_url_is_rejected(demo_payload: dict[str, Any]) -> None:
    payload = deepcopy(demo_payload)
    payload["requests"][0]["url"] = "https://other.invalid/"
    decision = PolicyEngine.validate_payload(payload, now=NOW)
    assert not decision.allowed
    assert any("target_host exactly" in error for error in decision.errors)


def test_rate_below_floor_is_rejected(demo_payload: dict[str, Any]) -> None:
    payload = deepcopy(demo_payload)
    payload["limits"]["request_interval_seconds"] = 1
    assert not PolicyEngine.validate_payload(payload, now=NOW).allowed


def test_payload_like_query_is_rejected(demo_payload: dict[str, Any]) -> None:
    payload = deepcopy(demo_payload)
    payload["stage_type"] = "public_parameter_baseline"
    payload["requests"][0]["url"] = "https://demo.invalid/?q=%3Cscript%3E"
    assert not PolicyEngine.validate_payload(payload, now=NOW).allowed
