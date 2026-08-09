from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from aegisscope.contracts.models import StageManifest
from aegisscope.contracts.results import StageStatus
from aegisscope.runner.cli import _claim_network_job
from aegisscope.runner.executor import EvidenceConflictError, StageExecutor


def test_dry_run_sends_zero_requests(tmp_path: Path, demo_payload: dict[str, Any]) -> None:
    manifest = StageManifest.model_validate(demo_payload)
    summary = StageExecutor(output_dir=tmp_path, network_gate=False).run(manifest)
    assert summary.stage_status == StageStatus.DRY_RUN
    assert summary.actual_requests == 0
    assert (tmp_path / "stage-summary.json").is_file()
    assert (tmp_path / "evidence-index.json").is_file()


def test_closed_runner_gate_overrides_network_manifest(
    tmp_path: Path, demo_payload: dict[str, Any]
) -> None:
    demo_payload["dry_run"] = False
    manifest = StageManifest.model_validate(demo_payload)
    summary = StageExecutor(output_dir=tmp_path, network_gate=False).run(manifest)
    assert summary.stage_status == StageStatus.DRY_RUN
    assert summary.actual_requests == 0


def test_runner_refuses_to_overwrite_evidence(
    tmp_path: Path, demo_payload: dict[str, Any]
) -> None:
    (tmp_path / "existing.txt").write_text("keep", encoding="utf-8")
    manifest = StageManifest.model_validate(demo_payload)
    with pytest.raises(EvidenceConflictError):
        StageExecutor(output_dir=tmp_path, network_gate=False).run(manifest)


def test_network_job_can_only_be_claimed_once(tmp_path: Path) -> None:
    assert _claim_network_job(tmp_path, "stage-demo-0001", "a" * 64)
    assert not _claim_network_job(tmp_path, "stage-demo-0001", "a" * 64)


def test_mocked_network_stage_stops_on_security_response(
    tmp_path: Path, demo_payload: dict[str, Any]
) -> None:
    demo_payload["dry_run"] = False
    demo_payload["requests"] = [
        {"method": "GET", "url": "https://demo.invalid/blocked"}
    ]
    demo_payload["limits"]["max_requests"] = 1

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="blocked")

    summary = StageExecutor(
        output_dir=tmp_path,
        network_gate=True,
        transport=httpx.MockTransport(handler),
    ).run(StageManifest.model_validate(demo_payload))

    assert summary.stage_status == StageStatus.STOPPED
    assert summary.actual_requests == 1
    assert summary.stop_reason == "security or rate-limit response: 403"


def test_mocked_network_stage_redacts_sensitive_body_before_disk(
    tmp_path: Path, demo_payload: dict[str, Any]
) -> None:
    demo_payload["dry_run"] = False
    demo_payload["requests"] = [
        {"method": "GET", "url": "https://demo.invalid/public"}
    ]
    demo_payload["limits"]["max_requests"] = 1
    sample_value = "Bearer " + ("a" * 26)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/plain"},
            text=f"example {sample_value}",
        )

    summary = StageExecutor(
        output_dir=tmp_path,
        network_gate=True,
        transport=httpx.MockTransport(handler),
    ).run(StageManifest.model_validate(demo_payload))

    saved_body = (tmp_path / "request-01" / "body.redacted.txt").read_text(
        encoding="utf-8"
    )
    assert summary.stage_status == StageStatus.STOPPED
    assert sample_value not in saved_body
    assert "<REDACTED:bearer_token>" in saved_body
