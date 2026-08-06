from __future__ import annotations

from pathlib import Path
from typing import Any

from aegisscope.contracts.models import StageManifest
from aegisscope.contracts.results import StageStatus
from aegisscope.runner.executor import StageExecutor


def test_dry_run_sends_zero_requests(tmp_path: Path, demo_payload: dict[str, Any]) -> None:
    manifest = StageManifest.model_validate(demo_payload)
    summary = StageExecutor(output_dir=tmp_path, network_gate=False).run(manifest)
    assert summary.stage_status == StageStatus.DRY_RUN
    assert summary.actual_requests == 0
    assert (tmp_path / "stage-summary.json").is_file()


def test_closed_runner_gate_overrides_network_manifest(
    tmp_path: Path, demo_payload: dict[str, Any]
) -> None:
    demo_payload["dry_run"] = False
    manifest = StageManifest.model_validate(demo_payload)
    summary = StageExecutor(output_dir=tmp_path, network_gate=False).run(manifest)
    assert summary.stage_status == StageStatus.DRY_RUN
    assert summary.actual_requests == 0
