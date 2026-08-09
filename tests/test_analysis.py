from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aegisscope.analysis.engine import EvidenceAnalysisError, EvidenceAnalyzer
from aegisscope.contracts.results import RequestResult, StageStatus, StageSummary


def _write_summary(root: Path, *, url: str = "https://demo.invalid/") -> None:
    summary = StageSummary(
        job_id="stage-demo-0001",
        target_host="demo.invalid",
        stage_status=StageStatus.COMPLETED,
        dry_run=False,
        started_at=datetime(2026, 8, 6, tzinfo=timezone.utc),
        ended_at=datetime(2026, 8, 6, tzinfo=timezone.utc),
        actual_requests=1,
        results=[
            RequestResult(
                index=1,
                method="GET",
                url=url,
                status_code=200,
                evidence_files=["request-01/response.json"],
            )
        ],
    )
    (root / "stage-summary.json").write_text(
        json.dumps(summary.model_dump(mode="json")), encoding="utf-8"
    )


def test_analysis_finds_ranked_candidates_without_network(tmp_path: Path) -> None:
    request_dir = tmp_path / "request-01"
    request_dir.mkdir()
    _write_summary(tmp_path)
    (request_dir / "response.json").write_text(
        json.dumps(
            {
                "status_code": 200,
                "headers": {"content-type": "text/html"},
                "content_type": "text/html",
                "body_redactions": [],
            }
        ),
        encoding="utf-8",
    )
    (request_dir / "body.redacted.txt").write_text(
        "<html><title>Index of /</title></html>", encoding="utf-8"
    )

    analysis = EvidenceAnalyzer().analyze(tmp_path)

    assert analysis.automatically_verified_findings == 0
    assert analysis.candidate_count >= 1
    assert analysis.candidates[0].rule_id == "directory_listing"
    assert all(candidate.reportable is False for candidate in analysis.candidates)


def test_analysis_refuses_tampered_indexed_evidence(tmp_path: Path) -> None:
    _write_summary(tmp_path)
    (tmp_path / "evidence-index.json").write_text(
        json.dumps(
            {
                "files": [
                    {
                        "path": "stage-summary.json",
                        "bytes": 1,
                        "sha256": "0" * 64,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(EvidenceAnalysisError, match="integrity mismatch"):
        EvidenceAnalyzer().analyze(tmp_path)
