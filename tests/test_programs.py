from __future__ import annotations

from pathlib import Path

from aegisscope.campaigns.models import CampaignCreateRequest
from aegisscope.campaigns.service import CampaignService
from aegisscope.campaigns.store import CampaignStore
from aegisscope.programs.models import ProgramSpecCreateRequest
from aegisscope.programs.service import ProgramService
from aegisscope.programs.store import ProgramStore


def _request() -> ProgramSpecCreateRequest:
    return ProgramSpecCreateRequest(
        program_name="Safe Demo",
        rule_version="2026.1",
        exact_hosts=["demo.invalid"],
        denied_hosts=["blocked.invalid"],
        forbidden_actions=["credential attacks", "denial of service"],
        evidence_requirements=["Preserve timestamps and hashes"],
        report_requirements=["Describe the verified impact without exaggeration"],
        automation_allowed=True,
        min_request_interval_seconds=8,
        max_requests_per_stage=4,
        source_reference="Local safe-demo rules",
        source_text="Authorized local demonstration rules. No real target access is allowed.",
    )


def test_program_spec_is_immutable_and_does_not_persist_source_text(tmp_path: Path) -> None:
    store = ProgramStore(tmp_path / "aegisscope.sqlite3")
    service = ProgramService(store)
    request = _request()
    spec = service.create(request)

    assert spec.spec_id.startswith("program-")
    assert spec.exact_hosts == ["demo.invalid"]
    assert spec.source_sha256
    persisted = (tmp_path / "aegisscope.sqlite3").read_bytes()
    assert request.source_text.encode("utf-8") not in persisted
    assert service.create(request).spec_id == spec.spec_id


def test_campaign_uses_bound_program_rate_snapshot(tmp_path: Path) -> None:
    database = tmp_path / "aegisscope.sqlite3"
    program_store = ProgramStore(database)
    spec = ProgramService(program_store).create(_request())
    campaigns = CampaignService(CampaignStore(database), program_store)
    campaign = campaigns.create(
        CampaignCreateRequest(
            program_name="Safe Demo",
            target_host="demo.invalid",
            allowlist=["demo.invalid"],
            objective="Plan a bounded baseline under the structured program snapshot.",
            program_spec_id=spec.spec_id,
        )
    )
    planned = campaigns.plan(campaign.campaign_id, [])
    proposal = planned.hypotheses[0].proposal

    assert campaign.program_spec_sha256
    assert proposal is not None
    assert proposal.limits.request_interval_seconds == 8
