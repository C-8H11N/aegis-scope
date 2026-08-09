from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from aegisscope.analysis.models import Confidence, LocalizedText, SeverityHint
from aegisscope.campaigns.models import (
    CampaignCreateRequest,
    CampaignDecisionRequest,
    CampaignStatus,
    HypothesisStatus,
    NextActionKind,
)
from aegisscope.campaigns.service import CampaignService, CampaignServiceError
from aegisscope.campaigns.store import CampaignStore
from aegisscope.traffic.models import (
    TrafficAnalysis,
    TrafficCandidate,
    TrafficCandidateKind,
)


def _text(zh_cn: str, en: str) -> LocalizedText:
    return LocalizedText(zh_cn=zh_cn, en=en)


def _candidate(kind: TrafficCandidateKind, *, score: int = 70) -> TrafficCandidate:
    suffix = {
        TrafficCandidateKind.AUTHORIZATION_BOUNDARY: "1" * 64,
        TrafficCandidateKind.SENSITIVE_FIELD_EXPOSURE: "2" * 64,
        TrafficCandidateKind.VERBOSE_ERROR: "3" * 64,
        TrafficCandidateKind.SECURITY_OBSERVATION: "4" * 64,
    }[kind]
    return TrafficCandidate(
        candidate_id=f"tcand-{suffix[:16]}",
        fingerprint=suffix,
        kind=kind,
        title=_text("测试线索", "Test lead"),
        severity_hint=SeverityHint.MEDIUM,
        confidence=Confidence.MEDIUM,
        risk_score=score,
        host="demo.invalid",
        endpoint_key="GET demo.invalid /api/profile/{id}",
        safe_urls=["https://demo.invalid/api/profile/1"],
        roles=["guest", "member"],
        evidence_refs=["traffic-a/req-1111111111111111"],
        rationale=_text("仅用于离线测试。", "Offline test only."),
        next_step=_text("人工复核。", "Review manually."),
    )


def _analysis(*candidates: TrafficCandidate) -> TrafficAnalysis:
    return TrafficAnalysis(
        analysis_id="traffic-analysis-1111111111111111",
        program_name="Safe Demo",
        import_ids=["traffic-1111111111111111"],
        generated_at=datetime.now(timezone.utc),
        endpoint_count=1,
        candidate_count=len(candidates),
        duplicate_cluster_count=0,
        candidates=list(candidates),
    )


def _service(tmp_path: Path) -> CampaignService:
    return CampaignService(CampaignStore(tmp_path / "aegisscope.sqlite3"))


def _request(*, max_stages: int = 5, max_requests: int = 50) -> CampaignCreateRequest:
    return CampaignCreateRequest(
        program_name="Safe Demo",
        target_host="demo.invalid",
        allowlist=["demo.invalid"],
        objective="Prioritize already-authorized offline research evidence.",
        max_stages=max_stages,
        max_total_requests=max_requests,
    )


def test_empty_campaign_creates_minimal_unapproved_baseline(tmp_path: Path) -> None:
    service = _service(tmp_path)
    campaign = service.create(_request())
    planned = service.plan(campaign.campaign_id, [])

    assert planned.status == CampaignStatus.AWAITING_STAGE_AUTHORIZATION
    assert planned.network_execution_enabled is False
    assert planned.target_execution_authorized is False
    assert planned.automatically_verified_findings == 0
    assert planned.next_action.kind == NextActionKind.AUTHORIZE_STAGE
    assert len(planned.hypotheses) == 1
    proposal = planned.hypotheses[0].proposal
    assert proposal is not None
    assert proposal.dry_run is True
    assert proposal.authorization_required is True
    assert proposal.target_host == "demo.invalid"
    assert [item.method.value for item in proposal.requests] == ["HEAD", "GET"]
    assert all(item.url == "https://demo.invalid/" for item in proposal.requests)


def test_auth_candidate_is_never_converted_to_credentialed_replay(tmp_path: Path) -> None:
    service = _service(tmp_path)
    campaign = service.create(_request())
    planned = service.plan(
        campaign.campaign_id,
        [_analysis(_candidate(TrafficCandidateKind.AUTHORIZATION_BOUNDARY))],
    )

    hypothesis = planned.hypotheses[0]
    assert planned.status == CampaignStatus.MANUAL_REVIEW
    assert planned.next_action.kind == NextActionKind.MANUAL_REVIEW
    assert hypothesis.status == HypothesisStatus.MANUAL_REVIEW
    assert hypothesis.requires_manual_tools is True
    assert hypothesis.proposal is None


def test_safe_observation_becomes_bounded_stage_proposal(tmp_path: Path) -> None:
    service = _service(tmp_path)
    campaign = service.create(_request())
    planned = service.plan(
        campaign.campaign_id,
        [_analysis(_candidate(TrafficCandidateKind.SECURITY_OBSERVATION))],
    )

    hypothesis = planned.hypotheses[0]
    assert hypothesis.status == HypothesisStatus.PROPOSED
    assert hypothesis.proposal is not None
    assert hypothesis.proposal.limits.max_requests == 2
    assert hypothesis.proposal.limits.request_interval_seconds >= 5
    assert hypothesis.proposal.limits.concurrency == 1


def test_human_disposition_advances_queue_and_enforces_budget(tmp_path: Path) -> None:
    service = _service(tmp_path)
    campaign = service.create(_request(max_stages=1, max_requests=2))
    planned = service.plan(campaign.campaign_id, [])
    hypothesis = planned.hypotheses[0]
    completed = service.record_decision(
        campaign.campaign_id,
        CampaignDecisionRequest(
            hypothesis_id=hypothesis.hypothesis_id,
            disposition="rejected",
            statement="Human review found the public response to be expected behavior.",
            consumed_requests=2,
        ),
    )

    assert completed.status == CampaignStatus.BUDGET_EXHAUSTED
    assert completed.budget.used_stages == 1
    assert completed.budget.used_requests == 2
    assert completed.next_action.kind == NextActionKind.NONE
    events = service.store.list_events(campaign.campaign_id)
    assert [event["event_type"] for event in events] == [
        "campaign_created",
        "campaign_planned",
        "hypothesis_disposition_recorded",
    ]
    with pytest.raises(CampaignServiceError, match="terminal disposition"):
        service.record_decision(
            campaign.campaign_id,
            CampaignDecisionRequest(
                hypothesis_id=hypothesis.hypothesis_id,
                disposition="supported",
                statement="A second disposition must not rewrite the append-only decision.",
                consumed_requests=0,
            ),
        )
