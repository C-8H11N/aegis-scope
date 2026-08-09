"""Deterministic campaign planner over already-redacted offline evidence."""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from aegisscope.analysis.models import Confidence, LocalizedText
from aegisscope.campaigns.models import (
    Campaign,
    CampaignBudget,
    CampaignCreateRequest,
    CampaignDecisionRequest,
    CampaignHypothesis,
    CampaignNextAction,
    CampaignStatus,
    HypothesisKind,
    HypothesisStatus,
    NextActionKind,
)
from aegisscope.campaigns.store import CampaignStore
from aegisscope.contracts.models import (
    HttpMethod,
    RequestSpec,
    StageLimits,
    StageProposal,
    StageType,
)
from aegisscope.security.integrity import canonical_sha256
from aegisscope.security.redaction import redact_text
from aegisscope.traffic.models import TrafficAnalysis, TrafficCandidate, TrafficCandidateKind


class CampaignServiceError(ValueError):
    pass


def _text(zh_cn: str, en: str) -> LocalizedText:
    return LocalizedText(zh_cn=zh_cn, en=en)


CONFIDENCE_WEIGHT = {
    Confidence.LOW: 25,
    Confidence.MEDIUM: 55,
    Confidence.HIGH: 85,
}


class CampaignService:
    """Turn offline evidence into a bounded hypothesis queue and one safe next action."""

    def __init__(self, store: CampaignStore) -> None:
        self.store = store

    def create(self, request: CampaignCreateRequest) -> Campaign:
        now = datetime.now(timezone.utc)
        safe_objective = redact_text(request.objective)[0]
        campaign = Campaign(
            campaign_id=f"campaign-{uuid4().hex[:16]}",
            program_name=request.program_name,
            objective=safe_objective,
            status=CampaignStatus.READY,
            target_host=request.target_host,
            allowlist=request.allowlist,
            denylist=request.denylist,
            budget=CampaignBudget(
                max_stages=request.max_stages,
                max_total_requests=request.max_total_requests,
            ),
            next_action=self._import_action(),
            created_at=now,
            updated_at=now,
        )
        self.store.create(campaign)
        return campaign

    def plan(self, campaign_id: str, analyses: list[TrafficAnalysis]) -> Campaign:
        campaign = self._require(campaign_id)
        if campaign.status in {CampaignStatus.STOPPED, CampaignStatus.BUDGET_EXHAUSTED}:
            raise CampaignServiceError(f"campaign cannot be planned from {campaign.status.value}")
        if len(analyses) > 20:
            raise CampaignServiceError("a campaign plan accepts at most 20 traffic analyses")
        if any(item.program_name != campaign.program_name for item in analyses):
            raise CampaignServiceError("traffic analysis belongs to a different program")

        existing = {item.fingerprint: item for item in campaign.hypotheses}
        duplicate_endpoints = {
            endpoint
            for analysis in analyses
            for cluster in analysis.duplicate_clusters
            for endpoint in cluster.endpoint_keys
        }
        for analysis in analyses:
            for candidate in analysis.candidates:
                if candidate.host != campaign.target_host:
                    continue
                hypothesis = self._from_candidate(campaign, candidate, duplicate_endpoints)
                existing.setdefault(hypothesis.fingerprint, hypothesis)

        if not existing:
            baseline = self._baseline_hypothesis(campaign)
            existing[baseline.fingerprint] = baseline

        hypotheses = sorted(
            existing.values(), key=lambda item: (-item.priority_score, item.hypothesis_id)
        )
        source_ids = sorted(
            set(campaign.source_analysis_ids)
            | {analysis.analysis_id for analysis in analyses}
        )
        next_action, status = self._select_next(campaign, hypotheses)
        updated = campaign.model_copy(
            update={
                "status": status,
                "source_analysis_ids": source_ids,
                "hypotheses": hypotheses,
                "next_action": next_action,
                "updated_at": datetime.now(timezone.utc),
            }
        )
        self.store.update(
            updated,
            event_type="campaign_planned",
            details={
                "analysis_count": len(analyses),
                "hypothesis_count": len(hypotheses),
                "next_action": next_action.kind.value,
                "network_executed": False,
            },
        )
        return updated

    def record_decision(
        self, campaign_id: str, request: CampaignDecisionRequest
    ) -> Campaign:
        campaign = self._require(campaign_id)
        mapping = {
            "supported": HypothesisStatus.SUPPORTED,
            "rejected": HypothesisStatus.REJECTED,
            "duplicate": HypothesisStatus.DUPLICATE,
            "exhausted": HypothesisStatus.EXHAUSTED,
        }
        found = False
        updated_hypotheses: list[CampaignHypothesis] = []
        for hypothesis in campaign.hypotheses:
            if hypothesis.hypothesis_id == request.hypothesis_id:
                found = True
                if hypothesis.status not in {
                    HypothesisStatus.PROPOSED,
                    HypothesisStatus.MANUAL_REVIEW,
                }:
                    raise CampaignServiceError("hypothesis already has a terminal disposition")
                updated_hypotheses.append(
                    hypothesis.model_copy(update={"status": mapping[request.disposition]})
                )
            else:
                updated_hypotheses.append(hypothesis)
        if not found:
            raise CampaignServiceError("hypothesis does not belong to this campaign")

        used_stages = campaign.budget.used_stages + (1 if request.consumed_requests else 0)
        used_requests = campaign.budget.used_requests + request.consumed_requests
        if (
            used_stages > campaign.budget.max_stages
            or used_requests > campaign.budget.max_total_requests
        ):
            raise CampaignServiceError("decision would exceed the campaign budget")
        budget = campaign.budget.model_copy(
            update={"used_stages": used_stages, "used_requests": used_requests}
        )
        shell = campaign.model_copy(update={"budget": budget})
        next_action, status = self._select_next(shell, updated_hypotheses)
        updated = shell.model_copy(
            update={
                "status": status,
                "hypotheses": updated_hypotheses,
                "next_action": next_action,
                "updated_at": datetime.now(timezone.utc),
            }
        )
        self.store.update(
            updated,
            event_type="hypothesis_disposition_recorded",
            details={
                "hypothesis_id": request.hypothesis_id,
                "disposition": request.disposition,
                "statement": redact_text(request.statement)[0],
                "consumed_requests": request.consumed_requests,
            },
        )
        return updated

    def _require(self, campaign_id: str) -> Campaign:
        campaign = self.store.get(campaign_id)
        if campaign is None:
            raise KeyError(f"unknown campaign_id: {campaign_id}")
        return campaign

    def _from_candidate(
        self,
        campaign: Campaign,
        candidate: TrafficCandidate,
        duplicate_endpoints: set[str],
    ) -> CampaignHypothesis:
        kind = HypothesisKind(candidate.kind.value)
        manual = candidate.kind in {
            TrafficCandidateKind.AUTHORIZATION_BOUNDARY,
            TrafficCandidateKind.SENSITIVE_FIELD_EXPOSURE,
            TrafficCandidateKind.VERBOSE_ERROR,
        }
        novelty = 30 if candidate.endpoint_key in duplicate_endpoints else 80
        evidence = min(95, 35 + len(candidate.evidence_refs) * 10 + len(candidate.roles) * 5)
        cost = 0 if manual else 2
        priority = self._priority(
            candidate.risk_score,
            candidate.confidence,
            novelty,
            evidence,
            cost,
        )
        proposal = None if manual else self._proposal(campaign, candidate.safe_urls, kind)
        fingerprint = canonical_sha256(
            {
                "campaign_target": campaign.target_host,
                "candidate": candidate.fingerprint,
                "kind": kind.value,
            }
        )
        return CampaignHypothesis(
            hypothesis_id=f"hyp-{fingerprint[:16]}",
            fingerprint=fingerprint,
            kind=kind,
            status=HypothesisStatus.MANUAL_REVIEW if manual else HypothesisStatus.PROPOSED,
            title=candidate.title,
            host=candidate.host,
            safe_urls=candidate.safe_urls,
            source_refs=candidate.evidence_refs,
            confidence=candidate.confidence,
            risk_score=candidate.risk_score,
            novelty_score=novelty,
            evidence_score=evidence,
            estimated_request_cost=cost,
            priority_score=priority,
            rationale=candidate.rationale,
            next_step=candidate.next_step,
            requires_manual_tools=manual,
            proposal=proposal,
        )

    def _baseline_hypothesis(self, campaign: Campaign) -> CampaignHypothesis:
        fingerprint = canonical_sha256(
            {"kind": HypothesisKind.BASELINE_COVERAGE.value, "host": campaign.target_host}
        )
        proposal = self._proposal(
            campaign,
            [f"https://{campaign.target_host}/"],
            HypothesisKind.BASELINE_COVERAGE,
        )
        return CampaignHypothesis(
            hypothesis_id=f"hyp-{fingerprint[:16]}",
            fingerprint=fingerprint,
            kind=HypothesisKind.BASELINE_COVERAGE,
            status=HypothesisStatus.PROPOSED,
            title=_text("建立公开入口安全基线", "Establish a public entry-point baseline"),
            host=campaign.target_host,
            safe_urls=[f"https://{campaign.target_host}/"],
            source_refs=[],
            confidence=Confidence.LOW,
            risk_score=20,
            novelty_score=100,
            evidence_score=10,
            estimated_request_cost=2,
            priority_score=self._priority(20, Confidence.LOW, 100, 10, 2),
            rationale=_text(
                "当前没有可用于排序的离线线索，先用最小公开请求建立响应基线。",
                "No offline candidates are available, so begin with a minimal public response baseline.",
            ),
            next_step=_text(
                "人工审核并单独授权这份两请求阶段提案。",
                "Review and separately authorize this two-request stage proposal.",
            ),
            requires_manual_tools=False,
            proposal=proposal,
        )

    @staticmethod
    def _priority(
        risk: int,
        confidence: Confidence,
        novelty: int,
        evidence: int,
        request_cost: int,
    ) -> int:
        score = (
            risk * 0.45
            + CONFIDENCE_WEIGHT[confidence] * 0.20
            + novelty * 0.20
            + evidence * 0.15
            - request_cost * 0.5
        )
        return max(0, min(100, round(score)))

    @staticmethod
    def _proposal(
        campaign: Campaign,
        safe_urls: list[str],
        kind: HypothesisKind,
    ) -> StageProposal:
        safe_paths: list[str] = []
        for value in safe_urls:
            parsed = urlsplit(value)
            if parsed.scheme != "https" or parsed.hostname != campaign.target_host:
                continue
            safe = urlunsplit(("https", campaign.target_host, parsed.path or "/", "", ""))
            if safe not in safe_paths:
                safe_paths.append(safe)
        if not safe_paths:
            safe_paths = [f"https://{campaign.target_host}/"]
        url = safe_paths[0]
        requests = [
            RequestSpec(method=HttpMethod.HEAD, url=url),
            RequestSpec(method=HttpMethod.GET, url=url),
        ]
        identity = canonical_sha256(
            {"campaign": campaign.campaign_id, "kind": kind.value, "url": url}
        )
        return StageProposal(
            proposal_id=f"proposal-{identity[:16]}",
            program_name=campaign.program_name,
            stage_type=StageType.BASIC_OBSERVATION,
            target_host=campaign.target_host,
            allowlist=campaign.allowlist,
            denylist=campaign.denylist,
            requests=requests,
            limits=StageLimits(max_requests=2, per_url_max=2),
            rationale=(
                "Campaign-generated minimum public baseline. This is an unapproved dry-run "
                "proposal; it cannot dispatch network traffic."
            ),
        )

    def _select_next(
        self,
        campaign: Campaign,
        hypotheses: list[CampaignHypothesis],
    ) -> tuple[CampaignNextAction, CampaignStatus]:
        if (
            campaign.budget.used_stages >= campaign.budget.max_stages
            or campaign.budget.used_requests >= campaign.budget.max_total_requests
        ):
            return (
                CampaignNextAction(
                    kind=NextActionKind.NONE,
                    title=_text("研究预算已耗尽", "Campaign budget exhausted"),
                    explanation=_text(
                        "系统已安全停止，不会自动提高请求上限。",
                        "The campaign stopped safely and will not raise request limits automatically.",
                    ),
                ),
                CampaignStatus.BUDGET_EXHAUSTED,
            )

        open_items = [
            item
            for item in hypotheses
            if item.status in {HypothesisStatus.PROPOSED, HypothesisStatus.MANUAL_REVIEW}
        ]
        if open_items and open_items[0].status == HypothesisStatus.PROPOSED:
            item = open_items[0]
            assert item.proposal is not None
            if (
                campaign.budget.used_stages + 1 > campaign.budget.max_stages
                or campaign.budget.used_requests + item.estimated_request_cost
                > campaign.budget.max_total_requests
            ):
                return self._budget_blocked()
            return (
                CampaignNextAction(
                    kind=NextActionKind.AUTHORIZE_STAGE,
                    hypothesis_id=item.hypothesis_id,
                    proposal_id=item.proposal.proposal_id,
                    title=_text("审核下一份最小化阶段提案", "Review the next minimal stage proposal"),
                    explanation=_text(
                        "提案已由离线证据和预算自动选择；目标执行仍需独立人工授权。",
                        "Offline evidence and budget selected this proposal; target execution still needs separate human authorization.",
                    ),
                ),
                CampaignStatus.AWAITING_STAGE_AUTHORIZATION,
            )

        if open_items and open_items[0].status == HypothesisStatus.MANUAL_REVIEW:
            item = open_items[0]
            return (
                CampaignNextAction(
                    kind=NextActionKind.MANUAL_REVIEW,
                    hypothesis_id=item.hypothesis_id,
                    title=_text("使用 Burp 人工复核高价值线索", "Review a high-value lead in Burp"),
                    explanation=_text(
                        "该方向涉及认证、角色或原始响应上下文，现有无凭据 Runner 不会自动重放。",
                        "This lead depends on authentication, roles, or raw context, so the credential-free runner will not replay it automatically.",
                    ),
                ),
                CampaignStatus.MANUAL_REVIEW,
            )
        return (
            CampaignNextAction(
                kind=NextActionKind.NONE,
                title=_text("当前假设队列已完成", "Current hypothesis queue completed"),
                explanation=_text(
                    "没有仍待处理的安全假设；可以导入新的脱敏流量后重新规划。",
                    "No open hypothesis remains. Import new redacted traffic before replanning.",
                ),
            ),
            CampaignStatus.COMPLETED,
        )

    @staticmethod
    def _budget_blocked() -> tuple[CampaignNextAction, CampaignStatus]:
        return (
            CampaignNextAction(
                kind=NextActionKind.NONE,
                title=_text("下一假设超出剩余预算", "Next hypothesis exceeds remaining budget"),
                explanation=_text(
                    "系统已安全停止，不会自动扩大阶段数或请求数。",
                    "The campaign stopped safely and will not expand stage or request limits.",
                ),
            ),
            CampaignStatus.BUDGET_EXHAUSTED,
        )

    @staticmethod
    def _import_action() -> CampaignNextAction:
        return CampaignNextAction(
            kind=NextActionKind.IMPORT_TRAFFIC,
            title=_text("导入已授权的脱敏流量", "Import authorized redacted traffic"),
            explanation=_text(
                "也可以直接运行离线规划，系统会生成最小公开基线提案。",
                "You may also plan immediately to create a minimal public baseline proposal.",
            ),
        )
