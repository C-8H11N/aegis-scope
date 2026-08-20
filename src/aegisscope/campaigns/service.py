"""Deterministic campaign planner over already-redacted offline evidence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from aegisscope.analysis.models import Confidence, EvidenceAnalysis, LocalizedText
from aegisscope.campaigns.models import (
    Campaign,
    CampaignBudget,
    CampaignCreateRequest,
    CampaignDecisionRequest,
    CampaignExecutionLink,
    CampaignHypothesis,
    CampaignNextAction,
    CampaignStatus,
    ExecutionLinkStatus,
    HypothesisKind,
    HypothesisStatus,
    NextActionKind,
)
from aegisscope.campaigns.store import CampaignStore
from aegisscope.contracts.models import (
    HttpMethod,
    RequestSpec,
    StageLimits,
    StageManifest,
    StageProposal,
    StageType,
)
from aegisscope.contracts.results import StageStatus, StageSummary
from aegisscope.programs.store import ProgramStore
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

    def __init__(self, store: CampaignStore, program_store: ProgramStore | None = None) -> None:
        self.store = store
        self.program_store = program_store

    def create(self, request: CampaignCreateRequest) -> Campaign:
        now = datetime.now(timezone.utc)
        safe_objective = redact_text(request.objective)[0]
        spec_sha256: str | None = None
        if request.program_spec_id:
            if self.program_store is None:
                raise CampaignServiceError("program spec storage is not configured")
            spec = self.program_store.get(request.program_spec_id)
            if spec is None:
                raise CampaignServiceError("unknown program_spec_id")
            if spec.program_name != request.program_name:
                raise CampaignServiceError("program spec belongs to a different program")
            if request.target_host not in spec.exact_hosts or request.target_host in spec.denied_hosts:
                raise CampaignServiceError("campaign target is outside the program spec")
            if any(host not in spec.exact_hosts for host in request.allowlist):
                raise CampaignServiceError("campaign allowlist exceeds the program spec")
            if StageType.BASIC_OBSERVATION not in spec.allowed_stage_types:
                raise CampaignServiceError("program spec does not allow public baseline proposals")
            if not spec.automation_allowed:
                raise CampaignServiceError(
                    "program spec prohibits automated stage proposals; use manual review"
                )
            spec_sha256 = canonical_sha256(spec.model_dump(mode="json"))
        campaign = Campaign(
            campaign_id=f"campaign-{uuid4().hex[:16]}",
            program_name=request.program_name,
            objective=safe_objective,
            status=CampaignStatus.READY,
            target_host=request.target_host,
            program_spec_id=request.program_spec_id,
            program_spec_sha256=spec_sha256,
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

    def sync_jobs(self, campaign_id: str, jobs: list[dict[str, object]]) -> Campaign:
        """Bind matching prepared jobs and ingest their saved result metadata.

        This method is offline-only. It reads local audit records, never invokes transport, and
        never converts an analyzer candidate into a confirmed vulnerability.
        """

        campaign = self._require(campaign_id)
        if len(jobs) > 500:
            raise CampaignServiceError("job sync accepts at most 500 local audit records")
        now = datetime.now(timezone.utc)
        links_by_job = {item.job_id: item for item in campaign.execution_links}
        hypotheses = {item.hypothesis_id: item for item in campaign.hypotheses}
        matched = 0
        newly_counted_stages = 0
        newly_counted_requests = 0
        processed_job_ids: set[str] = set()

        for hypothesis in campaign.hypotheses:
            proposal = hypothesis.proposal
            if proposal is None:
                continue
            proposal_sha256 = canonical_sha256(proposal.model_dump(mode="json"))
            for job in jobs:
                if not self._job_matches_proposal(job, proposal, proposal_sha256):
                    continue
                job_id_value = job.get("job_id")
                if not isinstance(job_id_value, str):
                    continue
                job_id = job_id_value
                if job_id in processed_job_ids:
                    continue
                manifest_sha256 = str(job.get("manifest_sha256") or "")
                if len(manifest_sha256) != 64 or any(
                    value not in "0123456789abcdef" for value in manifest_sha256
                ):
                    continue
                existing = links_by_job.get(job_id)
                if existing is not None and existing.hypothesis_id != hypothesis.hypothesis_id:
                    continue
                raw_summary = job.get("summary")
                summary = self._validated_summary(
                    raw_summary,
                    job_id=job_id,
                    target_host=campaign.target_host,
                    manifest_sha256=manifest_sha256,
                )
                invalid_summary = raw_summary is not None and summary is None
                summary_sha256_value = job.get("summary_sha256")
                summary_sha256 = (
                    summary_sha256_value
                    if isinstance(summary_sha256_value, str)
                    and len(summary_sha256_value) == 64
                    and all(value in "0123456789abcdef" for value in summary_sha256_value)
                    else None
                )
                analysis = self._validated_analysis(
                    job.get("analysis"),
                    job_id=job_id,
                    target_host=campaign.target_host,
                    source_summary_sha256=summary_sha256,
                )
                actual_requests = summary.actual_requests if summary else 0
                stage_status = summary.stage_status.value if summary else None
                stop_reason = (
                    "invalid local stage summary"
                    if invalid_summary
                    else redact_text(summary.stop_reason)[0]
                    if summary and summary.stop_reason
                    else None
                )
                candidate_count = analysis.candidate_count if analysis else 0
                observation_count = analysis.observation_count if analysis else 0
                safety_stop_count = analysis.safety_stop_count if analysis else 0
                status = (
                    ExecutionLinkStatus.FAILED
                    if invalid_summary
                    else self._execution_status(
                        str(job.get("status") or ""), stage_status, analysis is not None
                    )
                )
                recommendation = self._review_recommendation(
                    stage_status=stage_status,
                    candidate_count=candidate_count,
                    safety_stop_count=safety_stop_count,
                )
                if invalid_summary:
                    recommendation = "exhausted"
                budget_counted = bool(existing and existing.budget_counted)
                if summary is not None and actual_requests > 0 and not budget_counted:
                    if hypothesis.status in {
                        HypothesisStatus.SUPPORTED,
                        HypothesisStatus.REJECTED,
                        HypothesisStatus.DUPLICATE,
                        HypothesisStatus.EXHAUSTED,
                    }:
                        # A terminal manual disposition may already have accounted for this
                        # stage in older Campaign records. Bind it without double charging.
                        budget_counted = True
                    else:
                        newly_counted_stages += 1
                        newly_counted_requests += actual_requests
                        budget_counted = True
                link = CampaignExecutionLink(
                    binding_id=(
                        existing.binding_id
                        if existing
                        else f"binding-{canonical_sha256({'campaign': campaign_id, 'job': job_id})[:16]}"
                    ),
                    hypothesis_id=hypothesis.hypothesis_id,
                    proposal_id=proposal.proposal_id,
                    proposal_sha256=proposal_sha256,
                    job_id=job_id,
                    manifest_sha256=manifest_sha256,
                    status=status,
                    stage_status=stage_status,
                    actual_requests=actual_requests,
                    stop_reason=stop_reason,
                    candidate_count=candidate_count,
                    observation_count=observation_count,
                    safety_stop_count=safety_stop_count,
                    summary_sha256=summary_sha256,
                    budget_counted=budget_counted,
                    review_recommendation=recommendation,
                    created_at=existing.created_at if existing else now,
                    updated_at=now,
                )
                links_by_job[job_id] = link
                processed_job_ids.add(job_id)
                matched += 1
                has_reviewable_result = (
                    summary is not None and summary.stage_status != StageStatus.DRY_RUN
                ) or invalid_summary
                if has_reviewable_result and hypothesis.status == HypothesisStatus.PROPOSED:
                    hypotheses[hypothesis.hypothesis_id] = hypothesis.model_copy(
                        update={"status": HypothesisStatus.RESULT_REVIEW}
                    )

        if matched == 0:
            self.store.update(
                campaign,
                event_type="campaign_job_sync_completed",
                details={"matched_jobs": 0, "network_executed": False},
            )
            return campaign

        budget = campaign.budget.model_copy(
            update={
                "used_stages": min(
                    campaign.budget.max_stages,
                    campaign.budget.used_stages + newly_counted_stages,
                ),
                "used_requests": min(
                    campaign.budget.max_total_requests,
                    campaign.budget.used_requests + newly_counted_requests,
                ),
            }
        )
        ordered_hypotheses = [hypotheses[item.hypothesis_id] for item in campaign.hypotheses]
        shell = campaign.model_copy(
            update={
                "budget": budget,
                "hypotheses": ordered_hypotheses,
                "execution_links": sorted(links_by_job.values(), key=lambda item: item.created_at),
            }
        )
        next_action, status = self._select_next(shell, ordered_hypotheses)
        updated = shell.model_copy(
            update={"status": status, "next_action": next_action, "updated_at": now}
        )
        self.store.update(
            updated,
            event_type="campaign_job_sync_completed",
            details={
                "matched_jobs": matched,
                "newly_counted_stages": newly_counted_stages,
                "newly_counted_requests": newly_counted_requests,
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
                    HypothesisStatus.RESULT_REVIEW,
                }:
                    raise CampaignServiceError("hypothesis already has a terminal disposition")
                updated_hypotheses.append(
                    hypothesis.model_copy(update={"status": mapping[request.disposition]})
                )
            else:
                updated_hypotheses.append(hypothesis)
        if not found:
            raise CampaignServiceError("hypothesis does not belong to this campaign")

        linked = any(
            item.hypothesis_id == request.hypothesis_id and item.budget_counted
            for item in campaign.execution_links
        )
        if linked and request.consumed_requests:
            raise CampaignServiceError(
                "actual request usage is already derived from the linked stage summary; submit 0"
            )
        used_stages = campaign.budget.used_stages + (
            1 if request.consumed_requests and not linked else 0
        )
        used_requests = campaign.budget.used_requests + (
            request.consumed_requests if not linked else 0
        )
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

    @staticmethod
    def _job_matches_proposal(
        job: dict[str, object], proposal: StageProposal, proposal_sha256: str
    ) -> bool:
        manifest_payload = job.get("manifest")
        if not isinstance(manifest_payload, dict):
            return False
        try:
            manifest = StageManifest.model_validate(manifest_payload)
        except ValueError:
            return False
        stored_digest = job.get("manifest_sha256")
        if (
            not isinstance(stored_digest, str)
            or canonical_sha256(manifest.model_dump(mode="json")) != stored_digest
        ):
            return False
        expected_note = f"Created from {proposal.proposal_id}; proposal_sha256={proposal_sha256}"
        return (
            expected_note in manifest.notes
            and manifest.program_name == proposal.program_name
            and manifest.stage_type == proposal.stage_type
            and manifest.target_host == proposal.target_host
            and manifest.allowlist == proposal.allowlist
            and manifest.denylist == proposal.denylist
            and manifest.requests == proposal.requests
            and manifest.limits == proposal.limits
        )

    @staticmethod
    def _execution_status(
        job_status: str, stage_status: str | None, analysis_verified: bool
    ) -> ExecutionLinkStatus:
        if job_status == "evidence_transfer_failed":
            return ExecutionLinkStatus.EVIDENCE_TRANSFER_FAILED
        if stage_status == "stopped":
            return ExecutionLinkStatus.STOPPED
        if stage_status == "failed" or job_status == "failed":
            return ExecutionLinkStatus.FAILED
        if analysis_verified:
            return ExecutionLinkStatus.OFFLINE_ANALYZED
        if stage_status in {"completed", "dry_run"}:
            return ExecutionLinkStatus.EVIDENCE_READY
        if job_status == "dispatching":
            return ExecutionLinkStatus.DISPATCHING
        return ExecutionLinkStatus.PREPARED

    @staticmethod
    def _validated_summary(
        value: object,
        *,
        job_id: str,
        target_host: str,
        manifest_sha256: str,
    ) -> StageSummary | None:
        if not isinstance(value, dict):
            return None
        try:
            summary = StageSummary.model_validate(value)
        except ValueError:
            return None
        result_count_is_valid = (
            summary.actual_requests == 0
            if summary.stage_status == StageStatus.DRY_RUN
            else summary.actual_requests == len(summary.results)
        )
        if (
            summary.job_id != job_id
            or summary.target_host != target_host
            or summary.manifest_sha256 != manifest_sha256
            or not result_count_is_valid
        ):
            return None
        return summary

    @staticmethod
    def _validated_analysis(
        value: object,
        *,
        job_id: str,
        target_host: str,
        source_summary_sha256: str | None,
    ) -> EvidenceAnalysis | None:
        if not isinstance(value, dict) or source_summary_sha256 is None:
            return None
        try:
            analysis = EvidenceAnalysis.model_validate(value)
        except ValueError:
            return None
        if (
            analysis.job_id != job_id
            or analysis.target_host != target_host
            or analysis.source_summary_sha256 != source_summary_sha256
            or not analysis.evidence_integrity.startswith("verified")
        ):
            return None
        return analysis

    @staticmethod
    def _review_recommendation(
        *, stage_status: str | None, candidate_count: int, safety_stop_count: int
    ) -> Literal["supported", "rejected", "duplicate", "exhausted"] | None:
        if stage_status in {"stopped", "failed"} or safety_stop_count:
            return "exhausted"
        if candidate_count:
            return "supported"
        if stage_status == "completed":
            return "rejected"
        return None

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
        fingerprint = canonical_sha256(
            {
                "campaign_target": campaign.target_host,
                "candidate": candidate.fingerprint,
                "kind": kind.value,
            }
        )
        proposal = (
            None
            if manual
            else self._proposal(campaign, candidate.safe_urls, kind)
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

    def _proposal(
        self,
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
        interval = 5.0
        max_requests = 2
        if campaign.program_spec_id and self.program_store is not None:
            spec = self.program_store.get(campaign.program_spec_id)
            if spec is None:
                raise CampaignServiceError("bound program spec no longer exists")
            if canonical_sha256(spec.model_dump(mode="json")) != campaign.program_spec_sha256:
                raise CampaignServiceError("bound program spec digest has changed")
            interval = spec.min_request_interval_seconds
            max_requests = min(max_requests, spec.max_requests_per_stage)
        requests = [
            RequestSpec(method=HttpMethod.HEAD, url=url),
            RequestSpec(method=HttpMethod.GET, url=url),
        ][:max_requests]
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
            limits=StageLimits(
                request_interval_seconds=interval,
                max_requests=max_requests,
                per_url_max=2,
            ),
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
        result_items = [
            item for item in hypotheses if item.status == HypothesisStatus.RESULT_REVIEW
        ]
        if result_items:
            item = result_items[0]
            link = next(
                (
                    value
                    for value in reversed(campaign.execution_links)
                    if value.hypothesis_id == item.hypothesis_id
                ),
                None,
            )
            recommendation = link.review_recommendation if link else None
            suffix_zh = f"；建议结论：{recommendation}" if recommendation else ""
            suffix_en = f"; suggested disposition: {recommendation}" if recommendation else ""
            return (
                CampaignNextAction(
                    kind=NextActionKind.REVIEW_RESULT,
                    hypothesis_id=item.hypothesis_id,
                    title=_text("复核已回流的阶段结果", "Review the synchronized stage result"),
                    explanation=_text(
                        "请求数已从阶段摘要自动计入预算，工具结论仍需人工确认" + suffix_zh,
                        "Request usage was derived from the stage summary; a human must still decide"
                        + suffix_en,
                    ),
                ),
                CampaignStatus.RESULT_REVIEW,
            )

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
