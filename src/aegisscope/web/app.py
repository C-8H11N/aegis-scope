"""Bilingual Web control plane. No endpoint directly executes a target request."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from aegisscope import __version__
from aegisscope.analysis.engine import EvidenceAnalysisError, EvidenceAnalyzer
from aegisscope.campaigns.models import (
    CampaignCreateRequest,
    CampaignDecisionRequest,
    CampaignPlanRequest,
)
from aegisscope.campaigns.service import CampaignService, CampaignServiceError
from aegisscope.campaigns.store import CampaignStore
from aegisscope.config import Settings
from aegisscope.contracts.models import JOB_ID_RE, PlannerInput, StageManifest
from aegisscope.findings.models import FindingTransition
from aegisscope.findings.service import FindingLifecycleError, FindingService
from aegisscope.findings.store import AnalystStore
from aegisscope.i18n import MESSAGES
from aegisscope.orchestrator import Orchestrator, PreparationError
from aegisscope.providers.openai_compatible import OpenAICompatiblePlanner, PlannerResponseError
from aegisscope.programs.models import ProgramSpecCreateRequest
from aegisscope.programs.service import ProgramService, ProgramSpecError
from aegisscope.programs.store import ProgramStore
from aegisscope.traffic.models import TrafficAnalysis

STATIC_DIR = Path(__file__).with_name("static")


def create_app(settings: Settings | None = None) -> FastAPI:
    runtime = settings or Settings.from_env()
    orchestrator = Orchestrator(runtime)
    analyst_store = AnalystStore(runtime.data_dir / "db" / "aegisscope.sqlite3")
    finding_service = FindingService(analyst_store)
    campaign_store = CampaignStore(runtime.data_dir / "db" / "aegisscope.sqlite3")
    program_store = ProgramStore(runtime.data_dir / "db" / "aegisscope.sqlite3")
    program_service = ProgramService(program_store)
    campaign_service = CampaignService(campaign_store, program_store)
    app = FastAPI(
        title="AegisScope Control Plane",
        description="Authorization-first SRC orchestration / 授权优先的 SRC 编排",
        version=__version__,
    )
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.middleware("http")
    async def local_security_boundary(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        allowed_hosts = {"127.0.0.1", "localhost", "::1", "testserver"}
        if request.url.hostname not in allowed_hosts:
            return JSONResponse(status_code=400, content={"detail": "invalid Host header"})
        origin = request.headers.get("origin")
        expected_origin = str(request.base_url).rstrip("/")
        if origin and origin.rstrip("/") != expected_origin:
            return JSONResponse(status_code=403, content={"detail": "cross-origin request denied"})
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > 1_048_576:
            return JSONResponse(status_code=413, content={"detail": "request body too large"})
        response = await call_next(request)
        if request.url.path == "/docs":
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; "
                "base-uri 'none'; frame-ancestors 'none'; object-src 'none'"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
                "form-action 'self'; object-src 'none'"
            )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/", response_class=FileResponse, include_in_schema=False)
    def home() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "messages": {language: catalog["ready"] for language, catalog in MESSAGES.items()},
            "network_execution": False,
        }

    @app.get("/api/v1/config")
    def safe_config() -> dict[str, Any]:
        return {
            "data_dir": str(runtime.data_dir),
            "ssh_alias": runtime.ssh_alias,
            "remote_root": runtime.remote_root,
            "language": runtime.language,
            "llm_configured": bool(
                runtime.llm_base_url and runtime.llm_api_key and runtime.llm_model
            ),
            "secrets_exposed": False,
        }

    @app.get("/api/v1/schema/stage")
    def stage_schema() -> dict[str, Any]:
        return StageManifest.model_json_schema()

    @app.post("/api/v1/manifests/validate")
    def validate_manifest(payload: dict[str, Any]) -> dict[str, Any]:
        return orchestrator.validate(payload).model_dump(mode="json")

    @app.post("/api/v1/jobs/prepare")
    def prepare_job(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            manifest = orchestrator.prepare(payload)
        except PreparationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        job = orchestrator.store.get_job(manifest.job_id)
        return {
            "job_id": manifest.job_id,
            "status": "prepared",
            "manifest_sha256": job["manifest_sha256"] if job else None,
            "messages": {language: catalog["prepared"] for language, catalog in MESSAGES.items()},
            "dispatched": False,
        }

    @app.get("/api/v1/jobs")
    def list_jobs(limit: int = 100) -> list[dict[str, Any]]:
        return orchestrator.store.list_jobs(limit=limit)

    @app.get("/api/v1/jobs/{job_id}")
    def get_job(job_id: str) -> dict[str, Any]:
        job = orchestrator.store.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        return job

    @app.get("/api/v1/traffic/imports")
    def list_traffic_imports(limit: int = 100) -> list[dict[str, Any]]:
        """List derived imports only; raw capture data is never returned."""

        return analyst_store.list_imports(limit)

    @app.get("/api/v1/traffic/analyses")
    def list_traffic_analyses(limit: int = 100) -> list[dict[str, Any]]:
        return analyst_store.list_analyses(limit)

    @app.get("/api/v1/findings")
    def list_findings(limit: int = 100) -> list[dict[str, Any]]:
        return [item.model_dump(mode="json") for item in analyst_store.list_findings(limit)]

    @app.post("/api/v1/programs")
    def create_program(request: ProgramSpecCreateRequest) -> dict[str, Any]:
        """Create an immutable structured rule snapshot; source_text is never persisted."""

        try:
            spec = program_service.create(request)
        except ProgramSpecError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return spec.model_dump(mode="json")

    @app.get("/api/v1/programs")
    def list_programs(limit: int = 100) -> list[dict[str, Any]]:
        return [item.model_dump(mode="json") for item in program_store.list(limit)]

    @app.get("/api/v1/programs/{spec_id}")
    def get_program(spec_id: str) -> dict[str, Any]:
        spec = program_store.get(spec_id)
        if spec is None:
            raise HTTPException(status_code=404, detail="program spec not found")
        return spec.model_dump(mode="json")

    @app.post("/api/v1/campaigns")
    def create_campaign(request: CampaignCreateRequest) -> dict[str, Any]:
        """Create a local planning campaign. This grants no target execution authority."""

        try:
            campaign = campaign_service.create(request)
        except CampaignServiceError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return campaign.model_dump(mode="json")

    @app.get("/api/v1/campaigns")
    def list_campaigns(limit: int = 100) -> list[dict[str, Any]]:
        return [item.model_dump(mode="json") for item in campaign_store.list(limit)]

    @app.get("/api/v1/campaigns/{campaign_id}")
    def get_campaign(campaign_id: str) -> dict[str, Any]:
        campaign = campaign_store.get(campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="campaign not found")
        return {
            "campaign": campaign.model_dump(mode="json"),
            "events": campaign_store.list_events(campaign_id),
        }

    @app.post("/api/v1/campaigns/{campaign_id}/plan")
    def plan_campaign(campaign_id: str, request: CampaignPlanRequest) -> dict[str, Any]:
        campaign = campaign_store.get(campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="campaign not found")
        analyses: list[TrafficAnalysis] = []
        if request.analysis_ids:
            for analysis_id in request.analysis_ids:
                analysis = analyst_store.get_analysis(analysis_id)
                if analysis is None:
                    raise HTTPException(
                        status_code=404, detail=f"traffic analysis not found: {analysis_id}"
                    )
                analyses.append(analysis)
        else:
            analyses = [
                TrafficAnalysis.model_validate(payload)
                for payload in analyst_store.list_analyses(100)
                if payload.get("program_name") == campaign.program_name
            ][:20]
        try:
            planned = campaign_service.plan(campaign_id, analyses)
        except CampaignServiceError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return planned.model_dump(mode="json")

    @app.post("/api/v1/campaigns/{campaign_id}/decisions")
    def record_campaign_decision(
        campaign_id: str, request: CampaignDecisionRequest
    ) -> dict[str, Any]:
        try:
            campaign = campaign_service.record_decision(campaign_id, request)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except CampaignServiceError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return campaign.model_dump(mode="json")

    @app.post("/api/v1/campaigns/{campaign_id}/sync-jobs")
    def sync_campaign_jobs(campaign_id: str) -> dict[str, Any]:
        """Offline-only binding of local job summaries to their originating proposal."""

        try:
            campaign = campaign_service.sync_jobs(campaign_id, orchestrator.store.list_jobs(500))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except CampaignServiceError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return campaign.model_dump(mode="json")

    @app.get("/api/v1/campaigns/{campaign_id}/proposal")
    def get_campaign_proposal(campaign_id: str) -> dict[str, Any]:
        campaign = campaign_store.get(campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="campaign not found")
        hypothesis = next(
            (
                item
                for item in campaign.hypotheses
                if item.hypothesis_id == campaign.next_action.hypothesis_id
                and item.proposal is not None
            ),
            None,
        )
        if hypothesis is None or hypothesis.proposal is None:
            raise HTTPException(status_code=404, detail="campaign has no pending stage proposal")
        return hypothesis.proposal.model_dump(mode="json")

    @app.get("/api/v1/findings/{finding_id}")
    def get_finding(finding_id: str) -> dict[str, Any]:
        finding = analyst_store.get_finding(finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="finding not found")
        return {
            "finding": finding.model_dump(mode="json"),
            "events": analyst_store.list_events(finding_id),
        }

    @app.post("/api/v1/findings/{finding_id}/transition")
    def transition_finding(
        finding_id: str, request: FindingTransition
    ) -> dict[str, Any]:
        try:
            finding = finding_service.transition(finding_id, request)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except FindingLifecycleError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return finding.model_dump(mode="json")

    @app.post("/api/v1/jobs/{job_id}/analyze")
    def analyze_job(job_id: str) -> dict[str, Any]:
        if not JOB_ID_RE.fullmatch(job_id):
            raise HTTPException(status_code=422, detail="invalid job_id")
        job = orchestrator.store.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        if job.get("analysis") is not None:
            return dict(job["analysis"])
        evidence_dir = runtime.data_dir / "evidence" / job_id
        saved_analysis = evidence_dir / "analysis" / "candidates.json"
        try:
            if saved_analysis.is_file():
                analysis = EvidenceAnalyzer().load(saved_analysis)
            else:
                analysis = EvidenceAnalyzer().analyze(evidence_dir)
                EvidenceAnalyzer().write(analysis, evidence_dir / "analysis")
        except (EvidenceAnalysisError, FileExistsError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        payload = analysis.model_dump(mode="json")
        orchestrator.store.set_analysis(job_id, payload)
        orchestrator.store.set_status(job_id, "offline_analyzed")
        orchestrator.store.append_event(
            job_id,
            "offline_analysis_completed",
            {
                "candidate_count": analysis.candidate_count,
                "observation_count": analysis.observation_count,
            },
        )
        return payload

    @app.post("/api/v1/proposals")
    def create_proposal(request: PlannerInput) -> dict[str, Any]:
        if not (runtime.llm_base_url and runtime.llm_api_key and runtime.llm_model):
            raise HTTPException(status_code=503, detail="model API is not configured")
        planner = OpenAICompatiblePlanner(
            base_url=runtime.llm_base_url,
            api_key=runtime.llm_api_key,
            model=runtime.llm_model,
        )
        try:
            proposal = planner.propose(request)
        except PlannerResponseError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        proposal_path = runtime.data_dir / "proposals" / f"{proposal.proposal_id}.json"
        proposal_path.write_text(
            json.dumps(proposal.model_dump(mode="json"), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return proposal.model_dump(mode="json")

    return app


app = create_app()
