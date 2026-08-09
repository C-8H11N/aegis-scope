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
from aegisscope.config import Settings
from aegisscope.contracts.models import JOB_ID_RE, PlannerInput, StageManifest
from aegisscope.i18n import MESSAGES
from aegisscope.orchestrator import Orchestrator, PreparationError
from aegisscope.providers.openai_compatible import OpenAICompatiblePlanner, PlannerResponseError

STATIC_DIR = Path(__file__).with_name("static")


def create_app(settings: Settings | None = None) -> FastAPI:
    runtime = settings or Settings.from_env()
    orchestrator = Orchestrator(runtime)
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
