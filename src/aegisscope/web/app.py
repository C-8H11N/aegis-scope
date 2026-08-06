"""Bilingual Web control plane. No endpoint directly executes a target request."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from aegisscope import __version__
from aegisscope.config import Settings
from aegisscope.contracts.models import PlannerInput, StageManifest
from aegisscope.i18n import MESSAGES
from aegisscope.orchestrator import Orchestrator, PreparationError
from aegisscope.providers.openai_compatible import OpenAICompatiblePlanner

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
        return {
            "job_id": manifest.job_id,
            "status": "prepared",
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

    @app.post("/api/v1/proposals")
    def create_proposal(request: PlannerInput) -> dict[str, Any]:
        if not (runtime.llm_base_url and runtime.llm_api_key and runtime.llm_model):
            raise HTTPException(status_code=503, detail="model API is not configured")
        planner = OpenAICompatiblePlanner(
            base_url=runtime.llm_base_url,
            api_key=runtime.llm_api_key,
            model=runtime.llm_model,
        )
        proposal = planner.propose(request)
        proposal_path = runtime.data_dir / "proposals" / f"{proposal.proposal_id}.json"
        proposal_path.write_text(
            json.dumps(proposal.model_dump(mode="json"), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return proposal.model_dump(mode="json")

    return app


app = create_app()
