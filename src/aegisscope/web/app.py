"""Bilingual Web control plane. No endpoint directly executes a target request."""

from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from aegisscope import __version__
from aegisscope.config import Settings
from aegisscope.contracts.models import PlannerInput, StageManifest
from aegisscope.i18n import MESSAGES
from aegisscope.orchestrator import Orchestrator, PreparationError
from aegisscope.providers.openai_compatible import OpenAICompatiblePlanner

HOME_PAGE = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AegisScope</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, Segoe UI, sans-serif; }
    body { max-width: 920px; margin: 0 auto; padding: 48px 24px; background:#08111f; color:#dbeafe; }
    h1 { font-size: 44px; margin-bottom: 8px; }
    .tag { color:#67e8f9; font-weight:600; }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:16px; margin-top:28px; }
    .card { border:1px solid #1e3a5f; border-radius:16px; padding:20px; background:#0b1b30; }
    code { color:#a5f3fc; }
    a { color:#67e8f9; }
  </style>
</head>
<body>
  <div class="tag">Authorization-first security orchestration</div>
  <h1>AegisScope</h1>
  <p>授权优先的 SRC 安全测试编排 / Authorization-first SRC assessment orchestration.</p>
  <div class="grid">
    <section class="card"><h2>中文</h2><p>模型只能生成待审批提案；范围、速率和执行权限由确定性策略控制。</p></section>
    <section class="card"><h2>English</h2><p>The model proposes work. Deterministic policy and explicit approval control execution.</p></section>
    <section class="card"><h2>API</h2><p><a href="/docs">OpenAPI documentation</a><br><code>GET /health</code></p></section>
  </div>
</body>
</html>"""


def create_app(settings: Settings | None = None) -> FastAPI:
    runtime = settings or Settings.from_env()
    orchestrator = Orchestrator(runtime)
    app = FastAPI(
        title="AegisScope Control Plane",
        description="Authorization-first SRC orchestration / 授权优先的 SRC 编排",
        version=__version__,
    )

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def home() -> str:
        return HOME_PAGE

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
