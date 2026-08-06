"""Windows-oriented control-plane CLI."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from aegisscope import __version__
from aegisscope.config import Settings
from aegisscope.contracts.models import Authorization, PlannerInput, StageManifest, StageProposal
from aegisscope.i18n import translate
from aegisscope.orchestrator import Orchestrator, PreparationError
from aegisscope.providers.openai_compatible import OpenAICompatiblePlanner
from aegisscope.runner.executor import StageExecutor
from aegisscope.reporting import ReportLanguage, load_report_template
from aegisscope.transport.ssh import OpenSshTransport

app = typer.Typer(
    name="aegisscope",
    help="Authorization-first SRC orchestration / 授权优先的 SRC 编排",
    no_args_is_help=True,
)
console = Console()


def _load_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise typer.BadParameter("JSON root must be an object")
    return payload


def _write_model(path: Path, model: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(model.model_dump(mode="json"), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


@app.command("version")
def version() -> None:
    """Show the installed version / 显示版本。"""

    console.print(f"AegisScope {__version__}")


@app.command("init")
def initialize() -> None:
    """Initialize local control-plane data / 初始化本地控制面数据。"""

    settings = Settings.from_env()
    Orchestrator(settings)
    console.print(f"[green]{translate('ready', settings.language)}[/green]")
    console.print(str(settings.data_dir))


@app.command("schema")
def schema(output: Path | None = typer.Option(None, help="Optional JSON output path")) -> None:
    """Print the strict stage schema / 输出严格阶段结构。"""

    content = json.dumps(StageManifest.model_json_schema(), ensure_ascii=False, indent=2)
    if output:
        output.write_text(content, encoding="utf-8")
    else:
        console.print_json(content)


@app.command("validate")
def validate(manifest: Path) -> None:
    """Validate without dispatch / 仅校验，不发送。"""

    settings = Settings.from_env()
    decision = Orchestrator(settings).validate(_load_object(manifest))
    color = "green" if decision.allowed else "red"
    key = "allowed" if decision.allowed else "denied"
    console.print(f"[{color}]{translate(key, settings.language)}[/{color}]")
    for error in decision.errors:
        console.print(f"[red]- {error}[/red]")
    for warning in decision.warnings:
        console.print(f"[yellow]- {warning}[/yellow]")
    if not decision.allowed:
        raise typer.Exit(2)


@app.command("prepare")
def prepare(manifest: Path) -> None:
    """Store an approved job locally; do not dispatch / 本地准备，不发送。"""

    settings = Settings.from_env()
    try:
        prepared = Orchestrator(settings).prepare_file(manifest)
    except PreparationError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    console.print(f"[green]{translate('prepared', settings.language)}[/green]")
    console.print(prepared.job_id)


@app.command("propose")
def propose(
    planner_input: Path,
    output: Path = typer.Option(Path("proposal.json"), help="Proposal output path"),
) -> None:
    """Use a configured API to create an unapproved proposal / 使用 API 生成待审批提案。"""

    settings = Settings.from_env()
    if not (settings.llm_base_url and settings.llm_api_key and settings.llm_model):
        console.print(f"[red]{translate('api_unconfigured', settings.language)}[/red]")
        raise typer.Exit(2)
    request = PlannerInput.model_validate(_load_object(planner_input))
    planner = OpenAICompatiblePlanner(
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key,
        model=settings.llm_model,
    )
    proposal = planner.propose(request)
    _write_model(output, proposal)
    console.print(f"[green]Proposal / 提案: {output}[/green]")
    console.print("Authorization required / 仍需人工授权")


@app.command("authorize")
def authorize(
    proposal_path: Path,
    statement: str = typer.Option(..., help="Exact user authorization statement"),
    output: Path = typer.Option(Path("stage.json"), help="Manifest output path"),
    valid_hours: int = typer.Option(1, min=1, max=24),
    network_enabled: bool = typer.Option(
        False, "--network-enabled", help="Create dry_run=false manifest after review"
    ),
) -> None:
    """Convert a reviewed proposal into a stage manifest / 将已审核提案转为阶段清单。"""

    proposal = StageProposal.model_validate(_load_object(proposal_path))
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=valid_hours)
    manifest = StageManifest(
        job_id=f"stage-{uuid4()}",
        program_name=proposal.program_name,
        stage_type=proposal.stage_type,
        target_host=proposal.target_host,
        allowlist=proposal.allowlist,
        denylist=proposal.denylist,
        authorization=Authorization(
            granted=True,
            scope="stage",
            user_statement=statement,
            granted_at=now,
            expires_at=expires,
        ),
        dry_run=not network_enabled,
        requests=proposal.requests,
        limits=proposal.limits,
        created_at=now,
        expires_at=expires,
        notes=f"Created from {proposal.proposal_id}",
    )
    _write_model(output, manifest)
    console.print(f"[green]Manifest / 阶段清单: {output}[/green]")
    console.print(f"dry_run={manifest.dry_run}")


@app.command("runner-dry-run")
def runner_dry_run(manifest: Path) -> None:
    """Exercise the runner locally with its network gate closed / 本地无网络演练。"""

    settings = Settings.from_env()
    decision = Orchestrator(settings).validate(_load_object(manifest))
    if not decision.allowed or decision.manifest is None:
        for error in decision.errors:
            console.print(f"[red]- {error}[/red]")
        raise typer.Exit(2)
    output = settings.data_dir / "jobs" / decision.manifest.job_id / "local-dry-run"
    summary = StageExecutor(output_dir=output, network_gate=False).run(decision.manifest)
    console.print(f"[green]{translate('dry_run', settings.language)}[/green]")
    console.print_json(json.dumps(summary.model_dump(mode="json"), ensure_ascii=False))


@app.command("report-template")
def report_template(
    language: str = typer.Option("zh-CN", help="zh-CN or en"),
    output: Path = typer.Option(Path("report.md")),
) -> None:
    """Write a bilingual report template / 输出中英文报告模板。"""

    if language not in {"zh-CN", "en"}:
        raise typer.BadParameter("language must be zh-CN or en")
    template = load_report_template(cast(ReportLanguage, language))
    output.write_text(template, encoding="utf-8")
    console.print(f"[green]Report template / 报告模板: {output}[/green]")


@app.command("dispatch")
def dispatch(
    manifest: Path,
    execute: bool = typer.Option(False, "--execute", help="Actually invoke SSH/SCP"),
) -> None:
    """Preview or perform the fixed SSH dispatch / 预览或执行固定 SSH 调度。"""

    settings = Settings.from_env()
    orchestrator = Orchestrator(settings)
    try:
        prepared = orchestrator.prepare_file(manifest)
    except PreparationError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    local_manifest = settings.data_dir / "jobs" / prepared.job_id / "manifest.json"
    local_output = settings.data_dir / "evidence" / prepared.job_id
    local_output.mkdir(parents=True, exist_ok=True)
    transport = OpenSshTransport(alias=settings.ssh_alias, remote_root=settings.remote_root)
    commands = transport.build_commands(
        manifest_path=local_manifest,
        job_id=prepared.job_id,
        local_output_dir=local_output,
    )
    table = Table(title="SSH dispatch plan / SSH 调度计划")
    table.add_column("Step")
    table.add_column("Command")
    for name, command in (
        ("upload", commands.upload),
        ("execute", commands.execute),
        ("download", commands.download),
    ):
        table.add_row(name, " ".join(command))
    console.print(table)
    if not execute:
        console.print("[yellow]Preview only / 仅预览[/yellow]")
        return
    transport.run(commands)
    console.print(f"[green]Evidence / 证据: {local_output}[/green]")


@app.command("serve")
def serve(
    host: str = typer.Option("127.0.0.1"),
    port: int = typer.Option(8765, min=1024, max=65535),
) -> None:
    """Run the local Web control plane / 启动本地 Web 控制面。"""

    if host not in {"127.0.0.1", "localhost", "::1"}:
        console.print("[red]MVP Web UI is restricted to loopback / MVP 仅允许本机监听[/red]")
        raise typer.Exit(2)
    uvicorn.run("aegisscope.web.app:app", host=host, port=port, reload=False)
