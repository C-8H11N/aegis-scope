"""Windows-oriented control-plane CLI."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from aegisscope import __version__
from aegisscope.analysis.engine import EvidenceAnalysisError, EvidenceAnalyzer
from aegisscope.campaigns.models import CampaignCreateRequest, CampaignDecisionRequest
from aegisscope.campaigns.service import CampaignService, CampaignServiceError
from aegisscope.campaigns.store import CampaignStore
from aegisscope.config import Settings
from aegisscope.contracts.models import (
    JOB_ID_RE,
    Authorization,
    PlannerInput,
    StageManifest,
    StageProposal,
)
from aegisscope.findings.models import FindingStatus, FindingTransition
from aegisscope.findings.service import FindingLifecycleError, FindingService
from aegisscope.findings.store import AnalystStore
from aegisscope.i18n import translate
from aegisscope.orchestrator import Orchestrator, PreparationError
from aegisscope.providers.openai_compatible import OpenAICompatiblePlanner, PlannerResponseError
from aegisscope.reporting import ReportLanguage, load_report_template
from aegisscope.runner.executor import StageExecutor
from aegisscope.security.integrity import atomic_write_new_text, canonical_sha256
from aegisscope.transport.ssh import OpenSshTransport
from aegisscope.traffic.analyzer import TrafficAnalysisError, TrafficAnalyzer
from aegisscope.traffic.importer import TrafficImportError, TrafficImporter
from aegisscope.traffic.models import TrafficAnalysis

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


def _analyst_store(settings: Settings) -> AnalystStore:
    settings.ensure_local_directories()
    return AnalystStore(settings.data_dir / "db" / "aegisscope.sqlite3")


def _campaign_store(settings: Settings) -> CampaignStore:
    settings.ensure_local_directories()
    return CampaignStore(settings.data_dir / "db" / "aegisscope.sqlite3")


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
    orchestrator = Orchestrator(settings)
    try:
        prepared = orchestrator.prepare_file(manifest)
    except PreparationError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    console.print(f"[green]{translate('prepared', settings.language)}[/green]")
    console.print(prepared.job_id)
    prepared_job = orchestrator.store.get_job(prepared.job_id)
    if prepared_job:
        console.print(f"SHA-256: {prepared_job['manifest_sha256']}")


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
    try:
        proposal = planner.propose(request)
    except PlannerResponseError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
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
    confirm_proposal_sha256: str | None = typer.Option(
        None,
        "--confirm-proposal-sha256",
        help="Required with --network-enabled; must match the reviewed proposal",
    ),
) -> None:
    """Convert a reviewed proposal into a stage manifest / 将已审核提案转为阶段清单。"""

    proposal = StageProposal.model_validate(_load_object(proposal_path))
    proposal_digest = canonical_sha256(proposal.model_dump(mode="json"))
    if network_enabled and confirm_proposal_sha256 != proposal_digest:
        console.print("[red]Proposal digest confirmation is required for network use.[/red]")
        console.print(f"SHA-256: {proposal_digest}")
        raise typer.Exit(2)
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
        notes=f"Created from {proposal.proposal_id}; proposal_sha256={proposal_digest}",
    )
    _write_model(output, manifest)
    console.print(f"[green]Manifest / 阶段清单: {output}[/green]")
    console.print(f"Proposal SHA-256: {proposal_digest}")
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


@app.command("analyze-evidence")
def analyze_evidence(
    evidence_dir: Path,
    output_dir: Path | None = typer.Option(
        None, help="Defaults to <evidence-dir>/analysis / 默认写入证据目录下的 analysis"
    ),
) -> None:
    """Find ranked candidates offline; send no requests / 离线发现并排序漏洞候选。"""

    analyzer = EvidenceAnalyzer()
    try:
        analysis = analyzer.analyze(evidence_dir)
        json_path, markdown_path = analyzer.write(
            analysis, output_dir or evidence_dir / "analysis"
        )
    except (EvidenceAnalysisError, FileExistsError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    console.print(
        f"[green]Candidates / 疑似漏洞: {analysis.candidate_count}; "
        f"observations / 观察: {analysis.observation_count}[/green]"
    )
    console.print(str(json_path))
    console.print(str(markdown_path))


@app.command("traffic-import")
def traffic_import(
    source: Path,
    program_name: str = typer.Option(..., "--program-name"),
    allow_host: list[str] = typer.Option(..., "--allow-host"),
    deny_host: list[str] | None = typer.Option(None, "--deny-host"),
    role: str = typer.Option("unknown", "--role"),
    source_format: str = typer.Option("auto", "--format"),
) -> None:
    """Import HAR/Burp XML as redacted derived data / 脱敏导入流量。"""

    settings = Settings.from_env()
    importer = TrafficImporter()
    try:
        document = importer.import_file(
            source,
            program_name=program_name,
            allowlist=allow_host,
            denylist=deny_host or [],
            role_hint=role,
            source_format=source_format,
        )
        output = settings.data_dir / "imports" / document.import_id
        paths = importer.write(document, output)
        _analyst_store(settings).put_import(document)
    except (TrafficImportError, FileExistsError, ValueError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    console.print(
        f"[green]Imported / 已导入: {document.record_count}; "
        f"out-of-scope skipped / 跳过范围外: {document.skipped_out_of_scope}[/green]"
    )
    console.print(str(paths[0]))
    console.print("Raw request bodies, cookies, and tokens were not persisted.")


@app.command("traffic-analyze")
def traffic_analyze(
    traffic_files: list[Path] = typer.Argument(..., help="1-20 derived traffic.json files"),
) -> None:
    """Compare redacted captures offline / 离线比较脱敏流量。"""

    settings = Settings.from_env()
    try:
        imports = [TrafficImporter.load(path) for path in traffic_files]
        analysis = TrafficAnalyzer().analyze(imports)
        output = settings.data_dir / "traffic-analyses" / analysis.analysis_id
        paths = TrafficAnalyzer().write(analysis, output)
        store = _analyst_store(settings)
        store.put_analysis(analysis)
        created = FindingService(store).ingest(analysis)
    except (TrafficImportError, TrafficAnalysisError, FileExistsError, ValueError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    console.print(
        f"[green]Candidates / 候选: {analysis.candidate_count}; "
        f"new findings / 新记录: {created}; confirmed / 已确认: 0[/green]"
    )
    console.print(str(paths[0]))


@app.command("campaign-create")
def campaign_create(
    specification: Path = typer.Argument(..., help="CampaignCreateRequest JSON file"),
    output: Path | None = typer.Option(None, "--output"),
) -> None:
    """Create a local autonomous planning campaign / 创建本地自主规划任务。"""

    settings = Settings.from_env()
    try:
        request = CampaignCreateRequest.model_validate(_load_object(specification))
        campaign = CampaignService(_campaign_store(settings)).create(request)
        if output:
            _write_model(output, campaign)
    except (ValueError, FileExistsError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    console.print(f"[green]Campaign / 研究任务: {campaign.campaign_id}[/green]")
    console.print("Local planning only; target execution is not authorized.")


@app.command("campaign-plan")
def campaign_plan(
    campaign_id: str,
    analysis_id: list[str] | None = typer.Option(None, "--analysis-id"),
    output: Path | None = typer.Option(None, "--output"),
) -> None:
    """Rank evidence and select one bounded next action / 排序证据并选择下一步。"""

    settings = Settings.from_env()
    analyst_store = _analyst_store(settings)
    campaign_store = _campaign_store(settings)
    campaign = campaign_store.get(campaign_id)
    if campaign is None:
        console.print("[red]Unknown campaign_id / 未知研究任务[/red]")
        raise typer.Exit(2)
    analyses: list[TrafficAnalysis] = []
    if analysis_id:
        for identity in analysis_id:
            analysis = analyst_store.get_analysis(identity)
            if analysis is None:
                console.print(f"[red]Unknown analysis_id: {identity}[/red]")
                raise typer.Exit(2)
            analyses.append(analysis)
    else:
        analyses = [
            TrafficAnalysis.model_validate(payload)
            for payload in analyst_store.list_analyses(100)
            if payload.get("program_name") == campaign.program_name
        ][:20]
    try:
        planned = CampaignService(campaign_store).plan(campaign_id, analyses)
        if output:
            _write_model(output, planned)
    except (CampaignServiceError, ValueError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    console.print(f"[green]{planned.status.value}: {planned.next_action.kind.value}[/green]")
    console.print(planned.next_action.title.zh_cn)
    console.print("No target request was sent / 未发送任何目标请求")


@app.command("campaign-list")
def campaign_list(limit: int = typer.Option(100, min=1, max=500)) -> None:
    """List local campaigns / 列出本地研究任务。"""

    settings = Settings.from_env()
    table = Table(title="Campaigns / 研究任务")
    for heading in ("ID", "Target", "Status", "Hypotheses", "Next action"):
        table.add_column(heading)
    for campaign in _campaign_store(settings).list(limit):
        table.add_row(
            campaign.campaign_id,
            campaign.target_host,
            campaign.status.value,
            str(len(campaign.hypotheses)),
            campaign.next_action.kind.value,
        )
    console.print(table)


@app.command("campaign-export-proposal")
def campaign_export_proposal(
    campaign_id: str,
    output: Path = typer.Option(Path("campaign-proposal.json"), "--output"),
) -> None:
    """Export the pending unapproved proposal / 导出待人工授权的阶段提案。"""

    settings = Settings.from_env()
    campaign = _campaign_store(settings).get(campaign_id)
    if campaign is None:
        console.print("[red]Unknown campaign_id / 未知研究任务[/red]")
        raise typer.Exit(2)
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
        console.print("[red]Campaign has no pending stage proposal.[/red]")
        raise typer.Exit(2)
    _write_model(output, hypothesis.proposal)
    console.print(f"[green]Proposal / 待授权提案: {output}[/green]")
    console.print("Use `aegisscope authorize` after human review; no network request was sent.")


@app.command("campaign-decision")
def campaign_decision(
    campaign_id: str,
    hypothesis_id: str = typer.Option(..., "--hypothesis-id"),
    disposition: str = typer.Option(..., "--disposition"),
    statement: str = typer.Option(..., "--statement"),
    consumed_requests: int = typer.Option(0, "--consumed-requests", min=0, max=20),
) -> None:
    """Record a human-reviewed result and continue planning / 记录人工结论并继续规划。"""

    settings = Settings.from_env()
    try:
        request = CampaignDecisionRequest(
            hypothesis_id=hypothesis_id,
            disposition=cast(Any, disposition),
            statement=statement,
            consumed_requests=consumed_requests,
        )
        campaign = CampaignService(_campaign_store(settings)).record_decision(
            campaign_id, request
        )
    except (CampaignServiceError, KeyError, ValueError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    console.print(f"[green]{campaign.status.value}: {campaign.next_action.kind.value}[/green]")


@app.command("finding-list")
def finding_list(limit: int = typer.Option(100, min=1, max=500)) -> None:
    """List local finding lifecycle records / 列出本地漏洞记录。"""

    settings = Settings.from_env()
    findings = _analyst_store(settings).list_findings(limit)
    table = Table(title="Findings / 漏洞记录")
    for heading in ("ID", "Status", "Severity", "Endpoint", "Reportable"):
        table.add_column(heading)
    for finding in findings:
        table.add_row(
            finding.finding_id,
            finding.status.value,
            finding.severity_hint.value,
            finding.endpoint_key,
            "yes" if finding.reportable else "no",
        )
    console.print(table)


@app.command("finding-transition")
def finding_transition(
    finding_id: str,
    to_status: FindingStatus = typer.Option(..., "--to"),
    statement: str = typer.Option(..., "--statement"),
    impact: str | None = typer.Option(None, "--impact"),
    remediation: str | None = typer.Option(None, "--remediation"),
    duplicate_of: str | None = typer.Option(None, "--duplicate-of"),
) -> None:
    """Apply a human-reviewed lifecycle transition / 人工审核后变更状态。"""

    settings = Settings.from_env()
    try:
        request = FindingTransition(
            to_status=to_status,
            statement=statement,
            impact=impact,
            remediation=remediation,
            duplicate_of=duplicate_of,
        )
        finding = FindingService(_analyst_store(settings)).transition(finding_id, request)
    except (FindingLifecycleError, KeyError, ValueError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    console.print(
        f"[green]{finding.finding_id}: {finding.status.value}; "
        f"reportable={finding.reportable}[/green]"
    )


@app.command("finding-report")
def finding_report(
    finding_id: str,
    output: Path = typer.Option(Path("finding-report.zh-CN.md"), "--output"),
    language: str = typer.Option("zh-CN", "--language"),
) -> None:
    """Render a report only after human confirmation / 仅为人工确认项生成报告。"""

    settings = Settings.from_env()
    try:
        path = FindingService(_analyst_store(settings)).render_report(
            finding_id, output, language=language
        )
    except (FindingLifecycleError, KeyError, FileExistsError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc
    console.print(f"[green]Report / 报告: {path}[/green]")


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
    local_digest = settings.data_dir / "jobs" / prepared.job_id / "manifest.sha256"
    local_output_root = settings.data_dir / "evidence"
    local_output_root.mkdir(parents=True, exist_ok=True)
    local_job_output = local_output_root / prepared.job_id
    transport_log = settings.data_dir / "jobs" / prepared.job_id / "dispatch-result.json"
    transport = OpenSshTransport(alias=settings.ssh_alias, remote_root=settings.remote_root)
    commands = transport.build_commands(
        manifest_path=local_manifest,
        manifest_digest_path=local_digest,
        job_id=prepared.job_id,
        local_output_dir=local_output_root,
    )
    table = Table(title="SSH dispatch plan / SSH 调度计划")
    table.add_column("Step")
    table.add_column("Command")
    for name, command in commands.ordered():
        table.add_row(name, " ".join(command))
    console.print(f"Manifest SHA-256: {local_digest.read_text(encoding='ascii').strip()}")
    console.print(table)
    if not execute:
        console.print("[yellow]Preview only / 仅预览[/yellow]")
        return
    if transport_log.exists() or local_job_output.exists():
        console.print(
            "[red]This job already has dispatch or evidence state; create a new authorized "
            "job_id instead of replaying it. / 该任务已有调度或证据状态，请重新授权并创建新 job_id。[/red]"
        )
        raise typer.Exit(2)
    orchestrator.store.set_status(prepared.job_id, "dispatching")
    orchestrator.store.append_event(prepared.job_id, "dispatch_started")
    result = transport.run(commands)
    atomic_write_new_text(
        transport_log,
        json.dumps(asdict(result), ensure_ascii=False, indent=2),
    )
    for step in result.steps:
        orchestrator.store.append_event(
            prepared.job_id,
            f"transport_{step.name}",
            {"returncode": step.returncode},
        )

    summary_path = local_job_output / "stage-summary.json"
    if summary_path.is_file():
        summary_payload = _load_object(summary_path)
        status = str(summary_payload.get("stage_status", "failed"))
        orchestrator.store.set_summary(prepared.job_id, status, summary_payload)
    else:
        execute_step = next((step for step in result.steps if step.name == "execute"), None)
        download_step = next((step for step in result.steps if step.name == "download"), None)
        if execute_step and execute_step.returncode == 0 and (
            download_step is None or download_step.returncode != 0
        ):
            orchestrator.store.set_status(prepared.job_id, "evidence_transfer_failed")
        else:
            orchestrator.store.set_status(prepared.job_id, "failed")

    if not result.succeeded:
        console.print(f"[red]Dispatch failed; redacted log / 调度失败，脱敏日志: {transport_log}[/red]")
        raise typer.Exit(3)

    console.print(f"[green]Evidence / 证据: {local_job_output}[/green]")
    try:
        analysis = EvidenceAnalyzer().analyze(local_job_output)
        analysis_paths = EvidenceAnalyzer().write(analysis, local_job_output / "analysis")
        orchestrator.store.set_analysis(
            prepared.job_id, analysis.model_dump(mode="json")
        )
        orchestrator.store.set_status(prepared.job_id, "offline_analyzed")
        orchestrator.store.append_event(
            prepared.job_id,
            "offline_analysis_completed",
            {
                "candidate_count": analysis.candidate_count,
                "observation_count": analysis.observation_count,
            },
        )
        console.print(
            f"[green]Auto triage / 自动研判: {analysis.candidate_count} candidates, "
            f"{analysis.observation_count} observations[/green]"
        )
        console.print(str(analysis_paths[1]))
    except (EvidenceAnalysisError, FileExistsError) as exc:
        orchestrator.store.append_event(
            prepared.job_id, "offline_analysis_failed", {"error": exc.__class__.__name__}
        )
        console.print(f"[yellow]Offline analysis not completed / 离线研判未完成: {exc}[/yellow]")


@app.command("recover-evidence")
def recover_evidence(
    job_id: str,
    execute: bool = typer.Option(False, "--execute", help="Perform SCP recovery only"),
) -> None:
    """Recover remote evidence without rerunning a target stage / 只恢复证据，不重放请求。"""

    settings = Settings.from_env()
    orchestrator = Orchestrator(settings)
    if not JOB_ID_RE.fullmatch(job_id):
        console.print("[red]Invalid job_id / 任务 ID 无效[/red]")
        raise typer.Exit(2)
    job = orchestrator.store.get_job(job_id)
    if job is None:
        console.print("[red]Unknown job_id / 未知任务[/red]")
        raise typer.Exit(2)
    recovery_root = (
        settings.data_dir / "recovery" / job_id / f"attempt-{uuid4().hex[:12]}"
    )
    transport = OpenSshTransport(alias=settings.ssh_alias, remote_root=settings.remote_root)
    command = transport.build_download_command(
        job_id=job_id, local_output_dir=recovery_root
    )
    console.print("Evidence-only recovery / 仅恢复证据（不会调用 Runner）")
    console.print(" ".join(command))
    if not execute:
        console.print("[yellow]Preview only / 仅预览[/yellow]")
        return
    recovery_root.mkdir(parents=True, exist_ok=False)
    result = transport.recover_evidence(command)
    orchestrator.store.append_event(
        job_id, "evidence_recovery", {"returncode": result.returncode}
    )
    if result.returncode != 0:
        console.print(f"[red]{result.stderr or 'SCP recovery failed'}[/red]")
        raise typer.Exit(3)
    recovered_job = recovery_root / job_id
    console.print(f"[green]Recovered / 已恢复: {recovered_job}[/green]")
    try:
        analysis = EvidenceAnalyzer().analyze(recovered_job)
        EvidenceAnalyzer().write(analysis, recovered_job / "analysis")
        orchestrator.store.set_analysis(job_id, analysis.model_dump(mode="json"))
        orchestrator.store.set_status(job_id, "offline_analyzed")
        console.print(
            f"[green]Auto triage / 自动研判: {analysis.candidate_count} candidates[/green]"
        )
    except EvidenceAnalysisError as exc:
        console.print(f"[yellow]Evidence recovered but analysis failed: {exc}[/yellow]")


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
