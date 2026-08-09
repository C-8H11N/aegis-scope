"""Deterministic, offline analysis of redacted AegisScope evidence.

The engine produces ranked candidates, never confirmed vulnerabilities. It does not
send requests, generate exploit payloads, expand scope, or consume credentials.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegisscope.analysis.models import (
    CandidateKind,
    Confidence,
    EvidenceAnalysis,
    LocalizedText,
    SeverityHint,
    VerificationPlan,
    VulnerabilityCandidate,
)
from aegisscope.contracts.results import StageSummary
from aegisscope.security.integrity import (
    atomic_write_new_text,
    canonical_sha256,
    sha256_file,
)

ERROR_MARKERS = re.compile(
    r"(?:traceback \(most recent call last\)|stack trace|uncaught exception|"
    r"sqlstate\[|at [\w.$]+\([\w.]+:\d+\)|debug mode)",
    re.I,
)
DIRECTORY_LISTING_MARKERS = re.compile(
    r"(?:<title>\s*index of\s*/|<h1>\s*index of\s*/|directory listing for)", re.I
)
SOURCE_MAP_MARKER = re.compile(r"(?:\/\/[#@]\s*sourceMappingURL=|sourceMappingURL\s*=)", re.I)
HIGH_RISK_REDACTIONS = {"api_key", "bearer_token", "jwt", "private_key"}


class EvidenceAnalysisError(ValueError):
    pass


def _read_bounded_text(root: Path, path: Path, *, max_bytes: int) -> str:
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise EvidenceAnalysisError("evidence path escapes evidence root") from exc
    if path.is_symlink() or not resolved.is_file():
        raise EvidenceAnalysisError(f"unsafe or missing evidence file: {path.name}")
    if resolved.stat().st_size > max_bytes:
        raise EvidenceAnalysisError(f"evidence file exceeds offline analysis limit: {path.name}")
    return resolved.read_text(encoding="utf-8")


def _text(zh_cn: str, en: str) -> LocalizedText:
    return LocalizedText(zh_cn=zh_cn, en=en)


def _verification(*, network_required: bool, purpose_zh: str, purpose_en: str) -> VerificationPlan:
    steps = [
        _text("先复核现有脱敏证据与最强的正常设计解释。", "Review redacted evidence and the strongest benign explanation first."),
        _text(purpose_zh, purpose_en),
    ]
    if network_required:
        steps.append(
            _text(
                "如离线证据不足，另行创建单一假设、最少请求的新阶段并获得明确授权。",
                "If offline evidence is insufficient, create a separately authorized single-hypothesis stage with minimal requests.",
            )
        )
    return VerificationPlan(
        network_required=network_required,
        new_authorization_required=network_required,
        steps=steps,
        stop_conditions=[
            _text("出现真实用户数据、认证流程、安全拦截或服务异常时立即停止。", "Stop on real user data, authentication, security blocking, or service instability."),
            _text("最小证据足以判断后立即停止，不扩大影响。", "Stop when the minimum evidence is sufficient; do not expand impact."),
        ],
    )


class EvidenceAnalyzer:
    """Analyze one completed evidence directory without network access."""

    def analyze(self, evidence_dir: Path) -> EvidenceAnalysis:
        root = evidence_dir.resolve()
        summary_path = root / "stage-summary.json"
        try:
            summary_payload = json.loads(
                _read_bounded_text(root, summary_path, max_bytes=2_097_152)
            )
            summary = StageSummary.model_validate(summary_payload)
        except (OSError, ValueError) as exc:
            raise EvidenceAnalysisError("stage-summary.json is invalid") from exc

        integrity = self._verify_index(root)
        candidates: dict[tuple[str, str], VulnerabilityCandidate] = {}
        for result in summary.results:
            response_path = root / f"request-{result.index:02d}" / "response.json"
            if not response_path.is_file():
                continue
            try:
                response = json.loads(
                    _read_bounded_text(root, response_path, max_bytes=1_048_576)
                )
            except (OSError, ValueError):
                continue
            if not isinstance(response, dict):
                continue
            body_path = root / f"request-{result.index:02d}" / "body.redacted.txt"
            body = (
                _read_bounded_text(root, body_path, max_bytes=1_048_576)
                if body_path.is_file()
                else ""
            )
            for candidate in self._analyze_response(
                summary.job_id,
                result.url,
                response,
                body,
                response_path,
                body_path if body_path.is_file() else None,
                root,
            ):
                key = (candidate.rule_id, candidate.affected_url)
                existing = candidates.get(key)
                if existing is None or candidate.risk_score > existing.risk_score:
                    candidates[key] = candidate

        ordered = sorted(
            candidates.values(), key=lambda item: (-item.risk_score, item.rule_id, item.affected_url)
        )
        return EvidenceAnalysis(
            job_id=summary.job_id,
            target_host=summary.target_host,
            generated_at=datetime.now(timezone.utc),
            source_summary_sha256=sha256_file(summary_path),
            evidence_integrity=integrity,
            candidate_count=sum(
                item.kind == CandidateKind.VULNERABILITY_CANDIDATE for item in ordered
            ),
            observation_count=sum(
                item.kind == CandidateKind.SECURITY_OBSERVATION for item in ordered
            ),
            safety_stop_count=sum(item.kind == CandidateKind.SAFETY_STOP for item in ordered),
            candidates=ordered,
            limitations=[
                _text(
                    "自动分析仅能发现线索；未进行服务器端影响验证，因此没有候选被自动标记为可提交漏洞。",
                    "Automation finds leads only; no server-side impact was verified, so no candidate is marked reportable.",
                ),
                _text(
                    "分析仅使用已保存且已脱敏的阶段证据，不会发起新的网络请求。",
                    "Analysis uses only saved, redacted stage evidence and sends no network requests.",
                ),
            ],
        )

    def write(self, analysis: EvidenceAnalysis, output_dir: Path) -> tuple[Path, Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = output_dir / "candidates.json"
        markdown_path = output_dir / "candidates.zh-CN.md"
        atomic_write_new_text(
            json_path,
            json.dumps(analysis.model_dump(mode="json"), ensure_ascii=False, indent=2),
        )
        lines = [
            f"# AegisScope 自动候选分析：{analysis.job_id}",
            "",
            "> 本报告只包含疑似漏洞和安全观察，不代表漏洞已经确认或可以直接提交。",
            "",
            f"- 目标：`{analysis.target_host}`",
            f"- 证据完整性：`{analysis.evidence_integrity}`",
            f"- 疑似漏洞：{analysis.candidate_count}",
            f"- 安全观察：{analysis.observation_count}",
            f"- 安全停止项：{analysis.safety_stop_count}",
            "",
        ]
        if not analysis.candidates:
            lines.extend(["未从当前证据中发现值得升级验证的候选。", ""])
        for index, candidate in enumerate(analysis.candidates, 1):
            safe_markdown_url = candidate.affected_url.replace("`", "%60")
            lines.extend(
                [
                    f"## {index}. {candidate.title.zh_cn}",
                    "",
                    f"- 类型：`{candidate.kind.value}`",
                    f"- 风险提示：`{candidate.severity_hint.value}`",
                    f"- 置信度：`{candidate.confidence.value}`",
                    f"- 排序分：`{candidate.risk_score}`",
                    f"- URL：`{safe_markdown_url}`",
                    f"- 可直接提交：`{str(candidate.reportable).lower()}`",
                    "",
                    candidate.rationale.zh_cn,
                    "",
                    "建议：" + candidate.verification.steps[-1].zh_cn,
                    "",
                ]
            )
        atomic_write_new_text(markdown_path, "\n".join(lines))
        return json_path, markdown_path

    @staticmethod
    def load(path: Path) -> EvidenceAnalysis:
        resolved = path.resolve()
        if path.is_symlink() or not resolved.is_file() or resolved.stat().st_size > 2_097_152:
            raise EvidenceAnalysisError("saved analysis is unsafe, missing, or too large")
        try:
            return EvidenceAnalysis.model_validate_json(resolved.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise EvidenceAnalysisError("saved analysis is invalid") from exc

    @staticmethod
    def _verify_index(root: Path) -> str:
        index_path = root / "evidence-index.json"
        if not index_path.is_file():
            return "not_available"
        try:
            payload = json.loads(_read_bounded_text(root, index_path, max_bytes=2_097_152))
            files = payload["files"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise EvidenceAnalysisError("evidence index is invalid") from exc
        if not isinstance(files, list):
            raise EvidenceAnalysisError("evidence index files must be a list")
        claimed_index_digest = payload.get("index_sha256")
        if claimed_index_digest is not None:
            unsigned_index = dict(payload)
            unsigned_index.pop("index_sha256", None)
            if canonical_sha256(unsigned_index) != claimed_index_digest:
                raise EvidenceAnalysisError("evidence index digest mismatch")
        for item in files:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                raise EvidenceAnalysisError("evidence index entry is invalid")
            candidate = (root / item["path"]).resolve()
            try:
                candidate.relative_to(root)
            except ValueError as exc:
                raise EvidenceAnalysisError("evidence index path escapes evidence root") from exc
            if not candidate.is_file() or sha256_file(candidate) != item.get("sha256"):
                raise EvidenceAnalysisError(f"evidence integrity mismatch: {item['path']}")
            if candidate.stat().st_size != item.get("bytes"):
                raise EvidenceAnalysisError(f"evidence size mismatch: {item['path']}")
        return "verified" if claimed_index_digest is not None else "verified_files_only"

    def _analyze_response(
        self,
        job_id: str,
        url: str,
        response: dict[str, Any],
        body: str,
        response_path: Path,
        body_path: Path | None,
        root: Path,
    ) -> list[VulnerabilityCandidate]:
        status = response.get("status_code")
        headers_raw = response.get("headers", {})
        headers = (
            {str(key).lower(): str(value) for key, value in headers_raw.items()}
            if isinstance(headers_raw, dict)
            else {}
        )
        content_type = str(response.get("content_type") or headers.get("content-type", "")).lower()
        evidence = [str(response_path.relative_to(root)).replace("\\", "/")]
        if body_path is not None:
            evidence.append(str(body_path.relative_to(root)).replace("\\", "/"))
        found: list[VulnerabilityCandidate] = []

        def add(
            rule_id: str,
            *,
            kind: CandidateKind,
            title: LocalizedText,
            category: str,
            severity: SeverityHint,
            confidence: Confidence,
            score: int,
            rationale: LocalizedText,
            benign: list[LocalizedText],
            verification: VerificationPlan,
        ) -> None:
            identity = canonical_sha256({"job": job_id, "rule": rule_id, "url": url})[:16]
            found.append(
                VulnerabilityCandidate(
                    candidate_id=f"cand-{identity}",
                    rule_id=rule_id,
                    kind=kind,
                    title=title,
                    category=category,
                    severity_hint=severity,
                    confidence=confidence,
                    risk_score=score,
                    affected_url=url,
                    evidence_files=evidence,
                    rationale=rationale,
                    benign_explanations=benign,
                    verification=verification,
                    reportable=False,
                )
            )

        redaction_values = response.get("body_redactions", [])
        body_redactions = (
            {str(value) for value in redaction_values}
            if isinstance(redaction_values, list)
            else set()
        )
        if HIGH_RISK_REDACTIONS.intersection(body_redactions):
            add(
                "sensitive_material_redacted",
                kind=CandidateKind.SAFETY_STOP,
                title=_text("响应疑似包含敏感凭据材料", "Response may contain sensitive credential material"),
                category="information_exposure",
                severity=SeverityHint.HIGH,
                confidence=Confidence.LOW,
                score=95,
                rationale=_text("脱敏器命中了高风险凭据模式。必须保持停止状态并先人工排除误报。", "The redactor matched a high-risk credential pattern. Keep the stage stopped and rule out false positives manually."),
                benign=[_text("示例代码、文档占位符或随机字符串可能触发正则。", "Example code, placeholders, or random strings may trigger the regex.")],
                verification=_verification(network_required=False, purpose_zh="只离线检查脱敏上下文，禁止重新请求或尝试使用任何值。", purpose_en="Inspect only the redacted context offline; never re-request or attempt to use any value."),
            )

        if body and ERROR_MARKERS.search(body) and isinstance(status, int) and status >= 400:
            add(
                "verbose_error_disclosure",
                kind=CandidateKind.VULNERABILITY_CANDIDATE,
                title=_text("公开错误响应疑似泄露调试或调用栈信息", "Public error response may disclose debug or stack details"),
                category="information_exposure",
                severity=SeverityHint.LOW,
                confidence=Confidence.MEDIUM,
                score=64,
                rationale=_text("错误状态正文包含典型调试、调用栈或数据库异常标记。", "An error response contains common debug, stack-trace, or database exception markers."),
                benign=[_text("页面可能是公开技术文档或转义后的示例内容。", "The page may be public documentation or escaped example content.")],
                verification=_verification(network_required=False, purpose_zh="确认泄露内容是否包含内部路径、组件或非公开实现细节。", purpose_en="Determine whether the content exposes internal paths, components, or non-public implementation details."),
            )

        if body and DIRECTORY_LISTING_MARKERS.search(body):
            add(
                "directory_listing",
                kind=CandidateKind.VULNERABILITY_CANDIDATE,
                title=_text("疑似启用了公开目录列表", "Public directory listing may be enabled"),
                category="security_misconfiguration",
                severity=SeverityHint.LOW,
                confidence=Confidence.HIGH,
                score=70,
                rationale=_text("响应正文呈现常见目录索引页面特征。", "The response body contains common directory-index page markers."),
                benign=[_text("该目录可能被明确设计为公开下载区。", "The directory may be intentionally public." )],
                verification=_verification(network_required=False, purpose_zh="先根据当前列表判断内容是否本应公开；不要自动访问列表中的文件。", purpose_en="Decide from the current listing whether the content is intended to be public; do not automatically fetch listed files."),
            )

        if body and SOURCE_MAP_MARKER.search(body):
            add(
                "source_map_reference",
                kind=CandidateKind.VULNERABILITY_CANDIDATE,
                title=_text("客户端资源引用 Source Map", "Client asset references a source map"),
                category="client_side_exposure",
                severity=SeverityHint.INFO,
                confidence=Confidence.HIGH,
                score=42,
                rationale=_text("已保存的公开客户端内容包含 Source Map 引用，但尚未访问映射文件。", "Saved public client content references a source map, but the map itself was not requested."),
                benign=[_text("Source Map 可能不存在、被限制，或不包含敏感源码。", "The source map may be absent, restricted, or contain no sensitive source." )],
                verification=_verification(network_required=True, purpose_zh="只有平台规则允许且单独授权后，才可对同一精确主机上的该固定映射 URL 发送一次 GET。", purpose_en="Only when program rules allow and a new stage is authorized may one GET be sent to that exact map URL on the same host."),
            )

        html_response = "html" in content_type or "<html" in body[:1000].lower()
        csp = headers.get("content-security-policy", "")
        if html_response and isinstance(status, int) and 200 <= status < 400:
            frame_ancestors = "frame-ancestors" in csp.lower()
            if "x-frame-options" not in headers and not frame_ancestors:
                add(
                    "missing_frame_protection",
                    kind=CandidateKind.VULNERABILITY_CANDIDATE,
                    title=_text("HTML 页面缺少显式嵌入保护", "HTML page lacks explicit framing protection"),
                    category="clickjacking_surface",
                    severity=SeverityHint.INFO,
                    confidence=Confidence.LOW,
                    score=34,
                    rationale=_text("响应未观察到 X-Frame-Options 或 CSP frame-ancestors。", "Neither X-Frame-Options nor CSP frame-ancestors was observed."),
                    benign=[_text("页面可能没有敏感操作，或嵌入行为是产品设计的一部分。", "The page may have no sensitive actions, or embedding may be intentional." )],
                    verification=_verification(network_required=False, purpose_zh="先离线确认页面是否包含可被诱导的敏感交互；仅缺少响应头不能认定漏洞。", purpose_en="First determine offline whether the page has sensitive interactions; a missing header alone is not a vulnerability."),
                )
            if csp and "'unsafe-inline'" in csp.lower() and "'unsafe-eval'" in csp.lower():
                add(
                    "weak_csp_policy",
                    kind=CandidateKind.SECURITY_OBSERVATION,
                    title=_text("CSP 同时允许 unsafe-inline 与 unsafe-eval", "CSP allows both unsafe-inline and unsafe-eval"),
                    category="defense_in_depth",
                    severity=SeverityHint.INFO,
                    confidence=Confidence.HIGH,
                    score=24,
                    rationale=_text("该策略削弱浏览器端纵深防御，但本身不能证明存在 XSS。", "This weakens browser defense in depth but does not prove XSS."),
                    benign=[_text("兼容旧前端框架可能需要该配置。", "Legacy frontend compatibility may require this configuration." )],
                    verification=_verification(network_required=False, purpose_zh="作为加固观察记录；没有独立注入证据时不要提交为 XSS。", purpose_en="Record as hardening guidance; do not submit as XSS without independent injection evidence."),
                )

        if (
            "strict-transport-security" not in headers
            and isinstance(status, int)
            and 200 <= status < 400
        ):
            add(
                "missing_hsts",
                kind=CandidateKind.SECURITY_OBSERVATION,
                title=_text("HTTPS 响应未观察到 HSTS", "HSTS was not observed on the HTTPS response"),
                category="transport_hardening",
                severity=SeverityHint.INFO,
                confidence=Confidence.HIGH,
                score=18,
                rationale=_text("当前响应头未包含 Strict-Transport-Security。该项通常属于加固观察。", "Strict-Transport-Security was absent from the response; this is usually a hardening observation."),
                benign=[_text("CDN、路径级配置或预加载状态可能影响实际风险。", "CDN behavior, path-specific configuration, or preload status may affect real risk." )],
                verification=_verification(network_required=False, purpose_zh="结合已有证据和平台收录规则判断是否仅为忽略级配置项。", purpose_en="Use existing evidence and program rules to determine whether this is only an informational configuration issue."),
            )

        if headers.get("access-control-allow-origin") == "*":
            add(
                "permissive_cors_observation",
                kind=CandidateKind.SECURITY_OBSERVATION,
                title=_text("响应使用通配符 CORS 来源", "Response uses a wildcard CORS origin"),
                category="cors_policy",
                severity=SeverityHint.INFO,
                confidence=Confidence.HIGH,
                score=20,
                rationale=_text("观察到 Access-Control-Allow-Origin: *；公开资源上这通常是正常设计。", "Access-Control-Allow-Origin: * was observed; this is commonly intentional for public resources."),
                benign=[_text("公开静态资源和无需认证的 API 可以合理使用通配符。", "Public static assets and unauthenticated APIs may reasonably use a wildcard." )],
                verification=_verification(network_required=False, purpose_zh="只有已有证据表明响应包含非公开敏感数据时才升级分析。", purpose_en="Escalate only if existing evidence shows that the response contains non-public sensitive data."),
            )
        return found
