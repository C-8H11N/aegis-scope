"""Deterministic, offline comparison of redacted traffic imports."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from aegisscope.analysis.models import Confidence, LocalizedText, SeverityHint
from aegisscope.security.integrity import atomic_write_new_text, canonical_sha256
from aegisscope.traffic.models import (
    DuplicateCluster,
    EndpointDiff,
    TrafficAnalysis,
    TrafficCandidate,
    TrafficCandidateKind,
    TrafficImport,
    TrafficRecord,
)

GUEST_ROLES = {"guest", "anonymous", "public", "unauthenticated"}
SENSITIVE_FIELD_RE = re.compile(
    r"(?:^|[._])(?:email|e-mail|phone|mobile|address|token|secret|password|passwd|"
    r"id_card|identity|bank|card|credential)(?:$|[._])",
    re.I,
)
PRIVILEGED_PATH_RE = re.compile(
    r"/(?:admin|account|profile|user|users|order|orders|invoice|billing|internal|manage|api)(?:/|$)",
    re.I,
)
VERBOSE_ERROR_RE = re.compile(
    r"(?:traceback|stack trace|exception at|sqlstate|syntax error|fatal error|"
    r"at [\w.$]+\([^\n]+:\d+\)|/var/www/|\\inetpub\\)",
    re.I,
)


class TrafficAnalysisError(ValueError):
    pass


def _text(zh_cn: str, en: str) -> LocalizedText:
    return LocalizedText(zh_cn=zh_cn, en=en)


def _ref(import_id: str, record: TrafficRecord) -> str:
    return f"{import_id}/{record.record_id}"


def _success(record: TrafficRecord) -> bool:
    return record.response_status is not None and 200 <= record.response_status < 300


class TrafficAnalyzer:
    """Correlate derived traffic without replaying a single HTTP request."""

    def analyze(self, imports: list[TrafficImport]) -> TrafficAnalysis:
        if not imports or len(imports) > 20:
            raise TrafficAnalysisError("analysis requires 1-20 derived traffic imports")
        programs = {document.program_name for document in imports}
        if len(programs) != 1:
            raise TrafficAnalysisError("all imports must belong to the same program")

        grouped: dict[str, list[tuple[str, TrafficRecord]]] = defaultdict(list)
        for document in imports:
            for record in document.records:
                grouped[record.endpoint_key].append((document.import_id, record))

        diffs = [self._diff(endpoint, rows) for endpoint, rows in sorted(grouped.items())]
        candidates: list[TrafficCandidate] = []
        for endpoint, rows in sorted(grouped.items()):
            candidates.extend(self._candidates(endpoint, rows))
        unique_candidates = {candidate.fingerprint: candidate for candidate in candidates}
        candidates = sorted(
            unique_candidates.values(), key=lambda item: (-item.risk_score, item.candidate_id)
        )
        duplicate_clusters = self._duplicate_clusters(imports)
        identity = canonical_sha256(
            {
                "imports": sorted((item.import_id, item.source_sha256) for item in imports),
                "candidate_fingerprints": sorted(unique_candidates),
            }
        )[:16]
        return TrafficAnalysis(
            analysis_id=f"traffic-analysis-{identity}",
            program_name=next(iter(programs)),
            import_ids=sorted(document.import_id for document in imports),
            generated_at=max(document.imported_at for document in imports),
            endpoint_count=len(grouped),
            candidate_count=len(candidates),
            duplicate_cluster_count=len(duplicate_clusters),
            diffs=diffs,
            candidates=candidates,
            duplicate_clusters=duplicate_clusters,
            automatically_verified_findings=0,
            limitations=[
                _text(
                    "全部结论来自已脱敏流量的离线差异分析，未发送新请求，也未验证真实安全影响。",
                    "All conclusions come from offline comparison of redacted traffic; no new request or security impact validation occurred.",
                ),
                _text(
                    "候选项不能直接提交；需要在新的、明确授权的最小化阶段中人工复核。",
                    "Candidates are not reportable and require human review in a separately authorized minimal validation stage.",
                ),
            ],
        )

    def write(self, analysis: TrafficAnalysis, output_dir: Path) -> tuple[Path, Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = output_dir / "traffic-analysis.json"
        markdown_path = output_dir / "traffic-analysis.zh-CN.md"
        if json_path.exists() or markdown_path.exists():
            raise FileExistsError("traffic analysis output is write-once")
        atomic_write_new_text(
            json_path,
            json.dumps(analysis.model_dump(mode="json"), ensure_ascii=False, indent=2),
        )
        lines = [
            f"# 离线流量分析：{analysis.analysis_id}",
            "",
            "> 本结果只包含待人工复核的线索，不代表已确认漏洞，也不会自动生成可提交报告。",
            "",
            f"- 项目：{analysis.program_name}",
            f"- 导入批次：{len(analysis.import_ids)}",
            f"- 归一化接口：{analysis.endpoint_count}",
            f"- 候选线索：{analysis.candidate_count}",
            f"- 疑似同代码重复簇：{analysis.duplicate_cluster_count}",
            f"- 自动确认漏洞：{analysis.automatically_verified_findings}",
            "",
            "## 候选线索",
            "",
        ]
        if not analysis.candidates:
            lines.append("未发现值得升级验证的候选线索。")
        for item in analysis.candidates:
            lines.extend(
                [
                    f"### {item.title.zh_cn}",
                    "",
                    f"- 类型：`{item.kind.value}`",
                    f"- 严重性提示：`{item.severity_hint.value}`",
                    f"- 置信度：`{item.confidence.value}`",
                    f"- 接口：`{item.endpoint_key}`",
                    f"- 说明：{item.rationale.zh_cn}",
                    f"- 下一步：{item.next_step.zh_cn}",
                    "",
                ]
            )
        atomic_write_new_text(markdown_path, "\n".join(lines))
        return json_path, markdown_path

    @staticmethod
    def load(path: Path) -> TrafficAnalysis:
        try:
            return TrafficAnalysis.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise TrafficAnalysisError("traffic analysis document is invalid") from exc

    @staticmethod
    def _diff(
        endpoint: str, rows: list[tuple[str, TrafficRecord]]
    ) -> EndpointDiff:
        statuses: dict[str, list[int]] = defaultdict(list)
        body_hashes: set[str] = set()
        shape_hashes: set[str] = set()
        auth_states: set[bool] = set()
        refs: list[str] = []
        for import_id, record in rows:
            if record.response_status is not None:
                statuses[record.role_hint].append(record.response_status)
            if record.response_body_sha256:
                body_hashes.add(record.response_body_sha256)
            if record.response_json_shape_sha256:
                shape_hashes.add(record.response_json_shape_sha256)
            auth_states.add(bool(record.authentication_markers))
            refs.append(_ref(import_id, record))
        first = rows[0][1]
        return EndpointDiff(
            endpoint_key=endpoint,
            host=first.host,
            roles=sorted({record.role_hint for _import_id, record in rows}),
            statuses={role: sorted(set(values)) for role, values in sorted(statuses.items())},
            body_changed=len(body_hashes) > 1,
            json_shape_changed=len(shape_hashes) > 1,
            authentication_state_changed=len(auth_states) > 1,
            record_refs=sorted(refs),
        )

    def _candidates(
        self, endpoint: str, rows: list[tuple[str, TrafficRecord]]
    ) -> list[TrafficCandidate]:
        result: list[TrafficCandidate] = []
        guests = [(import_id, record) for import_id, record in rows if record.role_hint in GUEST_ROLES]
        authenticated = [
            (import_id, record)
            for import_id, record in rows
            if record.role_hint not in GUEST_ROLES and record.role_hint != "unknown"
        ]
        guest_success = [row for row in guests if _success(row[1]) and not row[1].authentication_markers]
        auth_success = [row for row in authenticated if _success(row[1])]

        if guest_success and auth_success and PRIVILEGED_PATH_RE.search(rows[0][1].normalized_path):
            matching_shape = any(
                guest.response_json_shape_sha256
                and guest.response_json_shape_sha256 == auth.response_json_shape_sha256
                for _guest_import, guest in guest_success
                for _auth_import, auth in auth_success
            )
            result.append(
                self._candidate(
                    kind=TrafficCandidateKind.AUTHORIZATION_BOUNDARY,
                    endpoint=endpoint,
                    rows=guest_success + auth_success,
                    title=_text("疑似未认证访问受限接口", "Possible unauthenticated access to a restricted endpoint"),
                    severity=SeverityHint.HIGH,
                    confidence=Confidence.MEDIUM if matching_shape else Confidence.LOW,
                    score=68 if matching_shape else 55,
                    rationale=_text(
                        "访客与已认证角色在疑似受限路径上均得到成功响应；离线数据不足以判断内容是否敏感或接口是否本应公开。",
                        "Guest and authenticated roles both received successful responses on a potentially restricted path; offline data cannot establish sensitivity or intended visibility.",
                    ),
                    next_step=_text(
                        "先由人工确认接口业务语义；如仍可疑，为单一接口申请新的最小化权限边界验证阶段。",
                        "Confirm the endpoint's business purpose first; if still suspicious, request a new minimal authorization-boundary validation stage for this endpoint only.",
                    ),
                )
            )

        authenticated_roles = {record.role_hint for _import_id, record in auth_success}
        identical_body = {
            record.response_body_sha256
            for _import_id, record in auth_success
            if record.response_body_sha256
        }
        if (
            len(authenticated_roles) >= 2
            and len(identical_body) == 1
            and PRIVILEGED_PATH_RE.search(rows[0][1].normalized_path)
        ):
            result.append(
                self._candidate(
                    kind=TrafficCandidateKind.AUTHORIZATION_BOUNDARY,
                    endpoint=endpoint,
                    rows=auth_success,
                    title=_text(
                        "不同认证角色的响应内容完全一致",
                        "Different authenticated roles received identical response content",
                    ),
                    severity=SeverityHint.MEDIUM,
                    confidence=Confidence.LOW,
                    score=50,
                    rationale=_text(
                        "至少两个认证角色在同一归一化受限接口上得到相同响应哈希；这可能是正常公共数据，也可能提示缺少角色或对象级权限差异。",
                        "At least two authenticated roles received the same response hash on a normalized restricted endpoint; this may be shared public data or a missing role/object authorization distinction.",
                    ),
                    next_step=_text(
                        "先确认两个角色的预期权限和测试对象所有权，再为一个自有对象申请最小化跨角色验证。",
                        "Confirm expected role permissions and test-object ownership, then request a minimal cross-role validation using one self-owned object.",
                    ),
                )
            )

        guest_sensitive = [
            row
            for row in guest_success
            if any(SENSITIVE_FIELD_RE.search(field) for field in row[1].response_json_fields)
        ]
        if guest_sensitive:
            result.append(
                self._candidate(
                    kind=TrafficCandidateKind.SENSITIVE_FIELD_EXPOSURE,
                    endpoint=endpoint,
                    rows=guest_sensitive,
                    title=_text("公开响应疑似包含敏感字段", "Public response may contain sensitive fields"),
                    severity=SeverityHint.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    score=62,
                    rationale=_text(
                        "未认证成功响应的 JSON 字段名命中敏感语义；导入器没有保存字段值，因此不能据此认定数据泄露。",
                        "JSON field names in an unauthenticated successful response have sensitive semantics; values were not stored, so exposure is not established.",
                    ),
                    next_step=_text(
                        "人工检查原始 Burp 记录是否仅含自有测试数据；必要时申请一次最小化字段可见性验证。",
                        "Review the original Burp record for self-owned test data only; request a minimal field-visibility validation if necessary.",
                    ),
                )
            )

        verbose = [
            row
            for row in rows
            if row[1].response_status is not None
            and row[1].response_status >= 400
            and VERBOSE_ERROR_RE.search(row[1].response_preview)
        ]
        if verbose:
            result.append(
                self._candidate(
                    kind=TrafficCandidateKind.VERBOSE_ERROR,
                    endpoint=endpoint,
                    rows=verbose,
                    title=_text("响应疑似暴露详细错误信息", "Response may expose verbose error details"),
                    severity=SeverityHint.LOW,
                    confidence=Confidence.MEDIUM,
                    score=42,
                    rationale=_text(
                        "脱敏预览中出现堆栈、路径或数据库错误模式；仍需排除演示文本、静态页面和代理注入。",
                        "The redacted preview contains stack, path, or database error patterns; demo text, static content, and proxy injection remain possible.",
                    ),
                    next_step=_text(
                        "先离线核对原始响应上下文，再决定是否需要低影响复现。",
                        "Review the original response context offline before deciding whether low-impact reproduction is warranted.",
                    ),
                )
            )
        return result

    @staticmethod
    def _candidate(
        *,
        kind: TrafficCandidateKind,
        endpoint: str,
        rows: list[tuple[str, TrafficRecord]],
        title: LocalizedText,
        severity: SeverityHint,
        confidence: Confidence,
        score: int,
        rationale: LocalizedText,
        next_step: LocalizedText,
    ) -> TrafficCandidate:
        refs = sorted({_ref(import_id, record) for import_id, record in rows})
        roles = sorted({record.role_hint for _import_id, record in rows})
        host = rows[0][1].host
        fingerprint = canonical_sha256(
            {"kind": kind.value, "endpoint": endpoint, "roles": roles}
        )
        return TrafficCandidate(
            candidate_id=f"tcand-{fingerprint[:16]}",
            fingerprint=fingerprint,
            kind=kind,
            title=title,
            severity_hint=severity,
            confidence=confidence,
            risk_score=score,
            host=host,
            endpoint_key=endpoint,
            safe_urls=sorted({record.safe_url for _import_id, record in rows})[:20],
            roles=roles,
            evidence_refs=refs,
            rationale=rationale,
            benign_explanations=[
                _text(
                    "接口可能按设计公开，或不同角色返回相同结构但不同数据。",
                    "The endpoint may be intentionally public, or roles may receive the same structure with different data.",
                ),
                _text(
                    "缓存、统一错误页或网关响应可能造成相似结果。",
                    "Caching, shared error pages, or gateway responses may create similar results.",
                ),
            ],
            next_step=next_step,
            new_authorization_required=True,
            reportable=False,
        )

    @staticmethod
    def _duplicate_clusters(imports: list[TrafficImport]) -> list[DuplicateCluster]:
        groups: dict[str, list[tuple[str, TrafficRecord]]] = defaultdict(list)
        for document in imports:
            for record in document.records:
                posture = {
                    name.lower(): value
                    for name, value in record.response_headers.items()
                    if name.lower()
                    in {"server", "x-powered-by", "content-security-policy", "x-frame-options"}
                }
                fingerprint = canonical_sha256(
                    {
                        "method": record.method,
                        "path": record.normalized_path,
                        "status_class": record.response_status // 100
                        if record.response_status
                        else None,
                        "shape": record.response_json_shape_sha256,
                        "posture": posture,
                    }
                )
                groups[fingerprint].append((document.import_id, record))
        clusters: list[DuplicateCluster] = []
        for fingerprint, rows in sorted(groups.items()):
            endpoint_keys = sorted({record.endpoint_key for _import_id, record in rows})
            hosts = sorted({record.host for _import_id, record in rows})
            if len(endpoint_keys) < 2 or len(hosts) < 2:
                continue
            clusters.append(
                DuplicateCluster(
                    fingerprint=fingerprint,
                    endpoint_keys=endpoint_keys,
                    hosts=hosts,
                    record_refs=sorted({_ref(import_id, record) for import_id, record in rows}),
                    rationale=_text(
                        "方法、归一化路径、状态类别、JSON 结构和部分技术响应头一致，可能属于同代码不同环境；仅用于提交前去重。",
                        "Method, normalized path, status class, JSON shape, and selected response posture match; this may be the same code across environments and is only a pre-submission deduplication hint.",
                    ),
                )
            )
        return clusters
