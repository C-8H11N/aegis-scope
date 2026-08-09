"""Human-gated candidate ingestion, transitions, and report rendering."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from aegisscope.findings.models import (
    REPORTABLE_STATUSES,
    Finding,
    FindingStatus,
    FindingTransition,
)
from aegisscope.findings.store import AnalystStore
from aegisscope.security.integrity import atomic_write_new_text
from aegisscope.traffic.models import TrafficAnalysis

ALLOWED_TRANSITIONS: dict[FindingStatus, set[FindingStatus]] = {
    FindingStatus.CANDIDATE: {
        FindingStatus.NEEDS_VALIDATION,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.DUPLICATE,
        FindingStatus.ACCEPTED_RISK,
    },
    FindingStatus.NEEDS_VALIDATION: {
        FindingStatus.CONFIRMED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.DUPLICATE,
        FindingStatus.ACCEPTED_RISK,
    },
    FindingStatus.CONFIRMED: {
        FindingStatus.SUBMITTED,
        FindingStatus.FIXED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.DUPLICATE,
    },
    FindingStatus.SUBMITTED: {FindingStatus.FIXED, FindingStatus.DUPLICATE},
    FindingStatus.ACCEPTED_RISK: {FindingStatus.FIXED},
    FindingStatus.FALSE_POSITIVE: set(),
    FindingStatus.DUPLICATE: set(),
    FindingStatus.FIXED: set(),
}


class FindingLifecycleError(ValueError):
    pass


def _markdown_inline(value: str) -> str:
    return value.replace("`", "\\`").replace("\n", "").replace("\r", "")


class FindingService:
    def __init__(self, store: AnalystStore) -> None:
        self.store = store

    def ingest(self, analysis: TrafficAnalysis) -> int:
        created = 0
        now = datetime.now(timezone.utc)
        for candidate in analysis.candidates:
            finding = Finding(
                finding_id=f"finding-{candidate.fingerprint[:16]}",
                source_candidate_id=candidate.candidate_id,
                fingerprint=candidate.fingerprint,
                program_name=analysis.program_name,
                title=candidate.title,
                host=candidate.host,
                endpoint_key=candidate.endpoint_key,
                safe_urls=candidate.safe_urls,
                status=FindingStatus.CANDIDATE,
                severity_hint=candidate.severity_hint,
                confidence=candidate.confidence,
                reportable=False,
                rationale=candidate.rationale,
                benign_explanations=candidate.benign_explanations,
                evidence_refs=candidate.evidence_refs,
                created_at=now,
                updated_at=now,
            )
            created += int(self.store.put_finding(finding))
        return created

    def transition(self, finding_id: str, request: FindingTransition) -> Finding:
        current = self.store.get_finding(finding_id)
        if current is None:
            raise KeyError(f"unknown finding_id: {finding_id}")
        if request.to_status not in ALLOWED_TRANSITIONS[current.status]:
            raise FindingLifecycleError(
                f"transition {current.status.value} -> {request.to_status.value} is not allowed"
            )
        if request.to_status == FindingStatus.CONFIRMED:
            impact = (request.impact or current.impact or "").strip()
            if len(impact) < 20 or not current.evidence_refs:
                raise FindingLifecycleError(
                    "confirmation requires a concrete impact statement and evidence references"
                )
        if request.to_status == FindingStatus.DUPLICATE and not request.duplicate_of:
            raise FindingLifecycleError("duplicate transition requires duplicate_of")
        now = datetime.now(timezone.utc)
        updated = current.model_copy(
            update={
                "status": request.to_status,
                "reportable": request.to_status in REPORTABLE_STATUSES,
                "impact": request.impact if request.impact is not None else current.impact,
                "remediation": request.remediation
                if request.remediation is not None
                else current.remediation,
                "duplicate_of": request.duplicate_of
                if request.duplicate_of is not None
                else current.duplicate_of,
                "updated_at": now,
            }
        )
        updated = Finding.model_validate(updated.model_dump(mode="python"))
        self.store.update_finding(
            updated, from_status=current.status.value, statement=request.statement
        )
        return updated

    def render_report(
        self, finding_id: str, output: Path, *, language: str = "zh-CN"
    ) -> Path:
        finding = self.store.get_finding(finding_id)
        if finding is None:
            raise KeyError(f"unknown finding_id: {finding_id}")
        if not finding.reportable or finding.status not in REPORTABLE_STATUSES:
            raise FindingLifecycleError("only human-confirmed findings can produce a report")
        if not finding.impact:
            raise FindingLifecycleError("a report requires a concrete impact statement")
        if language not in {"zh-CN", "en"}:
            raise FindingLifecycleError("report language must be zh-CN or en")
        remediation = finding.remediation or (
            "请结合业务语义补充服务端修复方案并执行权限边界回归测试。"
            if language == "zh-CN"
            else "Add a server-side fix based on business semantics and run authorization-boundary regression tests."
        )
        evidence = "\n".join(f"- `{item}`" for item in finding.evidence_refs)
        safe_urls = "\n".join(f"- `{_markdown_inline(item)}`" for item in finding.safe_urls)
        if language == "en":
            content = f"""# {finding.host}: {finding.title.en}

> Status: `{finding.status.value}`. This report was generated from a human-confirmed local record. The tool did not exploit the issue or expand impact automatically.

## 1. Basic information

- Program: {finding.program_name}
- Severity hint: {finding.severity_hint.value}
- Affected asset: `{finding.host}`
- Affected endpoint: `{finding.endpoint_key}`
- Candidate source: `{finding.source_candidate_id}`

### Redacted risk-point URLs

{safe_urls}

## 2. Description

{finding.rationale.en}

## 3. Security impact

{finding.impact}

## 4. Evidence index

{evidence}

The final submission must add the sanitized HTTP request/response sample, account information required by the program, and complete low-impact reproduction steps from the human-reviewed Burp record. A derived record cannot replace those materials.

## 5. Remediation

{remediation}

## 6. Validation boundary

Automated analysis processed redacted derived data only. It sent no new request, accessed no unrelated user data, performed no bulk test, and executed no exploit. Human review supplied the confirmed status and impact statement; re-check the original evidence and program rules before submission.
"""
        else:
            content = f"""# {finding.host} {finding.title.zh_cn}

> 状态：`{finding.status.value}`。本报告由人工确认后的本地记录生成，工具未自动利用漏洞，也未自动扩大影响。

## 一、基本信息

- 项目名称：{finding.program_name}
- 风险提示：{finding.severity_hint.value}
- 受影响资产：`{finding.host}`
- 受影响接口：`{finding.endpoint_key}`
- 线索来源：`{finding.source_candidate_id}`

### 脱敏风险点链接

{safe_urls}

## 二、漏洞描述

{finding.rationale.zh_cn}

## 三、安全影响

{finding.impact}

## 四、证据索引

{evidence}

正式提交前必须由人工从已复核的 Burp 记录补充脱敏后的 HTTP 请求/响应样例、平台要求的测试账号信息和完整低影响复现步骤；派生记录不能替代这些材料。

## 五、修复建议

{remediation}

## 六、验证边界

自动分析仅处理已脱敏派生数据，没有发送新请求、读取无关用户数据、执行批量测试或漏洞利用。确认状态及影响说明来自人工审核事件，应在提交前再次核对原始证据和 SRC 规则。
"""
        atomic_write_new_text(output, content)
        return output
