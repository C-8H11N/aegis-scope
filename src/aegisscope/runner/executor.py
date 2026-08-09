"""Bounded HTTP stage executor.

This module does not expose arbitrary command execution, authentication, custom headers,
request bodies, redirects, concurrency, crawling, scanning, fuzzing, or exploitation.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from aegisscope import __version__
from aegisscope.contracts.models import StageManifest
from aegisscope.contracts.results import RequestResult, StageStatus, StageSummary
from aegisscope.security.integrity import (
    atomic_write_new_text,
    canonical_sha256,
    sha256_file,
)
from aegisscope.security.redaction import redact_headers, redact_text, redact_url

EventSink = Callable[[dict[str, Any]], None]
SENSITIVE_BODY_HITS = {
    "api_key",
    "bearer_token",
    "cn_id",
    "email",
    "jwt",
    "payment_card",
    "phone",
    "private_key",
}
LOGIN_MARKERS = (
    '<input type="password"',
    "<input type='password'",
    "name=\"captcha\"",
    "name='captcha'",
    "验证码",
    "人机验证",
)


class EvidenceConflictError(RuntimeError):
    """Raised when a run would overwrite existing evidence."""


class StageExecutor:
    def __init__(
        self,
        *,
        output_dir: Path,
        network_gate: bool = False,
        manifest_sha256: str | None = None,
        transport: httpx.BaseTransport | None = None,
        event_sink: EventSink | None = None,
    ) -> None:
        self.output_dir = output_dir
        self.network_gate = network_gate
        self.manifest_sha256 = manifest_sha256
        self.transport = transport
        self.event_sink = event_sink or (lambda _event: None)

    def run(self, manifest: StageManifest) -> StageSummary:
        started = datetime.now(timezone.utc)
        if self.output_dir.exists() and any(self.output_dir.iterdir()):
            raise EvidenceConflictError(
                f"refusing to overwrite non-empty evidence directory: {self.output_dir}"
            )
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._emit("stage_started", manifest.job_id, target=manifest.target_host)

        if manifest.dry_run or not self.network_gate:
            results = [
                RequestResult(
                    index=index,
                    method=item.method.value,
                    url=redact_url(item.url)[0],
                    url_redactions=redact_url(item.url)[1],
                )
                for index, item in enumerate(manifest.requests, 1)
            ]
            summary = StageSummary(
                job_id=manifest.job_id,
                target_host=manifest.target_host,
                manifest_sha256=self.manifest_sha256,
                stage_status=StageStatus.DRY_RUN,
                dry_run=True,
                started_at=started,
                ended_at=datetime.now(timezone.utc),
                actual_requests=0,
                stop_reason="network gate closed or manifest dry_run is true",
                results=results,
            )
            self._write_summary(summary)
            self._emit("stage_dry_run", manifest.job_id, actual_requests=0)
            return summary

        request_results: list[RequestResult] = []
        stop_reason: str | None = None
        with httpx.Client(
            follow_redirects=False,
            timeout=httpx.Timeout(manifest.limits.timeout_seconds),
            headers={"User-Agent": f"AegisScope/{__version__} authorized-stage"},
            trust_env=False,
            transport=self.transport,
        ) as client:
            for index, request in enumerate(manifest.requests, 1):
                if index > 1:
                    time.sleep(manifest.limits.request_interval_seconds)
                result = self._execute_one(client, manifest, index)
                request_results.append(result)
                self._emit(
                    "request_finished",
                    manifest.job_id,
                    index=index,
                    status_code=result.status_code,
                    stop_reason=result.stop_reason,
                )
                if result.stop_reason or result.error:
                    stop_reason = result.stop_reason or result.error
                    break

        status = StageStatus.STOPPED if stop_reason else StageStatus.COMPLETED
        summary = StageSummary(
            job_id=manifest.job_id,
            target_host=manifest.target_host,
            manifest_sha256=self.manifest_sha256,
            stage_status=status,
            dry_run=False,
            started_at=started,
            ended_at=datetime.now(timezone.utc),
            actual_requests=len(request_results),
            stop_reason=stop_reason,
            results=request_results,
        )
        self._write_summary(summary)
        self._emit(
            "stage_finished",
            manifest.job_id,
            stage_status=status.value,
            actual_requests=len(request_results),
        )
        return summary

    def _execute_one(
        self, client: httpx.Client, manifest: StageManifest, index: int
    ) -> RequestResult:
        request = manifest.requests[index - 1]
        safe_url, url_redactions = redact_url(request.url)
        request_dir = self.output_dir / f"request-{index:02d}"
        request_dir.mkdir(parents=True, exist_ok=True)
        request_file = request_dir / "request.json"
        atomic_write_new_text(
            request_file,
            json.dumps(
                {
                    "method": request.method.value,
                    "url": safe_url,
                    "url_redactions": url_redactions,
                },
                ensure_ascii=False,
                indent=2,
            ),
        )

        started = time.monotonic()
        try:
            with client.stream(request.method.value, request.url) as response:
                captured = bytearray()
                over_limit = False
                for chunk in response.iter_bytes():
                    remaining = manifest.limits.max_response_bytes - len(captured)
                    if remaining <= 0:
                        over_limit = True
                        break
                    captured.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        over_limit = True
                        break

                duration_ms = int((time.monotonic() - started) * 1000)
                body_bytes = bytes(captured)
                body_digest = hashlib.sha256(body_bytes).hexdigest()
                safe_headers, header_hits = redact_headers(dict(response.headers))
                content_type = response.headers.get("content-type", "").lower()
                body_hits: list[str] = []
                safe_body = ""
                redacted_body_sha256: str | None = None
                evidence_files = [
                    str(request_file.relative_to(self.output_dir)).replace("\\", "/")
                ]

                body_text = ""
                textual = any(
                    marker in content_type
                    for marker in ("text/", "json", "javascript", "xml", "html")
                )
                if body_bytes and textual and request.method.value != "HEAD":
                    encoding = response.encoding or "utf-8"
                    body_text = body_bytes.decode(encoding, errors="replace")
                    safe_body, body_hits = redact_text(body_text)
                    redacted_body_sha256 = hashlib.sha256(safe_body.encode("utf-8")).hexdigest()
                    body_file = request_dir / "body.redacted.txt"
                    atomic_write_new_text(body_file, safe_body)
                    evidence_files.append(
                        str(body_file.relative_to(self.output_dir)).replace("\\", "/")
                    )

                response_meta = {
                    "status_code": response.status_code,
                    "headers": safe_headers,
                    "header_redactions": header_hits,
                    "content_type": content_type,
                    "captured_bytes": len(body_bytes),
                    "body_sha256": body_digest,
                    "redacted_body_sha256": redacted_body_sha256,
                    "body_redactions": body_hits,
                    "truncated": over_limit,
                }
                response_file = request_dir / "response.json"
                atomic_write_new_text(
                    response_file,
                    json.dumps(response_meta, ensure_ascii=False, indent=2),
                )
                evidence_files.append(
                    str(response_file.relative_to(self.output_dir)).replace("\\", "/")
                )

                stop_reason = self._stop_reason(
                    manifest=manifest,
                    status_code=response.status_code,
                    location=response.headers.get("location"),
                    body_text=body_text,
                    body_hits=body_hits,
                    over_limit=over_limit,
                )
                return RequestResult(
                    index=index,
                    method=request.method.value,
                    url=safe_url,
                    url_redactions=url_redactions,
                    status_code=response.status_code,
                    duration_ms=duration_ms,
                    response_bytes=len(body_bytes),
                    body_sha256=body_digest,
                    evidence_files=evidence_files,
                    stop_reason=stop_reason,
                )
        except httpx.TimeoutException:
            return RequestResult(
                index=index,
                method=request.method.value,
                url=safe_url,
                url_redactions=url_redactions,
                duration_ms=int((time.monotonic() - started) * 1000),
                error="request timeout",
                stop_reason="request timeout",
                evidence_files=[str(request_file.relative_to(self.output_dir)).replace("\\", "/")],
            )
        except httpx.HTTPError as exc:
            return RequestResult(
                index=index,
                method=request.method.value,
                url=safe_url,
                url_redactions=url_redactions,
                duration_ms=int((time.monotonic() - started) * 1000),
                error=f"HTTP transport error: {exc.__class__.__name__}",
                stop_reason="HTTP transport error",
                evidence_files=[str(request_file.relative_to(self.output_dir)).replace("\\", "/")],
            )

    @staticmethod
    def _stop_reason(
        *,
        manifest: StageManifest,
        status_code: int,
        location: str | None,
        body_text: str,
        body_hits: list[str],
        over_limit: bool,
    ) -> str | None:
        if over_limit:
            return "response size limit reached"
        if status_code in {403, 429}:
            return f"security or rate-limit response: {status_code}"
        if status_code >= 500:
            return f"server error response: {status_code}"
        if location and 300 <= status_code < 400:
            destination = urlsplit(urljoin(f"https://{manifest.target_host}/", location))
            if destination.hostname is None or destination.hostname.lower() != manifest.target_host:
                return "cross-host redirect"
        lowered = body_text.lower()
        if any(marker.lower() in lowered for marker in LOGIN_MARKERS):
            return "login or captcha flow detected"
        if SENSITIVE_BODY_HITS.intersection(body_hits):
            return "sensitive data pattern detected and redacted"
        return None

    def _write_summary(self, summary: StageSummary) -> None:
        summary_path = self.output_dir / "stage-summary.json"
        atomic_write_new_text(
            summary_path,
            json.dumps(summary.model_dump(mode="json"), ensure_ascii=False, indent=2),
        )
        files = []
        for path in sorted(self.output_dir.rglob("*")):
            if path.is_file() and path.name != "evidence-index.json":
                files.append(
                    {
                        "path": str(path.relative_to(self.output_dir)).replace("\\", "/"),
                        "bytes": path.stat().st_size,
                        "sha256": sha256_file(path),
                    }
                )
        index = {
            "schema_version": 1,
            "job_id": summary.job_id,
            "manifest_sha256": self.manifest_sha256,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "files": files,
        }
        index["index_sha256"] = canonical_sha256(index)
        atomic_write_new_text(
            self.output_dir / "evidence-index.json",
            json.dumps(index, ensure_ascii=False, indent=2),
        )

    def _emit(self, event: str, job_id: str, **fields: Any) -> None:
        self.event_sink(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": event,
                "job_id": job_id,
                **fields,
            }
        )
