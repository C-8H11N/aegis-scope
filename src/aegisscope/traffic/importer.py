"""Bounded HAR and Burp XML import with redaction before persistence."""

from __future__ import annotations

import base64
import binascii
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from aegisscope.contracts.models import normalize_exact_host
from aegisscope.security.integrity import (
    atomic_write_new_text,
    canonical_sha256,
    sha256_bytes,
    sha256_file,
)
from aegisscope.security.redaction import redact_headers, redact_text, redact_url
from aegisscope.traffic.models import (
    TrafficImport,
    TrafficRecord,
    TrafficSourceKind,
)

MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 5000
MAX_MESSAGE_BYTES = 2 * 1024 * 1024
SAFE_RESPONSE_HEADERS = {
    "access-control-allow-credentials",
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-allow-origin",
    "cache-control",
    "content-security-policy",
    "content-type",
    "location",
    "referrer-policy",
    "server",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "x-powered-by",
}
PATH_ID_PATTERNS = (
    re.compile(r"(?<=/)[0-9]{2,}(?=/|$)"),
    re.compile(r"(?<=/)[0-9a-f]{8}-[0-9a-f-]{27,}(?=/|$)", re.I),
    re.compile(r"(?<=/)[0-9a-f]{16,}(?=/|$)", re.I),
)
SENSITIVE_JSON_FIELD_RE = re.compile(
    r"(?:password|passwd|secret|token|cookie|session|authorization|private[_-]?key)", re.I
)


class TrafficImportError(ValueError):
    pass


def _clean_label(value: str, limit: int) -> str:
    return re.sub(r"[\x00-\x1f\x7f]+", " ", value).strip()[:limit]


def normalize_path(path: str) -> str:
    normalized = path or "/"
    for pattern in PATH_ID_PATTERNS:
        normalized = pattern.sub("{id}", normalized)
    return normalized[:1024]


def _safe_role(value: str) -> str:
    role = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,39}", role):
        raise TrafficImportError("role_hint must use 1-40 safe label characters")
    return role


def _header_map(items: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                result[item["name"]] = str(item.get("value", ""))
    elif isinstance(items, dict):
        result = {str(name): str(value) for name, value in items.items()}
    return result


def _auth_markers(headers: dict[str, str]) -> list[str]:
    names = {name.lower() for name in headers}
    markers = []
    if "authorization" in names or "proxy-authorization" in names:
        markers.append("authorization_header")
    if "cookie" in names:
        markers.append("cookie_header")
    if "x-api-key" in names:
        markers.append("api_key_header")
    return markers


def _json_field_paths(value: Any, *, prefix: str = "", limit: int = 200) -> list[str]:
    fields: list[str] = []

    def visit(item: Any, path: str) -> None:
        if len(fields) >= limit:
            return
        if isinstance(item, dict):
            for key in sorted(item):
                safe_key = redact_text(_clean_label(str(key), 100))[0]
                child = f"{path}.{safe_key}" if path else safe_key
                fields.append(child)
                visit(item[key], child)
        elif isinstance(item, list) and item:
            visit(item[0], f"{path}[]")

    visit(value, prefix)
    return sorted(set(fields))[:limit]


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class TrafficImporter:
    def import_file(
        self,
        source: Path,
        *,
        program_name: str,
        allowlist: list[str],
        denylist: list[str] | None = None,
        role_hint: str = "unknown",
        source_format: str = "auto",
    ) -> TrafficImport:
        path = source.resolve()
        if path.is_symlink() or not path.is_file():
            raise TrafficImportError("traffic source must be a regular file")
        if path.stat().st_size > MAX_SOURCE_BYTES:
            raise TrafficImportError("traffic source exceeds 32 MiB")
        safe_program_name = _clean_label(program_name, 200)
        if len(safe_program_name) < 2:
            raise TrafficImportError("program_name must contain at least two characters")
        normalized_allowlist = [normalize_exact_host(host) for host in allowlist]
        normalized_denylist = [normalize_exact_host(host) for host in (denylist or [])]
        if not normalized_allowlist:
            raise TrafficImportError("an explicit allowlist is required")
        role = _safe_role(role_hint)
        kind = self._detect_kind(path, source_format)
        if kind == TrafficSourceKind.HAR:
            raw_records = self._load_har(path)
        else:
            raw_records = self._load_burp_xml(path)

        records: list[TrafficRecord] = []
        skipped_scope = 0
        skipped_invalid = 0
        warnings: list[str] = []
        for raw in raw_records[:MAX_RECORDS]:
            try:
                record = self._derive_record(raw, role)
            except (TrafficImportError, ValueError, TypeError):
                skipped_invalid += 1
                continue
            if record.host not in normalized_allowlist or record.host in normalized_denylist:
                skipped_scope += 1
                continue
            records.append(record)
        if len(raw_records) > MAX_RECORDS:
            warnings.append(f"record cap reached; ignored {len(raw_records) - MAX_RECORDS} entries")
        if not records:
            raise TrafficImportError("no valid in-scope traffic records were found")
        source_digest = sha256_file(path)
        import_identity = canonical_sha256(
            {
                "source_sha256": source_digest,
                "role_hint": role,
                "allowlist": normalized_allowlist,
                "denylist": normalized_denylist,
            }
        )[:16]
        source_name = f"source-{source_digest[:12]}{path.suffix.lower()[:10]}"
        return TrafficImport(
            import_id=f"traffic-{import_identity}",
            program_name=safe_program_name,
            source_kind=kind,
            source_name=source_name,
            source_sha256=source_digest,
            role_hint=role,
            allowlist=normalized_allowlist,
            denylist=normalized_denylist,
            imported_at=datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc),
            record_count=len(records),
            skipped_out_of_scope=skipped_scope,
            skipped_invalid=skipped_invalid,
            records=records,
            warnings=warnings,
        )

    def write(self, document: TrafficImport, output_dir: Path) -> tuple[Path, Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = output_dir / "traffic.json"
        markdown_path = output_dir / "import-summary.zh-CN.md"
        if json_path.exists() or markdown_path.exists():
            raise FileExistsError("traffic import output is write-once")
        atomic_write_new_text(
            json_path,
            json.dumps(document.model_dump(mode="json"), ensure_ascii=False, indent=2),
        )
        hosts = sorted({record.host for record in document.records})
        endpoints = sorted({record.endpoint_key for record in document.records})
        lines = [
            f"# 流量导入摘要：{document.import_id}",
            "",
            "> 仅保存脱敏后的派生数据；原始 Cookie、Token、请求正文和响应敏感值不会复制到项目中。",
            "",
            f"- 项目：{document.program_name}",
            f"- 来源类型：`{document.source_kind.value}`",
            f"- 角色标签：`{document.role_hint}`",
            f"- 范围内记录：{document.record_count}",
            f"- 跳过范围外记录：{document.skipped_out_of_scope}",
            f"- 无效记录：{document.skipped_invalid}",
            f"- 主机数：{len(hosts)}",
            f"- 归一化接口数：{len(endpoints)}",
            "",
        ]
        atomic_write_new_text(markdown_path, "\n".join(lines))
        return json_path, markdown_path

    @staticmethod
    def load(path: Path) -> TrafficImport:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
            raise TrafficImportError("derived traffic document is unsafe, missing, or too large")
        try:
            return TrafficImport.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise TrafficImportError("derived traffic document is invalid") from exc

    @staticmethod
    def _detect_kind(path: Path, source_format: str) -> TrafficSourceKind:
        requested = source_format.strip().lower()
        if requested == "auto":
            requested = "har" if path.suffix.lower() in {".har", ".json"} else "burp_xml"
        try:
            return TrafficSourceKind(requested)
        except ValueError as exc:
            raise TrafficImportError("source_format must be auto, har, or burp_xml") from exc

    @staticmethod
    def _load_har(path: Path) -> list[dict[str, Any]]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            entries = payload["log"]["entries"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise TrafficImportError("HAR structure is invalid") from exc
        if not isinstance(entries, list):
            raise TrafficImportError("HAR entries must be a list")
        records: list[dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            request = entry.get("request", {})
            response = entry.get("response", {})
            if not isinstance(request, dict) or not isinstance(response, dict):
                continue
            content = response.get("content", {})
            body = ""
            mime_type = ""
            if isinstance(content, dict):
                body = str(content.get("text", ""))
                mime_type = str(content.get("mimeType", ""))
                if content.get("encoding") == "base64" and body:
                    try:
                        body = base64.b64decode(body, validate=True)[:MAX_MESSAGE_BYTES].decode(
                            "utf-8", errors="replace"
                        )
                    except (binascii.Error, ValueError, TypeError):
                        body = ""
            records.append(
                {
                    "url": request.get("url"),
                    "method": request.get("method"),
                    "request_headers": _header_map(request.get("headers", [])),
                    "response_status": response.get("status"),
                    "response_headers": _header_map(response.get("headers", [])),
                    "response_body": body[:MAX_MESSAGE_BYTES],
                    "response_mime": mime_type,
                    "response_size": response.get("bodySize", len(body.encode("utf-8"))),
                    "captured_at": entry.get("startedDateTime"),
                }
            )
        return records

    @staticmethod
    def _load_burp_xml(path: Path) -> list[dict[str, Any]]:
        content = path.read_bytes()
        if b"<!DOCTYPE" in content.upper() or b"<!ENTITY" in content.upper():
            raise TrafficImportError("XML entities and doctypes are forbidden")
        try:
            root = ET.fromstring(content)  # noqa: S314 - entities and doctypes rejected above
        except ET.ParseError as exc:
            raise TrafficImportError("Burp XML is invalid") from exc
        records: list[dict[str, Any]] = []
        for item in root.findall(".//item"):
            request_bytes = TrafficImporter._decode_burp_message(item.find("request"))
            response_bytes = TrafficImporter._decode_burp_message(item.find("response"))
            request_line, request_headers, _request_body = TrafficImporter._parse_http_message(
                request_bytes
            )
            status_line, response_headers, response_body = TrafficImporter._parse_http_message(
                response_bytes
            )
            method = (item.findtext("method") or request_line.split(" ", 1)[0]).upper()
            status_text = item.findtext("status") or ""
            if not status_text and status_line.startswith("HTTP/"):
                parts = status_line.split(" ", 2)
                status_text = parts[1] if len(parts) > 1 else ""
            records.append(
                {
                    "url": item.findtext("url"),
                    "method": method,
                    "request_headers": request_headers,
                    "response_status": status_text,
                    "response_headers": response_headers,
                    "response_body": response_body[:MAX_MESSAGE_BYTES].decode(
                        "utf-8", errors="replace"
                    ),
                    "response_mime": next(
                        (
                            value
                            for name, value in response_headers.items()
                            if name.lower() == "content-type"
                        ),
                        "",
                    ),
                    "response_size": len(response_body),
                    "captured_at": item.findtext("time"),
                }
            )
            if len(records) >= MAX_RECORDS:
                break
        return records

    @staticmethod
    def _decode_burp_message(element: ET.Element | None) -> bytes:
        if element is None or not element.text:
            return b""
        text = element.text.strip()
        if element.attrib.get("base64", "false").lower() == "true":
            try:
                return base64.b64decode(text, validate=True)[:MAX_MESSAGE_BYTES]
            except (binascii.Error, ValueError, TypeError):
                return b""
        return text.encode("utf-8", errors="replace")[:MAX_MESSAGE_BYTES]

    @staticmethod
    def _parse_http_message(content: bytes) -> tuple[str, dict[str, str], bytes]:
        head, separator, body = content.partition(b"\r\n\r\n")
        if not separator:
            head, _separator, body = content.partition(b"\n\n")
        lines = head.decode("iso-8859-1", errors="replace").splitlines()
        start_line = lines[0] if lines else ""
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()
        return start_line, headers, body

    @staticmethod
    def _derive_record(raw: dict[str, Any], role_hint: str) -> TrafficRecord:
        raw_url = str(raw.get("url") or "")
        parsed = urlsplit(raw_url)
        if parsed.scheme.lower() not in {"http", "https"} or parsed.hostname is None:
            raise TrafficImportError("record URL is invalid")
        host = normalize_exact_host(parsed.hostname)
        method = str(raw.get("method") or "GET").upper()
        if not re.fullmatch(r"[A-Z]{2,12}", method):
            raise TrafficImportError("record method is invalid")
        normalized, path_hits = redact_text(normalize_path(parsed.path))
        parameter_names = sorted(
            {redact_text(_clean_label(name, 100))[0] for name, _value in parse_qsl(parsed.query)}
        )[:100]
        try:
            port = parsed.port
        except ValueError as exc:
            raise TrafficImportError("record URL port is invalid") from exc
        netloc = host
        default_port = 443 if parsed.scheme.lower() == "https" else 80
        if port is not None and port != default_port:
            netloc = f"{host}:{port}"
        safe_url, url_hits = redact_url(
            urlunsplit((parsed.scheme.lower(), netloc, normalized, parsed.query, ""))
        )
        endpoint_key = f"{method} {host} {normalized}"
        if parameter_names:
            endpoint_key += "?" + "&".join(parameter_names)

        request_headers = _header_map(raw.get("request_headers", {}))
        response_headers_raw = _header_map(raw.get("response_headers", {}))
        selected_headers = {
            name.lower(): value[:4096]
            for name, value in response_headers_raw.items()
            if name.lower() in SAFE_RESPONSE_HEADERS
        }
        safe_headers, header_hits = redact_headers(selected_headers)
        for name, value in tuple(safe_headers.items()):
            if name.lower() == "content-security-policy":
                safe_headers[name] = f"sha256:{sha256_bytes(value.encode('utf-8'))}"
                continue
            if name.lower() == "location":
                value, location_hits = redact_url(value)
                header_hits.extend(location_hits)
            value, value_hits = redact_text(value)
            safe_headers[name] = value
            header_hits.extend(value_hits)

        body_text = str(raw.get("response_body") or "")[:MAX_MESSAGE_BYTES]
        safe_preview, body_hits = redact_text(body_text[:16_384])
        safe_preview = safe_preview[:8192]
        json_fields: list[str] = []
        mime_type = str(raw.get("response_mime") or "").lower()
        if body_text and ("json" in mime_type or body_text.lstrip().startswith(("{", "["))):
            try:
                json_fields = _json_field_paths(json.loads(body_text))
            except (ValueError, TypeError):
                json_fields = []
        shape_digest = canonical_sha256(json_fields) if json_fields else None
        try:
            status = int(raw.get("response_status"))
        except (TypeError, ValueError):
            status = None
        if status is not None and not 100 <= status <= 599:
            status = None
        try:
            response_size = max(0, min(int(raw.get("response_size") or 0), 100_000_000))
        except (TypeError, ValueError):
            response_size = len(body_text.encode("utf-8"))
        identity = canonical_sha256(
            {
                "method": method,
                "url_sha256": sha256_bytes(raw_url.encode("utf-8")),
                "status": status,
                "body_sha256": sha256_bytes(body_text.encode("utf-8")) if body_text else None,
                "role": role_hint,
            }
        )[:16]
        redaction_hits = sorted(set(url_hits + path_hits + header_hits + body_hits))
        if any(SENSITIVE_JSON_FIELD_RE.search(field) for field in json_fields):
            redaction_hits.append("sensitive_json_field_name")
        return TrafficRecord(
            record_id=f"req-{identity}",
            method=method,
            host=host,
            safe_url=safe_url,
            normalized_path=normalized,
            endpoint_key=endpoint_key,
            original_url_sha256=sha256_bytes(raw_url.encode("utf-8")),
            role_hint=role_hint,
            authentication_markers=_auth_markers(request_headers),
            request_parameter_names=parameter_names,
            response_status=status,
            response_bytes=response_size,
            response_headers=safe_headers,
            response_body_sha256=sha256_bytes(body_text.encode("utf-8")) if body_text else None,
            response_json_fields=json_fields,
            response_json_shape_sha256=shape_digest,
            response_preview=safe_preview,
            redaction_hits=sorted(set(redaction_hits)),
            captured_at=_parse_time(raw.get("captured_at")),
        )
