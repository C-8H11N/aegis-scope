from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from aegisscope.findings.models import FindingStatus, FindingTransition
from aegisscope.findings.service import FindingLifecycleError, FindingService
from aegisscope.findings.store import AnalystStore
from aegisscope.traffic.analyzer import TrafficAnalyzer
from aegisscope.traffic.importer import TrafficImporter


def _har_entry(
    url: str,
    *,
    request_headers: list[dict[str, str]] | None = None,
    status: int = 200,
    body: str = '{"user":{"email":"researcher@example.invalid"}}',
) -> dict[str, object]:
    return {
        "startedDateTime": "2026-08-09T08:00:00Z",
        "request": {
            "method": "GET",
            "url": url,
            "headers": request_headers or [],
        },
        "response": {
            "status": status,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"mimeType": "application/json", "text": body},
            "bodySize": len(body),
        },
    }


def _write_har(path: Path, entries: list[dict[str, object]]) -> None:
    path.write_text(json.dumps({"log": {"entries": entries}}), encoding="utf-8")


def test_har_import_is_scoped_and_redacted_before_persistence(tmp_path: Path) -> None:
    source = tmp_path / "capture.har"
    secret = "Bearer abcdefghijklmnopqrstuvwxyz123456"
    _write_har(
        source,
        [
            _har_entry(
                "https://demo.invalid/api/profile/123?token=raw-query-secret",
                request_headers=[
                    {"name": "Cookie", "value": "session=raw-cookie-secret"},
                    {"name": "Authorization", "value": secret},
                ],
                body=(
                    '{"user":{"email":"person@example.invalid",'
                    '"token":"abcdefghijklmnop"}}'
                ),
            ),
            _har_entry("https://outside.invalid/api/profile/123"),
        ],
    )

    document = TrafficImporter().import_file(
        source,
        program_name="Offline Test",
        allowlist=["demo.invalid"],
        role_hint="guest",
    )
    output = tmp_path / "derived"
    json_path, _summary = TrafficImporter().write(document, output)
    persisted = json_path.read_text(encoding="utf-8")

    assert document.record_count == 1
    assert document.skipped_out_of_scope == 1
    assert document.records[0].normalized_path == "/api/profile/{id}"
    assert set(document.records[0].authentication_markers) == {
        "authorization_header",
        "cookie_header",
    }
    assert "raw-query-secret" not in persisted
    assert "raw-cookie-secret" not in persisted
    assert secret not in persisted
    assert "person@example.invalid" not in persisted
    assert "<REDACTED" in persisted
    assert not (output / source.name).exists()


def test_burp_xml_base64_import_keeps_only_derived_data(tmp_path: Path) -> None:
    request = b"GET /public HTTP/1.1\r\nHost: demo.invalid\r\nCookie: secret=hidden\r\n\r\n"
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        b'{"status":"ok"}'
    )
    xml = f"""<items><item>
<time>2026-08-09T08:00:00Z</time><url>https://demo.invalid/public</url>
<method>GET</method><status>200</status>
<request base64="true">{base64.b64encode(request).decode()}</request>
<response base64="true">{base64.b64encode(response).decode()}</response>
</item></items>"""
    source = tmp_path / "burp.xml"
    source.write_text(xml, encoding="utf-8")

    document = TrafficImporter().import_file(
        source,
        program_name="Offline Test",
        allowlist=["demo.invalid"],
        role_hint="guest",
    )

    assert document.record_count == 1
    assert document.records[0].authentication_markers == ["cookie_header"]
    assert document.records[0].response_json_fields == ["status"]


def test_offline_analysis_creates_candidates_and_duplicate_hints(tmp_path: Path) -> None:
    guest_source = tmp_path / "guest.har"
    member_source = tmp_path / "member.har"
    duplicate_source = tmp_path / "duplicate.har"
    _write_har(guest_source, [_har_entry("https://demo.invalid/api/profile/123")])
    _write_har(
        member_source,
        [
            _har_entry(
                "https://demo.invalid/api/profile/456",
                request_headers=[{"name": "Cookie", "value": "session=test-only"}],
            )
        ],
    )
    _write_har(
        duplicate_source,
        [_har_entry("https://uat-demo.invalid/api/profile/789")],
    )
    importer = TrafficImporter()
    guest = importer.import_file(
        guest_source,
        program_name="Offline Test",
        allowlist=["demo.invalid"],
        role_hint="guest",
    )
    member = importer.import_file(
        member_source,
        program_name="Offline Test",
        allowlist=["demo.invalid"],
        role_hint="member",
    )
    duplicate = importer.import_file(
        duplicate_source,
        program_name="Offline Test",
        allowlist=["uat-demo.invalid"],
        role_hint="guest",
    )

    analysis = TrafficAnalyzer().analyze([guest, member, duplicate])

    assert analysis.automatically_verified_findings == 0
    assert analysis.candidate_count >= 2
    assert all(candidate.reportable is False for candidate in analysis.candidates)
    assert any(
        candidate.kind.value == "authorization_boundary" for candidate in analysis.candidates
    )
    assert analysis.duplicate_cluster_count >= 1


def test_finding_confirmation_and_report_require_human_transition(tmp_path: Path) -> None:
    source = tmp_path / "guest.har"
    _write_har(source, [_har_entry("https://demo.invalid/api/profile/123")])
    imported = TrafficImporter().import_file(
        source,
        program_name="Offline Test",
        allowlist=["demo.invalid"],
        role_hint="guest",
    )
    analysis = TrafficAnalyzer().analyze([imported])
    store = AnalystStore(tmp_path / "aegisscope.sqlite3")
    service = FindingService(store)
    assert service.ingest(analysis) >= 1
    finding = store.list_findings()[0]

    with pytest.raises(FindingLifecycleError, match="human-confirmed"):
        service.render_report(finding.finding_id, tmp_path / "early.md")
    finding = service.transition(
        finding.finding_id,
        FindingTransition(
            to_status=FindingStatus.NEEDS_VALIDATION,
            statement="Human reviewed the offline candidate and requests minimal validation.",
        ),
    )
    finding = service.transition(
        finding.finding_id,
        FindingTransition(
            to_status=FindingStatus.CONFIRMED,
            statement="Human confirmed the behavior using self-owned test data only.",
            impact="An unauthenticated user can read the self-owned test profile without a session.",
            remediation="Enforce authentication and object-level authorization on the server.",
        ),
    )
    report = service.render_report(finding.finding_id, tmp_path / "report.md")

    assert finding.reportable is True
    assert report.is_file()
    assert "工具未自动利用漏洞" in report.read_text(encoding="utf-8")
