from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from aegisscope.config import Settings
from aegisscope.web.app import create_app


def test_health_is_bilingual_and_offline(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path,
        ssh_alias="kali-src",
        remote_root="~/src-runner",
        llm_base_url=None,
        llm_api_key=None,
        llm_model=None,
        language="zh-CN",
    )
    client = TestClient(create_app(settings))
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["network_execution"] is False
    assert set(body["messages"]) == {"zh-CN", "en"}


def test_dashboard_and_static_assets_are_served(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path,
        ssh_alias="kali-src",
        remote_root="~/src-runner",
        llm_base_url=None,
        llm_api_key=None,
        llm_model=None,
        language="zh-CN",
    )
    client = TestClient(create_app(settings))

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "AegisScope" in dashboard.text
    assert "manifest-json" in dashboard.text
    assert "findings-body" in dashboard.text
    assert "候选默认不可提交" in dashboard.text
    assert "frame-ancestors 'none'" in dashboard.headers["content-security-policy"]
    assert dashboard.headers["x-frame-options"] == "DENY"

    stylesheet = client.get("/static/styles.css")
    assert stylesheet.status_code == 200
    assert "prefers-reduced-motion" in stylesheet.text


def test_web_rejects_non_loopback_host_header(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path,
        ssh_alias="kali-src",
        remote_root="~/src-runner",
        llm_base_url=None,
        llm_api_key=None,
        llm_model=None,
        language="zh-CN",
    )
    client = TestClient(create_app(settings))
    response = client.get("/health", headers={"Host": "attacker.example"})
    assert response.status_code == 400
    cross_origin = client.post(
        "/api/v1/manifests/validate",
        headers={"Origin": "http://localhost:9999"},
        json={},
    )
    assert cross_origin.status_code == 403


def test_finding_api_is_local_and_starts_empty(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path,
        ssh_alias="kali-src",
        remote_root="~/src-runner",
        llm_base_url=None,
        llm_api_key=None,
        llm_model=None,
        language="zh-CN",
    )
    client = TestClient(create_app(settings))

    listing = client.get("/api/v1/findings")
    assert listing.status_code == 200
    assert listing.json() == []
    missing = client.post(
        "/api/v1/findings/finding-0000000000000000/transition",
        json={
            "to_status": "needs_validation",
            "statement": "Human review statement for a missing record.",
        },
    )
    assert missing.status_code == 404
