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
