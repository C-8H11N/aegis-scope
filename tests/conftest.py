from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def demo_payload() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "examples" / "safe-demo" / "stage.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload
