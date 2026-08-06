"""Small built-in bilingual message catalog for the MVP."""

from __future__ import annotations

MESSAGES: dict[str, dict[str, str]] = {
    "zh-CN": {
        "ready": "AegisScope 已就绪",
        "prepared": "阶段已准备，尚未发送到 Kali",
        "allowed": "策略校验通过",
        "denied": "策略校验拒绝",
        "dry_run": "仅演练：未发送任何网络请求",
        "api_unconfigured": "尚未配置模型 API",
    },
    "en": {
        "ready": "AegisScope is ready",
        "prepared": "Stage prepared; nothing was sent to Kali",
        "allowed": "Policy validation passed",
        "denied": "Policy validation denied",
        "dry_run": "Dry run: no network request was sent",
        "api_unconfigured": "The model API is not configured",
    },
}


def translate(key: str, language: str = "zh-CN") -> str:
    catalog = MESSAGES.get(language, MESSAGES["en"])
    return catalog.get(key, MESSAGES["en"].get(key, key))
