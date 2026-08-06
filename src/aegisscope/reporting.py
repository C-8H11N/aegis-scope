"""Bilingual report-template access."""

from __future__ import annotations

from importlib.resources import files
from typing import Literal

ReportLanguage = Literal["zh-CN", "en"]


def load_report_template(language: ReportLanguage) -> str:
    filename = "report.zh-CN.md" if language == "zh-CN" else "report.en.md"
    resource = files("aegisscope.report_templates").joinpath(filename)
    return resource.read_text(encoding="utf-8")
