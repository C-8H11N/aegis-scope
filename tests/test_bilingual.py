from aegisscope.i18n import translate
from aegisscope.reporting import load_report_template


def test_bilingual_messages_exist() -> None:
    assert "就绪" in translate("ready", "zh-CN")
    assert "ready" in translate("ready", "en")


def test_bilingual_report_templates_exist() -> None:
    assert "漏洞标题" in load_report_template("zh-CN")
    assert "Vulnerability title" in load_report_template("en")
