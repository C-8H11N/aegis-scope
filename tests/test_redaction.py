from aegisscope.security.redaction import redact_headers, redact_text


def test_sensitive_headers_are_removed() -> None:
    headers, hits = redact_headers({"Set-Cookie": "session=secret", "Server": "demo"})
    assert headers["Set-Cookie"] == "<REDACTED>"
    assert headers["Server"] == "demo"
    assert "header:set-cookie" in hits


def test_tokens_and_personal_data_are_removed() -> None:
    test_token = "abcdefghijkl" + "mnop"
    text, hits = redact_text(f"Authorization: Bearer {test_token} user@example.com")
    assert test_token not in text
    assert "user@example.com" not in text
    assert {"bearer_token", "email"}.issubset(hits)
