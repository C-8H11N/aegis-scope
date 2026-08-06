# Contributing

[English](CONTRIBUTING.md) | [简体中文](CONTRIBUTING.zh-CN.md)

1. Open an issue describing the defensive use case and safety impact.
2. Keep changes focused and include tests.
3. Run `ruff check .`, `mypy src`, and `pytest`.
4. Use only loopback, mocked transports, or `.invalid` targets in tests.
5. Do not submit offensive payload libraries, exploitation automation, credentials, or real
   program evidence.

All contributions must preserve the dual policy gate and default dry-run behavior.
