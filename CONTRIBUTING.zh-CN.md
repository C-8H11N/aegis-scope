# 参与贡献

[English](CONTRIBUTING.md) | [简体中文](CONTRIBUTING.zh-CN.md)

1. 先通过 Issue 说明防御用途和安全影响；
2. 每个变更应保持聚焦并附带测试；
3. 运行 `ruff check .`、`mypy src` 和 `pytest`；
4. 测试只能使用本机、模拟传输或 `.invalid` 目标；
5. 不得提交攻击载荷库、自动利用、凭据或真实项目证据。

所有贡献都必须保留双重 Policy 校验和默认 dry-run。
