# Stage protocol / 阶段协议

The canonical contract is `StageManifest` in `src/aegisscope/contracts/models.py`. Unknown
fields fail closed. The protocol intentionally has no generic command, request headers, body,
cookie, token, credential, proxy, concurrency, redirect, scanner, or exploit field.

权威协议是 `src/aegisscope/contracts/models.py` 中的 `StageManifest`。未知字段默认拒绝。
协议刻意不提供通用命令、自定义请求头、正文、Cookie、Token、凭据、代理、并发、跳转、
扫描器或漏洞利用字段。

## Authorization / 授权

An authorization record contains the user's exact statement, stage scope, grant time, and
expiry. The manifest cannot outlive the authorization. In the MVP this is an auditable record,
not cryptographic proof; signed manifests are planned for 0.2.

授权记录包含用户授权原文、阶段范围、授权时间和过期时间。清单不得晚于授权过期时间。
MVP 中它是可审计记录而非密码学证明；签名清单计划在 0.2 实现。

## Two-key network gate / 双钥网络闸门

Network access requires both:

1. `dry_run` is explicitly `false` in the reviewed manifest;
2. the runner process is invoked with `--execute`.

网络访问必须同时满足：已审核清单中 `dry_run=false`，且 Runner 进程带有 `--execute`。
任意一项缺失时，实际请求数都必须为零。
