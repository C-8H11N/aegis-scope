# Stage protocol / 阶段协议

The canonical contract is `StageManifest` in `src/aegisscope/contracts/models.py`. Unknown
fields fail closed. The protocol intentionally has no generic command, request headers, body,
cookie, token, credential, proxy, concurrency, redirect, scanner, or exploit field.

权威协议是 `src/aegisscope/contracts/models.py` 中的 `StageManifest`。未知字段默认拒绝。
协议刻意不提供通用命令、自定义请求头、正文、Cookie、Token、凭据、代理、并发、跳转、
扫描器或漏洞利用字段。

## Authorization / 授权

An authorization record contains the user's exact statement, stage scope, grant time, and
expiry. The manifest cannot outlive the authorization. This is an auditable record, not
cryptographic proof. Public-key signatures remain a future hardening item.

授权记录包含用户授权原文、阶段范围、授权时间和过期时间。清单不得晚于授权过期时间。
当前版本会为规范化清单生成 SHA-256，并在 Kali 执行前再次校验，用于发现传输错误或
内容不一致。SHA-256 不是签名，不能代替用户授权；公钥签名仍属于后续加固项。

## Two-key network gate / 双钥网络闸门

Network access requires both:

1. `dry_run` is explicitly `false` in the reviewed manifest;
2. the runner process is invoked with `--execute`.

网络访问必须同时满足：已审核清单中 `dry_run=false`，且 Runner 进程带有 `--execute`。
任意一项缺失时，实际请求数都必须为零。

## Integrity and replay / 完整性与防重放

Windows prepares both `manifest.json` and `manifest.sha256`. The runner canonicalizes the
received JSON and rejects a digest mismatch before policy validation. A network-enabled
`job_id` is claimed once under `~/src-runner/state/consumed/`; a second execution is denied.
Retries that could send target traffic require a newly authorized job ID.

Windows 同时准备 `manifest.json` 与 `manifest.sha256`。Runner 会规范化收到的 JSON，
摘要不一致时在策略校验和网络请求之前拒绝执行。启用网络的 `job_id` 会在
`~/src-runner/state/consumed/` 中消费一次；任何可能重新发送目标请求的重试都必须使用
重新授权的新任务 ID。

## Evidence and offline triage / 证据与离线研判

Evidence files are write-once, query values are redacted, and `evidence-index.json` records
file hashes. The offline analyzer ranks vulnerability candidates, observations, and safety
stops from redacted evidence. It never marks a candidate reportable without manual impact
validation and never sends a request.

证据文件默认不可覆盖，查询参数值会脱敏，`evidence-index.json` 保存文件哈希。离线分析器
从脱敏证据中生成疑似漏洞、安全观察和安全停止项；在人工确认实际影响前，任何候选都不会
被标记为可提交漏洞，分析过程也不会发送请求。
