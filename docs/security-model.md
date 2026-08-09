# Security model / 安全模型

## Non-negotiable invariants / 不可变安全条件

- Exact target host only / 仅限精确主机；
- Explicit stage authorization / 必须具有明确阶段授权；
- HTTPS and fixed safe methods / HTTPS 与固定安全方法；
- Concurrency one, delay at least five seconds / 并发 1，间隔至少 5 秒；
- No redirects, auth, cookies, tokens, body, or arbitrary headers / 无跳转、认证、正文；
- No arbitrary shell or model-controlled command / 无任意 Shell 或模型控制命令；
- Minimal redacted evidence / 最小化脱敏证据；
- Manifest digest verification and one-time network job IDs / 清单摘要校验与网络任务一次性消费；
- Write-once evidence with a hashed index / 不可覆盖证据与哈希索引；
- Immediate bounded stop conditions / 明确且立即生效的停止条件。

## Prompt injection / 提示词注入

Program rules, model output, target content, Burp captures, logs, and downloaded JavaScript are
untrusted data. They cannot modify policy, grant authorization, select a new host, or invoke a
tool. The runner never sends target content back into its execution loop.

项目规则、模型输出、目标内容、Burp 流量、日志和下载的 JavaScript 都是不可信数据，
不能修改策略、授予权限、选择新主机或调用工具。Runner 不会把目标内容重新作为执行
指令输入。

The offline analyzer treats all target-derived content as data. Its deterministic rules may
create candidates and observations, but cannot authorize a stage, modify a manifest, send a
request, or mark a finding reportable.

HAR and Burp XML imports require an explicit exact-host allowlist. Raw messages, request bodies,
cookies, authorization values, and response secrets are not copied into project storage. Only
redacted derived records are persisted. A finding becomes reportable only through a constrained,
audited human lifecycle transition with concrete impact and evidence references.

离线分析器把所有目标内容视为数据。确定性规则可以生成候选和观察项，但不能授予阶段
权限、修改清单、发送请求或把疑似问题标记为可提交漏洞。

HAR 与 Burp XML 导入必须提供精确主机允许列表。原始报文、请求正文、Cookie、授权值和
响应敏感值不会复制到项目存储中，仅保存脱敏后的派生记录。疑似问题只有经过受约束、
可审计的人工状态变更，并补充具体影响与证据索引后，才可成为报告对象。

## Failure behavior / 失败行为

Policy errors fail closed. Transfer retries may repeat file transfer but must not repeat a target
request automatically. Timeouts, sensitive content, cross-host redirects, `403`, `429`, and
`5xx` stop the stage. A missing optional tool never causes automatic installation.

策略错误默认拒绝。文件传输可以重试，但目标请求不得自动重放。超时、敏感内容、跨
主机跳转、`403`、`429` 和 `5xx` 会停止阶段；缺少工具不会触发自动安装。
