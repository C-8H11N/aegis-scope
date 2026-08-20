# Autonomous Campaign Mode / 自主研究任务模式

## 中文

Campaign 模式是 AegisScope 的离线研究编排层。它保存一个精确主机的长期研究状态，读取
已经脱敏的流量分析，按风险、置信度、新颖度、证据完整度和请求成本对假设排序，并只选择
一个最有价值的下一动作。

它能自动完成：

- 对已有候选去重并建立优先级队列；
- 记录阶段数和请求数总预算；
- 为公开、无认证的低影响观察生成严格 `StageProposal`；
- 把认证、角色、对象权限和原始响应上下文类线索交给人工 Burp 复核；
- 在预算耗尽、没有剩余假设或需要人工能力时安全停止；
- 保存 Campaign 状态和追加式审计事件。
- 绑定结构化项目规则快照并校验其摘要；
- 将匹配的 Job、阶段摘要和离线分析回流到原假设；
- 从阶段摘要自动、且只计一次实际请求预算。

它不能自动完成：

- 授权目标访问；
- 把提案变成可联网阶段；
- 调用 Kali 或发送 HTTP 请求；
- 重放 Cookie、Token、登录态或请求正文；
- 确认漏洞、生成可提交结论或扩大资产范围。

### 快速体验

```powershell
aegisscope program-import .\examples\safe-demo\program.json
aegisscope campaign-create .\examples\safe-demo\campaign.json
aegisscope campaign-list
aegisscope campaign-plan <campaign-id>
aegisscope campaign-export-proposal <campaign-id> --output proposal.json
aegisscope campaign-sync <campaign-id>
```

内置示例使用保留的 `.invalid` 域名。`campaign-plan` 只读本地 SQLite 数据；如果没有匹配
的离线分析，只会生成一份含 `HEAD` 和 `GET` 的两请求、永久未授权、`dry_run: true` 提案。
人工审核提案后，仍需用现有 `authorize` 命令记录独立的阶段授权。
阶段运行和离线分析完成后，`campaign-sync` 只读取本地 SQLite 记录，将结果转入人工复核；
它不会连接 Kali，也不会访问目标。

## English

Campaign mode is AegisScope's offline research orchestration layer. It preserves long-running
state for one exact host, reads redacted traffic analyses, ranks hypotheses by risk, confidence,
novelty, evidence quality, and request cost, and selects one highest-value next action.

It can bind an immutable program-rule snapshot, deduplicate leads, enforce cumulative budgets,
create a strict unapproved proposal for a public low-impact observation, route
authentication-dependent leads to manual Burp review, synchronize matching saved job results,
and retain an append-only audit trail. Result synchronization is local-only. It cannot authorize
target access, invoke Kali, send HTTP, replay credentials, confirm a vulnerability, or expand
scope.
