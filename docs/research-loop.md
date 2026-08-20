# Research Loop / 研究闭环

## 中文

AegisScope 0.5 将结构化项目规则、Campaign 假设、已授权任务和本地证据连接为一条可审计闭环。该闭环只读取本地 SQLite 审计数据，不会因为“同步结果”而调用 SSH、Kali 或目标网络。

### 规则快照

`ProgramSpec` 保存精确主机、禁止动作、阶段类型、速率、请求上限、认证政策、证据要求和报告要求。导入时会对原始规则正文计算 SHA-256，但不会把正文写入数据库。Campaign 可以绑定一个规则快照，并记录快照摘要。

### 执行绑定

Campaign 只绑定同时满足以下条件的本地 Job：

1. 清单声明来自当前待审提案；
2. 提案 SHA-256 与授权清单记录一致；
3. 项目、精确主机、阶段类型、请求和限制完全一致；
4. Job 具有本地清单摘要和审计记录。

绑定不会授权或执行任务。实际网络阶段仍需独立的 `authorize` 与 `dispatch --execute`。

### 结果回流

`campaign-sync` 或控制台中的“同步阶段结果”会读取已经保存的阶段摘要与离线分析：

- 从阶段摘要计算实际请求数，避免人工填写漂移和重复计数；
- 保存停止原因、候选数、观察数、安全停止数和摘要哈希；
- 生成保守的建议结论；
- 将假设转入人工结果复核状态。

建议结论不是漏洞结论。只有人工复核证据并记录 disposition 后，队列才会继续。

## English

AegisScope 0.5 links an immutable structured program snapshot, a Campaign hypothesis, an independently authorized job, and saved local evidence. Synchronization is offline-only and never invokes SSH, Kali, or a target.

Jobs are bound only when proposal identity, proposal digest, manifest contracts, program, exact host, requests, and limits all match. Actual request usage is derived from the saved stage summary, counted once, and routed to a human result-review state. Analyzer candidates remain leads and can never confirm a vulnerability automatically.
