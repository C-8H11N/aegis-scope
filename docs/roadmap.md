# Roadmap / 路线图

## 0.1 - Offline-first MVP / 离线优先 MVP

- Shared strict contracts and dual policy gate / 共享严格协议与双重策略校验；
- Windows CLI/Web control plane / Windows CLI 与 Web 控制面；
- Constrained Kali runner and SSH/SCP transport / 受限 Kali Runner 与 SSH/SCP；
- Bilingual docs, UI messages, and report templates / 双语文档、界面消息和报告模板。

## 0.2 - Local laboratory validation / 本地实验室验证

- Completed: manifest digest verification and one-time job consumption / 已完成清单摘要校验与任务防重放；
- Completed: write-once evidence, hashed index, and bounded offline candidate analysis / 已完成不可覆盖证据、哈希索引和有界离线候选分析；
- Completed: transfer failure recovery without automatic request replay / 已完成不自动重放请求的传输失败恢复；
- Completed: deterministic mocked HTTP scenarios for runner stop and redaction behavior / 已完成 Runner 停止与脱敏行为的确定性模拟 HTTP 场景；
- Completed: cross-capture evidence diffing and duplicate hints / 已完成跨流量证据差异分析与重复线索；
- Next: Ed25519 authorization signatures / 下一步：Ed25519 授权签名。

## 0.3 - Analyst workflow / 分析员工作流

- Completed: HAR/Burp export ingestion and redaction-before-persistence / 已完成 HAR/Burp 导出导入与落盘前脱敏；
- Completed: endpoint/role diffing and same-code duplicate clustering / 已完成接口角色差异与同代码重复聚类；
- Completed: human-governed finding lifecycle and bilingual report renderer / 已完成人工治理的疑似问题生命周期与双语报告渲染；
- Next: richer object-level authorization and business-flow views / 下一步：更丰富的对象级权限与业务流程视图；
- Provider plugins with local-model support / Provider 插件与本地模型支持。

## 0.4 - Autonomous Campaign Mode / 自主研究任务模式

- Completed: exact-host campaign state and cumulative request/stage budgets / 已完成精确主机任务状态与累计预算；
- Completed: deterministic evidence-to-hypothesis ranking and deduplication / 已完成证据到假设的确定性排序与去重；
- Completed: one-next-action planner with safe manual routing / 已完成单一下一动作规划与安全人工分流；
- Completed: bilingual Campaign CLI, API, and dashboard / 已完成双语 Campaign CLI、API 与控制台；
- Next: signed authorization bundles and loopback end-to-end campaign simulation / 下一步为签名授权包与本地回环端到端模拟。

## 0.5 - Research Loop / 研究闭环

- Completed: immutable structured program-rule snapshots and source digests / 已完成不可变结构化项目规则快照与来源摘要；
- Completed: proposal-to-job-to-evidence binding with digest and contract matching / 已完成提案、任务与证据的摘要及协议绑定；
- Completed: automatic offline result synchronization and actual-budget reconciliation / 已完成离线结果自动回流与真实请求预算核对；
- Completed: bilingual dashboard result synchronization and human result-review state / 已完成双语控制台结果同步与人工结果复核状态；
- Next: Ed25519 signed authorization bundles and tamper-evident audit chains / 下一步：Ed25519 签名授权包与防篡改审计哈希链；
- Next: richer object-level authorization and business-flow graph / 下一步：更丰富的对象级权限与业务流程图。

## 1.0 - Stable authorization platform / 稳定授权平台

- Versioned protocol compatibility / 版本化协议兼容；
- Optional multi-runner HTTPS/mTLS transport / 可选多 Runner HTTPS/mTLS；
- Reproducible releases and signed artifacts / 可复现发布与签名制品；
- External security review / 外部安全评审。
