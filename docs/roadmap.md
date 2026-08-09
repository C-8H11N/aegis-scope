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
- Next: Ed25519 authorization signatures, evidence diffing, and duplicate detection / 下一步：Ed25519 授权签名、证据差异分析与重复检测。

## 0.3 - Analyst workflow / 分析员工作流

- Burp export ingestion and redaction / Burp 导出导入与脱敏；
- Finding lifecycle and bilingual report renderer / 疑似问题生命周期与双语报告渲染；
- Provider plugins with local-model support / Provider 插件与本地模型支持。

## 1.0 - Stable authorization platform / 稳定授权平台

- Versioned protocol compatibility / 版本化协议兼容；
- Optional multi-runner HTTPS/mTLS transport / 可选多 Runner HTTPS/mTLS；
- Reproducible releases and signed artifacts / 可复现发布与签名制品；
- External security review / 外部安全评审。
