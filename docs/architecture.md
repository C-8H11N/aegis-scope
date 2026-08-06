# Architecture / 架构

## English

AegisScope is a single repository with three trust domains:

1. **Control plane**: local Web/CLI, model provider, approval, SQLite, evidence, reports.
2. **Shared core**: immutable contracts, deterministic scope policy, redaction.
3. **Kali runner**: fixed stage registry, bounded HTTP client, temporary redacted output.

The control plane transfers a canonical JSON manifest over SCP, invokes a fixed Python module
over SSH, streams JSONL events, and downloads the job output. Transport authentication and
behavior authorization are separate: SSH authenticates the user and host; the contract and
policy engine authorize the exact stage.

The model never receives a tool capable of executing a target request. It returns a strict
proposal containing only a stage type, exact URLs, methods, and rationale. Local code adds
scope and requires a separate authorization record.

## 中文

AegisScope 在一个仓库中划分三个信任域：

1. **控制面**：本地 Web/CLI、模型 Provider、审批、SQLite、证据和报告；
2. **共享核心**：不可变协议、确定性范围策略和脱敏；
3. **Kali Runner**：固定阶段注册表、受限 HTTP 客户端和临时脱敏输出。

控制面通过 SCP 传输规范化 JSON 清单，通过 SSH 调用固定 Python 模块，接收 JSONL
进度并下载结果。SSH 只负责认证用户和主机；阶段协议和策略引擎负责授权具体行为。

模型不会获得能够直接发送目标请求的工具。它只能返回包含阶段类型、精确 URL、方法
和理由的严格提案，范围与授权记录由本地代码另行添加。
