# AegisScope

[English](README.md) | [简体中文](README.zh-CN.md)

**授权优先的 SRC 安全测试编排 Agent。**

AegisScope 将 Windows 控制面与受限 Kali Runner 分离，把授权范围、请求速率、
人工审批、证据最小化和停止条件实现为不可由模型绕过的确定性策略。

> Alpha 安全边界：模型只能生成待审批提案，不能授予权限、扩大范围或向 Kali
> 发送任意 Shell 命令。

## 架构

```text
Windows 控制面                            Kali Runner
--------------                            -----------
Web / CLI                                 清单校验器
模型提案适配器             SSH/SCP         固定阶段注册表
范围与策略引擎          ------------->     低影响 HTTP 执行器
人工阶段授权            <-------------     脱敏证据
SQLite 审计记录                            JSONL 进度与摘要
证据分析和报告
```

首版使用系统 OpenSSH。Kali 不需要开放新端口或运行常驻 Web 服务；两端在任何网络
动作前都会校验同一份阶段清单。

## 已实现功能

- 严格 Pydantic 阶段协议，拒绝未知字段；
- 精确主机 allowlist/denylist 校验；
- 仅允许 HTTPS `HEAD`、`GET`、`OPTIONS`；
- 并发固定为 1、间隔至少 5 秒、请求和响应大小受限；
- 默认 dry-run，Kali 端还需要显式 `--execute`；
- 跨主机跳转、`403`、`429`、`5xx`、登录/验证码、超时和敏感信息自动停止；
- 敏感响应头和正文自动脱敏；
- Windows SQLite 任务审计；
- FastAPI 控制 API 与 Typer CLI；
- OpenAI 兼容模型适配器，但只能生成未授权提案；
- 使用 `shell=False` 的固定 SSH/SCP 调度；
- 中英文 Web、CLI 消息与报告模板。

## 明确不支持

- 端口扫描、子域名枚举、爬虫、模糊测试和目录爆破；
- 密码测试、凭据攻击和批量数据获取；
- 自动利用、WebShell、持久化、提权和拒绝服务；
- 模型生成的任意 Shell 命令；
- 自动扩大资产范围或跟随重定向。

## Windows 快速开始

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
aegisscope init
aegisscope validate .\examples\safe-demo\stage.json
aegisscope runner-dry-run .\examples\safe-demo\stage.json
aegisscope serve
```

访问 `http://127.0.0.1:8765`。Web API 只负责准备和审计清单，不会直接调度目标请求。

## Kali Runner

Kali 端安装到 `~/src-runner` 下的独立虚拟环境，不修改系统 Python：

```bash
mkdir -p ~/src-runner/app ~/src-runner/input ~/src-runner/output ~/src-runner/logs
python3 -m venv ~/src-runner/venv
~/src-runner/venv/bin/python -m pip install ./aegis-scope
```

Windows 部署脚本仅在用户亲自使用 `-Execute` 时上传明确列出的项目文件，并且不会
直接读取 SSH 私钥。

## 安全演示

`examples/safe-demo/stage.json` 使用保留的 `.invalid` 域名并永久保持 dry-run，因此
不会产生网络请求。

## 正式阶段流程

1. 导入官方规则和精确范围；
2. 通过模型 API 或人工方式生成提案；
3. 审核 URL、方法、上限、停止条件和排除项；
4. 在阶段清单中记录用户的明确授权原文；
5. 在 Windows 准备任务；
6. 通过固定 SSH 传输执行一次；
7. Kali 重复校验、保守执行并返回脱敏证据；
8. 人工复核证据后才能认定漏洞。

连接模型 API 不等于授权目标，仅提供一个域名也不足以开始测试。

## 配置与秘密

使用环境变量或被 Git 忽略的本地 `.env`。不得将 API Key、SSH 私钥、Cookie、
Token、真实授权范围或证据提交到仓库。变量名称见 `.env.example`。

## 当前状态

`0.1.0` 是离线优先 MVP。启用网络闸门前，应先完成协议、策略、dry-run 和本地模拟
测试。参阅 `SECURITY.md` 与 `docs/security-model.md`。

## 许可证

Apache-2.0。开源许可证不替代 SRC 授权或适用法律。
