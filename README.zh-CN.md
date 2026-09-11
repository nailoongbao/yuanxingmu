# 元星木 · Yuanxingmu

**模型提请求，系统管权限。**

让 Agent 在受限环境里工作，把资料读取、外部发送和任务权限交给环境之外的服务。读过私密资料后，任务就不能再向公开目的地发送；重连、恢复和派生子任务都不能清掉这条限制。

[English](README.md) · [官网](https://yh-l20.github.io/agent-defense-check/) · [看实机演示](https://yh-l20.github.io/agent-defense-check/demo.html) · [运行说明与边界](docs/yuanxingmu.md) · [真实运行记录](examples/yuanxingmu/verified-core-report.json)

![元星木：让能力增长，权限有界](site/assets/yuanxingmu-poster.svg)

这是一个 **Linux 本地研究原型**。使用真实 bubblewrap、SQLite、独立 HTTP 接收进程和合成资料验证；没有调用攻击模型，没有生产防御率，也没有完整的企业权限接入。当前公开仓库地址保留 `agent-defense-check`，系统名称为元星木。

## 先跑起来

需要 Linux、Python 3.12+ 和支持此隔离配置的 bubblewrap（已测 0.9.0）。Ubuntu/WSL 环境示例：

```bash
sudo apt-get install bubblewrap
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python -I -m yuanxingmu doctor
.venv/bin/python -I -m yuanxingmu demo --output output/yuanxingmu-first-run
```

输出目录每次使用新名字。`doctor` 会实际创建隔离环境；不可用时停止，不能退回宿主直接执行。Windows 用户须在 Linux/WSL 内运行新核心。

演示同时检查禁止动作和正常工作：私密正文及其编码不能外发，宿主资料和授权数据库不可直接读取；重启 broker、既有子任务继续运行后仍受限。独立接收端应只收到 **2 次内部发送、1 次干净任务的公开发送**，全部工作进程退出。

## 三个部分

| 部分 | 做什么 |
| --- | --- |
| 任务权限库 | 保存允许读取的资源、允许发送的目的地，以及整个任务家族已经读过的数据标签。状态只收紧，显式撤销覆盖子任务。 |
| 资料与发送服务 | 先保存读取记录，再交出资料；每次发送都重新核对目的地。只接受预先配置的资源/目的地 ID，不接受任意 URL 或模型自报的任务身份。 |
| Linux 执行环境 | 使用现成 bubblewrap 关闭直接网络、隐藏宿主 home 和授权库，只挂一个工作目录和该任务专用 socket。 |

权限依据任务已经读过什么，而不是猜它这次的措辞是否恶意。请求里夹带不同 task ID、换连接、把正文编码，都不能扩大权限。

**代价也很明确：读过私密资料后，即使发送无害公开摘要也会被保守阻止。** 当前没有自动脱敏放行；新的公开任务必须使用独立、经可信宿主选择的输入和工作目录。同一工作目录不能换新任务身份使用。

## 接自己的命令

可信宿主准备资源与目的地配置，然后执行：

```bash
python -I -m yuanxingmu run --policy policy.json --state authority-state \
  --task review-001 --new-task --workspace /absolute/public-workspace \
  -- /usr/bin/python3 -m yuanxingmu.client read private
```

恢复时使用同一状态目录和 `--task`，去掉 `--new-task`。完整配置与发送例子见[运行说明](docs/yuanxingmu.md)。这条命令的配置、任务创建与工作目录选择由可信宿主管理，不能交给被防护的 Agent 自由调用。

[OpenClaw 原生执行](examples/yuanxingmu/openclaw/README.md)与 [Hermes 原生终端环境](examples/yuanxingmu/hermes/README.md)已分别完成接入演示。OpenClaw 使用本地脚本模型发起真实工具调用；Hermes 验证原生工具调用链，没有运行模型对话。结果只覆盖各示例列出的工具和配置。

[独立 Linux CI 记录](examples/yuanxingmu/verified-hosted-report.json)保存了 33 项测试和 19 项核心演示检查的结果。它验证执行核心，不包含这两种框架的 WebUI 或真实模型攻击评测。

## 为什么做它

模型能力增长后，攻击者更容易组合合法工具、寻找检查遗漏、并行重试。元星木选择把“能不能真的做成”放到模型之外，建设可接入现有 Agent 的执行权限边界。bubblewrap、凭证代理和信息流控制都有成熟先例；这里尝试做的是把任务身份、持久读取限制和实际执行连接起来。

我们没有证明整体超过 [AgentWard / 玄甲](https://github.com/FIND-Lab/AgentWard)。它已经提供 OpenClaw 检测、审批与会话干预；元星木目前验证的是另一层的执行约束，详见[实现对比与产品判断](docs/positioning.md)。

原有 MCP 接入验收工具和已发布 `v0.1.0a1` 保留：[旧版说明](LEGACY-MCP.zh-CN.md)。新版没有覆盖旧 release，也不把旧实验算作新核心的验证。
