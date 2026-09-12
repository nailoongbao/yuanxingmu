# 在防护中运行 OpenAI Agents 任务

`yuanxingmu sdk-run --framework openai_agents` 将真实 OpenAI Agents SDK `Runner` 接入元星木的隔离进程。资料助手先读取资料，可以直接回答，也可以通过 SDK 原生 handoff 交给执行助手处理消息、上传、表单和待复核提案。两个助手沿用同一个宿主任务、资料限制和自动额度，交接不会获得新的权限。

这是 main 源码中的固定工作流程，尚未包含在 runtime `0.7.0a2`、installer `0.4.0a2` 下载中。它不接管任意已有 Agent、自定义工具、嵌套 Agent、MCP 服务器或远程会话；[原有工具适配](native-adapters.md)可以单独使用，但只提供工具适配不能保护整个应用进程。

## 安装与运行

先准备一个已启用分层防护、保护字段及回答缓冲的 Hermes/OpenClaw 工作实例，停止它的原生服务。使用 Linux/WSL 的系统 Python 建立 SDK 环境：

```bash
/usr/bin/python3 -m venv ~/yuanxingmu-openai-agents
~/yuanxingmu-openai-agents/bin/python -m pip install -r docs/openai-agents-runtime-requirements.txt

yuanxingmu sdk-run \
  --framework openai_agents \
  --profile /absolute/path/to/profile \
  --sdk-python /absolute/path/to/openai-agents-venv/bin/python \
  --session customer-summary \
  --prompt-file /absolute/path/to/task.txt \
  --max-steps 12 \
  --max-tokens 2048 \
  --timeout 600
```

固定版本为 `openai-agents 0.22.2`、`openai 3.13.0`、`pydantic 2.13.5`。SDK 环境须位于工作实例目录之外，解释器来自 `/usr` 下的系统 Python。宿主读取安装元数据，不在可信宿主进程中导入 SDK。

模型沿用原工作实例的配置，经宿主的 Chat Completions 通道连接；不要求模型来自 OpenAI。模型密钥留在宿主，worker 无法另选模型服务器、宿主路径或审批接口。SDK tracing、远程会话及自动模型重试在这条入口中关闭。

发送给模型的工具声明会展开固定对象结构，保留原来的必填字段、类型、数量及额外字段限制。执行端仍严格校验参数，不会把字符串猜成对象。不同模型能否正确遵循声明，须按实际运行结果判断。

启动前会按固定入口的工具并集重新做基础配置检查。若原工作把 `allowed_tools` 固定为原生 Hermes/OpenClaw 工具，清单不匹配会阻止启动；入口不会自动放宽限制。应在受信任的工作配置中核对本页工具清单，必要时建立单独的 SDK 工作实例。

## 两个助手怎样工作

| 助手 | 模型可见工具 | 工作范围 |
|---|---|---|
| 资料助手 | `yuanxingmu_read`、`yuanxingmu_describe`、`yuanxingmu_action_targets`、`yuanxingmu_handoff_to_executor` | 读取资料、了解原任务与目标，回答或交接。 |
| 执行助手 | `yuanxingmu_describe`、`yuanxingmu_action_targets`、`yuanxingmu_propose_action`、`yuanxingmu_draft_email`，以及有自动范围时的 `yuanxingmu_request_action` | 处理已登记目标的消息、上传、表单或保存待复核提案。 |

交接只允许从资料助手转向固定执行助手，不接受额外参数，也不能转向任意助手。在一条模型回复中同时要求普通工具和交接，或发起多个交接，会在整批执行前被拒绝。

这个分工改变模型可见的工具和任务职责，**不是两个独立的宿主权限域**。两个助手共用受限进程和宿主任务，宿主仍对每次资料访问和操作复核。模型或 worker 不能通过角色名称、交接、新会话或另换 SDK 重置原有额度。

原工作已有自动范围时，正常消息、文本上传和表单无需逐项确认；范围外请求按宿主策略拒绝或保存待复核提案。保存邮件草稿不等于发送邮件，保存文件操作提案也不等于自动修改宿主文件。入口没有即时 `send`、任意代码执行、任意网络或宿主审批工具。

## 暂停、恢复与执行权限

SDK 自带的暂停状态用于保存运行进度。程序核对宿主保存的原模型回复后自动推进；这是内部调度步骤，不要求用户反复点击确认，也不构成对外操作的授权。真正发送前，宿主仍检查原任务、目标、内容、预算和撤销状态。

同名会话需要显式加 `--resume`。未完成会话须沿用原任务文本。已完成会话可以重新返回保存的答案，宿主仍重新检查最终回答；新任务文本继续沿用原权限和额度。同名会话不能换成其他 SDK 或另一个运行环境恢复。

恢复时工具声明也必须一致；声明格式发生变化的旧检查点会被拒绝，不会自动转换。另开 SDK 会话仍保留原宿主任务的剩余额度，不能把换会话当作重新授权。

读取或提交后的确定拒绝结果可以交给模型处理；RPC 或 SDK 异常、操作仍在执行、结果不确定、任务被暂停或撤销时，后续操作停止。宿主已保存响应但投递中断可以重放；宿主未确认的模型请求或对外操作不会自动重试。宿主对同一任务组、相同目标和规范化内容的未确认操作还有精确重复检查，换编号也不能重发；它不等于识别所有改写后的重复业务。

检查点属于工作数据，可能含对话和资料正文，应妥善保存。入口保存 SDK 原生 RunState JSON、固定助手映射和暂停期间的请求及工具结果。恢复时先校验格式和记录；继续执行待处理工具前，重新核对宿主保存的原模型回复和当前权限。缓存不能恢复已撤销的权限。原任务授权、模型回复记录及操作账本保存在 worker 无法访问的宿主位置。

## 参考与范围

实现核对了官方 [Agents SDK](https://developers.openai.com/api/docs/guides/agents/sdk)、[运行循环](https://developers.openai.com/api/docs/guides/agents/running-agents)、[交接](https://developers.openai.com/api/docs/guides/agents/orchestration)与[自动检查及人工复核](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals)文档，并以固定版本源码验证具体调用行为。

基础配置检查核对固定入口的声明，不是依赖源码或任意 Agent 的全面审计。任意 Agent 图、双向或动态交接、并行多 Agent、托管工具与远程会话尚未覆盖；整个进程组的 CPU、内存及工作目录磁盘总配额仍未实现。
