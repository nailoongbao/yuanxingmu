# 在隔离环境中运行 smolagents 任务

这是 **main 开发源码新增的入口**，尚未包含在已发布的 runtime `0.7.0a2` 或 installer `0.4.0a2` 中。以下命令需要安装当前源码；旧安装包不会自动获得它。

`yuanxingmu sdk-run` 把一个完整的 smolagents `ToolCallingAgent` 模型循环接到元星木已有的防护服务。它使用已停止的 OpenClaw 或 Hermes 工作实例，沿用原来的任务身份、资料、保护字段、操作对象和复核记录；另开一个 SDK 会话不会清除这些限制。

这条入口固定使用 **smolagents 1.26.0**。它是一个有明确工具范围的运行入口，不会接管用户任意 Python Agent、既有自定义工具、`CodeAgent`、其他 Agent 或第三方插件。

`sdk-run` 省略 `--framework` 时仍使用本页入口；另有 [`--framework langgraph`](langgraph-runtime.zh-CN.md) 的固定图入口、[`--framework openai_agents`](openai-agents-runtime.zh-CN.md) 的固定助手交接入口，以及 [`--framework pydantic_ai`](pydantic-ai-runtime.zh-CN.md) 的原生延迟工具入口。各入口按自身固定依赖建立 SDK 环境，同一会话名不能跨框架恢复。

启动时会按本次 SDK 的实际工具清单重新做基础配置检查。原工作实例若把 `allowed_tools` 固定为原生 Hermes/OpenClaw 工具名，清单不匹配会阻止启动，入口不会自动放宽限制。应在受信任的工作配置中核对本入口的工具清单，必要时为 SDK 建立独立工作实例。

## 开始运行

准备一个已启用分层防护、保护字段和回答缓冲的工作实例，并在工作台确认它已经停止。需要 Linux 或 WSL、可用的 bubblewrap，以及单独安装 smolagents 1.26.0 和 pydantic 2.x 的虚拟环境；SDK 虚拟环境应位于工作实例目录之外。本入口复用工作实例已配置的模型，不在命令行或 worker 中传入模型密钥。

在源码目录使用系统 Python 建立独立 SDK 环境：

```bash
/usr/bin/python3 -m venv ~/yuanxingmu-smolagents
~/yuanxingmu-smolagents/bin/python -m pip install -r docs/sdk-runtime-requirements.txt
```

虚拟环境的解释器须来自 `/usr` 下的系统 Python。原实例若固定了与 SDK 不同的工具清单，基础检查会拒绝运行；不会自动修改原授权或关闭检查。

将本次任务写入一个 UTF-8 文本文件，然后运行：

```bash
yuanxingmu sdk-run \
  --profile /absolute/path/to/profile \
  --sdk-python /absolute/path/to/sdk-venv/bin/python \
  --session customer-summary \
  --prompt-file /absolute/path/to/task.txt \
  --max-steps 12 \
  --max-tokens 2048 \
  --timeout 600
```

`--session` 是用户选择的会话名称。首次使用会创建宿主持久身份；已有会话必须显式加 `--resume`。继续已经完成的会话时，可以修改任务文件来提出下一轮要求。恢复未完成的会话时，任务文本必须与中断前一致。

运行结束后只返回一份 JSON，其中 `answer` 是宿主再次检查后的回答。若检查决定暂扣回答，宿主返回 `withheld` 和安全提示。未知工具、参数错误、无法确认的传输结果以及模型步数耗尽会停止这一轮；不会为了给出回答再额外请求模型。

## 能使用什么工具

| 工具 | 实际行为 |
|---|---|
| `yuanxingmu_read` | 读取宿主登记的资料，沿用资料限制和输入检查。 |
| `yuanxingmu_describe` | 查询当前任务权限与资料限制。 |
| `yuanxingmu_action_targets` | 查询宿主登记的操作对象。 |
| `yuanxingmu_propose_action` | 向原有操作账本提交待复核提案；worker 不能批准或执行。 |
| `yuanxingmu_draft_email` | 保存待复核的邮件草稿，worker 不能批准或发送。 |
| `yuanxingmu_request_action`，有既定自动范围时开放 | 请求自动发消息、上传内容或提交表单；宿主按原先授权的目标、次数和内容限制检查，再决定是否执行。 |
| SDK 自带的 `final_answer` | 结束这一轮并提交文本回答，宿主检查后才显示。 |

每一批工具调用按顺序执行。即时发送 `send` 没有重复请求去重能力，因此不在本入口中开放；宿主 Broker 套接字也拒绝这个操作，不能通过绕过工具对象直接请求它。其他工具、终端、代码执行、技能加载和多 Agent 委派均不在当前入口的范围内。

原工作实例已有自动操作范围时，宿主会在只读启动配置中启用 `automatic_actions`，工具列表才增加 `yuanxingmu_request_action`；默认没有这个工具。它只处理消息、上传和表单，使用原有自动权限与次数账本，不能自动改写或删除宿主文件。每次请求仍经过保护字段、资料限制、任务检查及原范围核对；正常且在授权内的操作可以直接完成，不需要逐次确认。范围之外按宿主策略拒绝、暂停或留下待复核提案。

`propose_action` 始终是待复核提案。人工复核仍走现有工作台或宿主复核入口；worker 接触不到复核套接字。可选自动工具的请求编号使用独立命名空间，不能拿一条普通提案的编号当作自动执行记录。

## 防护接在哪里

整个 SDK 进程及其子进程位于 bubblewrap 隔离环境。宿主只挂入选定的只读程序、SDK 虚拟环境、只读启动配置、工作目录，以及单独的 Broker 和模型套接字。worker 没有直接对外网络或真实模型密钥。

当前入口设有运行时间、模型步数、输出和模型记录容量上限；尚未限制整个进程组的 CPU、内存与工作目录磁盘用量，不能据此保证宿主免受资源耗尽影响。

模型请求只能经过宿主固定的模型服务。宿主在返回模型响应之前执行现有回答检查，再为工具调用写入独立编号并持久保存。工具操作继续经过原 Broker；最终回答从 worker 返回后，宿主还会检查一次。这个接入复用了原有检查和权限限制，没有新增一种“保证模型意图正确”的判断。

## 中断与恢复

宿主模型记录保存请求摘要与已检查响应，工具编号由宿主生成。worker 的 JSON 检查点只保存对话、当前步骤和已完成工具结果，不保存密钥、可充当批准凭证的权限材料或可重新加载的 Python 对象。

恢复未完成步骤时，worker 把原请求交回宿主，取得宿主重新核对当前权限后的同一响应。它不会直接执行检查点中缓存的工具指令。如果返回内容与原记录不一致，会保留原检查点并停止。

已经完成并写入检查点的工具不会自动再派发。若 Broker 已接受提案或完成自动操作、worker 却来不及记录结果，恢复时会使用原调用编号提交相同请求，由 Broker 返回已有记录，避免再产生一次外部效果。这就是本入口开放可去重的 `request_action`、同时排除即时 `send` 的原因。无法确认的宿主模型请求不会自动重发到上游。

自动操作返回“仍在执行”或“结果不确定”时，本轮也会停止；恢复时遇到同样的记录仍会停止。网络错误不等于内容尚未送达，不能据此让模型换个编号自动重发。

同一请求再次查询宿主时，也会保留“先前相同操作的结果未确认”的原因，阻止继续同批后续操作。旧检查点中仍保留不确定状态或原因的记录同样会停止；旧版本若已把原因丢失并缓存为普通待处理结果，升级不会逐项重放历史工具或自动纠正该缓存，应核对宿主操作账本。后续实际请求仍受当前权限、额度和精确重复检查约束。

每个会话的检查点绑定同一 `session_id`、`task_id`、模型和自动工具开关。其他会话不能直接拿它恢复；新会话仍共享原工作实例的任务与资料限制。检查点位于任务工作目录，可以包含资料正文；它是工作数据，不是授权凭证。

## 当前验证范围

**2026-09-13 GLM‑5.2 实测：** 冻结源码 `f5232ba` 上，真实 `ToolCallingAgent` 一次完成消息、文本上传和表单三种自动操作，每处一份正确接收记录；已完成会话重开没有再次调用工作模型或发送，撤销后拒绝继续。首轮失败和验证限制一并保留在[实测报告](evidence/smolagents-runtime-2026-09-13/REPORT.zh-CN.md)。这是 CLI 入口的合成正常任务，未启动 Hermes/OpenClaw WebUI，不能替代攻击测试或中途恢复的故障测试。

新增的 [`test_smolagents_runtime.py`](../tests/test_smolagents_runtime.py) 在固定 SDK 环境中运行了 15 项测试、零跳过。测试实际执行 `Agent.run`、Unix HTTP 模型桥、Broker 和提案复核，并包含本机接收端收据、不同调用编号、参数拒绝、上下文退出、检查点绑定、批内中断、Broker 接受后丢失本地记录、恢复响应变化和步数上限。

另有 [`test_smolagents_automatic_runtime.py`](../tests/test_smolagents_automatic_runtime.py) 的原 11 项自动操作测试、零跳过，使用实际 Guards、固定自动范围及本机模型和检查服务。消息、上传、表单都产生了真实本地收据；越范围、危险文件操作、伪造参数、检查拦截和撤权均未产生外部效果。宿主已经执行、worker 尚未记录结果时中断，恢复后仍是一份收据、一次额度消耗。接收端收到内容后故意丢失回执的场景还验证了同批停止、恢复后仍停止，以及仍带不确定状态的旧检查点会停止。本次另补了换编号请求得到“先前结果未确认”后，多次恢复仍停止的用例。

[`test_smolagents_runtime_timeouts.py`](../tests/test_smolagents_runtime_timeouts.py) 的 4 项测试使用真实延迟检查服务和 Unix Broker，按比例缩短 15 秒与 120 秒等待期限，验证读取、待复核提案和自动发送不会因旧的短等待提前退出；恢复发送仍只有一份收据和一次额度消耗。它们没有用外部模型来测响应速度。

这些测试使用定程模型服务，验证完整程序调用路径和故障恢复；它们不代表真实模型的攻击阻断率。宿主模型记录、整个隔离进程、固定套接字和撤权路径分别由 [`test_yuanxingmu_sdk_model_store.py`](../tests/test_yuanxingmu_sdk_model_store.py) 与 [`test_yuanxingmu_sdk_runtime.py`](../tests/test_yuanxingmu_sdk_runtime.py) 检查，实际运行时需要固定 SDK 环境和可用的 Linux 隔离条件。旧的十一组工具适配证据仍然只是各自当时的组件验证，不会自动升级成其他框架的完整防护结论。

宿主原本就会拦截新的自动请求重复同一任务组中、同一目标与相同规范化内容的未确认操作，即使请求换了编号也一样；先前操作可以来自人工尝试或子任务。此 SDK 入口进一步在不确定结果后停止整批操作。改变文字后再次申请同一业务仍可能落在精确比较之外，宿主继续按目标、内容限制和总额度检查。
