# 在防护中运行 LangGraph 任务

`yuanxingmu sdk-run --framework langgraph` 用真实 LangGraph `StateGraph` 和原生 `ToolNode` 完成模型、工具、回答的循环。整个 Python 进程及其子进程在隔离环境中运行；模型密钥、资料访问权限、自动操作范围和最终回答检查继续由宿主控制。

这是开发源码入口，尚未包含在 runtime `0.7.0a2` 或 installer `0.4.0a2` 下载包中。它提供固定的受保护任务流程，不会自动接管任意已有图、自定义节点、工具、插件、远程图或多 Agent 应用。已有的 [LangChain/LangGraph 工具适配](native-adapters.md)仍可单独使用，但工具适配本身不提供完整进程隔离。

## 开始运行

准备一个已经启用分层防护、保护字段和回答缓冲的 Hermes 或 OpenClaw 工作实例，并先停止它的原生页面服务。安装当前元星木源码，使用 Linux/WSL 的系统 Python 建立独立 SDK 环境：

```bash
/usr/bin/python3 -m venv ~/yuanxingmu-langgraph
~/yuanxingmu-langgraph/bin/python -m pip install -r docs/langgraph-runtime-requirements.txt
```

固定版本为 LangGraph `1.2.11`、prebuilt `1.1.0`、checkpoint `4.2.0`、LangChain Core `1.6.2`、Pydantic `2.13.5`。宿主检查安装元数据，不在可信宿主进程中导入 SDK。虚拟环境须位于工作实例目录之外，解释器来自 `/usr` 下的系统 Python。

把任务写入 UTF-8 文件后运行：

```bash
yuanxingmu sdk-run \
  --framework langgraph \
  --profile /absolute/path/to/profile \
  --sdk-python /absolute/path/to/langgraph-venv/bin/python \
  --session customer-summary \
  --prompt-file /absolute/path/to/task.txt \
  --max-steps 12 \
  --max-tokens 2048 \
  --timeout 600
```

模型连接沿用原工作实例。命令不接收模型密钥，也不能让模型选择服务器、宿主文件路径或新的任务权限。运行后输出 JSON；只有宿主检查后的回答会出现在 `answer` 中。

启动时会按本次 SDK 的实际工具清单重新做基础配置检查。如果原工作实例的 `allowed_tools` 固定为 Hermes/OpenClaw 的原生工具名，清单不同会阻止启动；入口不会自动放宽这项配置。应在受信任的工作配置中核对本页工具清单，必要时为 SDK 建立独立工作实例；其权限仍须按任务设置。

省略 `--framework` 仍使用原有的 [smolagents 入口](sdk-runtime.zh-CN.md)。同名会话绑定原框架、运行环境和任务身份，不能通过换框架直接恢复；选择新的会话名也仍沿用原任务组的权限、数据限制和自动操作额度。

## 可以自动做什么

| 工具 | 行为 |
|---|---|
| `yuanxingmu_read` | 读取登记资料，保留资料限制和输入检查。 |
| `yuanxingmu_describe` | 查询原任务的权限与限制。 |
| `yuanxingmu_action_targets` | 查询已登记的操作对象。 |
| `yuanxingmu_propose_action` | 保存待复核提案。 |
| `yuanxingmu_draft_email` | 保存待复核邮件草稿。 |
| `yuanxingmu_request_action` | 仅在原工作实例已有自动范围时开放；检查后执行授权的消息、上传和表单。 |

自动工具沿用原来的目标、次数和内容限制，正常授权范围内的操作无需逐次确认。范围外的动作按照宿主策略拒绝或保留待复核提案。邮件发送、宿主文件覆盖和删除没有加入这个入口的自动执行范围。

此图以不含工具调用的普通模型正文结束，不提供 smolagents 的 `final_answer` 工具。即时 `send`、终端、代码执行、任意网络连接和审批接口也不开放。宿主 Broker 同时限制可接收的操作，不能靠跳过 SDK 工具对象来直接调用这些接口。

## 一批操作如何执行

先检查整批工具名称和参数，再逐项调用原生 `ToolNode`，每次只交给它一个工具调用。仅设置线程数为一仍可能把整批任务放进执行队列；逐项派发才能在当前结果不确定时阻止后续操作启动。

每次操作前，worker 都通过固定模型套接字，重新核对宿主保存的原模型请求和回复。工具编号由宿主持久生成，不能只根据检查点里的一段工具指令执行。SDK 工具错误、模型传输结果无法确认、自动操作仍在执行或结果不确定时，停止本轮；达到模型步数上限也不会追加一次模型调用来编造总结。

宿主还有独立的精确重复检查：新的自动请求不能重复同一任务组中目标、规范化内容和目标绑定一致的未确认操作，换编号也一样；先前操作可以来自人工尝试或子任务。它不等于识别所有改写措辞后的重复业务；内容检查和总额度继续适用。

## 中断和恢复

当前开发入口尚未逐项核验完成答案和全部旧轮历史的宿主原件；仅应恢复自己生成、未被其他程序改写的检查点。当前权限检查和操作去重不构成对已改写历史内容的完整性保证。

原生图使用同步持久化和仅保存 JSON 数据的 checkpoint saver。恢复未完成会话时，使用 LangGraph 的 `invoke(None)` 恢复路径；已登记动作仍由宿主按原编号去重。若宿主已经接受操作、worker 尚未来得及记录结果，恢复后核对同一操作记录，不能当作新动作再次执行。

同一请求再次查询宿主时，也会保留“先前相同操作的结果未确认”的原因，阻止继续同批后续操作。旧检查点中仍保留不确定状态或原因的记录同样会停止；旧版本若已把原因丢失并缓存为普通待处理结果，升级不会逐项重放历史工具或自动纠正该缓存，应核对宿主操作账本。后续实际请求仍受当前权限、额度和精确重复检查约束。

同名会话需要显式加 `--resume`。未完成的会话须沿用原任务文本。已经完成的会话可返回已保存答案，宿主仍会重新检查回答；在该会话提出新的任务文本时，继续沿用原权限和额度。

检查点只保存工作数据，不是批准凭证。持久化格式不使用 pickle、可调用对象或动态构造对象；宿主模型记录和会话身份位于 worker 不可访问的位置。工作目录内的检查点可能包含对话和资料正文，应按工作数据管理。

## 验证与限制

**2026-09-13 GLM‑5.2 实测：** 冻结源码 `ce355a8` 上，真实图一次完成消息、文本上传和表单，各产生一份正确接收记录；已完成会话重开没有再次调用工作模型或发送，撤销后拒绝继续。[实测报告](evidence/langgraph-runtime-2026-09-13/REPORT.zh-CN.md)保留模型回复、接收正文、源码哈希和限制。这是明确指导的合成正常任务，未启动 Hermes/OpenClaw WebUI。

本入口的测试由三部分组成：固定 SDK 下的真实图与工具循环、带本机接收端的自动操作、故障与恢复。宿主测试还单独运行完整隔离子进程，并检查框架切换、原任务权限和撤销。

```bash
PYTHONPATH=.:tests ~/yuanxingmu-langgraph/bin/python -m unittest \
  tests.test_langgraph_runtime \
  tests.test_langgraph_automatic_runtime \
  tests.test_langgraph_runtime_faults -v
```

上述三个 LangGraph 模块在固定环境中 26/26 通过、零跳过；连同 smolagents 和共享宿主模块，九个 SDK 模块在 Linux 上共 113/113 通过、零跳过。完整发现的 1123 项在 Linux 上 947 项通过、176 项跳过，在 Windows 上 374 项通过、749 项跳过；均无失败或错误。

这些本机定程模型测试证明实际调用路径与故障处理，不代表真实模型攻击阻断率；跳过的用例不算通过。模型请求有宿主容量上限，任务有时间和输出上限，但尚未提供整个进程组的 CPU、内存和工作目录磁盘配额。
