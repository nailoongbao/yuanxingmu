# Google ADK、CrewAI、Agno 原生工具适配

这批新增的是 **Google ADK、CrewAI、Agno** 三个适配器。已有 LangChain/LangGraph、OpenAI Agents、Pydantic AI 三项保持；本批不包含 AutoGen。

每个适配器把现有 Broker 的六项操作注册成框架自己的工具：读资料、按权限发送、查看权限、列出操作对象、提交待确认操作、保存邮件草稿。工具对象、调用上下文和派发方法均使用实际安装的 SDK。完整参数及行为见 [原生工具说明](native-adapters.md)。

这里验证的是工具接入。没有运行模型对话，也没有验证完整 Agent 进程隔离。框架的其他工具、文件访问、联网、子 Agent 和持久化恢复仍需由可信主机统一约束。`send` 可能按权限立即发送；必须逐项人工确认的流程应使用 `propose_action` 或 `draft_email`，并从提供给 Agent 的列表移除 `send`。

## 接入 Google ADK 和 Agno

主机先绑定明确的 worker socket 和持久化会话 ID；二者都不是模型参数：

```python
from yuanxingmu.adapters import NativeTools

client = NativeTools(
    socket_path="/run/yuanxingmu/worker.sock",
    session_id="host-persisted-session-id",
)

# Google ADK 的 BaseTool 扩展，交给 LlmAgent(tools=tools)。
from yuanxingmu.adapters.google_adk import build_tools
tools = build_tools(client)

# Agno 的 Function，交给 Agent(tools=tools)。
from yuanxingmu.adapters.agno import build_tools
tools = build_tools(client)  # 用于 Agent.arun / FunctionCall.aexecute
sync_tools = build_tools(client, asynchronous=False)  # 用于 Agent.run / execute
```

ADK 从真正的 `ToolContext.function_call_id` 读取调用身份。其 `ToolContext` 在本次版本中是 `Context` 的别名。适配器使用 SDK 的 `BaseTool` 扩展点与 `parameters_json_schema`，并在执行时独立验证参数；它不会依赖普通 `FunctionTool` 丢弃多余参数的行为。

Agno 把实际 `FunctionCall` 注入隐藏参数 `fc`，适配器读取 `fc.call_id`。SDK 会移除模型试图提供的 `fc`，测试已确认模型值不能替换实际身份。工具关闭结果缓存，确保每次都到 Broker 查询当前权限和提案状态。

缺少调用身份时不能提交提案。新建适配器后，只要框架、主机会话 ID、操作和实际调用 ID 相同，原提案仍能被找回；同一身份换内容返回冲突。

## CrewAI 需要主机为每次派发保存一个编号

本次 CrewAI 的 `BaseTool`、`CrewStructuredTool` 和 `ToolCallHookContext` 没有给工具注入稳定调用 ID。它需要显式的主机派发编号，不能把模型参数冒充成框架身份，也不能在每次重试时临时生成新编号。

```python
from yuanxingmu.adapters.crewai import HostInvocations, build_tools

invocations = HostInvocations()
tools = build_tools(client, invocations=invocations)
# 注册时传给 CrewAI Agent(tools=tools, cache=False, ...)。

# 以下代码属于可信主机的“单次工具派发”入口。
# host_saved_nonce 在派发前保存，查询或恢复原提案时仍使用同一个值。
selected = next(tool for tool in tools if tool.name == "yuanxingmu_propose_action")
native_tool = selected.to_structured_tool()
with invocations.bind(host_saved_nonce):
    result = await native_tool.ainvoke({
        "proposal": {
            "kind": "message",
            "target_id": "registered-chat",
            "payload": {"body": "请核对这条消息"},
        }
    })
```

`bind` 只包住这一次工具派发。每个新的调用使用新的已保存编号；不要把一个编号包住整个 Agent 对话。直接注册工具后若没有主机派发绑定，读权限等查询仍可用，提案会被拒绝。这个适配器没有暗中安装全局 CrewAI 钩子；应用必须接好自己的主机派发入口。

编号保存在当前执行上下文中，不出现在工具 schema 中。嵌套绑定、异常退出和并发调用均已测试。`BaseTool.run`、`BaseTool.arun` 及转换后的原生 `CrewStructuredTool.invoke/ainvoke` 都保留该绑定；转换时使用异步 callable，避免 SDK 把同步 callable 放入不传播上下文的线程池。不要另行把派发扔进一个不传播上下文的线程；缺少绑定会拒绝提案。

这些 Python 对象自身不是安全隔离。能在同一进程任意执行 Python 的代码仍需通过主机进程边界限制。框架自行序列化工具和自动恢复整个 Agent 的行为未在本轮验证；恢复工具应重新调用工厂，并提供原主机会话 ID 和原派发编号。

## 实际验证

Linux / WSL、Python 3.12.3，使用独立的依赖环境：

| 组件 | 实际版本 | 调用路径 |
| --- | --- | --- |
| Google ADK / Google GenAI | 2.9.0 / 2.23.0 | `LlmAgent` 注册，实际 `ToolContext`，原生 `BaseTool.run_async` 扩展。 |
| CrewAI / CrewAI Core | 1.15.21 / 1.15.21 | `Agent` 注册，实际 `BaseTool` / `CrewStructuredTool` 同步和异步派发。 |
| Agno | 3.0.9 | `Agent` 注册，实际 `FunctionCall.execute/aexecute` 和隐藏 `fc` 注入。 |
| Pydantic / OpenAI 依赖 | 2.12.5 / 2.54.0 | 本批安装依赖；没有调用 OpenAI 接口。 |

CrewAI 注册时使用一个任何调用都会报错的 `NeverRunLLM` 测试对象，仅满足其 Agent 注册接口。该对象及其他模型运行入口从未执行。ADK 的模型名称只是未运行的占位字符串，Agno 没有启动模型 runner。

记录包含 **38 项新增 SDK 测试与 7 项共享客户端测试，合计 45 项通过、0 跳过**。覆盖真实 Unix socket、localhost 接收记录、私密读后的公网发送拒绝、允许的内部发送、五类待确认操作、主机确认后的临时文件效果、邮件草稿、重放状态、变更内容冲突、权限撤销、伪造参数、并发身份，以及 CrewAI 的主机编号差异。

SDK 和 Broker 在同一测试进程内。测试层禁止模型及外部连接、外部 DNS、`connect_ex`，仅允许当前 fixture 的 Unix socket 和 localhost 接收端；任何越界网络尝试会使测试失败。本轮没有越界网络尝试。此限制只用于防止测试误调用，不是产品沙箱效果证明。

依赖：[additional-native-adapters-requirements.txt](additional-native-adapters-requirements.txt)。本批 CrewAI 要求 OpenAI `<3`，旧三项测试环境固定 OpenAI `3.x`，因此应保留两个独立虚拟环境，不要直接合并依赖清单。

```sh
python3 -m venv /tmp/yxm-additional-sdk-env
/tmp/yxm-additional-sdk-env/bin/python -m pip install -r docs/additional-native-adapters-requirements.txt
/tmp/yxm-additional-sdk-env/bin/python -B tests/run_additional_sdk_adapters.py \
  --output /tmp/yxm-additional-sdk-evidence.json
```

输出路径必须是新路径，已有记录不会覆盖。缺依赖、失败、跳过或运行期间源码变化都会使证据命令失败。普通无 SDK 环境的测试发现可以跳过这些可选测试；跳过不算 SDK 验证成功。

最终证据：[additional-native-adapters-2026-09-12-verified.json](evidence/additional-native-adapters-2026-09-12-verified.json)。记录含完整已安装包版本、SDK 关键源码与项目源码摘要、测试身份、原生调用记录、Broker 审计、localhost 收据及 SDK 自身的弃用提示。没有复用旧 MCP 示例证据，也没有得出模型攻击成功率结论。
