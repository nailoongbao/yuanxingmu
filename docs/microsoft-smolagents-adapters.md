# Microsoft Agent Framework 与 smolagents 原生工具接入

本批验证实际 SDK 工具注册、单次派发和真实本地 Broker。两项都只保护注册的六个元星木工具：读资料、按权限发送、查看权限、列出操作对象、提交待确认操作、保存邮件草稿。

**没有运行完整模型循环，没有验证整进程隔离。smolagents CodeAgent 的任意 Python 执行明确未覆盖。** 其他工具、网络、文件、终端、子 Agent 和最终回答均不会因安装这六个工具自动受控。生成代码环境需要单独隔离及验证。

`send` 按 Broker 策略可以立即发送，不会去重或自动重试；如果每次动作都要用户确认，应从模型工具列表移除 `send`，只提供 `propose_action` / `draft_email`。提案只能由独立主机入口批准，模型不能用批准参数绕过。六项业务参数见 [原生工具说明](native-adapters.md)。

## 先由主机固定连接与会话

```python
from yuanxingmu.adapters import NativeTools

client = NativeTools(
    socket_path="/run/yuanxingmu/worker.sock",
    session_id="host-persisted-session-id",
)
```

连接和会话编号不出现在模型参数里。相同会话恢复时沿用编号；新会话更换编号。它不是凭证，真正的任务权限由 Broker socket 决定。这些 Python 对象本身不能隔离同进程任意代码。

## Microsoft Agent Framework

```python
from yuanxingmu.adapters.microsoft_agent_framework import build_tools

tools = build_tools(client)
# 交给现有 Agent(client=your_client, tools=tools, ...)。
```

实际依赖为 `agent-framework-core 1.18.0`。适配器使用原生 `FunctionTool` 扩展，保留 SDK 参数验证和结果处理。该版本的 `FunctionTool.invoke` 单独接收 `tool_call_id`，自动工具派发在直接路径和 function middleware 路径都会传入真实编号。

编号只在这一调用的上下文中暂存，结束后恢复；并发派发互不覆盖。适配器不读取模型参数、任意 `context.metadata` 或整段 `AgentSession` 来替代编号。测试确认：middleware 改写自己的 `metadata.call_id` 不会改变实际提案身份；只给会话和 metadata、却不给原生编号，不能提交提案。直接调用底层函数也不能复用上一调用留下的身份。

SDK 的 `approval_mode` 设为 `never_require`，表示无需再批准“创建待审提案”这一步；它不赋予实际外部动作批准权。实际执行仍由 Broker 的独立主机审批控制。应用若自行增加 SDK 审批层，不能把 SDK 同意视为 Broker 已批准。

重新构建工具后，同一主机会话、操作和原生调用编号仍找回原提案；改变内容会冲突，已取消或已执行记录返回当前状态。若框架重试时换了编号，Broker 会把它视为新调用，因此恢复时必须保留原编号。框架整段会话序列化、模型循环、多 Agent 转交与 FIDES 联合策略未在本批验收。

## smolagents

```python
from yuanxingmu.adapters.smolagents import HostInvocations, build_tools

invocations = HostInvocations()
tools = build_tools(client, invocations=invocations)
# 交给现有 ToolCallingAgent(tools=tools, model=your_model, add_base_tools=False)。

# 下面属于可信主机的单次派发入口。
# host_saved_nonce 在派发前持久化，恢复原调用时沿用。
with invocations.bind(host_saved_nonce):
    result = agent.execute_tool_call("yuanxingmu_propose_action", {
        "proposal": {
            "kind": "message",
            "target_id": "registered-chat",
            "payload": {"body": "请核对这条消息"},
        },
    })
```

实际依赖为 `smolagents 1.26.0`。工具是 SDK 原生 `Tool` 对象，验证经过真实 `ToolCallingAgent.execute_tool_call` 和 `Tool.__call__`。框架生成的消息虽然有调用 ID，但 `process_tool_calls` 只把名称和参数传给工具；测试用带 ID 的真实消息对象验证了这一限制：未绑定主机编号，提案仍被拒绝。

应用需要在每一次工具派发前保存并绑定主机编号。适配器没有安装全局派发钩子。**不要把同一个编号绑定到整段 Agent 对话或整批 `process_tool_calls`**；不同调用必须使用各自编号。只把工具列表放进 `ToolCallingAgent`，还没有完成提案路径的接线。查询类操作无需提案编号，仍可用。

smolagents 会把参数中的字符串替换为 Agent state 中的值。测试既确认正常替换可创建待审提案，也确认替换所得对象不能携带伪造的 socket、批准字段或其他额外属性。参数验证在工具实际执行前再次完整进行，包含嵌套对象和所有动作类型。

原生 schema 导出存在一项明确限制：`get_tool_json_schema` 硬编码生成顶层对象，未声明 `additionalProperties: false`。本适配没有篡改 SDK 全局函数，也不把它记录为完全封闭的原生声明。嵌套对象保持封闭；执行期仍使用完整严格 schema，实际拒绝额外字段。五类动作以互斥的 `oneOf` 分支保留，避免 SDK 将顶层 `anyOf` 简化成类型列表。模型服务对这些声明的兼容性仍需在完整模型运行中验证。

本批没有运行 `CodeAgent`、Python executor 或任意生成代码，不能据此声称代码无法直接访问文件/网络；其隔离列为未覆盖。工具自动序列化、整个 Agent 恢复及持久化 host nonce 的应用实现也未验证。

## 实际测试与重跑

环境为 Linux / WSL、Python 3.12.3，使用新的独立虚拟环境，保留前八项框架原有依赖。

| 组件 | 实际版本 | 验证路径 |
| --- | --- | --- |
| Microsoft Agent Framework Core | 1.18.0 | `Agent` 注册、原生 `FunctionTool.invoke`、自动单次派发及 `FunctionMiddlewarePipeline`。 |
| smolagents | 1.26.0 | `ToolCallingAgent` 注册、真实 `Tool`、`execute_tool_call`，以及消息 ID 不被注入的 `process_tool_calls` 对照。 |
| Pydantic / Hugging Face Hub / msgspec | 2.13.5 / 1.31.0 / 0.21.1 | SDK 和 schema 依赖；未调用模型或 Hugging Face 服务。 |

**30 项 SDK 测试与 7 项共享客户端测试，共 37 项通过、0 跳过。** 覆盖私密读后公网发送拒绝、允许的内部发送、五类动作在主机确认前无效果、确认后的 localhost 收据和临时文件变化、邮件草稿、撤权、伪造参数、重建后的去重、内容冲突、重放状态、并发身份及上述框架差异。

注册 Agent 时使用实际 SDK 模型基类的测试子类，模型入口一旦调用即失败；本次零模型入口调用。Microsoft 单次派发测试调用固定版本的私有 `_auto_invoke_function`，并不等于执行 `Agent.run`。

每项测试只允许连接自己的真实 Broker Unix socket 和 localhost 接收端。外部 DNS、`connect_ex` 及其他连接被禁止，任何越界尝试都会使测试失败；本次零越界尝试。这是测试保护，不能当作产品进程隔离证据。

```sh
python3 -m venv /tmp/yxm-microsoft-smolagents-env
/tmp/yxm-microsoft-smolagents-env/bin/python -m pip install -r docs/microsoft-smolagents-adapters-requirements.txt
/tmp/yxm-microsoft-smolagents-env/bin/python -m pip check
/tmp/yxm-microsoft-smolagents-env/bin/python -B tests/run_microsoft_smolagents_adapters.py \
  --output /tmp/yxm-microsoft-smolagents-evidence.json
```

输出必须使用新路径，不覆盖历史记录。缺依赖、失败、跳过或运行期间源码变化，均导致证据命令失败。普通环境可跳过未安装的可选 SDK 检查，但跳过不算验证成功。

[证据记录](evidence/microsoft-smolagents-adapters-2026-09-12.json)包含精确版本、完整安装包清单、SDK 和项目源码哈希、原生工具类型、真实调用记录、编号来源、Broker 审计及本地效果。旧 MCP/工具实验与本批新适配分别记录，未复用旧实验当作本批成功证据。
