# AutoGen 与 LlamaIndex 原生工具接入

这两项适配器把六个 Broker 操作注册成框架自己的工具：读资料、按权限发送、查看权限、列出操作对象、提交待确认操作和保存邮件草稿。危险动作是否执行仍由 Broker 决定，适配器负责把实际工具调用送到主机固定的 Broker。

**已验证的是原生工具接入。没有运行模型对话，没有验证完整 Agent 进程隔离。** 直接调用其他工具、联网、访问文件、启动子 Agent 等路径还需要主机统一限制。能在同一 Python 进程执行任意代码的 Agent，不会被这些 Python 对象本身隔离。

`send` 可以按策略立即发送，而且没有自动重试或去重；要求每次人工确认的应用应从模型工具列表移除 `send`，只提供 `propose_action` / `draft_email`。后两者只能提交，不能批准。各操作参数见 [原生工具说明](native-adapters.md)。

## 固定主机连接

```python
from yuanxingmu.adapters import NativeTools

client = NativeTools(
    socket_path="/run/yuanxingmu/worker.sock",
    session_id="host-persisted-session-id",
)
```

主机在创建 Agent 之前选定 socket 和会话编号；它们不出现在模型参数里。恢复同一个会话时保留编号，新会话更换编号。会话编号不是凭证，Broker socket 决定实际任务权限。

## AutoGen 使用框架实际传入的调用编号

```python
from yuanxingmu.adapters.autogen import build_tools

tools = build_tools(client)
# 注册到现有 AssistantAgent(..., tools=tools)。
# 也可用于 AutoGen StaticWorkbench 或 ToolAgent。
```

本次安装的 `autogen-core` / `autogen-agentchat` 均为 **0.7.5**。该版本的 `BaseTool.run_json` 接收独立的 `call_id`，`AssistantAgent`、Workbench 和 Core `ToolAgent` 会转交真实调用编号。适配器使用这个隐藏参数，并保留 SDK 的原生 schema 验证、结果处理和调用记录。模型提供的 `call_id`、socket、批准标记或凭证字段都会在进入 Broker 前被拒绝。

AutoGen 的底层 `run` 方法不接收编号，所以适配器只在当前异步调用上下文中暂存 `run_json` 的实际编号，退出时恢复。并发派发互不覆盖。直接调用 `run`、使用未提供编号的旧 dispatcher，均不能提交提案。不要靠模型参数补上缺失编号。

同一框架、主机会话、操作和调用编号会找到同一提案；内容改变时返回冲突，已取消或已执行的提案返回现有状态。框架若为重试生成了新编号，就会被当成新调用；恢复时主机必须保留原编号。

派发前已经取消的 AutoGen 请求不会到达 Broker。提交之后发生取消或响应丢失，不能据此认定外部动作没有发生，适配器也不会自动重试。

## LlamaIndex 要求主机为单次派发保存编号

本次 `llama-index-core` 为 **0.14.24**。其 `FunctionTool.call/acall` 接收业务参数，工作流的单次 `ToolCall.tool_id` 没有被传给工具；可注入的 `Context` 属于整个工作流，不能作为每次调用的唯一身份。

因此，LlamaIndex 接入需要一个明确的主机派发入口：派发前保存编号，只把该编号绑定到这一次调用。适配器不会安装全局钩子，也不会假装模型参数就是框架身份。

```python
from yuanxingmu.adapters.llama_index import HostInvocations, build_tools

invocations = HostInvocations()
tools = build_tools(client, invocations=invocations)
# 注册到现有 FunctionAgent(..., tools=tools)。

# 下面属于可信主机的单次派发入口。
# host_saved_nonce 必须在派发前保存，恢复原调用时继续使用。
tool = next(t for t in tools if t.metadata.name == "yuanxingmu_propose_action")
with invocations.bind(host_saved_nonce):
    result = await tool.acall(proposal={
        "kind": "message",
        "target_id": "registered-chat",
        "payload": {"body": "请核对这条消息"},
    })
```

每次新调用使用新的已保存编号。**不要把一个编号绑定到整个 Agent 对话。** 仅把工具注册给 `FunctionAgent`，却没有接好逐次派发入口，提案会被拒绝；读权限等查询可以正常使用。测试确认，仅提供原生工作流 `Context` 不能绕过这个要求。

原生 `FunctionTool.call` 和 `acall` 均保留绑定，并在执行时再次按严格 schema 验证业务参数。主机绑定通过标准库 `ContextVar` 传递；手动创建不传播上下文的线程会丢掉绑定，提案随之被拒绝。框架自行序列化和恢复整个工作流尚未验证；重建工具时应提供原主机会话编号，并在派发时绑定原调用编号。

LlamaIndex 原生 `ToolMetadata` 导出参数时会删除顶层 `additionalProperties`。本适配器使用 metadata 扩展保留完整封闭 schema，并验证真正的原生工具声明。执行时的独立参数验证同样拒绝额外字段。

## 可复现验证

验证环境为 Linux / WSL、Python 3.12.3，单独创建虚拟环境，没有合并或更改前六项框架的依赖环境。

| 组件 | 实际版本 | 实际验证路径 |
| --- | --- | --- |
| AutoGen Core / AgentChat | 0.7.5 / 0.7.5 | 实际 `BaseTool`、`AssistantAgent` 注册及单次工具派发、Core `ToolAgent` runtime 消息。 |
| LlamaIndex Core | 0.14.24 | 实际 `FunctionTool.call/acall`、`FunctionAgent` 注册及单次 `_call_tool` 派发。 |
| LlamaIndex Workflows / Instrumentation | 2.23.3 / 0.6.0 | 本批原生工作流与 SDK 依赖。 |
| Pydantic | 2.13.5 | 原生和执行期 schema 验证。 |

Agent 注册使用实际 SDK 模型基类的测试子类，所有生成入口若被调用都会失败；这些入口未执行。测试主动调用固定 SDK 版本中的 `AssistantAgent._execute_tool_call` 和 `FunctionAgent._call_tool` 私有方法，只测试工具派发，不能据此宣称跑过完整模型循环或其他版本。

测试包含 **29 项 SDK 检查与 7 项共享客户端检查，共 36 项通过、0 跳过**。覆盖私密读后公网发送拒绝、允许的内部发送、五类操作在主机确认前没有效果、确认后的 localhost 收据及临时文件变化、邮件草稿、撤权、伪造参数、并发编号、重建后的去重、取消/完成状态重放，以及上述两个框架的身份差异。

每个测试只允许连接自己的真实 Broker Unix socket 和 localhost 接收端。外部 DNS、`connect_ex`、其他连接及模型调用均被测试守卫拒绝，任何越界尝试都会使测试失败。这是测试保护，不是产品沙箱证明。

```sh
python3 -m venv /tmp/yxm-autogen-llama-env
/tmp/yxm-autogen-llama-env/bin/python -m pip install -r docs/autogen-llama-adapters-requirements.txt
/tmp/yxm-autogen-llama-env/bin/python -m pip check
/tmp/yxm-autogen-llama-env/bin/python -B tests/run_autogen_llama_adapters.py \
  --output /tmp/yxm-autogen-llama-evidence.json
```

输出必须使用新路径；已有历史记录不会覆盖。缺少依赖、失败、跳过或运行期间源码改变均导致证据命令失败。无 SDK 的普通测试环境可以跳过可选测试，跳过不构成验证成功。

证据：[autogen-llama-adapters-2026-09-12.json](evidence/autogen-llama-adapters-2026-09-12.json)。记录包括精确包版本、完整安装包清单、关键 SDK 源码和项目源码哈希、原生工具类型、调用编号来源、请求及结果、Broker 审计、本地接收记录，以及上游的 Pydantic 弃用提示。没有复用旧 MCP 示例，也没有测试真实攻击模型的绕过成功率。

扩展共享框架名称列表后，前六项适配器也在各自原有环境回归通过：[LangChain、OpenAI Agents、Pydantic AI 为 39/39](evidence/native-adapters-2026-09-12-autogen-llama-extension.json)，[Google ADK、CrewAI、Agno 为 45/45](evidence/additional-native-adapters-2026-09-12-autogen-llama-extension.json)。两次均零跳过、运行期间源码未变化。各批包含重复的共享客户端检查，不能把合计运行次数当成独立场景数。
