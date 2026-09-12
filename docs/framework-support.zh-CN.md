# 框架支持范围与接入顺序

核查日期：**2026-09-12**。GitHub 星数和最近 push 取自官方仓库 API，时间为 **03:33:48 UTC**；星数只帮助选择优先级，不代表安全效果。版本取官方 release 或对应包注册表，表内特意区分仓库 release 与 Python 包版本。

元星木目前有 **OpenClaw 和 Hermes 的专用运行入口**，另有 **十一组已验证的原生 SDK 工具适配**：LangChain/LangGraph、OpenAI Agents、PydanticAI、Google ADK、CrewAI、Agno、AutoGen、LlamaIndex、Microsoft Agent Framework、smolagents、Mastra。十一组适配验证了工具注册和实际调用，没有运行完整模型循环，也没有完成这些框架的进程隔离或五层防御整体验收。允许填写某个框架名，不等于支持了该框架。

## 最新版本与实际证据

“旧工具实验”指早期 Invariant Gateway、原生工具包装或 MCP 连接行为的研究。多数由脚本明确调用工具，没有真实模型或 Agent 循环；它们不算新元星木适配通过，也不算框架漏洞证明。实验中出现私密测试内容到达接收端，应如实记录为该配置下策略未阻止，不能列作防御成功。

| 官方仓库 | 星数 | 参考版本 | 现有证据；新元星木状态 |
|---|---:|---|---|
| [OpenClaw](https://github.com/openclaw/openclaw) | 389,463 | `v2026.9.4` | 专用插件、外层 Gateway 隔离和工具执行边界。已有真实模型原生运行、撤销/重启和邮件证据；新增五层仍需逐项原生验收。 |
| [Hermes Agent](https://github.com/NousResearch/hermes-agent) | 244,644 | `v2026.9.11`，当前固定 distribution `0.21.2` | 专用 terminal provider、官方执行中间件、插件与 dashboard 已接入。[GLM14 五层固定案例](evidence/hermes-glm14-2026-09-12/REPORT.zh-CN.md)已验证五类危险候选、正常读写/草稿/命令、三次真实工作台恢复及暂停后新聊天；同源码的 [native13 本地模型对照](evidence/hermes-five-layers-2026-09-12/REPORT.zh-CN.md)保留两次正常语义误拦。另一次较新 [AUTO15](evidence/hermes-auto15-2026-09-12/REPORT.zh-CN.md)自动发送一条消息后，回答误拦导致连续流程失败。已有五层视频；更多来源、设置变化和连续自动工作仍未全面验收。 |
| [LangChain](https://github.com/langchain-ai/langchain) / [LangGraph](https://github.com/langchain-ai/langgraph) | 146,150 / 41,490 | Python `langchain 1.4.0` / `langgraph 1.2.11` | 新 SDK 工具适配已验证：实际使用 `langchain-core 1.6.2`、`langgraph 1.2.11`，通过原生工具及编译图中的 `ToolNode` 调用 Broker；没有 LLM。完整进程、checkpoint 恢复和五层防御仍未验收。 |
| [AutoGen](https://github.com/microsoft/autogen) | 60,941 | `autogen-core 0.7.5` / `autogen-agentchat 0.7.5` | 新 `BaseTool` 适配已验证，使用实际 `AssistantAgent` 单次工具派发和 `ToolAgent` runtime，绑定原生 `call_id`。没有 Team 或完整模型循环、代码执行器隔离验收；旧 MCP 实验单独保留。 |
| [CrewAI](https://github.com/crewAIInc/crewAI) | 58,383 | `1.15.21` | 新 SDK 工具适配已验证，覆盖 `BaseTool` / `CrewStructuredTool` 同步和异步派发。每次派发的稳定编号由主机保存和绑定；不是框架自动提供的调用 ID。没有 Crew/Flow 模型循环或进程隔离验收。 |
| [LlamaIndex](https://github.com/run-llama/llama_index) | 52,127 | `llama-index-core 0.14.24` | 新原生 `FunctionTool.call/acall` 适配已验证，保留封闭的工具参数声明。主机须为每次派发保存和绑定独立编号；没有 AgentWorkflow、完整模型循环或恢复验收。 |
| [Agno](https://github.com/agno-agi/agno) | 42,141 | `3.0.9` | 新 SDK 工具适配已验证，实际调用 `FunctionCall.execute/aexecute`，使用框架隐藏注入的调用身份；工具结果缓存关闭。没有 Agent/Team 模型循环或进程隔离验收。 |
| [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) | 29,375 | `openai-agents 0.22.2` | 新原生 `FunctionTool` 适配已验证，使用真实 `ToolContext` 调用 Broker，已不依赖旧 MCP 失败路径。注册了 Agent，但没有运行 Runner、handoff 或模型。 |
| [smolagents](https://github.com/huggingface/smolagents) | 29,286 | `1.26.0` | 新原生 `Tool` 接入已验证，经过 `ToolCallingAgent.execute_tool_call`；逐次主机编号必需，原生消息 ID 不会注入工具。原生声明缺少顶层禁止额外字段标记，执行期完整严格验证。仅保护六个注册工具；没有模型循环，`CodeAgent` 任意 Python 执行和进程隔离未覆盖。[说明与证据](microsoft-smolagents-adapters.md)。 |
| [Mastra](https://github.com/mastra-ai/mastra) | 27,956 | `@mastra/core 1.66.0`，Node `24.16.0` | 新 Node 原生工具适配已通过实际 Agent 注册、执行包装器、真实 Unix Broker 和本机效果检查；恢复分支再次严格验参。没有完整模型或 workflow 循环、进程隔离验证。 |
| [Google ADK](https://github.com/google/adk-python) | 21,504 | `google-adk 2.9.0` | 新 `BaseTool` 适配已验证：注册于 `LlmAgent`，使用实际 `ToolContext` 和 `run_async` 调用 Broker。没有 Runner、子 Agent 或模型循环验收。 |
| [PydanticAI](https://github.com/pydantic/pydantic-ai) | 19,870 | 最新参考 `2.43.0`；本次实际验证 `pydantic-ai-slim 2.42.0` | 新原生工具适配已在完整依赖环境验证，通过 `FunctionToolset.get_tools/call_tool` 和真实 `RunContext` 调用 Broker；旧缺依赖记录不再代表这条适配路径。`TestModel` 只提供接口上下文，没有运行模型。 |
| [Microsoft Agent Framework](https://github.com/microsoft/agent-framework) | 13,483 | Python `agent-framework-core 1.18.0` | 新原生 `FunctionTool` 接入已验证：`Agent` 注册、实际单次派发及 function middleware，使用原生 `tool_call_id`。仅保护六个注册工具；没有 `Agent.run`、模型循环、FIDES 联合策略或进程隔离验收。旧 MCP/FIDES 实验不能替代本批证据。[说明与证据](microsoft-smolagents-adapters.md)。 |

LangGraph 最新 GitHub release 名为 `sdk==0.4.4`，不是上表 Python 图运行包的版本；Microsoft Agent Framework 最新 GitHub release 是 `dotnet-1.21.0`，不是 Python core 版本。LangChain 最新 release 为 `langchain-core==1.6.3`，也不应替换成 `langchain` 包版本。各仓库截至核查时均未归档；AutoGen 最近 push 为 2026-04-15，smolagents 为 2026-08-25，其余上述仓库为 2026-09-11/12。这只是活动快照。

### Hermes 五层原生记录与视频

`native13` 与 `GLM14` 固定在元星木源码 `6881138`，使用同一任务、12 条逐字冻结输入和合成材料；每轮都有 11 次真实工具调用。native13 使用本地 Qwen3-4B 工作模型与 Qwen3-8B 检查模型，出现两次正常语义误拦、共五次真实工作台恢复。GLM14 的工作与检查均为远程 GLM-5.2，使用独立请求与不同上下文，thinking 关闭；这一组正常场景未观察到语义误拦，共三次真实恢复。两轮都完成一次人工批准后的精确 50 字节写入，均没有邮件获准或发送。

五段中文解说视频对应 GLM14：[外部资料](../site/assets/videos/hermes-glm14-input/hermes-glm14-input.mp4)、[长期记忆](../site/assets/videos/hermes-glm14-memory/hermes-glm14-memory.mp4)、[任务偏移](../site/assets/videos/hermes-glm14-alignment/hermes-glm14-alignment.mp4)、[危险命令](../site/assets/videos/hermes-glm14-tools/hermes-glm14-tools.mp4)、[环境与技能](../site/assets/videos/hermes-glm14-skills/hermes-glm14-skills.mp4)。[视频清单](../site/assets/videos/hermes-glm14-manifest.json)绑定源码、原片与证据摘要。技能片的准确拦截原因来自实际日志核对，网页只显示通用未完成提示。

它们是固定案例证据，没有重复采样；模型实际生成参数也有标点差异，不能据此排名模型或推算攻击阻断率。[协议对照](evidence/hermes-glm14-2026-09-12/COMPARISON.zh-CN.md)保留这些限制。GLM14 视频不覆盖后来新增的自动执行代码。

较新 `9bd6605` 的 [AUTO15 连续自动工作](evidence/hermes-auto15-2026-09-12/REPORT.zh-CN.md)只运行到第三个步骤：创建时一次授权后，真实自动发送 1 条公开消息到本机接收端，没有逐次批准或人工恢复；发送后的正常回答被误拦，工作暂停。上传、表单、可疑内容后继续等后续步骤未提交，整轮验收未通过。读取阶段还保留了本地回答额外列出内部底价的问题，不能把它写成已经外发给客户。

## 十一组 SDK 工具接入的已完成范围

每组注册六项真实工具：读取资料、按权限发送、查看权限、列出操作对象、提交待确认操作、保存邮件草稿。调用通过真实 Unix socket 到达主机 Broker；测试使用真实 localhost 接收端和临时文件。按权限直接发送与提交待确认草稿是不同操作；需要每次人工确认的应用应仅提供草稿/提案入口，移除直接 `send` 工具。

| 验证批次 | 实际版本与结果 | 可复核记录 |
|---|---|---|
| LangChain/LangGraph、OpenAI Agents、PydanticAI | `langchain-core 1.6.2`、`langgraph 1.2.11`、`openai-agents 0.22.2`、`openai 3.13.0`、`pydantic-ai-slim 2.42.0`；32 项 SDK 测试与 7 项共享客户端测试，39/39 通过。 | [接入说明](native-adapters.md)、[本次扩展后的复跑记录](evidence/native-adapters-2026-09-12-framework-extension.json) |
| Google ADK、CrewAI、Agno | `google-adk 2.9.0`、`google-genai 2.23.0`、`crewai 1.15.21`、`agno 3.0.9`；38 项 SDK 测试与相同的 7 项共享客户端测试，45/45 通过。 | [新增适配说明](additional-native-adapters.md)、[复核记录](evidence/additional-native-adapters-2026-09-12-verified.json) |
| AutoGen、LlamaIndex | `autogen-core 0.7.5`、`autogen-agentchat 0.7.5`、`llama-index-core 0.14.24`；29 项 SDK 测试与相同的 7 项共享客户端测试，36/36 通过。 | [接入说明](autogen-llama-adapters.md)、[记录](evidence/autogen-llama-adapters-2026-09-12.json) |
| Microsoft Agent Framework、smolagents | `agent-framework-core 1.18.0`、`smolagents 1.26.0`；30 项 SDK 测试与相同的 7 项共享客户端测试，37/37 通过。 | [接入说明](microsoft-smolagents-adapters.md)、[记录](evidence/microsoft-smolagents-adapters-2026-09-12.json) |
| Mastra | `@mastra/core 1.66.0`、Node `24.16.0`；30 项原生工具/Broker 检查及 10 项 Node Unix 传输检查，40/40 通过。 | [接入说明](mastra-native-adapter.md)、[记录](evidence/mastra-native-adapter-2026-09-12.json) |

五批均无跳过。共享客户端的 7 项在各批重复，不重复计算为独立测试。不同 SDK 的依赖范围不同，例如第二批依赖 OpenAI 2.x，第一批使用 3.x，应保留独立环境。记录中的源码哈希说明当次检查的版本；后续修改 Broker、暂停或回答检查，不会自动获得旧记录的验证结论。

这些 SDK 测试没有模型生成的攻击，也没有验证整个 Agent 无法绕过工具。模型接口、额外工具、任意 Python/终端、第三方插件和子任务仍需独立纳入主机边界。**安装这十一组工具不会自动启用 OpenClaw/Hermes 专用运行入口的回答缓冲或整进程隔离。**

## 每个框架究竟要接哪里

下表是实现入口和**整体验收仍需完成的工作**。其中十一组原生工具已经通过上表的组件验证，其余入口不能据此标为通过。通用原则是：读取的外部内容先检查；每次真实副作用在主机边界再次授权；工具重连、子任务、暂停恢复都保留同一权限身份；终端或代码执行器不能绕过这个边界。

| 框架 | 要接入的实际位置 | 必须补做的原生验收 |
|---|---|---|
| OpenClaw | 插件消息/工具钩子、sandbox provider、会话与 supervisor 生命周期；现有 [`integrations/openclaw`](../yuanxingmu/integrations/openclaw/plugin/CONTRACT.md)。 | 官方 WebUI 每层候选调用；用户审批恢复；工具返回不同结构；所有启用插件的副作用入口；重启与撤销。 |
| Hermes | 官方 terminal environment provider、执行中间件、原生工具 dispatcher、插件与 dashboard 生命周期；[`hermes_backend.py`](../yuanxingmu/hermes_backend.py)、[`hermes.py`](../yuanxingmu/hermes.py)。 | native13/GLM14 已补齐同源码五层固定样本和真实工作台恢复。继续验证正常记忆写入、更多文件/终端/CLI/子任务来源、运行中设置及后来新增规则。AUTO15 的连续自动流程失败，仍需重新冻结后独立验收；不能由单次自动消息推断上传、表单或全部入口受控。 |
| LangChain / LangGraph | 工具 wrapper / `ToolNode` 前后；`StateGraph`、checkpoint/thread 身份；子图与并行节点。 | 真正运行图和模型；从 checkpoint 恢复、重连、分叉后权限保持；检查点不能由 Agent 改写授权状态；非 MCP 工具同样受控。 |
| OpenAI Agents | Function tool guardrails 和 `needs_approval`，`Runner` 的暂停状态、恢复、handoff、session；真实执行仍在主机边界。 | input guardrail 只覆盖首个 Agent，output guardrail 只覆盖最终输出；不能据此覆盖全部中间工具。用真实 Runner 验证审批中断、同一 state 恢复和 handoff 后权限。 |
| PydanticAI | 已有原生 toolset 与 `RunContext` 适配；继续接准备/审批入口和持久化运行身份。 | 已建立固定版本工具环境；还需验证模型循环、延迟审批及整个运行的恢复。 |
| AutoGen | `BaseTool` / `Workbench` / `McpWorkbench`；单 Agent 与 team 会话身份。 | 兼容 MCP 版本；不同成员、重连和恢复不能创建全新授权身份；非 MCP 工具及代码执行器也受控。 |
| Microsoft Agent Framework | 已有原生 `FunctionTool` 与真实 `tool_call_id` 适配，直接与 function middleware 派发均已验证；继续接 `AgentSession`、FIDES。 | 真正 `Agent.run` 与模型；FIDES 联合策略的正常/危险对照；会话序列化/恢复、多 Agent 转交和进程隔离。 |
| CrewAI | 已有 `BaseTool` / `CrewStructuredTool` 适配；应用须在每次主机派发时绑定已保存编号；另接 Crew/Flow 上下文和代码执行工具。 | 真实 Crew/Flow 与模型；委派、cache 和自动恢复不能绕过或丢失编号；未绑定编号的提案会被拒绝，不能假定工具列表已完成全部接线。 |
| Google ADK | `before_tool_callback` / `after_tool_callback`、`BaseTool.run_async`、SessionService。 | 真正 Runner/Agent 循环；工具结果进入上下文前检查；子 Agent 和持久化会话；原生工具与 MCP 同时覆盖。 |
| Mastra | 已有 `createTool` / `Tool.execute` 原生适配；Agent 使用原生 toolCallId，workflow 由主机逐次绑定编号；恢复分支再次验参。 | 完整模型、workflow 挂起/恢复、并发与不同工具后端仍需验收；原生工具适配绕开旧 MCP 探针的发现路径。 |
| LlamaIndex | 已有 `FunctionTool.call/acall` 原生适配，主机逐次派发编号；另接 workflow/AgentWorkflow 的 Context 和工具结果流。 | 同步/异步组件已验证；继续验证事件恢复、子 Agent、模型循环与整个工作流的派发身份。 |
| smolagents | 已有 `ToolCallingAgent.execute_tool_call` / `Tool.__call__` 适配；应用须在每次派发绑定已保存编号。原生声明顶层限制由执行期严格验证补足。 | 真实模型循环和持久化恢复；`CodeAgent` 生成 Python 可直接操作文件/网络，其执行器必须单独隔离验证；六个注册工具的保护不覆盖其他执行路径。 |
| Agno | `Function` / Toolkit hooks，Agent/Team 的 session 和 storage。 | 模型循环、Team 委派、持久化恢复、工具 hook 旁路与直接代码执行；所有调用绑定同一宿主任务。 |

OpenAI 接入判断同时核对了官方[Agents SDK](https://developers.openai.com/api/docs/guides/agents/sdk)与[guardrails / approvals](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals)说明。这里没有把输入/输出 guardrail 当作文件系统、网络和凭证权限的替代。

## 对 2–4 人团队的实际顺序

1. **第一批：OpenClaw、Hermes。** 两者用户量最高，也有现成原生接入代码；先把官方 WebUI、五层检查、消息/上传/表单/文件操作做成真实可复现的完整例子。补齐每层正常对照、用户批准后执行、拒绝后无副作用和重启撤销。
2. **第二批：LangChain/LangGraph、OpenAI Agents、PydanticAI。** 原生工具组件已通过，下一步沿现有适配完成模型循环、主机隔离、审批中断和恢复；旧工具测试不能替代这些工作。
3. **第三批：CrewAI、Google ADK、Agno。** 原生工具组件已通过，下一步完成团队/工作流、持久化恢复和真实模型；CrewAI 先落实主机派发编号，不把适配工厂当成自动接入。
4. **第四批：Microsoft Agent Framework、AutoGen、LlamaIndex、smolagents。** 原生工具组件已有上述记录，继续补全模型循环与应用级接线；Microsoft 新旧框架分别验收，smolagents 的生成代码执行器需要独立隔离。**Mastra** 原生工具和 Unix 传输已完成第五批验证，继续补完整 workflow 与模型运行。

顺序综合用户量、现有代码、近期活动和接入成本，并非星数排名。与其一次列出十几个绿色勾，先交付两个可直接安装、官方 WebUI 真正能演示的支持对象更有价值。

## 一个框架何时可以标记“已验证”

验收记录必须固定框架/包版本、元星木源码、模型和策略；用官方运行入口完成正常任务及实际危险候选。至少覆盖外部内容、记忆改写、语义偏移、危险命令、基础扫描、授权发送/写入，以及断开重连、恢复、子任务和撤销。每次需要同时观察工具请求、主机判定、用户审批和最终接收端/文件结果。

组件用例可以验证超时、非法裁判响应、链接路径等不易稳定触发的边界，但不能替代原生运行。每种验证都应原样记录：原生模型没有发起危险候选是“未触发”；依赖、模型或 Gateway 失败是“不可用”；观察模式是“记录而未拦截”。

可公开复核的既有记录包括[原生 OpenClaw](../examples/yuanxingmu/real_openclaw/evidence/REPORT.zh-CN.md)、[邮件](../examples/yuanxingmu/email/evidence/report.md)、[Hermes 旧工具探针](../examples/yuanxingmu/hermes/observed-results.json)与[旧运行验证的范围](verification.md)。其余旧框架研究结果保留在本地研究记录中；未纳入仓库的日志不作为读者可复现的发布证据。

主机能力的独立组件证据包括暂停/恢复 16 项、一次性审批账本与主机套接字合计 15 项、早期运行中设置管理接口 4 项。回答协议及真实 Unix HTTP 最初为 17 项；当前套件为 25 项，包括逐层观察不能绕过撤权的检查。这些数字不是新的框架端到端通过次数。回答缓冲只检查正文、拒绝和思考文本；带 `live_settings_v1` 的新实例支持主机运行中改设置，旧实例仍须确认停止，新入口待官方框架验收。浏览器桌面提醒需要页面开启；另有[主机后台提醒](background-notifications.zh-CN.md)，关闭浏览器后仍可由运行中的 Workbench 向固定 JSON 接收端投递。通用协议已通过本机接收端验证，没有宣称第三方 IM 或邮件提供商已验收。详见[回答显示前检查与暂停恢复](response-and-quarantine.md)。

玄甲逐功能对照见[功能覆盖与缺口](agentward-coverage.zh-CN.md)。
