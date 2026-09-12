# Mastra 原生 Node 工具接入

本适配使用 `@mastra/core 1.66.0` 的真实 `createTool` / `Tool`，把六个元星木操作接到主机固定的 Unix Broker。它独立于旧 `@mastra/mcp` 工具发现实验，不需要经过 MCP。

**范围仅限这六个注册工具。没有运行完整模型或 workflow 循环，没有验证 Agent 进程隔离。** 模型的其他工具、浏览器、文件系统、workspace/sandbox、代码执行和子 Agent 均需另外约束。Node 对象、闭包和 `AsyncLocalStorage` 本身不是安全隔离边界。

## 接入

运行环境须为 Linux、Node **>=22.13.0**，本次验证使用 Node **24.16.0**。依赖和锁文件在 [`yuanxingmu/adapters/mastra`](../yuanxingmu/adapters/mastra/package.json)。这批是独立 JavaScript 适配，不会给 Python 客户端增加一个假定可用的框架名称。

```javascript
import { NativeTools, HostInvocations, buildTools } from './yuanxingmu/adapters/mastra/index.mjs';

const client = new NativeTools({
  socketPath: '/run/yuanxingmu/worker.sock',
  sessionId: 'host-persisted-session-id',
});
const invocations = new HostInvocations();
const tools = buildTools(client, { invocations });
// 将 Object.fromEntries(tools.map(tool => [tool.id, tool])) 交给现有 Mastra Agent。
```

socket 和会话编号由主机选定，不接受模型参数覆盖，也不读取环境变量作为备选地址。会话编号不是凭证，Broker socket 决定任务权限。相同会话恢复时沿用编号，新会话使用新编号。

工具名为 `yuanxingmu_read`、`yuanxingmu_send`、`yuanxingmu_describe`、`yuanxingmu_action_targets`、`yuanxingmu_propose_action`、`yuanxingmu_draft_email`。业务参数与 [Python 原生工具](native-adapters.md) 一致；表单字段使用 `[{name, value}]`，客户端拒绝重复名称后转成 Broker 对象。

`send` 可以按策略立即发送，没有自动重试或去重。需要逐项人工确认时从模型工具列表移除 `send`，只提供 `propose_action` / `draft_email`。它们只创建待审记录，实际执行由独立主机入口批准。

## 每次调用的身份

Agent 路径使用 `context.agent.toolCallId`。框架的工具执行包装器会把调用选项中的编号传入该字段，测试已通过真实 `Agent.getToolsForExecution` 包装器验证这条传递路径。

直接调用或 workflow 没有这个字段时，主机必须为**每次派发**保存一个编号，再绑定到这一次执行：

```javascript
const selected = tools.find(tool => tool.id === 'yuanxingmu_propose_action');
const result = await invocations.run(hostSavedNonce, () => selected.execute({
  proposal: {
    kind: 'message',
    target_id: 'registered-chat',
    payload: { body: '请核对这条消息' },
  },
}, workflowContext));
```

不能把整个 workflow 的 `runId`、`workflowId`、会话编号或内容摘要当成单次身份。未绑定编号的提案会被拒绝。不要用一个编号包住整个 Agent 对话或一批不同调用；新调用使用新的已保存编号，恢复原调用沿用原编号。这个模块没有替应用实现编号持久化或安装全局 workflow 钩子。

Agent 编号与主机编号分别命名。同样的编号文本走两条路径，不会误找同一提案。提案键为 `mastra_v1_` 加 SHA-256，摘要输入为无空格、非 ASCII 字符转义的 JSON 数组：`["yuanxingmu-mastra-v1", sessionId, operation, identitySource, identityValue]`。来源是 `agent_tool_call_id` 或 `host_invocation_nonce`，均由执行上下文而非模型参数提供。重建后同身份找回同一记录；内容改变时返回冲突，已取消或已执行记录返回其当前状态。

## 恢复与网络失败

实际 SDK 源码和[独立接口探针](evidence/mastra-interface-2026-09-12.json)确认：Mastra 的 `resumeData` 路径会跳过原始 `inputSchema` 验证。因此，本适配在 `execute` 内及 Broker 客户端再次完整校验输入，包括恢复时的嵌套对象，不能让恢复流程绕过批准字段、目标或 socket 检查。

派发前已经中止的调用不会到达 Broker。请求已提交后的中止、超时或断线不代表动作未发生。客户端始终只发一次，不自动重试；提案恢复仍使用原编号，直接 `send` 的未知结果需要主机核对。

客户端限制请求和单行响应为 1 MiB，要求完整换行、合法 UTF-8 和对象响应。连接中断、无换行、响应超限和超时均失败关闭。它没有另开 HTTP 或环境变量备选通道。

## 验证与复跑

测试使用独立 Linux Node 环境中的实际 Mastra / Zod 包、真实 Unix socket、真实 Broker、localhost 接收端和临时文件。仓库适配源码被复制到该环境，复制前后逐文件核对哈希，避免把依赖目录写进仓库。

本批包含 **30 项 SDK/Broker 检查及 10 项 JavaScript 客户端/真实 Unix 传输检查，共 40 项**。覆盖私密读后禁止公网发送、允许内部发送、五类主机确认操作、邮件草稿、撤权、伪造参数、并发身份、重建去重、重放状态、Agent/workflow 身份区分、恢复时二次校验，以及断线/超时不重试、响应格式和大小限制。

已注册真实 `Agent` 并核对 `listTools`，同时调用真实 `Agent.getToolsForExecution` 工具包装器。测试的调用选项和上下文由 fixture 提供，模型接口是调用即报错的测试对象，没有执行模型生成；这不等于验证过模型生成的调用 ID、完整 Agent 循环、持久化 workflow 恢复或子 Agent。

```sh
# 使用 Node >=22.13 的 npm，创建与仓库分开的环境。
mkdir -p /tmp/yxm-mastra-sdk
cp yuanxingmu/adapters/mastra/package*.json /tmp/yxm-mastra-sdk/
npm --prefix /tmp/yxm-mastra-sdk ci --ignore-scripts --no-audit --no-fund
python3 -B tests/run_mastra_native_adapter.py \
  --node /absolute/path/to/node \
  --sdk-env /tmp/yxm-mastra-sdk \
  --output /tmp/yxm-mastra-evidence.json
```

证据输出必须用新路径。缺依赖、Node 版本不符、跳过、失败、锁文件不符或运行期间源码改变都会使验证命令失败。记录含包版本、锁文件、SDK 和项目源码哈希、Node 二进制哈希、实际工具对象、调用与 Broker 审计、本地效果及测试范围。

Node 工具进程的连接仅允许自己的 Broker；Python Broker 只允许测试接收端；传输专项用例只连接自己的临时 Unix socket。任意越界连接或模型入口调用都会使测试失败。这些是测试守卫，不构成产品沙箱验证。

最终证据：[mastra-native-adapter-2026-09-12.json](evidence/mastra-native-adapter-2026-09-12.json)。前述 Windows 接口探针只证明接口行为，没有连接 Broker，其结果没有被计为本批防御测试。
