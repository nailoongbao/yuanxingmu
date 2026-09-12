# Native SDK tools

This package connects LangChain/LangGraph, the OpenAI Agents SDK, and Pydantic AI to an existing Yuanxingmu Broker. Each framework receives six real native tool objects. The adapters preserve the Broker's permission checks and separate proposal submission from host approval.

**This is tool adaptation only.** The validation below invokes tools through installed SDKs and real Broker sockets. It does not run an LLM or demonstrate that a hostile agent process cannot bypass its tools. A common host supervisor must separately isolate the process, restrict other network and file access, protect credentials and review sockets, and control delegation. An ordinary Python tool list cannot provide those boundaries.

The separate [LangGraph runtime](langgraph-runtime.zh-CN.md) and [OpenAI Agents runtime](openai-agents-runtime.zh-CN.md) provide fixed, complete model loops in host-isolated processes with native checkpoint recovery. OpenAI Agents includes a fixed researcher-to-executor handoff. Their tool scopes, model evidence and limits are documented separately; these entries do not automatically protect arbitrary applications using the factories below.

## Bind a host session

```python
from yuanxingmu.adapters import NativeTools

# Supplied by the trusted host, never read from model arguments.
client = NativeTools(
    socket_path="/run/yuanxingmu/broker.sock",
    session_id="host-persisted-session-id",
)
```

The socket is absolute and explicit; the client ignores `YUANXINGMU_BROKER_SOCKET`. The Broker binds that socket to its task. There is no tool parameter for choosing a task, socket, endpoint URL, credential, approval, revision or request key. The session ID is a host-selected persistence identifier, not a credential. Keep it when resuming the same session; allocate another for a genuinely new session.

Choose the factory for the installed framework:

```python
from yuanxingmu.adapters.langchain import build_tools
tools = build_tools(client)  # StructuredTool instances; accepted by ToolNode

# Or:
from yuanxingmu.adapters.openai_agents import build_tools
tools = build_tools(client)  # FunctionTool instances; accepted by Agent(tools=tools)

# Or:
from yuanxingmu.adapters.pydantic_ai import build_tools
tools = build_tools(client)  # Tool instances; accepted by Agent / FunctionToolset
```

Importing `yuanxingmu.adapters.NativeTools` needs only the standard library and Yuanxingmu. Each factory imports its optional SDK. There are no model, tracing or connection-test calls in the factories. Applications remain responsible for their own SDK tracing configuration.

## Tool arguments and behavior

| Native tool | Model arguments | Behavior |
| --- | --- | --- |
| `yuanxingmu_read` | `resource` | Read a registered resource and retain its data restrictions. |
| `yuanxingmu_send` | `destination`, `body` | Send immediately if the Broker's current task policy allows it. |
| `yuanxingmu_describe` | None | Inspect the bound task's permissions and restrictions. |
| `yuanxingmu_action_targets` | None | List registered proposal targets without exposing endpoint credentials. |
| `yuanxingmu_propose_action` | `proposal: {kind, target_id, payload}` | Save a message, upload, form, overwrite or delete proposal for separate host review. |
| `yuanxingmu_draft_email` | `draft: {recipient, subject, body}` | Save an email draft for separate host review. |

`send` is an existing policy-governed immediate-send operation. A workflow that requires review before every outward effect should omit that tool and use reviewed proposals. The tool list has no commit, approve, cancel or account-selection operation.

Action payloads match the Broker except that form fields use explicit pairs:

```json
{
  "proposal": {
    "kind": "form",
    "target_id": "registered-form",
    "payload": {
      "fields": [
        {"name": "name", "value": "Example"},
        {"name": "note", "value": "Please review"}
      ]
    }
  }
}
```

The adapter converts those pairs to the Broker's field dictionary and rejects duplicate names. Other payloads are `{"body":"..."}` for messages, `{"filename":"...","content":"..."}` for uploads, `{"content":"..."}` for overwrite, and `{}` for delete. The Broker checks the selected registered target and its allowed form fields. File paths and network destinations belong to host configuration. Text content may contain URLs without gaining authority to use them as endpoints.

All public object schemas reject extra fields. Each invocation also validates actual arguments before contacting the Broker. OpenAI's `FunctionTool` and Pydantic AI's `Tool.from_schema` do not, by themselves, enforce their advertised JSON schema at invocation time; these adapters explicitly validate it. The LangChain adapter uses a small `StructuredTool` subclass solely to retain the closed public schema that its SDK-generated subset otherwise drops. Execution and call-ID injection still use the native SDK.

## Proposal identity and uncertain results

Proposal request keys are SHA-256 hashes of a version tag, framework identifier, host session ID, operation and native tool-call ID. They are never model arguments. LangChain supplies `InjectedToolCallId`; OpenAI supplies `ToolContext.tool_call_id`; Pydantic AI supplies `RunContext.tool_call_id`. Missing or empty IDs reject proposal submission. Rebuilding an adapter with the same host session preserves the key.

The same native call and content returns the existing proposal. Different content under that identity is a conflict. A new call ID is a new proposal, even if the content is identical; this is not content deduplication. A replay may return a cancelled or completed record. Always inspect the current `status` rather than treating every response as a newly pending proposal.

There are no automatic transport retries. Cancelling an asynchronous caller does not stop an already-running socket request. In particular, an uncertain `send` response may already have produced an effect, and repeating it can duplicate the effect. Proposal submission can be recovered using the original call identity; host approval and one-attempt execution remain in the Broker's separate review workflow.

## Actual validation

The pinned environment is listed in [native-adapters-requirements.txt](native-adapters-requirements.txt). The recorded run used Python 3.12.3 on Linux/WSL:

| Component | Installed version | Native invocation exercised |
| --- | --- | --- |
| LangChain Core | 1.6.2 | `StructuredTool` validation and native hidden call-ID injection. |
| LangGraph / prebuilt / checkpoint | 1.2.11 / 1.1.0 / 4.2.0 | A compiled `StateGraph` invoking a real `ToolNode`. |
| OpenAI Agents SDK / OpenAI | 0.22.2 / 3.13.0 | Registration on `Agent`, then `FunctionTool.on_invoke_tool` with a real `ToolContext`. |
| Pydantic AI Slim / Pydantic | 2.42.0 / 2.13.5 | Registration on `Agent`, then `FunctionToolset.get_tools` and `call_tool` with a real `RunContext`. |

The SDK `Agent` objects are registered, but their model runners are not invoked. Pydantic AI's `TestModel` is only context required by its native tool interface; it is not run as an actor. There are no model-generated attack attempts or attack-success claims in these results.

Run all 39 checks and export new evidence:

```sh
python3 -m venv /tmp/yxm-native-sdk-env
/tmp/yxm-native-sdk-env/bin/python -m pip install -r docs/native-adapters-requirements.txt
/tmp/yxm-native-sdk-env/bin/python -B tests/run_native_sdk_adapters.py \
  --output /tmp/yxm-native-adapters-result.json
```

Use a fresh output path: the runner will not overwrite prior evidence. It fails on missing dependencies, skipped tests, failed assertions or source changes during the run. Standard dependency-free test discovery can skip optional SDK tests; a skipped run does not count as SDK validation.

The suite includes 32 native SDK tests and seven shared-client tests. Native tests use actual Unix socket requests to the Broker and actual localhost HTTP receipts. They check private reads followed by denied public sends, allowed internal sends, all five reviewed action kinds, email draft submission, revocation, forged host fields, stable native IDs, changed-content conflicts, and completed/cancelled replay states. File effects are exercised only on temporary fixture files after a host-side commit.

The test harness restricts socket connections to its own Broker and HTTP receiver to prevent accidental model or external calls. That test restriction is not part of the product's security boundary. Broker and SDK fixtures are in the same test process, and this is neither full process isolation nor a complete model workflow. No legacy MCP example results are reused.

Fresh evidence: [native-adapters-2026-09-12.json](evidence/native-adapters-2026-09-12.json). It includes exact package versions, source hashes, test identities, native tool call transcripts and local receipt records.
