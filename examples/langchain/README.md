# Keep a finished task's tools from reopening its connection

This example uses **released LangChain 1.4.0 tools**, the existing Invariant Gateway, and the same two independent synthetic services as the core demo. No model, real mailbox or production data is involved.

The application reads private test data, closes its MCP client, then calls a previously returned sending tool with that data. The old tool can reopen the connection. The gateway sees a new history with no private read, and the receiving service gets the data.

`TaskToolScope` makes the tool references expire when their owning task ends. It uses the official `MCPAdapter`, preserving each returned `StructuredTool`'s schema, metadata, response format and error handling. It wraps the original asynchronous callable to enforce the task lifetime. In-task calls still go through the actual adapter and configured gateway.

## What the actual run showed

The gateway/aggregator versions are those in the [core verification record](../../docs/verification.md). Host versions are pinned in [requirements.txt](requirements.txt).

| Host usage | Observed outcome |
|---|---|
| Calls without an outer adapter context, using the default stdio keep-alive | All 3 prohibited sends blocked; both internal corrections arrived |
| Calls within the official adapter context | The same 3 blocked / 2 arrived |
| Explicitly close the client, then reuse its old sending tool and private data | 1 prohibited send arrived through a new gateway session |
| Calls within `TaskToolScope` | All 3 prohibited sends blocked; both internal corrections arrived |
| Reuse the scoped sending tool after scope exit | `TaskScopeClosed`; no new backend activity or policy request |
| Separate new task containing only public data | Public send arrived |

The modern default stdio path already retained the underlying session in this test. An SDK context opening and closing does not prove that its underlying session or process restarted. This example demonstrates an application recovery boundary; it does not establish that LangChain's default is unsafe or disclose a new upstream vulnerability.

The raw local run is `.research/langchain-host/integration-04` in the author's workspace. [observed-result.json](observed-result.json) contains selected fields and hashes from that run. Run the example to obtain a complete new set of host calls, policy events, downstream receipts and process observations.

## Run it on Windows

First install the two core demo environments using the [repository instructions](../../README.md). Add a separate host environment because modern LangChain and the older Gateway require different dependency sets:

```powershell
python -m venv .venv-host
& .\.venv-host\Scripts\python.exe -m pip install -r .\examples\langchain\requirements.txt .

$gatewayPython = (Resolve-Path .\.venv-gateway\Scripts\python.exe).Path
$aggregationPython = (Resolve-Path .\.venv-aggregation\Scripts\python.exe).Path
& .\.venv-host\Scripts\python.exe .\examples\langchain\experiment.py --gateway-python $gatewayPython --aggregation-python $aggregationPython --output .\output\langchain-first-run --with-task-scope
```

Use a new output directory. The full host experiment has been run on Windows; it is not a Linux host-integration claim.

The example explicitly constructs `Client(..., mode="legacy")` for this pinned Gateway route. The initial automatic protocol negotiation trial failed tool-directory validation before reading or sending data: the modern response needed `cacheScope`, `resultType` and `ttlMs`, which this older gateway's transformed directory lacked. Public legacy negotiation made the combination usable. That initial failure was not counted as a security block, and SDK validation remains enabled.

The result status is `observed_with_correlated_evidence`, not a claim that every row is secure: one row intentionally records the allowed reconnection and resulting prohibited receipt. Examine the per-workflow results.

## Use the lifetime helper

Keep the whole task, including tool execution, within the scope:

```python
from fastmcp.client.transports import StdioTransport
from task_tools import TaskToolScope

async with TaskToolScope(
    lambda: StdioTransport(**gateway_entry),  # a fresh, exclusively owned target
    mode="legacy",                           # for the pinned route in this example
) as scope:
    tools = scope.tools
    await run_your_task(tools)

# Retaining `tools` does not extend their lifetime. Old references now refuse calls.
```

This is an experimental helper alongside the example, not a general recovery API. A scope is used once, on one event loop, for one user's task. Do not pass a factory that returns another task's transport or cache these tool references for unrelated tasks. `MCPAdapter` can clone a supplied client, so the helper holds and closes the adapter's actual client.

Closing rejects new calls first, lets already admitted calls finish, then closes the adapter and its keep-alive transport. If draining or cleanup times out, it raises `TaskScopeDrainTimeout` and remains closed to new admissions. Keep the event loop alive and `await scope.wait_closed(timeout=...)` to observe eventual cleanup; a timeout is not success. `scope.state == "closed"` reports completed cleanup calls. The demo separately observes actual backend process exit; it does not promise graceful finalizers.

Seven focused component tests exercise lifetime, admitted calls, cancellation, drain timeout and cleanup failure with real `StructuredTool` objects and a fake adapter. They are separate from the real-runtime experiment:

```powershell
& .\.venv-host\Scripts\python.exe -m unittest discover -s .\examples\langchain -p test_task_tools.py -v
```

Creating a new scope while carrying old private model memory into it remains unresolved. The application must preserve the applicable protection state or refuse that recovery. Direct tool access, shell/network bypasses, cross-user sharing and arbitrary policy compatibility are also outside this helper.

## Upstream references

- [LangChain connection lifetimes](https://docs.langchain.com/oss/python/langchain/mcp/connections#one-session-per-invocation)
- [Released MCPAdapter implementation](https://github.com/langchain-ai/langchain/blob/79cab2dc7f58be720cac43db3677b4c1fd971f91/libs/langchain_v1/langchain/mcp/adapter.py#L207)
- [Released asynchronous tool conversion](https://github.com/langchain-ai/langchain/blob/79cab2dc7f58be720cac43db3677b4c1fd971f91/libs/langchain_v1/langchain/mcp/tools.py#L261)
