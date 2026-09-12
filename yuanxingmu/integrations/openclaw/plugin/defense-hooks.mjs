/** Native hooks for the host-held semantic and content checks. */
import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { requestSocket } from "./socket-client.mjs";

// The official runner defaults before_tool_call to 15 s. The host can perform
// more than one bounded model check, so let IPC stop first and return an
// explicit refusal. An operator's shorter SDK timeout also fails closed in the
// supported OpenClaw runtime; it must not be presented as a detection success.
const BROKER_CHECK_TIMEOUT_MS = 60000;
const HOOK_CHECK_TIMEOUT_MS = 65000;

function bound(context, config) {
  try { return typeof context?.sessionKey === "string" && context.sessionKey.length > 0
    && (context.workspaceDir === undefined || realpathSync(context.workspaceDir) === config.workspace); }
  catch { return false; }
}

function plainText(value, depth = 0) {
  if (depth > 12) throw new Error("tool_result_too_deep");
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "boolean" || typeof value === "number") return String(value);
  if (Array.isArray(value)) return value.map(item => plainText(item, depth + 1)).join("\n");
  if (typeof value === "object") return Object.entries(value).map(([key,item]) => key + ": " + plainText(item, depth + 1)).join("\n");
  throw new Error("tool_result_invalid");
}

export function registerDefenseHooks(api, config) {
  if (!config.defenseEnabled) return;
  api.on("before_tool_call", async (event, context) => {
    // Broker tools check their actual arguments again on the host, where the
    // send occurs. The native exec must be checked before its implementation.
    if (typeof event?.toolName !== "string") return {block:true, blockReason:"工具请求格式无效，本次操作没有执行。"};
    if (event.toolName.startsWith("yuanxingmu_")) return;
    if (!bound(context, config)) return {block:true, blockReason:"元星木无法确认这次操作属于当前工作，已停止。"};
    try {
      const result = await requestSocket(config.brokerSocket,
        {op:"guard_tool", tool:event.toolName, arguments:event.params},
        {timeoutMs:BROKER_CHECK_TIMEOUT_MS, signal:context?.abortSignal});
      if (result.allowed === false && result.verdict === "review") return {requireApproval:{
        title:"元星木：这一步需要本人确认", description:result.message,
        severity:"warning", timeoutMs:300000, timeoutBehavior:"deny", allowedDecisions:["allow-once","deny"]
      }};
      if (result.allowed !== true) return {block:true, blockReason:result.message || "元星木已拦下这次操作：" + result.reason};
    } catch {
      return {block:true, blockReason:"防护检查尚未得到确认，本次操作没有执行。请查看工作台。"};
    }
  }, {priority:100, timeoutMs:HOOK_CHECK_TIMEOUT_MS});

  // OpenClaw's transcript write hook is synchronous. A bounded separate Python
  // process talks to the host; it never imports code from the writable workspace.
  api.on("before_message_write", (event, context) => {
    if (event.message?.role !== "toolResult") return;
    let message = "工具返回的安全检查未完成，本次内容暂不交给 AI。";
    if (bound({...context, sessionKey:context?.sessionKey || event.sessionKey}, config)) {
      try {
        const source = "import json,sys;sys.path.insert(0,sys.argv.pop(1));from yuanxingmu.client import request;print(json.dumps(request('inspect_input',socket_path=sys.argv[1],text=json.load(sys.stdin))))";
        const text = plainText(event.message.content);
        if (Buffer.byteLength(text, "utf8") > 262144) throw new Error("tool_result_too_large");
        const result = spawnSync(config.python, ["-I", "-B", "-c", source, config.corePath, config.brokerSocket], {
          input:JSON.stringify(text), encoding:"utf8", timeout:10000,
          maxBuffer:1024*1024, env:{PATH:"/usr/bin:/bin",LANG:"C.UTF-8"}, cwd:config.corePath
        });
        if (result.status === 0) {
          const check = JSON.parse(result.stdout);
          if (check.allowed === true) return;
          if (typeof check.message === "string") message = check.message;
        }
      } catch { /* A missing verdict withholds content. */ }
    }
    return {block:false, message:{...event.message,
      content:[{type:"text", text:"元星木已暂扣这段工具返回。" + message}], isError:true}};
  });
}
