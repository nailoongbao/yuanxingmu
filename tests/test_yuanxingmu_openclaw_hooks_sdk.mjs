/** Official installed OpenClaw loader + policy executor, no Agent or model.
 *
 * Set YUANXINGMU_OPENCLAW_SDK_ROOT to the pinned OpenClaw package directory.
 * The local Unix socket returns synthetic verdicts; the tool implementation
 * records harmless receipts. No command text submitted here is executed.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { after, test } from "node:test";

const sdkRoot = process.env.YUANXINGMU_OPENCLAW_SDK_ROOT;
const skip = process.platform !== "linux" ? "official host integration requires Linux"
  : !sdkRoot ? "set YUANXINGMU_OPENCLAW_SDK_ROOT to exercise the actual installed SDK" : false;

if (skip) test("official OpenClaw hook registration and execution", {skip}, () => {});
else {
  const version = JSON.parse(fs.readFileSync(path.join(sdkRoot, "package.json"), "utf8")).version;
  assert.equal(version, "2026.9.4", "this contract is pinned to OpenClaw 2026.9.4");
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "yxm-native-hook-test-"));
  const oldHome = process.env.HOME, oldState = process.env.OPENCLAW_STATE_DIR;
  process.env.HOME = temp;
  process.env.OPENCLAW_STATE_DIR = path.join(temp, "state");
  const dist = path.join(sdkRoot, "dist");
  async function upstream(chunkPrefix, symbol) {
    const candidates = fs.readdirSync(dist).filter(name => name.startsWith(chunkPrefix) && name.endsWith(".mjs"));
    assert.equal(candidates.length, 1, "resolve the exact upstream runtime chunk");
    const file = path.join(dist, candidates[0]);
    const source = fs.readFileSync(file, "utf8");
    const alias = source.match(new RegExp("\\b" + symbol + " as ([A-Za-z_$][A-Za-z0-9_$]*)\\b"));
    assert.ok(alias, "upstream export must remain available: " + symbol);
    return (await import(pathToFileURL(file)))[alias[1]];
  }
  const acquire = await upstream("loader-runtime-load-", "acquirePluginRegistryForInspection");
  const initialize = await upstream("hook-runner-global-", "initializeGlobalHookRunner");
  const reset = await upstream("hook-runner-global-", "resetGlobalHookRunner");
  const getRunner = await upstream("hook-runner-global-", "getGlobalHookRunner");
  const wrapTool = await upstream("agent-tools.before-tool-call-", "wrapToolWithBeforeToolCallHook");

  after(() => {
    reset();
    if (oldHome === undefined) delete process.env.HOME; else process.env.HOME = oldHome;
    if (oldState === undefined) delete process.env.OPENCLAW_STATE_DIR; else process.env.OPENCLAW_STATE_DIR = oldState;
    fs.rmSync(temp, {recursive:true, force:true});
  });

  let ordinal = 0;
  async function fixture({respond, timeoutMs, fullOnly = false} = {}) {
    reset();
    const root = path.join(temp, "case-" + (++ordinal));
    for (const name of ["", "workspace", "trusted-core", "audit", "run"]) fs.mkdirSync(path.join(root, name), {recursive:true});
    const source = fileURLToPath(new URL("../yuanxingmu/integrations/openclaw/plugin/", import.meta.url));
    const plugin = path.join(root, "plugin");
    fs.cpSync(source, plugin, {recursive:true});
    // A checkout on Windows/WSL can report 0777 for every source file. The host
    // installer writes private Linux files; reproduce that installation here.
    fs.chmodSync(plugin, 0o700);
    for (const name of fs.readdirSync(plugin)) {
      const file = path.join(plugin, name);
      if (fs.lstatSync(file).isFile()) fs.chmodSync(file, 0o600);
    }
    if (fullOnly) {
      // Reproduce the old integration defect with unchanged hook code.
      const entry = path.join(plugin, "index.mjs");
      const text = fs.readFileSync(entry, "utf8");
      fs.writeFileSync(entry, text.replace("register(api) {", "register(api) {\n    if (api.registrationMode !== \"full\") return;"));
    }
    const requests = [], sockets = new Set(), timers = new Set();
    const server = net.createServer(client => {
      sockets.add(client); client.on("close", () => sockets.delete(client)); client.on("error", () => {});
      let data = "";
      client.on("data", chunk => {
        data += chunk.toString("utf8");
        if (!data.includes("\n")) return;
        const request = JSON.parse(data.split("\n")[0]); requests.push(request);
        const answer = respond ? respond(request) : {allowed:true, verdict:"allow"};
        if (answer === null) return;
        const send = () => { if (!client.destroyed) client.end(JSON.stringify(answer.value ?? answer) + "\n"); };
        if (answer.delay) {
          const timer = setTimeout(() => {timers.delete(timer); send();}, answer.delay); timers.add(timer);
        } else send();
      });
    });
    const brokerSocket = path.join(root, "run/broker.sock");
    await new Promise((resolve, reject) => {server.once("error", reject); server.listen(brokerSocket, resolve);});
    const config = {plugins:{allow:["yuanxingmu"], slots:{memory:"none"}, load:{paths:[plugin]}, entries:{yuanxingmu:{
      enabled:true,
      ...(timeoutMs ? {hooks:{timeouts:{before_tool_call:timeoutMs}}} : {}),
      config:{python:"/usr/bin/python3", corePath:path.join(root,"trusted-core"), workspace:path.join(root,"workspace"),
        brokerSocket, operatorSocket:path.join(root,"run/operator.sock"), bwrap:"/usr/bin/bwrap",
        auditPath:path.join(root,"audit/events.jsonl"), resourceIds:[], destinationIds:[], defenseEnabled:true}
    }}}};
    let handle;
    try {
      handle = await acquire({config, env:process.env, workspaceDir:path.join(root,"workspace"), onlyPluginIds:["yuanxingmu"]});
      const record = handle.registry.plugins.find(p => p.id === "yuanxingmu");
      assert.equal(record?.status, "loaded", JSON.stringify(handle.registry.diagnostics));
      initialize(handle.registry);
    } catch (error) {
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => server.close(resolve));
      await handle?.release();
      throw error;
    }
    const receipts = [];
    const tool = wrapTool({name:"exec", label:"Fixture", description:"Harmless receipt recorder",
      parameters:{type:"object", properties:{command:{type:"string"}}, required:["command"]},
      async execute(callId, params) {receipts.push({callId, params}); return {content:[{type:"text", text:"fixture executed"}]};}
    }, {sessionKey:"agent:fixture:main", runId:"fixture-" + ordinal, workspaceDir:path.join(root,"workspace"), config});
    return {handle, requests, receipts, tool, sockets, async close() {
      for (const timer of timers) clearTimeout(timer);
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => server.close(resolve));
      await handle.release(); reset();
    }};
  }

  test("scoped discovery registry must contain both actual defense hooks", async () => {
    const f = await fixture();
    try {
      const hooks = f.handle.registry.typedHooks;
      assert.deepEqual(hooks.map(h => h.hookName).sort(), ["before_message_write", "before_tool_call"]);
      assert.equal(hooks.find(h => h.hookName === "before_tool_call").timeoutMs, 65000);
      assert.equal(f.handle.registry.diagnostics.length, 0);
    } finally {await f.close();}
  });

  test("old full-only registration reproduces the missing-policy defect", async () => {
    const f = await fixture({fullOnly:true});
    try {
      assert.equal(f.handle.registry.typedHooks.length, 0);
      await f.tool.execute("old-gap", {command:"fixture text only"});
      assert.equal(f.requests.length, 0);
      assert.equal(f.receipts.length, 1);
    } finally {await f.close();}
  });

  test("official tool wrapper reaches host check then runs only the allowed fixture", async () => {
    const f = await fixture({respond: request => request.arguments.command === "sudo true"
      ? {allowed:false, verdict:"block", message:"synthetic dangerous-command verdict"}
      : {allowed:true, verdict:"allow"}});
    try {
      await f.tool.execute("allowed", {command:"printf harmless"});
      const denied = await f.tool.execute("denied", {command:"sudo true"});
      assert.deepEqual(f.requests.map(r => r.arguments.command), ["printf harmless", "sudo true"]);
      assert.equal(f.receipts.length, 1);
      assert.equal(denied.details.status, "blocked");
      assert.equal(denied.details.deniedReason, "plugin-before-tool-call");
      assert.equal(f.requests[0].op, "guard_tool");
    } finally {await f.close();}
  });

  test("native SDK hook timeout fails closed even if the host later says allow", async () => {
    const f = await fixture({timeoutMs:25, respond:() => ({delay:100, value:{allowed:true, verdict:"allow"}})});
    try {
      assert.equal(f.handle.registry.typedHooks.find(h => h.hookName === "before_tool_call").timeoutMs, 25);
      await assert.rejects(f.tool.execute("timeout", {command:"printf harmless"}), /before_tool_call hook failed/);
      await new Promise(resolve => setTimeout(resolve, 130));
      assert.equal(f.requests.length, 1);
      assert.equal(f.receipts.length, 0);
    } finally {await f.close();}
  });

  test("native cancellation closes pending IPC without executing the tool", async () => {
    const f = await fixture({respond:() => null});
    try {
      const abort = new AbortController();
      const pending = f.tool.execute("cancelled", {command:"printf harmless"}, abort.signal);
      const waitUntil = Date.now() + 2000;
      while (f.requests.length === 0 && Date.now() < waitUntil) await new Promise(resolve => setTimeout(resolve, 5));
      assert.equal(f.requests.length, 1);
      abort.abort(new Error("fixture cancellation"));
      // SDK may expose either a blocked result or a cancellation failure; neither executes.
      await pending.catch(() => {});
      await new Promise(resolve => setTimeout(resolve, 10));
      assert.equal(f.receipts.length, 0);
      assert.equal(f.sockets.size, 0);
    } finally {await f.close();}
  });

  test("official hook runner preserves single-use approval and deny-on-timeout", async () => {
    const f = await fixture({respond:() => ({allowed:false, verdict:"review", message:"Please review the exact operation"})});
    try {
      const result = await getRunner().runBeforeToolCall({toolName:"exec", params:{command:"fixture"}}, {sessionKey:"agent:fixture:main"});
      assert.deepEqual(result.requireApproval.allowedDecisions, ["allow-once", "deny"]);
      assert.equal(result.requireApproval.timeoutBehavior, "deny");
      assert.equal(result.requireApproval.pluginId, "yuanxingmu");
      assert.equal(f.receipts.length, 0);
    } finally {await f.close();}
  });
}
