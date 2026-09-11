/** Native sandbox provider migrated from the verified OpenClaw exec integration. */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, realpathSync } from "node:fs";
import { registerSandboxBackend } from "openclaw/plugin-sdk/sandbox";
import { workerArgv } from "./worker-launch.mjs";

function hostEnvironment(config) {
  return { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", PYTHONPATH: config.corePath,
    PYTHONDONTWRITEBYTECODE: "1" };
}

function audit(config, event) {
  appendFileSync(config.auditPath, JSON.stringify({ time: new Date().toISOString(), ...event }) + "\n", { mode: 0o600 });
}

async function runShell(config, params, runtimeId) {
  if (params.signal?.aborted) throw new Error("Sandbox command cancelled before launch");
  const argv = workerArgv(config, ["/bin/sh", "-c", params.script, "yuanxingmu-shell", ...(params.args ?? [])]);
  const commandBytes = Buffer.from(JSON.stringify([params.script, ...(params.args ?? [])]), "utf8");
  audit(config, { event: "native_run_shell", runtimeId,
    command_sha256: createHash("sha256").update(commandBytes).digest("hex"),
    command_bytes: commandBytes.length, command_encoding: "script_and_args_json" });
  return await new Promise((resolve, reject) => {
    const child = spawn(argv[0], argv.slice(1), { env: hostEnvironment(config), stdio: ["pipe", "pipe", "pipe"], detached: true });
    let stdout = Buffer.alloc(0), stderr = Buffer.alloc(0), killed = false;
    const kill = () => {
      killed = true;
      if (child.pid) {
        try { process.kill(-child.pid, "SIGTERM"); }
        catch (error) { if (error.code !== "ESRCH") throw error; }
      }
    };
    const timeout = setTimeout(kill, 20000);
    params.signal?.addEventListener("abort", kill, { once: true });
    const cleanup = () => { clearTimeout(timeout); params.signal?.removeEventListener("abort", kill); };
    child.stdout.on("data", (data) => { stdout = Buffer.concat([stdout, data]); if (stdout.length > 1024 * 1024) kill(); });
    child.stderr.on("data", (data) => { stderr = Buffer.concat([stderr, data]); if (stderr.length > 1024 * 1024) kill(); });
    child.stdin.on("error", (error) => { if (error.code !== "EPIPE") kill(); });
    child.on("error", (error) => { cleanup(); reject(error); });
    child.on("close", (code) => {
      cleanup();
      const result = { stdout, stderr, code: code ?? 1 };
      audit(config, { event: "native_run_shell_finished", runtimeId, code: result.code, killed });
      if (killed || (!params.allowFailure && result.code !== 0)) reject(new Error("Yuanxingmu sandbox shell failed: " + stderr.toString("utf8")));
      else resolve(result);
    });
    child.stdin.end(params.stdin);
  });
}

export function registerNativeSandbox(api, config) {
  const workspace = config.workspace;
  const unregister = registerSandboxBackend("yuanxingmu", {
    resolveWorkdir: () => "/workspace",
    factory: async (params) => {
      if (realpathSync(params.workspaceDir) !== workspace || params.cfg.workspaceAccess !== "rw") {
        throw new Error("Yuanxingmu requires its host-selected scratch workspace");
      }
      const runtimeId = "yuanxingmu-" + createHash("sha256").update(config.brokerSocket + "\0" + params.scopeKey).digest("hex").slice(0, 24);
      audit(config, { event: "native_backend_created", runtimeId, sessionKey: params.sessionKey,
        scopeKey: params.scopeKey, workspace, brokerSocket: config.brokerSocket });
      return {
        id: "yuanxingmu", runtimeId, runtimeLabel: runtimeId, workdir: "/workspace",
        workdirValidation: "backend", workdirRoots: ["/workspace"], capabilities: {},
        async validateWorkdir(workdir) { return workdir === "/workspace" ? "/workspace" : null; },
        async buildExecSpec({ command, workdir, env, usePty }) {
          if (usePty) throw new Error("PTY is not supported by this provider");
          if (workdir && workdir !== "/workspace") throw new Error("Unsupported sandbox workdir");
          const argv = workerArgv(config, ["/bin/sh", "-lc", command]);
          audit(config, { event: "native_build_exec_spec", runtimeId,
            command_sha256: createHash("sha256").update(command, "utf8").digest("hex"),
            command_bytes: Buffer.byteLength(command, "utf8"), command_encoding: "utf8",
            receivedEnvKeys: Object.keys(env).sort(), envPolicy: "host-selected worker environment only" });
          return { argv, env: hostEnvironment(config), stdinMode: "pipe-closed" };
        },
        async finalizeExec(result) {
          audit(config, { event: "native_exec_finished", runtimeId,
            status: result.status, exitCode: result.exitCode, timedOut: result.timedOut });
        },
        async runShellCommand(params) { return await runShell(config, params, runtimeId); },
      };
    },
  });
  api.lifecycle.registerRuntimeLifecycle({ id: "yuanxingmu-native-backend",
    cleanup({ reason, sessionKey, runId }) {
      if (sessionKey === undefined && runId === undefined && (reason === "disable" || reason === "restart")) unregister();
    },
  });
}
