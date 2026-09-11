/** Native OpenClaw sandbox provider. The trusted worker owns all isolation. */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { buildJsonPluginConfigSchema, definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { registerSandboxBackend } from "openclaw/plugin-sdk/sandbox";

const manifest = JSON.parse(readFileSync(new URL("./openclaw.plugin.json", import.meta.url), "utf8"));

function hostEnvironment(config) {
  // The model-supplied exec env is never the launcher's environment or an
  // authority source. Only host-selected non-secret runtime settings enter it.
  return { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", PYTHONPATH: config.corePath,
    PYTHONDONTWRITEBYTECODE: "1" };
}

function workerArgv(config, command) {
  // Native exec inherits the writable workspace as cwd. Python -m alone would
  // import an attacker-created yuanxingmu package there BEFORE the sandbox.
  // -I ignores cwd/PYTHONPATH; this fixed host-owned bootstrap adds only corePath.
  const bootstrap = "import sys; sys.path.insert(0, sys.argv.pop(1)); from yuanxingmu.worker import main; main()";
  return [config.python, "-I", "-c", bootstrap, config.corePath, "--workspace", config.workspace,
    "--broker-socket", config.brokerSocket, "--bwrap", config.bwrap,
    "--readonly", config.corePath, "--env-json", JSON.stringify({ PYTHONPATH: config.corePath }),
    "--", ...command];
}

function audit(config, event) {
  appendFileSync(config.auditPath, JSON.stringify({ time: new Date().toISOString(), ...event }) + "\n",
    { mode: 0o600 });
}

async function runShell(config, params, runtimeId) {
  if (params.signal?.aborted) throw new Error("Sandbox command cancelled before launch");
  const argv = workerArgv(config, ["/bin/sh", "-c", params.script, "yuanxingmu-shell", ...(params.args ?? [])]);
  audit(config, { event: "native_run_shell", runtimeId, argv });
  return await new Promise((resolve, reject) => {
    const child = spawn(argv[0], argv.slice(1), { env: hostEnvironment(config),
      stdio: ["pipe", "pipe", "pipe"], detached: true });
    let stdout = Buffer.alloc(0), stderr = Buffer.alloc(0), killed = false;
    const kill = () => {
      killed = true;
      if (child.pid) {
        try { process.kill(-child.pid, "SIGTERM"); } catch (error) {
          if (error.code !== "ESRCH") throw error;
        }
      }
    };
    const timeout = setTimeout(kill, 20000);
    params.signal?.addEventListener("abort", kill, { once: true });
    const cleanup = () => { clearTimeout(timeout); params.signal?.removeEventListener("abort", kill); };
    child.stdout.on("data", (data) => {
      stdout = Buffer.concat([stdout, data]);
      if (stdout.length > 1024 * 1024) kill();
    });
    child.stderr.on("data", (data) => {
      stderr = Buffer.concat([stderr, data]);
      if (stderr.length > 1024 * 1024) kill();
    });
    child.stdin.on("error", (error) => { if (error.code !== "EPIPE") kill(); });
    child.on("error", (error) => { cleanup(); reject(error); });
    child.on("close", (code) => {
      cleanup();
      const result = { stdout, stderr, code: code ?? 1 };
      audit(config, { event: "native_run_shell_finished", runtimeId, code: result.code, killed });
      if (killed || (!params.allowFailure && result.code !== 0)) {
        reject(new Error("Yuanxingmu sandbox shell failed: " + stderr.toString("utf8")));
      } else resolve(result);
    });
    child.stdin.end(params.stdin);
  });
}

export default definePluginEntry({
  id: manifest.id,
  name: manifest.name,
  description: manifest.description,
  configSchema: buildJsonPluginConfigSchema(manifest.configSchema),
  register(api) {
    if (api.registrationMode !== "full") return;
    if (process.platform !== "linux") throw new Error("Yuanxingmu example requires Linux; no host fallback");
    const config = Object.freeze({ ...api.pluginConfig });
    for (const key of manifest.configSchema.required) {
      if (typeof config[key] !== "string" || !path.isAbsolute(config[key]) || config[key].includes("\0")) {
        throw new Error("Invalid trusted plugin path: " + key);
      }
    }
    const workspace = realpathSync(config.workspace);
    const unregister = registerSandboxBackend("yuanxingmu", {
      resolveWorkdir: () => "/workspace",
      factory: async (params) => {
        if (realpathSync(params.workspaceDir) !== workspace || params.cfg.workspaceAccess !== "rw") {
          throw new Error("This example requires its host-selected scratch workspace");
        }
        const runtimeId = "yuanxingmu-" + createHash("sha256")
          .update(config.brokerSocket + "\0" + params.scopeKey).digest("hex").slice(0, 24);
        audit(config, { event: "native_backend_created", runtimeId, sessionKey: params.sessionKey,
          scopeKey: params.scopeKey, workspace, brokerSocket: config.brokerSocket });
        return {
          id: "yuanxingmu", runtimeId, runtimeLabel: runtimeId, workdir: "/workspace",
          workdirValidation: "backend", workdirRoots: ["/workspace"], capabilities: {},
          async validateWorkdir(workdir) { return workdir === "/workspace" ? "/workspace" : null; },
          async buildExecSpec({ command, workdir, env, usePty }) {
            if (usePty) throw new Error("PTY is not supported by this example");
            if (workdir && workdir !== "/workspace") throw new Error("Unsupported sandbox workdir");
            const argv = workerArgv(config, ["/bin/sh", "-lc", command]);
            audit(config, { event: "native_build_exec_spec", runtimeId, command, argv,
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
    api.lifecycle.registerRuntimeLifecycle({ id: "yuanxingmu-example-backend",
      cleanup({ reason, sessionKey, runId }) {
        if (sessionKey === undefined && runId === undefined && (reason === "disable" || reason === "restart")) unregister();
      },
    });
  },
});
