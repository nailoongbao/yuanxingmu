/** Official SDK entry for the dedicated, fixed-task Yuanxingmu profile. */
import { readFileSync } from "node:fs";
import { buildJsonPluginConfigSchema, definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { readTrustedConfig } from "./config.mjs";
import { registerNativeSandbox } from "./sandbox-provider.mjs";
import { registerBrokerTools } from "./tools.mjs";
import { registerRevocationCommand, registerStatusCommand } from "./commands.mjs";
import { registerDefenseHooks } from "./defense-hooks.mjs";

const manifest = JSON.parse(readFileSync(new URL("./openclaw.plugin.json", import.meta.url), "utf8"));

export default definePluginEntry({
  id: manifest.id,
  name: manifest.name,
  description: manifest.description,
  configSchema: buildJsonPluginConfigSchema(manifest.configSchema),
  register(api) {
    // The agent builds a scoped "discovery" registry for actual tool runs.
    // Pure tool/hook declarations must also exist there, not only at gateway
    // activation. Starting a sandbox provider remains a full-mode lifecycle.
    if (!["full", "discovery"].includes(api.registrationMode)) return;
    const config = readTrustedConfig(api.pluginConfig);
    registerBrokerTools(api, config);
    registerDefenseHooks(api, config);
    if (api.registrationMode === "full") {
      registerNativeSandbox(api, config);
      registerStatusCommand(api, config);
      registerRevocationCommand(api, config);
    }
  },
});
