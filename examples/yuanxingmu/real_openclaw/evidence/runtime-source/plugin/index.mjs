/** Official SDK entry for the dedicated, fixed-task Yuanxingmu profile. */
import { readFileSync } from "node:fs";
import { buildJsonPluginConfigSchema, definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { readTrustedConfig } from "./config.mjs";
import { registerNativeSandbox } from "./sandbox-provider.mjs";
import { registerBrokerTools } from "./tools.mjs";
import { registerRevocationCommand } from "./commands.mjs";

const manifest = JSON.parse(readFileSync(new URL("./openclaw.plugin.json", import.meta.url), "utf8"));

export default definePluginEntry({
  id: manifest.id,
  name: manifest.name,
  description: manifest.description,
  configSchema: buildJsonPluginConfigSchema(manifest.configSchema),
  register(api) {
    if (api.registrationMode !== "full") return;
    const config = readTrustedConfig(api.pluginConfig);
    registerNativeSandbox(api, config);
    registerBrokerTools(api, config);
    registerRevocationCommand(api, config);
  },
});
