/** Host-selected configuration. None of these fields is a model tool argument. */
import { existsSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PATH_KEYS = ["python", "corePath", "workspace", "brokerSocket", "bwrap", "auditPath", "operatorSocket"];
const ALL_KEYS = [...PATH_KEYS, "resourceIds", "destinationIds"];

function inside(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(".." + path.sep) && relative !== ".." && !path.isAbsolute(relative));
}

function canonicalTarget(value) {
  return existsSync(value) ? realpathSync(value) : path.join(realpathSync(path.dirname(value)), path.basename(value));
}

export function readTrustedConfig(value) {
  if (process.platform !== "linux") throw new Error("Yuanxingmu requires Linux; no host fallback");
  if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.keys(value).length !== ALL_KEYS.length + (Object.hasOwn(value, "reviewedMail") ? 1 : 0)
      || Object.keys(value).some((key) => !ALL_KEYS.includes(key) && key !== "reviewedMail")
      || (Object.hasOwn(value, "reviewedMail") && typeof value.reviewedMail !== "boolean")) {
    throw new Error("Invalid Yuanxingmu plugin configuration fields");
  }
  const result = {};
  result.reviewedMail = value.reviewedMail === true;
  for (const key of PATH_KEYS) {
    if (typeof value[key] !== "string" || !path.isAbsolute(value[key]) || value[key].includes("\0")) {
      throw new Error("Invalid trusted plugin path: " + key);
    }
    result[key] = canonicalTarget(value[key]);
  }
  const pluginDirectory = realpathSync(path.dirname(fileURLToPath(import.meta.url)));
  for (const key of PATH_KEYS.filter((key) => key !== "workspace")) {
    if (inside(result[key], result.workspace) || inside(result.workspace, result[key])) {
      throw new Error("Trusted plugin path overlaps writable workspace: " + key);
    }
  }
  if (inside(pluginDirectory, result.workspace) || inside(result.workspace, pluginDirectory)) {
    throw new Error("Plugin code must be outside the writable workspace");
  }
  if (result.brokerSocket === result.operatorSocket) throw new Error("Broker and operator sockets must differ");
  for (const key of ["resourceIds", "destinationIds"]) {
    if (!Array.isArray(value[key]) || value[key].some((item) => typeof item !== "string"
        || item.length === 0 || item.length > 128 || /[\u0000-\u001f\u007f]/u.test(item))
        || new Set(value[key]).size !== value[key].length) {
      throw new Error("Invalid configured identifier list: " + key);
    }
    result[key] = Object.freeze([...value[key]]);
  }
  return Object.freeze(result);
}

export function isBoundContext(context, config) {
  try {
    return context?.sandboxed === true && typeof context.sessionKey === "string"
      && context.sessionKey.length > 0 && typeof context.workspaceDir === "string"
      && path.isAbsolute(context.workspaceDir) && realpathSync(context.workspaceDir) === config.workspace;
  } catch {
    return false;
  }
}
