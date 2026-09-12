/** Authenticated owner commands; no management tool is registered for models. */
import { appendFileSync } from "node:fs";
import { requestSocket } from "./socket-client.mjs";

const LAYERS = [
  ["input", "外部内容"], ["memory", "记忆文件"], ["command", "命令执行"],
  ["alignment", "任务与回答"], ["foundation", "安装与技能"],
];
const WORKBENCH_HELP = "工作台：回到元星木工作台，选择当前工作，再打开“防护记录”。若网页已关闭，用原来的元星木启动器重新打开，使用终端显示的本机管理链接。修改设置、核对后恢复暂停都在已登录的工作台完成。";
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);

function foundationStatus(protection) {
  if (protection.layers?.foundation?.enabled === false) return "该层已关闭，当前不执行检查";
  const scan = protection.foundation_scan;
  if (!object(scan)) return "未确认";
  if (scan.state === "stale") return "设置已变更，需下次启动重新检查";
  if (scan.state === "missing") return "未取得检查报告，无法确认";
  if (scan.state !== "current") return "未确认";
  if (scan.assessed === false) return "未完成实际检查";
  if (scan.assessed !== true || typeof scan.complete !== "boolean" ||
      !["allow", "block", "review"].includes(scan.verdict) ||
      ![null, "allow", "block", "review"].includes(scan.would_verdict)) return "未确认";
  if ([scan.verdict, scan.would_verdict].some(value => value === "block" || value === "review")) {
    return "发现待处理项，请到工作台查看";
  }
  return scan.complete ? "已完成本次检查" : "检查未完整完成，请到工作台查看";
}

function statusText(result) {
  // Render only our own labels, never server-supplied paths, URLs, errors,
  // objectives or incident text. A Gateway URL is not a Workbench URL.
  const confirmed = result?.operator_action === "status";
  const ready = confirmed && result.status === "ready";
  const task = confirmed && object(result.task) ? result.task : {};
  const protection = ready && object(result.protection) && result.protection.schema_version === 1
    ? result.protection : {};
  const taskKnown = (task.active === false && task.revoked === true) || (task.active === true && task.revoked === false);
  const available = protection.state === "available" && taskKnown &&
    typeof protection.paused === "boolean" && protection.revoked === task.revoked;
  const notConfigured = protection.state === "not_configured" && taskKnown;
  const permission = task.active === false && task.revoked === true ? "已永久收回"
    : task.active === true && task.revoked === false ? "尚未撤销，仍按已授予范围处理" : "未确认";
  const pause = available && protection.paused === true ? "已暂停"
    : available && protection.paused === false ? "未暂停"
    : notConfigured ? "未启用五层自动暂停" : "未确认";
  const lines = ["元星木防护状态", `资料读取与发送权限：${permission}`, `工作暂停：${pause}`,
    ready ? "五层当前设置：" : "权限服务状态未确认，无法确认五层是否生效："];
  for (const [key, label] of LAYERS) {
    const layer = available && object(protection.layers) ? protection.layers[key] : null;
    const mode = notConfigured ? "未启用" : !object(layer) ? "未确认"
      : layer.enabled === false ? "关闭"
      : layer.enabled === true && layer.mode === "enforce" ? "拦截"
      : layer.enabled === true && layer.mode === "observe" ? "只记录，不拦截" : "未确认";
    lines.push(`- ${label}：${mode}`);
  }
  if (available) {
    const enabled = value => value === true ? "开启" : value === false ? "关闭" : "未确认";
    if (protection.layers?.foundation?.enabled === false) {
      lines.push("基础配置和技能语义检查：随安装与技能层关闭。");
    } else if (protection.layers?.foundation?.enabled === true) {
      lines.push(`基础配置检查：${enabled(protection.foundation_config_enabled)}；技能语义检查：${enabled(protection.skill_semantic_enabled)}`);
    }
    lines.push(`最近安装与技能检查：${foundationStatus(protection)}`);
  } else if (!notConfigured) {
    lines.push("未取得可核对的实时防护状态，请到工作台查看。");
  }
  lines.push(WORKBENCH_HELP);
  return lines.join("\n");
}

export function registerStatusCommand(api, config) {
  api.registerCommand({
    name: "yuanxingmu",
    description: "查看当前防护、暂停与撤权状态，以及工作台打开方式",
    acceptsArgs: false,
    requireAuth: true,
    requiredScopes: ["operator.admin"],
    async handler(context) {
      if (context.isAuthorizedSender !== true || !Array.isArray(context.gatewayClientScopes) ||
          !context.gatewayClientScopes.includes("operator.admin")) {
        return { text: "只有已认证的管理者可以查看当前防护状态。" };
      }
      if (context.args != null && (typeof context.args !== "string" || context.args.trim())) {
        return { text: "此命令不接受参数，只查看当前工作的防护状态。修改设置请到已登录的元星木工作台。" };
      }
      try {
        const result = await requestSocket(config.operatorSocket, { op: "status" }, { timeoutMs: 10000 });
        return { text: statusText(result) };
      } catch {
        return { text: statusText(null) };
      }
    },
  });
}

export function registerRevocationCommand(api, config) {
  api.registerCommand({
    name: "yuanxingmu-revoke",
    description: "收回资料读取和发送权限",
    acceptsArgs: false,
    requireAuth: true,
    requiredScopes: ["operator.admin"],
    async handler(context) {
      if (!context.isAuthorizedSender || !context.gatewayClientScopes?.includes("operator.admin")) {
        return { text: "只有已认证的管理者可以收回资料读取和发送权限。" };
      }
      if (context.args?.trim()) return { text: "此命令不接受参数，只能收回当前配置绑定任务的资料读取和发送权限。" };
      try {
        const result = await requestSocket(config.operatorSocket, { op: "revoke" }, { timeoutMs: 10000 });
        if (result.operator_action !== "revoke" || result.task?.active !== false || result.task?.revoked !== true) {
          return { text: "权限服务没有确认撤销完成，请查看实际任务状态。" };
        }
        // The broker owns durable revocation. An auxiliary log failure must not
        // misrepresent that confirmed outcome as an unconfirmed revocation.
        try {
          appendFileSync(config.auditPath, JSON.stringify({ time: new Date().toISOString(),
            event: "authenticated_user_revocation", sessionKey: context.sessionKey,
            authorizedSender: true, scopes: context.gatewayClientScopes,
            task_id: result.task.task_id, active: false, revoked: true }) + "\n", { mode: 0o600 });
        } catch {
          return { text: "权限服务已确认收回资料读取和发送权限。本地运算仍可继续。附加操作日志写入失败，请查看权限服务记录。" };
        }
        return { text: "已收回当前任务的资料读取和发送权限。之后的读取和发送请求会被拒绝，本地运算仍可继续。" };
      } catch {
        return { text: "权限服务未返回可核对的确认，不能确定此次撤销是否完成，请查看任务状态。" };
      }
    },
  });
}
