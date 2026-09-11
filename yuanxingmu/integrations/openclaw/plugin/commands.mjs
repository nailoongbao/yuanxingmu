/** An authenticated owner command; no management tool is registered for models. */
import { appendFileSync } from "node:fs";
import { requestSocket } from "./socket-client.mjs";

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
