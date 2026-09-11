/** Native tools bind one persistent task through its fixed host socket. */
import { isBoundContext } from "./config.mjs";
import { requestSocket } from "./socket-client.mjs";
import { createHash } from "node:crypto";

const MAX_CONTENT = 256 * 1024;

function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function identifierSchema(ids, description) {
  return { type: "string", minLength: 1, maxLength: 128, description,
    ...(ids.length ? { enum: [...ids] } : {}) };
}

function resultMessage(operation, result) {
  if (result.allowed === null) return operation === "send"
    ? "权限服务没有返回可核对的结果；发送是否发生不能据此确定。"
    : "权限服务没有返回可核对的结果，此次请求未得到确认。";
  if (result.allowed === false) {
    if (result.reason === "task_revoked") return "资料读取和发送权限已被收回，此次请求被拒绝。本地运算不受这个撤销操作控制。";
    if (result.reason === "destination_cannot_receive_labels") return "这个接收位置没有获准接收工作资料，本次发送已拦下。可以改发给获准接收内部资料的位置。请用日常中文向用户说明。";
    return "请求未获准。原因：" + result.reason;
  }
  if (operation === "send") {
    return result.outcome === "acknowledged"
      ? "获准接收位置返回成功确认。"
      : "请求已获准，但没有收到成功确认；不能据此判断接收方是否已收到内容。";
  }
  if (operation === "draft_email") {
    if (result.status === "pending") return "草稿已交给元星木工作台。请用户核对收件人、主题和全文后亲自确认发送；现在尚未发送邮件。";
    if (result.status === "acknowledged") return "这封邮件此前已经提交，邮箱服务已接收。此次没有重复发送；这不代表收件人已经收到或阅读。";
    if (result.status === "unconfirmed" || result.status === "sending") return "这封邮件已有发送记录，但结果尚未确认。请用户先核对工作台和邮箱，不要重复起草或发送。";
    if (result.status === "cancelled") return "这份草稿已经弃用，没有重新创建或发送。";
    return "这份草稿已有处理记录，没有重新创建或发送。请用户在工作台核对实际状态。";
  }
  return operation === "read" ? "权限服务已返回资料。" : "以下为当前任务的实际权限状态。";
}

function toolResult(operation, result) {
  return { content: [{ type: "text", text: resultMessage(operation, result) + "\n" + JSON.stringify(result) }], details: result };
}

function payloadFor(operation, args, config, requestKey) {
  if (operation === "describe") return exactKeys(args, []) ? { op: "describe" } : null;
  if (operation === "read") {
    return exactKeys(args, ["resource"]) && typeof args.resource === "string" && config.resourceIds.includes(args.resource)
      ? { op: "read", resource: args.resource } : null;
  }
  if (operation === "draft_email") {
    return config.reviewedMail && exactKeys(args, ["recipient", "subject", "body"])
      && [args.recipient, args.subject, args.body].every(value => typeof value === "string")
      && args.recipient.length <= 254 && args.subject.length <= 400 && Buffer.byteLength(args.body, "utf8") <= 64 * 1024
      ? { op: "draft_email", request_key: requestKey, draft: args } : null;
  }
  return exactKeys(args, ["destination", "body"]) && typeof args.destination === "string"
    && config.destinationIds.includes(args.destination) && typeof args.body === "string"
    && Buffer.byteLength(args.body, "utf8") <= MAX_CONTENT
    ? { op: "send", destination: args.destination, body: args.body } : null;
}

export function registerBrokerTools(api, config) {
  const declarations = [
    { name: "yuanxingmu_read", operation: "read", label: "读取获准资料",
      description: "通过权限服务读取操作者配置的资料。参数只能使用获准资料名称，不能提供文件路径。内容会交给此配置选定的模型处理。",
      parameters: { type: "object", additionalProperties: false, required: ["resource"],
        properties: { resource: identifierSchema(config.resourceIds, "操作者配置的资料名称") } } },
    { name: "yuanxingmu_send", operation: "send", label: "发送到获准位置",
      description: "请求权限服务将内容发送到操作者配置的固定接收位置。不能提供网址、收件地址或权限标签；是否可以发送由当前任务权限决定。",
      parameters: { type: "object", additionalProperties: false, required: ["destination", "body"],
        properties: { destination: identifierSchema(config.destinationIds, "操作者配置的接收位置名称"),
          body: { type: "string", maxLength: MAX_CONTENT, description: "要发送的正文，UTF-8 编码后不超过 256 KiB" } } } },
    { name: "yuanxingmu_status", operation: "describe", label: "查看资料权限",
      description: "查看这个配置绑定任务的实际资料权限。新建聊天和重新连接不会清除已经累积的限制。",
      parameters: { type: "object", properties: {}, additionalProperties: false } },
  ];
  if (config.reviewedMail) declarations.push({ name: "yuanxingmu_prepare_email", operation: "draft_email", label: "起草待核对邮件",
    description: "将一封纯文本邮件交给元星木工作台供用户核对。此工具不会发送邮件；必须由用户在工作台亲自确认。不能传入发件账户、密码、批准标记或额外收件人。",
    parameters: { type: "object", additionalProperties: false, required: ["recipient", "subject", "body"], properties: {
      recipient: {type:"string", maxLength:254, description:"一个明确的收件邮箱，不含姓名、抄送或列表"},
      subject: {type:"string", maxLength:200, description:"邮件主题"},
      body: {type:"string", maxLength:65536, description:"等待用户核对的完整纯文本正文"}
    } } });
  for (const declaration of declarations) {
    const { operation, ...descriptor } = declaration;
    api.registerTool((context) => {
      if (!isBoundContext(context, config)) return null;
      return { ...descriptor,
        async execute(_toolCallId, args, signal) {
          if (!isBoundContext(context, config)) {
            return toolResult(operation, { allowed: false, reason: "unbound_tool_context" });
          }
          if (operation === "draft_email" && (typeof _toolCallId !== "string" || !_toolCallId || _toolCallId.length > 1024)) {
            return toolResult(operation, {allowed:false, reason:"invalid_tool_call_id"});
          }
          const requestKey = operation === "draft_email" ? createHash("sha256").update(context.sessionKey + "\0" + _toolCallId).digest("hex") : null;
          const payload = payloadFor(operation, args, config, requestKey);
          if (!payload) return toolResult(operation, { allowed: false, reason: "invalid_tool_arguments" });
          if (signal?.aborted) return toolResult(operation, { allowed: false, reason: "cancelled_before_request" });
          try {
            const result = await requestSocket(config.brokerSocket, payload, { signal });
            if (typeof result.allowed !== "boolean") throw new Error("invalid_broker_response");
            return toolResult(operation, result);
          } catch {
            // A transport failure after dispatch does not prove non-delivery.
            return toolResult(operation, { allowed: null, reason: "broker_response_unavailable", outcome: "unknown" });
          }
        },
      };
    }, { name: declaration.name, optional: true });
  }
}
