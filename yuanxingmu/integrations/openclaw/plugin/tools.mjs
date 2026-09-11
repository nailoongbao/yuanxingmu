/** Native tools bind one persistent task through its fixed host socket. */
import { isBoundContext } from "./config.mjs";
import { requestSocket } from "./socket-client.mjs";

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
  return operation === "read" ? "权限服务已返回资料。" : "以下为当前任务的实际权限状态。";
}

function toolResult(operation, result) {
  return { content: [{ type: "text", text: resultMessage(operation, result) + "\n" + JSON.stringify(result) }], details: result };
}

function payloadFor(operation, args, config) {
  if (operation === "describe") return exactKeys(args, []) ? { op: "describe" } : null;
  if (operation === "read") {
    return exactKeys(args, ["resource"]) && typeof args.resource === "string" && config.resourceIds.includes(args.resource)
      ? { op: "read", resource: args.resource } : null;
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
  for (const declaration of declarations) {
    const { operation, ...descriptor } = declaration;
    api.registerTool((context) => {
      if (!isBoundContext(context, config)) return null;
      return { ...descriptor,
        async execute(_toolCallId, args, signal) {
          if (!isBoundContext(context, config)) {
            return toolResult(operation, { allowed: false, reason: "unbound_tool_context" });
          }
          const payload = payloadFor(operation, args, config);
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
