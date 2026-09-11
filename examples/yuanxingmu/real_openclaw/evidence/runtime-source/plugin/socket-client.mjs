/** Bounded local IPC; only host-selected endpoints enter this function. */
import { connect } from "node:net";

export const MAX_MESSAGE = 1024 * 1024;

export function requestSocket(socketPath, payload, { signal, timeoutMs = 15000 } = {}) {
  const encoded = Buffer.from(JSON.stringify(payload) + "\n", "utf8");
  if (encoded.length > MAX_MESSAGE) return Promise.reject(new Error("request_too_large"));
  if (signal?.aborted) return Promise.reject(new Error("request_aborted"));
  return new Promise((resolve, reject) => {
    const client = connect({ path: socketPath });
    let chunks = [], size = 0, settled = false;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", aborted);
      client.destroy();
      if (error) reject(error);
      else resolve(result);
    };
    const aborted = () => finish(new Error("request_aborted"));
    const timer = setTimeout(() => finish(new Error("broker_timeout")), timeoutMs);
    signal?.addEventListener("abort", aborted, { once: true });
    if (signal?.aborted) { aborted(); return; }
    client.once("connect", () => client.write(encoded));
    client.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_MESSAGE) { finish(new Error("broker_response_too_large")); return; }
      chunks.push(chunk);
      const data = Buffer.concat(chunks, size);
      const newline = data.indexOf(10);
      if (newline < 0) return;
      try {
        if (data.subarray(newline + 1).toString("utf8").trim()) throw new Error("extra_response_data");
        const result = JSON.parse(data.subarray(0, newline).toString("utf8"));
        if (!result || typeof result !== "object" || Array.isArray(result)) throw new Error("invalid_response_object");
        finish(null, result);
      } catch {
        finish(new Error("invalid_broker_response"));
      }
    });
    client.once("error", () => finish(new Error("broker_transport_error")));
    client.once("end", () => finish(new Error("broker_response_incomplete")));
  });
}
