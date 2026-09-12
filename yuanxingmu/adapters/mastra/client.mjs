/** Fixed Unix Broker client. This object is not a process isolation boundary. */
import { createHash } from 'node:crypto';
import { Socket } from 'node:net';
import { isAbsolute } from 'node:path';
import { z } from 'zod';

const closed = z.strictObject;
const text = z.string();
const empty = closed({});
const proposal = (kind, payload) => closed({ kind: z.literal(kind), target_id: text, payload });
export const SCHEMAS = Object.freeze({
  read: closed({ resource: text }), send: closed({ destination: text, body: text }),
  describe: empty, action_targets: empty,
  propose_action: closed({ proposal: z.discriminatedUnion('kind', [
    proposal('message', closed({ body: text })),
    proposal('upload', closed({ filename: text, content: text })),
    proposal('form', closed({ fields: z.array(closed({ name: text, value: text })).max(64) })),
    proposal('overwrite', closed({ content: text })), proposal('delete', empty),
  ]) }),
  draft_email: closed({ draft: closed({ recipient: text, subject: text, body: text }) }),
});
export const OPERATIONS = Object.freeze(Object.keys(SCHEMAS));
export const MAX_MESSAGE = 1024 * 1024;
const proposals = new Set(['propose_action', 'draft_email']);
const count = value => [...value].length;
const canonical = value => JSON.stringify(value).replace(/[\u007f-\uffff]/g,
  char => '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0'));

export class NativeTools {
  constructor({ socketPath, sessionId, timeoutMs = 15000 }) {
    if (typeof socketPath !== 'string' || !isAbsolute(socketPath) || socketPath.includes('\0'))
      throw new Error('native_tools_require_absolute_socket');
    if (typeof sessionId !== 'string' || !sessionId || count(sessionId) > 256)
      throw new Error('native_tools_require_host_session');
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 120000)
      throw new Error('invalid_socket_timeout');
    this.socketPath = socketPath;
    this.sessionId = sessionId;
    this.timeoutMs = timeoutMs;
    Object.freeze(this);
  }

  requestKey(operation, identity) {
    if (!proposals.has(operation)) throw new Error('invalid_native_proposal_context');
    if (!identity || !['agent_tool_call_id', 'host_invocation_nonce'].includes(identity.source)
      || typeof identity.value !== 'string' || !identity.value || count(identity.value) > 512)
      throw new Error('native_tool_call_id_required');
    // Native Agent IDs and host dispatch nonces have different namespaces.
    const binding = ['yuanxingmu-mastra-v1', this.sessionId, operation, identity.source, identity.value];
    return 'mastra_v1_' + createHash('sha256').update(canonical(binding)).digest('hex');
  }

  async invoke(operation, arguments_, identity) {
    if (!Object.hasOwn(SCHEMAS, operation)) throw new Error('invalid_native_operation');
    const fields = SCHEMAS[operation].parse(arguments_);
    if (operation === 'propose_action' && fields.proposal.kind === 'form') {
      const submitted = Object.create(null);
      for (const { name, value } of fields.proposal.payload.fields) {
        if (Object.hasOwn(submitted, name)) throw new Error('duplicate_form_field');
        submitted[name] = value;
      }
      fields.proposal.payload.fields = submitted;
    }
    if (proposals.has(operation)) fields.request_key = this.requestKey(operation, identity);
    const payload = Buffer.from(JSON.stringify({ op: operation, ...fields }) + '\n');
    if (payload.length > MAX_MESSAGE) throw new Error('request_too_large');
    // One connection and one request only. Uncertain outcomes are never retried.
    return await new Promise((resolve, reject) => {
      const connection = new Socket();
      let received = Buffer.alloc(0);
      let settled = false;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        connection.destroy();
        if (error) reject(error); else resolve(value);
      };
      connection.setTimeout(this.timeoutMs);
      connection.once('timeout', () => finish(new Error('broker_socket_timeout')));
      connection.once('error', error => finish(error));
      connection.once('end', () => finish(new Error('broker_response_missing_or_too_large')));
      connection.once('close', () => finish(new Error('broker_response_missing_or_too_large')));
      connection.on('data', chunk => {
        received = Buffer.concat([received, chunk]);
        const newline = received.indexOf(10);
        if ((newline < 0 && received.length > MAX_MESSAGE) || newline + 1 > MAX_MESSAGE) {
          finish(new Error('broker_response_missing_or_too_large'));
          return;
        }
        if (newline < 0) return;
        try {
          const result = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(received.subarray(0, newline)));
          if (!result || Array.isArray(result) || typeof result !== 'object') throw new Error('invalid_broker_response');
          finish(null, result);
        } catch (error) { finish(error); }
      });
      try { connection.connect({ path: this.socketPath }, () => connection.write(payload)); }
      catch (error) { finish(error); }
    });
  }
}
