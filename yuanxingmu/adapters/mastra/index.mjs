/** Native Mastra tools; only these six registered operations reach this Broker. */
import { AsyncLocalStorage } from 'node:async_hooks';
import { createTool } from '@mastra/core/tools';
import { NativeTools, OPERATIONS, SCHEMAS } from './client.mjs';
export { NativeTools } from './client.mjs';

export class HostInvocations {
  #storage = new AsyncLocalStorage();
  run(nonce, callback) {
    if (typeof nonce !== 'string' || !nonce || [...nonce].length > 512)
      throw new Error('host_invocation_nonce_required');
    if (typeof callback !== 'function') throw new TypeError('host_dispatch_callback_required');
    return this.#storage.run(nonce, callback);
  }
  current() { return this.#storage.getStore(); }
}

const descriptions = {
  read: 'Read one host-registered resource; its data restrictions remain attached to this task.',
  send: 'Send text immediately to a host-registered destination if the Broker permits it. Do not retry an uncertain result; sends are not deduplicated.',
  describe: 'Inspect this Broker task permissions and data restrictions.',
  action_targets: 'List host-registered targets available for reviewed action proposals.',
  propose_action: 'Save an action proposal for separate host review. This tool cannot approve or execute it. Repeated calls return the existing proposal and status.',
  draft_email: 'Save an email draft for separate host review. This tool cannot approve or send it. Repeated calls return the existing draft and status.',
};

export function buildTools(client, { invocations = new HostInvocations() } = {}) {
  if (!(client instanceof NativeTools)) throw new TypeError('native_tools_required');
  if (!(invocations instanceof HostInvocations)) throw new TypeError('host_invocations_required');
  return OPERATIONS.map(operation => createTool({
    id: 'yuanxingmu_' + operation, description: descriptions[operation], inputSchema: SCHEMAS[operation],
    execute: async (arguments_, context) => {
      if (context?.abortSignal?.aborted) throw new Error('native_dispatch_already_aborted');
      // Mastra skips its inputSchema validation when resuming. Always validate
      // here as well, including nested objects and resumed input.
      const argumentsCopy = SCHEMAS[operation].parse(arguments_);
      const nativeId = context?.agent?.toolCallId;
      const identity = nativeId !== undefined && nativeId !== null
        ? { source: 'agent_tool_call_id', value: nativeId }
        : { source: 'host_invocation_nonce', value: invocations.current() };
      return await client.invoke(operation, argumentsCopy, identity);
    },
  }));
}
