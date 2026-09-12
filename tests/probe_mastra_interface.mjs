// Interface research only: no adapter, Broker, model or external effects.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { syncBuiltinESMExports } from 'node:module';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';

const sdkRoot = resolve(process.argv[2]);
const output = resolve(process.argv[3]);
if (existsSync(output)) throw new Error('Use a fresh evidence path');
const attempts = [];
const rejectNetwork = () => { attempts.push('network'); throw new Error('Interface probe forbids all network'); };
net.Socket.prototype.connect = rejectNetwork;
net.connect = net.createConnection = tls.connect = rejectNetwork;
http.request = http.get = https.request = https.get = rejectNetwork;
dns.lookup = dns.resolve = dns.promises.lookup = dns.promises.resolve = rejectNetwork;
globalThis.fetch = rejectNetwork;
syncBuiltinESMExports();

const root = join(sdkRoot, '@mastra/core');
const record = {
  scope: 'Actual installed SDK interface probe with caller-supplied synthetic contexts only',
  adapter_implemented: false, broker_connected: false, model_loop_run: false,
  trusted_native_identity_injection_validated: false, node: process.version, platform: process.platform,
  package: JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version,
  source_hashes: Object.fromEntries(['dist/tools/index.js', 'dist/tools/types.d.ts', 'dist/tool-CYfsCURf.js'].map(p =>
    [p, createHash('sha256').update(readFileSync(join(root, p))).digest('hex')])),
  observations: [], assertions: [], prohibited_network_attempts: attempts,
};
try {
  const { createTool, Tool, isValidationError } = await import(pathToFileURL(join(root, 'dist/tools/index.js')));
  const { z } = await import(pathToFileURL(join(sdkRoot, 'zod/index.js')));
  const calls = [];
  const tool = createTool({
    id: 'interface_only', description: 'Local interface probe without effects',
    inputSchema: z.strictObject({ value: z.string(), nested: z.strictObject({ note: z.string() }) }),
    resumeSchema: z.strictObject({ accepted: z.boolean() }),
    execute: async (input, context) => {
      const row = { input, agent_call_id: context.agent?.toolCallId ?? null,
        workflow_run_id: context.workflow?.runId ?? null };
      calls.push(row);
      return row;
    },
  });
  assert(tool instanceof Tool);
  record.assertions.push('real_sdk_tool');
  const valid = { value: 'synthetic', nested: { note: 'synthetic' } };
  const plain = await tool.execute(valid, {});
  assert.equal(plain.agent_call_id, null);
  record.assertions.push('direct_call_has_no_agent_identity');
  for (const args of [{ ...valid, socket_path: '/synthetic/forged.sock' },
    { ...valid, nested: { note: 'synthetic', approved: true } }]) {
    const before = calls.length;
    assert(isValidationError(await tool.execute(args, {})));
    assert.equal(calls.length, before);
  }
  record.assertions.push('normal_dispatch_rejects_extra_fields_before_callback');
  const agentContext = { agentId: 'fixture-agent', toolCallId: 'synthetic-caller-supplied-id', messages: [] };
  const organized = await tool.execute(valid, agentContext);
  assert.equal(organized.agent_call_id, agentContext.toolCallId);
  record.assertions.push('flat_context_is_organized_into_agent_context');
  const resumed = await tool.execute({ ...valid, socket_path: '/synthetic/extra.sock' },
    { agent: { ...agentContext, resumeData: { accepted: true } } });
  assert.equal(resumed.input.socket_path, '/synthetic/extra.sock');
  record.assertions.push('resume_context_skips_original_input_schema_validation');
  const workflow = await tool.execute(valid, { workflowId: 'fixture-workflow', runId: 'fixture-run' });
  assert.equal(workflow.agent_call_id, null);
  assert.equal(workflow.workflow_run_id, 'fixture-run');
  record.assertions.push('workflow_run_identity_is_not_agent_tool_call_identity');
  assert.deepEqual(attempts, []);
  record.observations = calls;
  record.status = 'interface_probe_passed';
} catch (error) {
  record.status = 'failed';
  record.error = { name: error.name, message: error.message };
  process.exitCode = 1;
} finally {
  writeFileSync(output, JSON.stringify(record, null, 2) + '\n', { flag: 'wx' });
  process.stdout.write(JSON.stringify({ status: record.status, assertions: record.assertions.length, output }) + '\n');
}
