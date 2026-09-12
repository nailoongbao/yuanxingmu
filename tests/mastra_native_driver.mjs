// Test-only host for real Mastra tools. Contexts are supplied by this fixture;
// it never runs Agent.generate/stream or claims framework identity injection.
import { pathToFileURL } from 'node:url';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { createInterface } from 'node:readline';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';

const [adapterPath, socketPath, sessionId] = process.argv.slice(2);
const attempts = [], connections = [], modelAttempts = [];
const denied = () => { attempts.push('network'); throw new Error('Native fixture prohibits external connections'); };
const originalConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (options, ...args) {
  if (!options || typeof options !== 'object' || options.path !== socketPath || options.port !== undefined) return denied();
  connections.push('broker_unix_socket');
  return originalConnect.call(this, options, ...args);
};
tls.connect = http.request = http.get = https.request = https.get = denied;
dns.lookup = dns.resolve = dns.promises.lookup = dns.promises.resolve = denied;
globalThis.fetch = denied;
syncBuiltinESMExports();

const require = createRequire(adapterPath);
const esm = specifier => pathToFileURL(require.resolve(specifier).replace(/\.cjs$/, '.js'));
const { z } = await import(esm('zod'));
const { Tool, isValidationError } = await import(esm('@mastra/core/tools'));
const { Agent } = await import(esm('@mastra/core/agent'));
const { NativeTools, HostInvocations, buildTools } = await import(pathToFileURL(adapterPath));
const invocations = new HostInvocations();
const client = new NativeTools({ socketPath, sessionId });
const tools = buildTools(client, { invocations });
if (!tools.every(tool => tool instanceof Tool)) throw new Error('Expected native Mastra Tool objects');
const model = {
  specificationVersion: 'v2', provider: 'fixture', modelId: 'never-run', supportedUrls: {},
  doGenerate: async () => { modelAttempts.push('generate'); throw new Error('No model runs in native tool tests'); },
  doStream: async () => { modelAttempts.push('stream'); throw new Error('No model runs in native tool tests'); },
};
const agent = new Agent({ id: 'native-tools-only', name: 'Native registration only', instructions: 'Local fixture',
  model, tools: Object.fromEntries(tools.map(tool => [tool.id, tool])) });
const registered = await agent.listTools();
if (!tools.every(tool => registered[tool.id] === tool)) throw new Error('Native Agent registration changed tools');
const reply = value => process.stdout.write(JSON.stringify(value) + '\n');
reply({ id: 0, ready: true, native_registration: agent.constructor.name,
  native_tools: tools.map(tool => ({ name: tool.id, class: '@mastra/core.' + tool.constructor.name })),
  schemas: Object.fromEntries(tools.map(tool => [tool.id, z.toJSONSchema(tool.inputSchema)])) });

async function execute(request) {
  if (request.command === 'shutdown') return { shutdown: true };
  if (request.command === 'request_key') return client.requestKey(request.operation, request.identity);
  if (request.command === 'scope_check') {
    const rows = [];
    await invocations.run('outer', async () => {
      try { await invocations.run('inner', async () => { rows.push(invocations.current()); throw new Error('fixture'); }); }
      catch (error) { if (error.message !== 'fixture') throw error; }
      rows.push(invocations.current());
    });
    rows.push(invocations.current() ?? null);
    return rows;
  }
  if (request.command === 'native_agent_dispatch') {
    const executionTools = await agent.getToolsForExecution({ runId: 'fixture-run' });
    return await executionTools['yuanxingmu_' + request.operation].execute(request.arguments,
      { toolCallId: request.call_id, messages: [] });
  }
  const tool = registered['yuanxingmu_' + request.operation];
  if (!tool) throw new Error('unknown_native_tool');
  let context = {};
  if (request.mode === 'agent' && request.call_id !== null) context.agent = {
    agentId: 'fixture-agent', toolCallId: request.call_id, messages: [],
  };
  if (request.mode === 'workflow') context.workflow = { workflowId: 'fixture-workflow', runId: 'same-run' };
  if (request.resume) context.agent = { ...context.agent, resumeData: { fixture: true } };
  if (request.aborted) { const controller = new AbortController(); controller.abort(); context.abortSignal = controller.signal; }
  const call = () => tool.execute(request.arguments, context);
  const result = request.mode !== 'agent' && request.call_id !== null
    ? await invocations.run(request.call_id, call) : await call();
  if (isValidationError(result)) throw new Error('native_schema_rejected');
  return result;
}

const input = createInterface({ input: process.stdin });
input.on('line', line => {
  const request = JSON.parse(line);
  void (async () => {
    try { reply({ id: request.id, result: await execute(request), attempts, connections, model_attempts: modelAttempts }); }
    catch (error) { reply({ id: request.id, error: { name: error.name, message: error.message }, attempts, connections, model_attempts: modelAttempts }); }
  })();
});
