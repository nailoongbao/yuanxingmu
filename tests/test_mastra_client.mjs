// Real Unix-socket transport checks for the standalone JavaScript client.
import assert from 'node:assert/strict';
import net from 'node:net';
import { mkdtemp, rmdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
const { NativeTools, MAX_MESSAGE } = await import(pathToFileURL(process.argv[2]));
const paths = new Set(), attempts = [], passed = [], failures = [];
const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (options, ...args) {
  if (!options || !paths.has(options.path) || options.port !== undefined) {
    attempts.push('unexpected_connection');
    throw new Error('Only fixture Unix sockets are permitted');
  }
  return connect.call(this, options, ...args);
};

async function fixture(handler, check, timeoutMs = 1000) {
  const directory = await mkdtemp(join(tmpdir(), 'yxm-mastra-client-'));
  const socketPath = join(directory, 'fixture.sock');
  const receipts = [], sockets = new Set();
  const server = net.createServer(socket => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    let data = '';
    socket.on('data', chunk => {
      data += chunk.toString('utf8');
      if (!data.endsWith('\n')) return;
      const request = JSON.parse(data);
      receipts.push(request);
      handler(socket, request);
    });
  });
  paths.add(socketPath);
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socketPath, resolve); });
  try { await check(new NativeTools({ socketPath, sessionId: 'fixed-host-session', timeoutMs }), receipts); }
  finally {
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
    paths.delete(socketPath);
    await rmdir(directory);
  }
}
const send = client => client.invoke('send', { destination: 'registered', body: 'synthetic' });
const accepted = socket => socket.end('{"allowed":true}\n');
const cases = {
  async invalid_configuration_and_identity_reject_before_connect() {
    assert.throws(() => new NativeTools({ socketPath: 'relative.sock', sessionId: 'fixed' }));
    assert.throws(() => new NativeTools({ socketPath: '/tmp/fixed.sock', sessionId: '' }));
    const client = new NativeTools({ socketPath: '/tmp/not-contacted.sock', sessionId: 'fixed' });
    await assert.rejects(client.invoke('draft_email', { draft: { recipient: 'x@example.test', subject: 's', body: 'b' } }),
      /native_tool_call_id_required/);
  },
  async fixed_socket_ignores_environment_and_returns_broker_status() {
    const saved = process.env.YUANXINGMU_BROKER_SOCKET;
    process.env.YUANXINGMU_BROKER_SOCKET = '/tmp/forged.sock';
    try {
      await fixture(accepted, async (client, receipts) => {
        assert.deepEqual(await send(client), { allowed: true });
        assert.equal(receipts.length, 1);
        assert.deepEqual(receipts[0], { op: 'send', destination: 'registered', body: 'synthetic' });
      });
    } finally {
      if (saved === undefined) delete process.env.YUANXINGMU_BROKER_SOCKET;
      else process.env.YUANXINGMU_BROKER_SOCKET = saved;
    }
  },
  async forged_fields_and_duplicate_form_fields_reject_before_connect() {
    await fixture(accepted, async (client, receipts) => {
      await assert.rejects(client.invoke('send', { destination: 'registered', body: 'synthetic', socket_path: '/tmp/forged.sock' }));
      await assert.rejects(client.invoke('propose_action', { proposal: { kind: 'form', target_id: 'form', payload: {
        fields: [{ name: 'note', value: 'a' }, { name: 'note', value: 'b' }],
      } } }, { source: 'host_invocation_nonce', value: 'fixed-call' }), /duplicate_form_field/);
      assert.equal(receipts.length, 0);
    });
  },
  async uncertain_response_is_never_retried() {
    await fixture(socket => socket.end(), async (client, receipts) => {
      await assert.rejects(send(client), /broker_response_missing_or_too_large/);
      assert.equal(receipts.length, 1);
    });
  },
  async missing_newline_is_rejected() {
    await fixture(socket => socket.end('{"allowed":true}'), async (client, receipts) => {
      await assert.rejects(send(client), /broker_response_missing_or_too_large/);
      assert.equal(receipts.length, 1);
    });
  },
  async oversized_response_is_rejected() {
    await fixture(socket => socket.end(Buffer.alloc(MAX_MESSAGE + 1, 120)), async client => {
      await assert.rejects(send(client), /broker_response_missing_or_too_large/);
    });
  },
  async invalid_utf8_is_rejected() {
    await fixture(socket => socket.end(Buffer.from([0xff, 0x0a])), async client => {
      await assert.rejects(send(client));
    });
  },
  async partial_response_timeout_is_never_retried() {
    await fixture(socket => socket.write('{"allowed":'), async (client, receipts) => {
      await assert.rejects(send(client), /broker_socket_timeout/);
      assert.equal(receipts.length, 1);
    }, 150);
  },
  async oversized_request_rejects_before_connect() {
    await fixture(accepted, async (client, receipts) => {
      await assert.rejects(client.invoke('send', { destination: 'registered', body: 'x'.repeat(MAX_MESSAGE) }), /request_too_large/);
      assert.equal(receipts.length, 0);
    });
  },
  async form_field_names_remain_own_data_properties() {
    await fixture(accepted, async (client, receipts) => {
      await client.invoke('propose_action', { proposal: { kind: 'form', target_id: 'registered', payload: {
        fields: [{ name: '__proto__', value: 'synthetic' }],
      } } }, { source: 'host_invocation_nonce', value: 'fixed-call' });
      assert.equal(receipts[0].proposal.payload.fields.__proto__, 'synthetic');
      assert(Object.hasOwn(receipts[0].proposal.payload.fields, '__proto__'));
    });
  },
};
for (const [name, check] of Object.entries(cases)) {
  try { await check(); passed.push(name); }
  catch (error) { failures.push({ name, error: error.message }); }
}
const result = { scope: 'Standalone JS client validation and actual fixture Unix transport', passed, failures,
  unexpected_network_attempts: attempts, model_loop_run: false };
process.stdout.write(JSON.stringify(result) + '\n');
if (failures.length || attempts.length) process.exitCode = 1;
