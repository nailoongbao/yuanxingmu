/** Demo-only wrapper around the unchanged native sandbox provider. */
import { connect } from 'node:net';
import { readFileSync, appendFileSync } from 'node:fs';
import { buildJsonPluginConfigSchema, definePluginEntry } from 'openclaw/plugin-sdk/plugin-entry';
import sandboxPlugin from './sandbox-entry.mjs';

const manifest = JSON.parse(readFileSync(new URL('./openclaw.plugin.json', import.meta.url), 'utf8'));

function revokeCurrentTask(socketPath) {
  return new Promise((resolve, reject) => {
    const client = connect({ path: socketPath });
    let data = '';
    client.setTimeout(5000);
    client.once('connect', () => client.write('{"op":"revoke"}\n'));
    client.on('data', (chunk) => {
      data += chunk.toString('utf8');
      if (data.length > 65536) {
        client.destroy(new Error('operator response too large'));
      } else if (data.includes('\n')) {
        client.end();
        try { resolve(JSON.parse(data.slice(0, data.indexOf('\n')))); }
        catch (error) { reject(error); }
      }
    });
    client.once('timeout', () => client.destroy(new Error('operator timeout')));
    client.once('error', reject);
    client.once('end', () => { if (!data.includes('\n')) reject(new Error('operator response incomplete')); });
  });
}

export default definePluginEntry({
  id: manifest.id,
  name: manifest.name,
  description: manifest.description,
  configSchema: buildJsonPluginConfigSchema(manifest.configSchema),
  register(api) {
    sandboxPlugin.register(api);
    if (api.registrationMode !== 'full') return;
    // No command arguments, model-generated URLs, credentials or task IDs.
    // This host-only Unix socket is absent from every worker mount.
    const operatorSocket = api.pluginConfig.operatorSocket;
    api.registerCommand({
      name: 'yuanxingmu-stop',
      description: '撤销当前元星木演示任务的权限',
      acceptsArgs: false,
      requireAuth: true,
      requiredScopes: ['operator.admin'],
      async handler(ctx) {
        if (!ctx.isAuthorizedSender || !ctx.gatewayClientScopes?.includes('operator.admin')) {
          return { text: '此操作仅限已经认证的演示管理者。' };
        }
        if (ctx.args?.trim()) return { text: '这个命令不接受参数，只能撤销当前演示任务。' };
        try {
          const result = await revokeCurrentTask(operatorSocket);
          appendFileSync(api.pluginConfig.auditPath, JSON.stringify({time: new Date().toISOString(),
            event: 'authenticated_user_revocation', sessionKey: ctx.sessionKey,
            authorizedSender: ctx.isAuthorizedSender, scopes: ctx.gatewayClientScopes, result}) + '\n');
          if (result.operator_action !== 'revoke' || result.task?.active !== false || result.task?.revoked !== true) {
            return { text: '权限服务没有确认撤销完成，请查看实际运行记录。' };
          }
          const counts = result.receiver_counts;
          const receiptText = counts ? `\n\n接收结果：公共测试箱 ${counts.public} 条，内部测试箱 ${counts.internal} 条。` : '';
          return { text: '已按你的指令撤销当前任务的权限。\n\n可以继续输入“改发到内部测试箱”，确认原有任务也无法再发送。' + receiptText };
        } catch {
          return { text: '权限服务未返回可核对的确认，本次不报告撤销成功。' };
        }
      },
    });
  },
});
