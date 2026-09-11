'use strict';

const scenarios = {
  private: { request: '读过私密资料后，尝试公开外发', task: '任务未被撤销', scope: '私密状态已记录', family: '本任务与全部子任务', decision: '停止执行', destination: '公开目的地', note: '整个任务组受到私密状态约束', explanation: '一旦读取私密资料，本任务与全部子任务都不能向公开目的地发送。先前创建的子任务也在范围内。', blocked: true },
  authorized: { request: '将资料发送到受控内部目的地', task: '任务未被撤销', scope: '私密状态仍然保留', family: '整个任务组继续受限', decision: '允许执行', destination: '受控内部目的地', note: '符合任务允许的内部发送范围', explanation: '拒绝公开外发之后，授权范围内的内部发送仍能继续。独立的公开任务也可以正常发送。', blocked: false },
  reconnect: { request: '重连或恢复后，尝试公开外发', task: '恢复原来的任务', scope: '恢复后仍为私密状态', family: '原任务组限制继续生效', decision: '停止执行', destination: '公开目的地', note: '连接变化不清除资料状态', explanation: '状态保存在模型之外。换连接或重启执行服务恢复后，同一任务与子任务仍受到此前私密读取的约束。', blocked: true },
  revoked: { request: '显式撤销后，再使用旧工具调用', task: '授权已被明确撤销', scope: '原有资料状态仍保留', family: '撤销传递到关联子任务', decision: '停止执行', destination: '已撤销任务的操作请求', note: '重新连接不恢复已撤销的授权', explanation: '撤销由受信任的管理端发起，并传递到关联子任务。原型不会把任务自然结束或连接断开等同于显式撤销。', blocked: true },
};

const tabs = [...document.querySelectorAll('[data-scenario]')];
function selectScenario(key, moveFocus = false) {
  const scenario = scenarios[key];
  if (!scenario) return;
  const fields = { 'request-text': scenario.request, 'task-text': scenario.task, 'scope-text': scenario.scope, 'family-text': scenario.family, 'decision-text': scenario.decision, 'destination-text': scenario.destination, 'result-note': scenario.note, 'scenario-explanation': scenario.explanation };
  Object.entries(fields).forEach(([id, value]) => { document.getElementById(id).textContent = value; });
  document.getElementById('result-step').classList.toggle('is-blocked', scenario.blocked);
  document.getElementById('result-symbol').setAttribute('d', scenario.blocked ? 'm10 10 12 12M22 10 10 22' : 'm8 16 5 5 11-11');
  document.getElementById('scenario-panel').setAttribute('aria-labelledby', 'tab-' + key);
  tabs.forEach((tab) => {
    const selected = tab.dataset.scenario === key;
    tab.setAttribute('aria-selected', String(selected));
    tab.tabIndex = selected ? 0 : -1;
    if (selected && moveFocus) tab.focus();
  });
}
tabs.forEach((tab, index) => {
  tab.addEventListener('click', () => selectScenario(tab.dataset.scenario));
  tab.addEventListener('keydown', (event) => {
    let next;
    if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
    if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
    if (event.key === 'Home') next = 0;
    if (event.key === 'End') next = tabs.length - 1;
    if (next !== undefined) { event.preventDefault(); selectScenario(tabs[next].dataset.scenario, true); }
  });
});

const menuToggle = document.querySelector('.menu-toggle');
const navigation = document.getElementById('main-nav');
function closeMenu() { menuToggle.setAttribute('aria-expanded', 'false'); menuToggle.setAttribute('aria-label', '打开导航'); navigation.classList.remove('is-open'); }
menuToggle.addEventListener('click', () => {
  const open = menuToggle.getAttribute('aria-expanded') !== 'true';
  menuToggle.setAttribute('aria-expanded', String(open));
  menuToggle.setAttribute('aria-label', open ? '关闭导航' : '打开导航');
  navigation.classList.toggle('is-open', open);
});
navigation.querySelectorAll('a').forEach((link) => link.addEventListener('click', closeMenu));
document.addEventListener('keydown', (event) => { if (event.key === 'Escape' && menuToggle.getAttribute('aria-expanded') === 'true') { closeMenu(); menuToggle.focus(); } });

document.getElementById('copy-repo').addEventListener('click', async () => {
  const feedback = document.getElementById('copy-feedback');
  const url = 'https://github.com/yh-l20/agent-defense-check';
  try { await navigator.clipboard.writeText(url); feedback.textContent = '已复制公开仓库地址。'; }
  catch { feedback.textContent = url; }
});

// Research results are a separate, editable data file. Pending entries stay
// visibly pending. A result without a valid HTTPS evidence URL is not promoted.
const evidence = window.YUANXINGMU_EVIDENCE;
if (evidence && Array.isArray(evidence.checks)) {
  const container = document.getElementById('evidence-rows');
  const labels = { pending: '待公开核验', observed: '已观察', partial: '部分观察' };
  document.getElementById('evidence-revision').textContent = evidence.revisionLabel || '结果待发布';
  if (evidence.published === true) document.getElementById('report-scope').textContent = '这些观察来自本地合成数据与真实进程，未调用真实 LLM。具体版本、正常任务结果与限制见链接记录，不代表生产环境中的防御率。';
  const fragment = document.createDocumentFragment();
  evidence.checks.forEach((check) => {
    let sourceUrl;
    try { const parsed = new URL(check.sourceUrl); if (parsed.protocol === 'https:' && evidence.published === true) sourceUrl = parsed.href; } catch { /* Pending evidence has no external URL. */ }
    const status = sourceUrl && Object.hasOwn(labels, check.status) ? check.status : 'pending';
    const row = document.createElement('div'); row.className = 'evidence-row'; row.setAttribute('role', 'row');
    const title = document.createElement('span'); title.setAttribute('role', 'cell'); title.textContent = check.question;
    const outcome = document.createElement('span'); outcome.setAttribute('role', 'cell');
    const badge = document.createElement('b'); badge.className = 'evidence-status ' + status; badge.textContent = labels[status]; outcome.append(badge);
    const source = document.createElement('span'); source.className = 'evidence-source'; source.setAttribute('role', 'cell');
    if (sourceUrl) { const link = document.createElement('a'); link.href = sourceUrl; link.textContent = check.sourceLabel || '查看记录 ↗'; link.target = '_blank'; link.rel = 'noopener noreferrer'; source.append(link); }
    else source.textContent = '尚未发布';
    row.append(title, outcome, source); fragment.append(row);
  });
  container.replaceChildren(fragment);
}
