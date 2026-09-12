"""Build genuine UI actions from the frozen protocol, without running any action."""
import json
from pathlib import Path

BUNDLE = Path(__file__).resolve().parent
protocol = json.loads((BUNDLE / 'protocol.json').read_text(encoding='utf-8'))
def save(name, text):
    with (BUNDLE / name).open('x', encoding='utf-8') as out:
        out.write(text + '\n')
save('observer-start.js', '''async page => {
  if (page.__auto19Audit) throw new Error('observer_already_started');
  page.__auto19Audit = [];
  page.on('request', request => {
    if (request.method() !== 'POST' || !request.url().startsWith('http://127.0.0.1:18975/api/')) return;
    let body = null; try {body = request.postDataJSON();} catch {}
    page.__auto19Audit.push({at: Date.now(), method: request.method(), path: request.url().replace('http://127.0.0.1:18975',''), body});
  });
  return {observing: true, time: Date.now()};
}''')
save('observer-read.js', '''async page => ({time:Date.now(), requests:page.__auto19Audit || null})''')
for target in protocol['targets']:
    save('register-' + target['id'] + '.js', '''async page => {
  const target = ''' + json.dumps(target, ensure_ascii=False) + ''';
  const panel=page.locator('#action-target-settings details');
  if (!(await panel.getAttribute('open') !== null)) await panel.locator('summary').click();
  await page.getByRole('button',{name:'添加操作对象',exact:true}).click();
  await page.locator('#targets-kind').selectOption(target.kind);
  await page.locator('#targets-label').fill(target.label);
  await page.locator('#targets-id').fill(target.id);
  if(target.kind==='message') await page.locator('#targets-provider').selectOption('standard');
  await page.locator('#targets-url').fill(target.url);
  if(target.kind==='form') await page.locator('#targets-form-fields').fill(target.form_fields.join('\\n'));
  const responsePromise=page.waitForResponse(r=>r.request().method()==='POST'&&r.url().endsWith('/api/action-targets'),{timeout:20000});
  await page.locator('#targets-save').click();
  const response=await responsePromise;
  const result=await response.json();
  await page.locator('#targets-list').getByRole('heading',{name:target.label,exact:true}).waitFor({state:'visible',timeout:20000});
  return {savedAt:Date.now(),target_id:target.id,status:response.status(),request:response.request().postDataJSON(),result};
}''')
save('fill-create.js', '''async page => {
  const protocol = ''' + json.dumps(protocol, ensure_ascii=False) + ''';
  await page.locator('#framework').selectOption('hermes');
  await page.locator('#work-name').fill(protocol.profile_name);
  await page.locator('#work-objective').fill(protocol.objective);
  await page.getByText('防护设置与技能',{exact:true}).click();
  await page.locator('#create-skills input[type="checkbox"]').check();
  await page.locator('#model-url').fill(protocol.working_model.url);
  await page.locator('#model-id').fill(protocol.working_model.id);
  await page.getByText('用另一个模型做防护检查（可选）',{exact:true}).click();
  await page.locator('#separate-judge').check();
  await page.locator('#judge-url').fill(protocol.judge.url);
  await page.locator('#judge-model-id').fill(protocol.judge.id);
  await page.locator('#judge-timeout').fill(String(protocol.judge.timeout_seconds));
  await page.locator('#document-files').setInputFiles(''' + json.dumps([str(BUNDLE / d['file']) for d in protocol['documents']]) + ''');
  const names=page.locator('#document-list input[type="text"]');
  await names.nth(1).waitFor({state:'visible',timeout:10000});
  await names.nth(0).fill('quote');
  await names.nth(1).fill('supplier_note');
  await page.locator('#automation-refresh').click();
  await page.locator('#automation-enabled').check();
  for(const id of ['team','archive','intake']) await page.locator('input[data-automation-target="'+id+'"]').check();
  await page.locator('#automation-choices').scrollIntoViewIfNeeded();
  return {filledAt:Date.now(),name:await page.locator('#work-name').inputValue(),objective:await page.locator('#work-objective').inputValue(),
    selected:await page.locator('input[data-automation-target]').evaluateAll(es=>es.map(e=>({id:e.dataset.automationTarget,checked:e.checked}))),
    modelKeyEmpty:(await page.locator('#api-key').inputValue())==='',judgeKeyEmpty:(await page.locator('#judge-api-key').inputValue())===''};
}''')
save('create-ui.js', '''async page => {
  const responsePromise=page.waitForResponse(r=>r.request().method()==='POST'&&r.url().endsWith('/api/profiles'),{timeout:20000});
  await page.locator('#create-submit').click();
  const response=await responsePromise;
  const body=response.request().postDataJSON();
  if(body.api_key||body.judge?.api_key) throw new Error('unexpected_credential_in_create_receipt');
  return {clickedAt:Date.now(),status:response.status(),request:body,result:await response.json()};
}''')
name = json.dumps(protocol['profile_name'], ensure_ascii=False)
for file, button, endpoint in [('start-work.js','启动工作','start'),('stop-work.js','暂时关闭','stop')]:
    save(file, '''async page => {
  const dialogs=page.getByRole('dialog');
  if(await dialogs.isVisible()) await dialogs.getByRole('button',{name:'关闭',exact:true}).click();
  const card=page.getByRole('article').filter({has:page.getByRole('heading',{name:''' + name + ''',exact:true})});
  const responsePromise=page.waitForResponse(r=>r.request().method()==='POST'&&r.url().endsWith('/''' + endpoint + ''''),{timeout:20000});
  await card.getByRole('button',{name:''' + json.dumps(button, ensure_ascii=False) + ''',exact:true}).click();
  const response=await responsePromise;
  return {clickedAt:Date.now(),status:response.status(),result:await response.json()};
}''')
for file, button in [('open-protection.js','防护记录'),('open-actions.js','核对操作')]:
    save(file, '''async page => {
  const dialogs=page.getByRole('dialog');
  if(await dialogs.isVisible()) await dialogs.getByRole('button',{name:'关闭',exact:true}).click();
  const card=page.getByRole('article').filter({has:page.getByRole('heading',{name:''' + name + ''',exact:true})});
  await card.getByRole('button',{name:''' + json.dumps(button, ensure_ascii=False) + ''',exact:true}).click();
  await page.getByRole('dialog').waitFor({state:'visible',timeout:20000});
  return {openedAt:Date.now(),text:await page.getByRole('dialog').innerText()};
}''')
print(json.dumps({'helpers_created': True, 'actions_executed': 0}))
