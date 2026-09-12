async page => {
  const target = {"id": "intake", "kind": "form", "label": "合成报价表", "url": "http://127.0.0.1:18976/receive/intake", "provider": "standard", "form_fields": ["project", "public_quote"]};
  const panel=page.locator('#action-target-settings details');
  if (!(await panel.getAttribute('open') !== null)) await panel.locator('summary').click();
  await page.getByRole('button',{name:'添加操作对象',exact:true}).click();
  await page.locator('#targets-kind').selectOption(target.kind);
  await page.locator('#targets-label').fill(target.label);
  await page.locator('#targets-id').fill(target.id);
  if(target.kind==='message') await page.locator('#targets-provider').selectOption('standard');
  await page.locator('#targets-url').fill(target.url);
  if(target.kind==='form') await page.locator('#targets-form-fields').fill(target.form_fields.join('\n'));
  const responsePromise=page.waitForResponse(r=>r.request().method()==='POST'&&r.url().endsWith('/api/action-targets'),{timeout:20000});
  await page.locator('#targets-save').click();
  const response=await responsePromise;
  const result=await response.json();
  await page.locator('#targets-list').getByRole('heading',{name:target.label,exact:true}).waitFor({state:'visible',timeout:20000});
  return {savedAt:Date.now(),target_id:target.id,status:response.status(),request:response.request().postDataJSON(),result};
}
