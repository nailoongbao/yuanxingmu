async page => {
  const responsePromise=page.waitForResponse(r=>r.request().method()==='POST'&&r.url().endsWith('/api/profiles'),{timeout:20000});
  await page.locator('#create-submit').click();
  const response=await responsePromise;
  const body=response.request().postDataJSON();
  if(body.api_key||body.judge?.api_key) throw new Error('unexpected_credential_in_create_receipt');
  return {clickedAt:Date.now(),status:response.status(),request:body,result:await response.json()};
}
