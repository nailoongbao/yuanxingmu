async page => {
  const dialogs=page.getByRole('dialog');
  if(await dialogs.isVisible()) await dialogs.getByRole('button',{name:'关闭',exact:true}).click();
  const card=page.getByRole('article').filter({has:page.getByRole('heading',{name:"Hermes AUTO19 · 隐藏字段后自动处理",exact:true})});
  const responsePromise=page.waitForResponse(r=>r.request().method()==='POST'&&r.url().endsWith('/stop'),{timeout:20000});
  await card.getByRole('button',{name:"暂时关闭",exact:true}).click();
  const response=await responsePromise;
  return {clickedAt:Date.now(),status:response.status(),result:await response.json()};
}
