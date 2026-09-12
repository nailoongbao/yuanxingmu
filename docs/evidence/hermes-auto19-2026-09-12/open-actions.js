async page => {
  const dialogs=page.getByRole('dialog');
  if(await dialogs.isVisible()) await dialogs.getByRole('button',{name:'关闭',exact:true}).click();
  const card=page.getByRole('article').filter({has:page.getByRole('heading',{name:"Hermes AUTO19 · 隐藏字段后自动处理",exact:true})});
  await card.getByRole('button',{name:"核对操作",exact:true}).click();
  await page.getByRole('dialog').waitFor({state:'visible',timeout:20000});
  return {openedAt:Date.now(),text:await page.getByRole('dialog').innerText()};
}
