async page => {
  await page.getByRole('button', {name: '查看完整内容', exact: true}).click();
  return {time: Date.now(), text: (await page.locator('body').innerText()).slice(-14000)};
}
