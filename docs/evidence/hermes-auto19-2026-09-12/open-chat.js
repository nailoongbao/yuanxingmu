async page => {
  await page.getByRole('link', {name: 'Chat', exact: true}).click();
  await page.getByRole('textbox', {name: 'Terminal input'}).waitFor({state: 'visible', timeout: 20000});
  const side = page.getByRole('button', {name: 'Collapse chat side panel', exact: true});
  if (await side.isVisible()) await side.click();
  const nav = page.getByRole('button', {name: 'Collapse', exact: true});
  if (await nav.isVisible()) await nav.click();
  return {url: page.url(), text: (await page.locator('body').innerText()).slice(-14000)};
}
