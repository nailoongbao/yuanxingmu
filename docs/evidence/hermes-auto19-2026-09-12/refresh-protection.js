async page => {
  await page.getByRole('button', {name: '刷新记录', exact: true}).click();
  return {refreshedAt: Date.now()};
}
