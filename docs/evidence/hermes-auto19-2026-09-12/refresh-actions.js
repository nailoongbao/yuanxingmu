async page => {
  await page.getByRole('button', {name: '刷新操作', exact: true}).click();
  return {refreshedAt: Date.now()};
}
