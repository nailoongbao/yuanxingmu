async page => ({time: Date.now(), text: (await page.getByRole('dialog').innerText()).slice(0, 8500)})
