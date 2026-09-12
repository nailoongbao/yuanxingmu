// Run from the repository root with playwright-cli run-code --filename <this file>.
// This is a browser UI contract fixture. Real transports and file effects are
// independently tested by test_yuanxingmu_actions.py; no external service is used.
async (page) => {
  const passed = [];
  const check = (value, name) => { if (!value) throw Error(name); passed.push(name); };
  await page.route("**/*", route => route.abort());
  await page.setViewportSize({width: 1180, height: 900});
  await page.setContent('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>操作确认界面测试</title></head><body><main class="page-shell"><div id="fixture-controls"></div></main></body></html>');
  await page.addStyleTag({path: "yuanxingmu/dashboard/web/styles.css"});
  await page.addScriptTag({path: "yuanxingmu/dashboard/web/actions.js"});
  await page.evaluate(() => {
    const kinds = ["message", "upload", "form", "overwrite", "delete"];
    const targets = kinds.map((kind, i) => ({target_id: "target" + i, kind, label: ["已登记群聊", "文件接收位置", "报名表", "正式报告", "旧版备忘"][i],
      provider: "standard", form_fields: kind === "form" ? ["name", "note"] : [],
      destination: ["overwrite", "delete"].includes(kind) ? "/host-only/reviewed/report-" + i + ".txt" : "http://127.0.0.1:18080",
      binding_digest: "b".repeat(64)}));
    const payloads = [{body: "消息全文\n<img src=x onerror=window.fixtureXSS=true>"}, {filename: "report.txt", content: "上传全文\n金额 3200"},
      {fields: {name: "李同学", note: "确认报名，保留这段完整文字"}}, {content: "新的报告全文\n预算 3200"}, {}];
    const actions = kinds.map((kind, i) => ({id: String(i + 1).repeat(32), kind, target_id: targets[i].target_id, target_label: targets[i].label,
      digest: String(i + 1).repeat(64), revision: 1, status: "pending", attempt_id: null, created_at: "2026-09-12T00:00:00Z",
      updated_at: "2026-09-12T00:00:00Z", approved_at: null, finished_at: null, target: targets[i],
      proposal: {kind, target_id: targets[i].target_id, payload: payloads[i]},
      before: ["overwrite", "delete"].includes(kind) ? {content: "原有完整内容\n不能偷偷改动这一行", sha256: "a".repeat(64), bytes: 61} : null,
      result: null}));
    const fixture = window.actionsFixture = {actions, targets, calls: [], effects: {}, jobs: new Map(), keys: new Map(), serial: 0,
      authorized: true, loseResponse: false, dropBeforeAccept: false,
      profile: {id: "f".repeat(32), name: "操作确认测试工作", features: ["reviewed_actions_v1"], revoked: false, pending: null}};
    const copy = value => structuredClone(value);
    const api = async (path, options = {}) => {
      fixture.calls.push({path, options: copy(options)});
      const failure = (text, uncertain, status = 409) => { const error = Error(text); error.uncertain = uncertain; error.status = status; return error; };
      if (path.startsWith("/api/requests/")) {
        const id = fixture.keys.get(path.split("/").at(-1));
        if (!id) throw failure("暂时找不到这次提交", false, 404);
        return {job: copy(fixture.jobs.get(id))};
      }
      if (path.startsWith("/api/jobs/")) return {job: copy(fixture.jobs.get(path.split("/").at(-1)))};
      const match = path.match(/\/actions(?:\/([0-9a-f]{32}))?(?:\/(edit|cancel|commit))?$/);
      if (!match) throw failure("unexpected route", false, 404);
      if (!match[1]) return {supported: true, active: !fixture.profile.revoked,
        actions: copy(fixture.actions.map(({proposal, target, before, result, ...summary}) => summary)),
        targets: copy(fixture.targets.map(({destination, binding_digest, ...target}) => target))};
      const row = fixture.actions.find(action => action.id === match[1]);
      if (!row) throw failure("unknown action", false, 404);
      if (!match[2]) return {action: copy(row), active: !fixture.profile.revoked};
      if (options.method !== "POST") throw failure("post required", false);
      if (fixture.dropBeforeAccept) throw failure("连接断开，尚未取得结果", true);
      if (options.body.revision !== row.revision || options.body.digest !== row.digest) throw failure("内容已经改变，请重新核对", false);
      if (fixture.profile.revoked) throw failure("权限已收回", false);
      const op = match[2];
      if (op === "edit") {
        row.proposal = copy(options.body.proposal); row.target_id = row.proposal.target_id;
        row.target = copy(fixture.targets.find(target => target.target_id === row.target_id));
        row.target_label = row.target.label; row.revision += 1; row.digest = "d".repeat(64);
      } else if (op === "cancel") row.status = "cancelled";
      else {
        if (options.body.confirm !== "commit") throw failure("confirmation missing", false);
        row.status = "acknowledged"; row.attempt_id = "c".repeat(32);
        fixture.effects[row.id] = (fixture.effects[row.id] || 0) + 1;
      }
      const id = (++fixture.serial).toString(16).padStart(32, "0");
      const job = {id, status: "succeeded", result: {profile: copy(fixture.profile)}};
      fixture.jobs.set(id, job); fixture.keys.set(options.key, id);
      if (fixture.loseResponse) { fixture.loseResponse = false; throw failure("首次响应丢失", true); }
      return {job: copy(job)};
    };
    const node = (tag, className, text) => {
      const element = document.createElement(tag); element.className = className || "";
      if (text !== undefined) element.textContent = text; return element;
    };
    fixture.widget = window.createYuanxingmuActions({api, node, newKey: () => "e".repeat(28) + (++fixture.serial).toString(16).padStart(4, "0"),
      authorized: () => fixture.authorized, getProfile: () => fixture.profile,
      upsertProfile: value => { fixture.profile = value; }, refreshProfiles: async () => {}});
    fixture.widget.boot(); fixture.widget.boot();
    document.getElementById("fixture-controls").append(fixture.widget.profileButton(fixture.profile));
  });
  check(await page.locator("#actions-dialog").count() === 1, "boot is idempotent");
  await page.locator("body").ariaSnapshot();
  await page.getByRole("button", {name: "核对操作", exact: true}).click();
  await page.getByRole("button", {name: "查看完整内容"}).first().waitFor();
  await page.locator("body").ariaSnapshot();
  check(await page.getByRole("button", {name: "查看完整内容"}).count() === 5, "all five action kinds listed");

  for (const [index, expected] of [[1, "消息全文"], [2, "上传全文"], [3, "确认报名，保留这段完整文字"], [4, "新的报告全文"], [5, "原有完整内容"]]) {
    await page.locator('button[data-action-id="' + String(index).repeat(32) + '"]').click();
    await page.locator("#actions-dialog .mail-read").waitFor({state: "visible"});
    await page.locator("#actions-dialog").ariaSnapshot();
    check((await page.locator("#actions-dialog .mail-read").innerText()).includes(expected), "complete review content for kind " + index);
    check(await page.locator("#actions-commit").isDisabled(), "unchecked action " + index + " cannot commit");
    if (index === 1) check(await page.locator("img").count() === 0 && !(await page.evaluate(() => window.fixtureXSS)), "untrusted markup remains text");
    await page.getByRole("button", {name: "返回操作列表", exact: true}).click();
  }

  await page.locator('button[data-action-id="' + "1".repeat(32) + '"]').click();
  await page.getByRole("button", {name: "修改提案", exact: true}).click();
  await page.locator("#actions-dialog").ariaSnapshot();
  await page.getByLabel("消息全文", {exact: true}).fill("用户修改后的完整消息");
  await page.getByRole("button", {name: "保存修改", exact: true}).click();
  await page.getByText("修改已保存，请重新核对对象和保存后的全文。", {exact: true}).waitFor();
  check(!(await page.locator("#actions-reviewed").isChecked()) && await page.locator("#actions-commit").isDisabled(), "editing invalidates previous review");
  check((await page.locator("#actions-dialog .mail-read").innerText()).includes("用户修改后的完整消息"), "saved content shown before approval");
  await page.evaluate(() => { window.actionsFixture.loseResponse = true; });
  await page.locator("#actions-reviewed").check();
  await page.locator("#actions-commit").click();
  await page.locator("#actions-check-request").waitFor({state: "visible"});
  await page.locator("#actions-dialog").ariaSnapshot();
  check(await page.locator("#actions-commit").isHidden(), "lost response hides second commit");
  await page.locator("#actions-check-request").click();
  await page.locator("#actions-dialog .mail-detail-meta .status-badge").filter({hasText: "已完成提交"}).waitFor();
  const reconciled = await page.evaluate(() => ({effects: window.actionsFixture.effects,
    posts: window.actionsFixture.calls.filter(call => call.options.method === "POST" && call.path.endsWith("/commit")),
    lookups: window.actionsFixture.calls.filter(call => call.path.startsWith("/api/requests/"))}));
  check(reconciled.posts.length === 1 && reconciled.effects["1".repeat(32)] === 1, "lost acknowledgement executes once");
  check(reconciled.posts[0].options.noRetry === true && reconciled.lookups[0].path.endsWith(reconciled.posts[0].options.key), "read-only reconciliation uses original key");

  await page.getByRole("button", {name: "返回操作列表", exact: true}).click();
  await page.locator('button[data-action-id="' + "4".repeat(32) + '"]').click();
  await page.locator("#actions-reviewed").check();
  await page.evaluate(() => { const row = window.actionsFixture.actions[3]; row.revision += 1; row.digest = "9".repeat(64); });
  await page.locator("#actions-commit").click();
  await page.getByText("内容已经改变，请重新核对", {exact: true}).waitFor();
  check(!(await page.locator("#actions-reviewed").isChecked()) && await page.locator("#actions-commit").isDisabled(), "stale version reloads and requires review");
  check(!(await page.evaluate(() => window.actionsFixture.effects["4".repeat(32)])), "stale content has no effect");
  await page.evaluate(() => { window.actionsFixture.profile.revoked = true; window.actionsFixture.widget.updateControls(); });
  check(await page.locator("#actions-reviewed").isDisabled() && await page.locator("#actions-commit").isDisabled(), "revocation disables confirmation");
  await page.evaluate(() => { window.actionsFixture.profile.revoked = false; });
  await page.getByRole("button", {name: "重新读取完整内容", exact: true}).click();
  await page.locator("#actions-reviewed").check();
  await page.locator("#actions-commit").click();
  await page.locator("#actions-dialog .mail-detail-meta .status-badge").filter({hasText: "已完成提交"}).waitFor();
  check(await page.evaluate(() => window.actionsFixture.effects["4".repeat(32)] === 1), "freshly reviewed file action executes once");

  await page.getByRole("button", {name: "返回操作列表", exact: true}).click();
  await page.locator('button[data-action-id="' + "2".repeat(32) + '"]').click();
  await page.evaluate(() => { window.actionsFixture.dropBeforeAccept = true; });
  await page.locator("#actions-reviewed").check();
  await page.locator("#actions-commit").click();
  await page.locator("#actions-check-request").waitFor({state: "visible"});
  await page.locator("#actions-check-request").click();
  await page.getByText("暂时找不到这次提交 只会查询这一次提交，不会重新执行。", {exact: true}).waitFor();
  const unresolved = await page.evaluate(() => window.actionsFixture.calls.filter(call => call.options.method === "POST" && call.path.includes("2".repeat(32))));
  check(unresolved.length === 1 && await page.locator("#actions-commit").isHidden(), "missing job lookup does not resubmit");

  await page.getByRole("button", {name: "返回操作列表", exact: true}).click();
  await page.locator('button[data-action-id="' + "5".repeat(32) + '"]').click();
  await page.setViewportSize({width: 390, height: 844});
  await page.locator("#actions-dialog").ariaSnapshot();
  check(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), "mobile review has no horizontal overflow");
  await page.screenshot({path: "../output/playwright/actions-v1/delete-mobile.png", fullPage: true});
  await page.setViewportSize({width: 1180, height: 900});
  await page.screenshot({path: "../output/playwright/actions-v1/delete-desktop.png", fullPage: true});
  await page.evaluate(() => {
    window.actionsFixture.widget.reset(); window.actionsFixture.actions = []; window.actionsFixture.targets = [];
    window.actionsFixture.dropBeforeAccept = false;
  });
  await page.getByRole("button", {name: "核对操作", exact: true}).click();
  await page.getByText("尚未登记操作对象", {exact: true}).waitFor();
  check(await page.getByText("尚未登记操作对象", {exact: true}).isVisible(), "empty configuration makes no service connection claim");
  await page.evaluate(() => { window.actionsFixture.authorized = false; window.actionsFixture.widget.reset(); });
  check(await page.locator("#actions-dialog .mail-read").innerText() === "", "reset clears private review content");
  return {scope: "browser UI fixture; transports and file effects verified separately", passed, total: passed.length};
}
