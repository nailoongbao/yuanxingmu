// Read-only real-browser fixture for automatic versus individual action authorization.
// No native Agent, model, receiver, or file effect is called.
async (page) => {
  const passed = [];
  const check = (value, name) => { if (!value) throw Error(name); passed.push(name); };
  await page.unroute("**/*");
  await page.route("**/*", route => route.abort());
  await page.route("http://127.0.0.1:29670/automatic-records", route => route.fulfill({contentType: "text/html",
    body: '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>自动操作记录测试</title></head><body><main class="wrap"><div id="fixture-controls"></div></main></body></html>'}));
  await page.goto("http://127.0.0.1:29670/automatic-records");
  await page.setViewportSize({width: 1180, height: 940});
  await page.addStyleTag({path: "yuanxingmu/dashboard/web/styles.css"});
  await page.addScriptTag({path: "yuanxingmu/dashboard/web/actions.js"});
  await page.evaluate(() => {
    const scenarios = [["message", "acknowledged"], ["upload", "acknowledged"], ["form", "acknowledged"],
      ["message", "unconfirmed"], ["message", "not_started"], ["message", "executing"],
      ["message", "acknowledged"], ["message", "acknowledged"], ["message", "pending"]];
    const actions = scenarios.map(([kind, status], index) => {
      const id = (index + 1).toString(16).repeat(32);
      const target = {target_id: "target" + index, kind, label: ["项目协作群", "项目资料库", "活动报名表"][index] || "固定协作对象",
        destination: "https://receiver.example.test/SECRET-ACTION-PATH?key=SECRET-QUERY",
        form_fields: kind === "form" ? ["name", "note"] : [], headers: {Authorization: "SECRET-HEADER"}};
      const payload = kind === "upload" ? {filename: "report.txt", content: "需要提交的完整报告"}
        : kind === "form" ? {fields: {name: "李同学", note: "完整报名信息"}} : {body: "授权范围内的消息全文"};
      const automatic = index < 6;
      return {id, kind, status, target_id: target.target_id, target_label: target.label, revision: 1,
        digest: "d".repeat(64), target, proposal: {kind, target_id: target.target_id, payload}, before: null,
        attempt_id: status === "pending" ? null : "e".repeat(32), approved_at: index === 6 ? "2026-09-12T00:02:00Z" : null,
        authorized_at: automatic || index === 6 ? "2026-09-12T00:02:00Z" : null,
        execution_mode: automatic ? "automatic" : index === 6 ? "manual" : null,
        authorization_source: automatic ? "frozen_task_scope" : index === 6 ? "host_confirmation" : null,
        authorization_sha256: automatic ? "f".repeat(64) : null};
    });
    const fixture = window.automaticRecordsFixture = {actions, calls: [], authorized: true,
      profile: {id: "a".repeat(32), name: "一次授权的工作", features: ["reviewed_actions_v1"], revoked: false, pending: null}};
    const api = async (path, options = {}) => {
      fixture.calls.push({path, method: options.method || "GET"});
      if (options.method === "POST") throw Error("This fixture is read-only");
      const match = path.match(/\/actions(?:\/([a-f0-9]{32}))?$/);
      if (!match) throw Error("Unexpected fixture route");
      if (!match[1]) return {supported: true, active: true, targets: actions.map(row => ({target_id: row.target_id,
        kind: row.kind, label: row.target_label, form_fields: row.target.form_fields})),
      actions: structuredClone(actions.map(({target, proposal, before, ...summary}) => summary))};
      return {active: true, action: structuredClone(actions.find(row => row.id === match[1]))};
    };
    const node = (tag, className, text) => {
      const element = document.createElement(tag);
      if (className) element.className = className;
      if (text !== undefined) element.textContent = text;
      return element;
    };
    fixture.widget = window.createYuanxingmuActions({api, node, newKey: () => "b".repeat(32),
      authorized: () => fixture.authorized, getProfile: () => fixture.profile,
      upsertProfile: () => {}, refreshProfiles: async () => {}});
    fixture.widget.boot();
    document.querySelector("#fixture-controls").append(fixture.widget.profileButton(fixture.profile));
  });
  await page.locator("body").ariaSnapshot();
  await page.getByRole("button", {name: "核对操作", exact: true}).click();
  await page.getByRole("button", {name: "查看完整内容"}).first().waitFor();
  check(await page.getByText("本次授权范围内自动执行", {exact: true}).count() === 6, "list distinguishes all automatic attempts including uncertain and not-started outcomes");
  check(await page.getByText("本人确认后执行", {exact: true}).count() === 1, "only the manual record claims an individual confirmation");
  check(await page.locator("#actions-title").innerText() === "操作与记录", "list includes completed automatic actions as records");

  for (let index = 0; index < 6; index += 1) {
    await page.locator('button[data-action-id="' + (index + 1).toString(16).repeat(32) + '"]').click();
    await page.locator("#actions-dialog .mail-read").waitFor({state: "visible"});
    await page.locator("#actions-dialog").ariaSnapshot();
    const detail = await page.locator("#actions-dialog .mail-read").innerText();
    check(detail.includes("本次授权范围内自动执行") && !detail.includes("本人确认后执行"), "truthful automatic authorization for scenario " + (index + 1));
    check(await page.locator("#actions-commit").isHidden() && await page.locator("#actions-reviewed").isHidden(), "automatic consumed attempt has no confirmation or retry control: " + (index + 1));
    check(detail.includes("https://receiver.example.test") && !detail.includes("SECRET-"), "action origin projection excludes hidden endpoint data: " + (index + 1));
    if (index === 0) {
      check(await page.locator("#actions-title").innerText() === "操作记录", "completed detail is presented as a record");
      check((await page.locator("#actions-dialog .mail-state-note").innerText()).includes("这不代表对方已经查看或处理"), "receiver acknowledgement is not claimed as end-user delivery");
    }
    if (index === 3) check((await page.locator("#actions-dialog .mail-state-note").innerText()).includes("这份记录不会再次执行"), "uncertain automatic result explicitly avoids re-execution");
    if (index === 4) check((await page.locator("#actions-dialog .mail-state-note").innerText()).includes("没有开始"), "not-started automatic record does not claim a completed effect");
    await page.getByRole("button", {name: "返回操作列表", exact: true}).click();
  }
  await page.locator('button[data-action-id="' + "7".repeat(32) + '"]').click();
  check((await page.locator("#actions-dialog .mail-read").innerText()).includes("本人确认后执行"), "manual record retains its confirmation source");
  await page.getByRole("button", {name: "返回操作列表", exact: true}).click();
  await page.locator('button[data-action-id="' + "8".repeat(32) + '"]').click();
  const legacy = await page.locator("#actions-dialog .mail-read").innerText();
  check(!legacy.includes("本人确认后执行") && !legacy.includes("本次授权范围内自动执行"), "legacy record without authorization metadata gains no invented source");
  await page.getByRole("button", {name: "返回操作列表", exact: true}).click();
  await page.locator('button[data-action-id="' + "9".repeat(32) + '"]').click();
  check(await page.locator("#actions-reviewed").isVisible() && await page.locator("#actions-commit").isDisabled(), "unconsumed pending action still requires explicit review");
  await page.evaluate(() => {
    const f = window.automaticRecordsFixture, row = f.actions[8];
    Object.assign(row, {status: "acknowledged", attempt_id: "c".repeat(32), execution_mode: "automatic",
      authorization_source: "frozen_task_scope", authorization_sha256: "f".repeat(64),
      approved_at: null, authorized_at: "2026-09-12T00:03:00Z"});
    // Exercise the production list-refresh handler while its detail remains selected.
    [...document.querySelectorAll("#actions-dialog button")].find(button => button.textContent === "刷新操作").click();
  });
  await page.locator("#actions-dialog .mail-read").getByText("本次授权范围内自动执行", {exact: true}).waitFor();
  check(await page.locator("#actions-commit").isHidden(), "status refresh also copies truthful automatic authorization metadata");
  await page.setViewportSize({width: 390, height: 844});
  await page.locator("#actions-dialog").ariaSnapshot();
  check(await page.locator("#actions-dialog").evaluate(element => element.scrollWidth <= element.clientWidth + 1), "automatic action detail fits the mobile dialog");
  await page.screenshot({path: "output/playwright/automatic-action-record-mobile.png", fullPage: true});
  await page.setViewportSize({width: 1180, height: 940});
  await page.screenshot({path: "output/playwright/automatic-action-record-desktop.png", fullPage: true});

  await page.evaluate(() => { window.automaticRecordsFixture.actions[8].approved_at = "2026-09-12T00:04:00Z"; });
  await page.getByRole("button", {name: "重新读取完整内容", exact: true}).click();
  await page.getByText("操作内容返回不完整，暂时不能确认。请重新读取。", {exact: true}).waitFor();
  check(await page.locator("#actions-dialog .mail-read").isHidden() && await page.locator("#actions-commit").isHidden(), "contradictory automatic and manual approval metadata is not displayed as valid");
  check(await page.evaluate(() => window.automaticRecordsFixture.calls.every(call => call.method === "GET")), "inspecting automatic records never sends a mutation or replay");
  await page.evaluate(() => { const fixture = window.automaticRecordsFixture; fixture.authorized = false; fixture.widget.reset(); });
  return {status: "passed", checks: passed.length, passed,
    scope: "Production actions.js against a read-only synthetic API; no actual operation, model, or Agent"};
}
