// Production creation form + automation component; every HTTP request is a local fixture.
// Run from the repository root using playwright-cli run-code --filename=tests/test_yuanxingmu_automation_ui.mjs.
// This exercises browser consent and request construction, not a native Agent, model, or delivery service.
async (page) => {
  const passed = [], posts = [], targetReads = [], unexpected = [], pageErrors = [];
  const check = (condition, name) => { if (!condition) throw Error(name); passed.push(name); };
  const copy = value => JSON.parse(JSON.stringify(value));
  const origin = "http://127.0.0.1:29669", token = "SYNTHETIC-AUTOMATION-MANAGEMENT";
  const jobs = new Map();
  let serial = 0, createMode = "success", targetMode = "success", infoMode = "success";
  const targetReleases = [];
  const target = (id, kind, label, letter) => ({id, target_id: id, kind, label,
    destination: "https://receiver.example.test/SECRET-WEBHOOK-PATH?key=SECRET-QUERY", provider: "standard",
    form_fields: kind === "form" ? ["name", "note"] : [], binding_digest: letter.repeat(64),
    headers: {Authorization: "SECRET-HEADER"}, api_key: "SECRET-KEY"});
  const originals = [target("team", "message", "项目协作群", "a"), target("docs", "upload", "项目资料库", "b"),
    target("form", "form", "活动报名表", "c"), {id: "old", kind: "delete", label: "旧报告"},
    {id: "report", kind: "overwrite", label: "正式报告"}];
  let targets = copy(originals);
  const info = {runtime: {available: true}, frameworks: {openclaw: {available: true}, hermes: {available: true}},
    limits: {document_bytes: 262144, document_count: 32, total_document_bytes: 1048576}, skills: []};
  page.on("pageerror", error => pageErrors.push(error.message));
  await page.unroute("**/*");
  await page.route("**/*", async route => {
    const request = route.request(), address = request.url();
    if (!address.startsWith(origin + "/")) { unexpected.push(address); return route.abort(); }
    const path = address.slice(origin.length).split(/[?#]/)[0];
    const json = (value, status = 200) => route.fulfill({status, contentType: "application/json", body: JSON.stringify(value)});
    if (path === "/") return route.fulfill({path: "yuanxingmu/dashboard/web/index.html", contentType: "text/html"});
    if (["/app.js", "/automation.js", "/styles.css", "/mark.svg"].includes(path)) {
      return route.fulfill({path: "yuanxingmu/dashboard/web" + path});
    }
    if (["/mail.js", "/actions.js", "/protection.js", "/targets.js", "/alerts.js"].includes(path)) {
      return route.fulfill({contentType: "text/javascript", body: "/* unrelated widget omitted in consent fixture */"});
    }
    if (path === "/api/info") return infoMode === "unauthorized" ? json({error: {message: "fixture unauthorized"}}, 401) : json(info);
    if (path === "/api/profiles" && request.method() === "GET") return json({profiles: []});
    if (path === "/api/action-targets") {
      targetReads.push({method: request.method(), headers: request.headers()});
      if (targetMode === "old") return json({error: {message: "SECRET-ERROR"}}, 404);
      const snapshot = copy(targets);
      if (targetMode === "hold") await new Promise(resolve => { targetReleases.push(resolve); });
      return json({targets: snapshot, applies_to: "new_profiles"});
    }
    if (path.startsWith("/api/jobs/")) return json({job: jobs.get(path.split("/").at(-1))});
    if (path === "/api/profiles" && request.method() === "POST") {
      posts.push({body: request.postDataJSON(), key: request.headers()["idempotency-key"]});
      if (createMode === "network") return route.abort();
      if (createMode === "uncertain") return json({error: {message: "合成结果暂不明确"}}, 503);
      if (createMode === "reject") return json({error: {message: "合成对象版本已变化"}}, 409);
      const id = (++serial).toString(16).padStart(32, "0");
      const job = {id, profile_id: "d".repeat(32), action: "create", status: "succeeded", result: {}};
      jobs.set(id, job);
      return json({job}, 202);
    }
    unexpected.push(path);
    return json({error: {message: "unexpected fixture route"}}, 404);
  });
  await page.setViewportSize({width: 1250, height: 1000});
  await page.goto(origin + "/#access=");
  await page.locator("#automation-enabled").waitFor();
  check(targetReads.length === 0 && await page.locator("#automation-enabled").isDisabled(), "no unauthenticated target read or consent control");
  await page.goto(origin + "/#access=" + token);
  await page.waitForFunction(() => !document.querySelector("#create-fields").disabled);
  await page.locator("body").ariaSnapshot();
  check(await page.locator("#create-action-automation").count() === 1, "one automation section mounts in the real creation form");
  check(!(await page.locator("#automation-enabled").isChecked()), "automatic scope is disabled by default");
  check(await page.locator("#automation-targets input").count() === 3, "only message upload and form are eligible");
  check(await page.locator("#automation-targets input:checked").count() === 0, "all fixed destinations start unchecked");
  check(targetReads.every(item => item.method === "GET" && item.headers.authorization === "Bearer " + token), "target configuration is read through the authenticated API");

  const fillWork = async name => {
    await page.locator("#work-name").fill(name);
    await page.locator("#work-objective").fill("整理本次资料，按我选定的范围提交。其余操作先核对。");
    await page.locator("#model-url").fill("http://127.0.0.1:29998/v1");
    await page.locator("#model-id").fill("synthetic-model-never-contacted");
  };
  const finished = () => page.waitForFunction(() => !document.querySelector("#create-fields").disabled
    && document.querySelector("#create-message").textContent.includes("已创建"));
  const choice = id => page.locator('input[data-automation-target="' + id + '"]');
  const refresh = async () => {
    await page.locator("#automation-refresh").click();
    await page.waitForFunction(() => !document.querySelector("#automation-refresh").disabled);
    await page.locator("#create-action-automation").ariaSnapshot();
  };
  const missingScope = body => !("action_automation" in body) && !("action_automation_bindings" in body);

  await fillWork("默认逐项核对");
  await page.locator("#create-submit").click();
  await finished();
  check(posts.length === 1 && missingScope(posts[0].body), "default creation omits both optional fields");
  await page.locator("#automation-enabled").check();
  await fillWork("未勾选对象");
  await page.locator("#create-submit").click();
  await finished();
  check(missingScope(posts.at(-1).body), "enabled control without explicit destinations grants nothing");

  await page.locator("#automation-enabled").check();
  for (const id of ["team", "docs", "form"]) await choice(id).check();
  const consentText = await page.locator("#automation-choices").innerText();
  check(consentText.includes("允许「项目协作群」接收本次工作的资料") && consentText.includes("8 KB") && consentText.includes("64 KB"), "explicit per-target material consent and fixed limits are readable");
  check(consentText.includes("https://receiver.example.test") && !consentText.includes("SECRET-"), "only a safe origin is rendered, never path query headers or keys");
  await page.getByText("这次授权包含什么", {exact: true}).click();
  const explanation = await page.locator("#create-action-automation").innerText();
  check(explanation.includes("发送结果不明确时不会自动重发") && explanation.includes("邮件、删除和覆盖仍待你核对"), "unknown results and excluded action kinds are explained");
  await page.evaluate(() => { document.querySelector("#automation-limits").dataset.maxAttempts = "999999"; });
  await fillWork("三个固定对象");
  await page.locator("#create-submit").click();
  await finished();
  const selected = posts.at(-1).body;
  check(JSON.stringify(selected.action_automation) === JSON.stringify({version: 1, max_attempts: 8,
    max_total_body_bytes: 65536, targets: {team: {accepted_labels: ["private"], max_body_bytes: 8192},
      docs: {accepted_labels: ["private"], max_body_bytes: 8192}, form: {accepted_labels: ["private"], max_body_bytes: 8192}}}), "payload has only the three explicit grants and bounded integer limits");
  check(JSON.stringify(selected.action_automation_bindings) === JSON.stringify({team: "a".repeat(64), docs: "b".repeat(64), form: "c".repeat(64)}), "creation binds exactly the reviewed target digests");
  check(!JSON.stringify(selected).includes("SECRET-") && !JSON.stringify(selected.action_automation).includes("https:"), "create body contains no endpoint or hidden target configuration");
  check(!(await page.locator("#automation-enabled").isChecked()) && await page.locator("#automation-targets input:checked").count() === 0, "successful create clears all consent for the next work");

  await page.locator("#automation-enabled").check();
  await choice("team").check();
  await page.locator("#automation-enabled").uncheck();
  await page.locator("#automation-enabled").check();
  check(!(await choice("team").isChecked()), "turning automatic scope off clears prior choices");
  await choice("team").check();
  await choice("docs").check();
  await refresh();
  check(await choice("team").isChecked() && await choice("docs").isChecked(), "unchanged authenticated bindings retain consent during refresh");
  targets[0].binding_digest = "e".repeat(64);
  targets[0].label = "配置已更新的项目群";
  await refresh();
  check(!(await choice("team").isChecked()) && await choice("docs").isChecked(), "changed destination loses consent while unchanged destination remains");
  check((await page.locator("#automation-feedback").innerText()).includes("相关勾选已清除"), "binding change has a visible explanation");
  await choice("team").check();
  targets = targets.filter(item => item.id !== "docs");
  await refresh();
  check(await choice("docs").count() === 0 && await choice("team").isChecked(), "removed target cannot remain selected or be sent");

  createMode = "network";
  await fillWork("网络中断后核对原请求");
  const beforeFailure = posts.length;
  await page.locator("#create-submit").click();
  await page.locator("#retry-create").waitFor({state: "visible"});
  const frozen = posts[beforeFailure];
  check(posts.length === beforeFailure + 2 && JSON.stringify(posts.at(-1)) === JSON.stringify(frozen), "network retry uses the identical keyed creation body");
  check(await page.locator("#automation-enabled").isDisabled(), "uncertain creation disables changes to the scope");
  await page.evaluate(() => {
    const input = document.querySelector('input[data-automation-target="form"]');
    input.checked = true;
    input.dispatchEvent(new Event("change", {bubbles: true}));
  });
  check(!(await choice("form").isChecked()), "synthetic change events cannot alter scope while creation is pending");
  targets[0].binding_digest = "f".repeat(64);
  await page.locator("#refresh-button").click();
  await page.waitForFunction(() => !document.querySelector("#refresh-button").disabled);
  check(!(await choice("team").isChecked()), "new settings are not silently accepted while a request is pending");
  createMode = "success";
  await page.locator("#retry-create").click();
  await finished();
  check(JSON.stringify(posts.at(-1)) === JSON.stringify(frozen), "manual retry retains the original frozen bindings even after a registry refresh");
  check(Object.keys(posts.at(-1).body.action_automation.targets).join() === "team", "retry does not add a newly checked or previously removed target");

  targets = copy(originals);
  await refresh();
  await page.locator("#automation-enabled").check();
  await choice("team").check();
  createMode = "reject";
  await fillWork("后台拒绝旧版本");
  await page.locator("#create-submit").click();
  await page.getByText("合成对象版本已变化", {exact: true}).waitFor();
  const rejected = posts.at(-1);
  check(await page.locator("#retry-create").isHidden() && await choice("team").isChecked(), "known rejection permits editing but does not invent a new scope");
  targets[0].binding_digest = "1".repeat(64);
  await refresh();
  check(!(await choice("team").isChecked()), "rejected stale binding must be explicitly selected again after refresh");
  await choice("team").check();
  createMode = "success";
  await page.locator("#create-submit").click();
  await finished();
  check(posts.at(-1).key !== rejected.key && posts.at(-1).body.action_automation_bindings.team === "1".repeat(64), "new request after explicit reselection uses the new binding and a new key");

  await page.locator("#automation-enabled").check();
  await choice("docs").check();
  createMode = "uncertain";
  await fillWork("服务端返回暂不明确");
  await page.locator("#create-submit").click();
  await page.locator("#retry-create").waitFor({state: "visible"});
  const httpUncertain = posts.at(-1);
  createMode = "success";
  await page.locator("#retry-create").click();
  await finished();
  check(JSON.stringify(posts.at(-1)) === JSON.stringify(httpUncertain), "uncertain HTTP response also retains the original scope and key");

  targets = [];
  await refresh();
  check(await page.locator("#automation-enabled").isDisabled() && await page.locator("#automation-empty").isVisible(), "no targets keeps optional automation unavailable without blocking creation");
  await fillWork("没有登记对象");
  await page.locator("#create-submit").click();
  await finished();
  check(missingScope(posts.at(-1).body), "empty registry preserves legacy create payload");
  targetMode = "old";
  await refresh();
  await fillWork("旧版服务");
  await page.locator("#create-submit").click();
  await finished();
  check(missingScope(posts.at(-1).body) && !(await page.locator("body").innerText()).includes("SECRET-ERROR"), "older API remains usable and raw service errors are not echoed");

  targetMode = "success";
  const invalidSets = [
    [target("team", "message", "缺少摘要", "a")].map(item => { delete item.binding_digest; return item; }),
    [target("team", "message", "错误摘要", "g")],
    [target("team", "message", "重复一", "a"), target("team", "message", "重复二", "b")],
    [{...target("team", "message", "外部明文", "a"), destination: "http://external.example.test/secret"}],
    [{...target("team", "message", "凭证地址", "a"), destination: "https://name:secret@example.test/private"}],
    [{...target("team", "message", "脚本来源", "a"), destination: "javascript:alert(1)"}],
    [target("_invalid", "message", "错误代号", "a")],
    [target("team", "unexpected", "未知类型", "a")],
    Array.from({length: 33}, (_, index) => target("target" + index, "message", "超限对象 " + index, "a"))
  ];
  for (let index = 0; index < invalidSets.length; index += 1) {
    targets = invalidSets[index];
    await refresh();
    check(await page.locator("#automation-enabled").isDisabled() && await page.locator("#automation-targets input").count() === 0,
      "invalid target schema is not selectable: case " + (index + 1));
  }
  targets = [target("constructor", "message", '<img src=x onerror="window.fixtureAutomationXSS=true">', "a")];
  await refresh();
  await page.locator("#automation-enabled").check();
  await choice("constructor").check();
  check(await page.locator("#automation-targets img").count() === 0 && !(await page.evaluate(() => window.fixtureAutomationXSS)), "untrusted labels render only as text");
  await fillWork("合法特殊代号");
  await page.locator("#create-submit").click();
  await finished();
  check(Object.hasOwn(posts.at(-1).body.action_automation.targets, "constructor") && Object.hasOwn(posts.at(-1).body.action_automation_bindings, "constructor"), "valid prototype-like IDs serialize as own target keys");

  targets = copy(originals);
  await refresh();
  await page.locator("#automation-enabled").check();
  await choice("team").check();
  await fillWork("一次选好范围");
  await page.locator("#create-action-automation").scrollIntoViewIfNeeded();
  await page.locator("#create-action-automation").ariaSnapshot();
  await page.screenshot({path: "output/playwright/automation-workbench-desktop.png", fullPage: true});
  await page.setViewportSize({width: 390, height: 844});
  await page.locator("#create-action-automation").scrollIntoViewIfNeeded();
  await page.locator("#create-action-automation").ariaSnapshot();
  check(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), "mobile consent controls fit the viewport without horizontal scrolling");
  await page.screenshot({path: "output/playwright/automation-workbench-mobile.png", fullPage: true});
  await page.locator("#create-action-automation").screenshot({path: "output/playwright/automation-consent-mobile.png"});
  const storage = await page.evaluate(() => ({local: {...localStorage}, session: {...sessionStorage}}));
  check(Object.keys(storage.local).length === 0 && Object.keys(storage.session).every(key => key === "yuanxingmu.workbench.access"), "destination selections and bindings are never persisted in browser storage");

  targetMode = "hold";
  await page.locator("#automation-refresh").click();
  await page.waitForFunction(() => document.querySelector("#automation-refresh").disabled);
  const beforeHeldCreate = posts.length;
  await page.locator("#create-submit").click();
  await page.getByText("请等待操作对象读取完成，再核对自动执行范围。", {exact: true}).waitFor();
  check(posts.length === beforeHeldCreate, "selected scope cannot be submitted during an incomplete target refresh");
  infoMode = "unauthorized";
  // Deliver a real API rejection while the older authenticated target response is still in flight.
  await page.locator("#refresh-button").click();
  await page.getByText("本机服务已拒绝这次访问凭证。请从启动工作台的终端重新打开完整启动链接。", {exact: true}).waitFor();
  targetMode = "success";
  for (const release of targetReleases) release();
  await page.waitForFunction(() => document.querySelector("#refresh-button").textContent === "刷新状态 ↻");
  check(!(await page.locator("#automation-enabled").isChecked()) && await page.locator("#automation-targets input").count() === 0, "authorization rejection clears all consent and target projections");
  await page.locator("#create-action-automation").ariaSnapshot();
  check(await page.locator("#automation-enabled").isDisabled() && await page.locator("#automation-targets input").count() === 0, "late response from old access cannot restore destinations or consent");
  check(unexpected.length === 0 && pageErrors.length === 0, "only fixture routes ran and no uncaught browser errors occurred");
  return {status: "passed", checks: passed.length, passed, create_requests: posts.length,
    scope: "Real production HTML/app.js/automation.js with synthetic authenticated API routes; no model, native Agent, or outbound delivery"};
}
