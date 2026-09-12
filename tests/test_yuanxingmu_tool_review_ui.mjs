// Independent browser fixture for host approval UI. No actual model, settings
// service, approval ledger, command or outbound effect is executed here.
async (page) => {
  const passed = [];
  const check = (value, name) => { if (!value) throw Error(name); passed.push(name); };
  await page.route("**/*", route => route.abort());
  await page.route("http://127.0.0.1:18989/tool-review-fixture", route => route.fulfill({contentType: "text/html", body:
    '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>工具审批界面测试</title></head><body><main class="wrap"><div id="fixture-controls"></div></main></body></html>'}));
  await page.goto("http://127.0.0.1:18989/tool-review-fixture");
  await page.setViewportSize({width: 1180, height: 920});
  await page.addStyleTag({path: "yuanxingmu/dashboard/web/styles.css"});
  await page.addScriptTag({path: "yuanxingmu/dashboard/web/protection.js"});
  await page.evaluate(() => {
    sessionStorage.removeItem("yuanxingmu.protection.requests");
    const fixture = window.toolReviewFixture = {profileId: "a".repeat(32), calls: [], keys: new Map(), jobs: new Map(), serial: 0,
      loss: false, reject: false, active: true, authorized: true, omitArguments: false, mismatchId: false, badDigest: false,
      review: {id: "b".repeat(32), digest: "c".repeat(64), status: "pending", tool: "terminal", reason: "请核对本次调用",
        created_at: 1000, expires_at: 1300, decided_at: null, consumed_at: null,
        arguments: {command: 'printf "<img src=x onerror=window.fixtureXSS=true>"', cwd: "/workspace", stdin_data: "SYNTHETIC-INPUT"}}};
    const copy = value => structuredClone(value);
    const error = (message, uncertain, status) => { const result = Error(message); result.uncertain = uncertain; result.status = status; return result; };
    fixture.api = async (path, options = {}) => {
      fixture.calls.push({path, options: copy(options)});
      const base = "/api/profiles/" + fixture.profileId;
      if (path.startsWith("/api/requests/")) {
        const id = fixture.keys.get(path.split("/").at(-1));
        if (!id) throw error("原请求不存在", false, 404);
        return {job: copy(fixture.jobs.get(id))};
      }
      if (path.startsWith("/api/jobs/")) return {job: copy(fixture.jobs.get(path.split("/").at(-1)))};
      if (path === base + "/protection" && !options.method) return {supported: true, objective: "核对本次代码调用", mode: "enforce", editable: true,
        layers: {foundation: true, input: true, memory: true, alignment: true, command: true}, events: []};
      if (path === base + "/tools") return {supported: true, active: fixture.active, reviews: [copy(fixture.review)]};
      if (path === base + "/tools/" + fixture.review.id) {
        const review = copy(fixture.review);
        if (fixture.omitArguments) delete review.arguments;
        if (fixture.mismatchId) review.id = "d".repeat(32);
        if (fixture.badDigest) review.digest = "not-a-digest";
        return {supported: true, active: fixture.active, review};
      }
      if (options.method !== "POST") throw error("unexpected read", false, 404);
      if (fixture.reject) throw error("这项工作正在处理其他操作", false, 409);
      const jobId = (++fixture.serial).toString(16).padStart(32, "0");
      const job = {id: jobId, status: fixture.loss ? "running" : "succeeded", result: {}};
      fixture.jobs.set(jobId, job); fixture.keys.set(options.key, jobId);
      if (fixture.loss) { fixture.loss = false; throw error("首次响应丢失", true, 0); }
      if (path.endsWith("/approve")) fixture.review.status = "approved";
      else if (path.endsWith("/deny")) fixture.review.status = "denied";
      else if (!path.endsWith("/protection")) throw error("unexpected mutation", false, 404);
      return {job: copy(job)};
    };
    fixture.node = (tag, className, text) => { const result = document.createElement(tag); result.className = className || ""; if (text !== undefined) result.textContent = text; return result; };
    fixture.rebuild = () => {
      fixture.widget?.reset(); document.getElementById("protection-dialog")?.remove();
      fixture.widget = window.createYuanxingmuProtection({api: fixture.api, node: fixture.node, authorized: () => fixture.authorized});
      fixture.widget.boot();
      document.getElementById("fixture-controls").replaceChildren(fixture.widget.profileButton({id: fixture.profileId, name: "审批检查"}));
    };
    fixture.rebuild();
  });
  const open = async () => { await page.getByRole("button", {name: "防护记录", exact: true}).click(); await page.getByRole("button", {name: "查看这一次操作", exact: true}).waitFor(); };
  const inspect = async () => { await page.getByRole("button", {name: "查看这一次操作", exact: true}).click(); await page.locator("#protection-dialog").ariaSnapshot(); };
  const refresh = async () => { await page.getByRole("button", {name: "刷新记录", exact: true}).click(); await page.getByRole("button", {name: "查看这一次操作", exact: true}).waitFor(); };
  await open(); await inspect();
  check(await page.getByRole("button", {name: "只允许这一次", exact: true}).isDisabled(), "approval requires explicit review checkbox");
  const displayed = await page.locator("#protection-dialog pre").first().innerText();
  check(displayed.includes("SYNTHETIC-INPUT") && displayed.includes("/workspace") && displayed.includes("printf"), "full command, cwd and stdin are shown for review");
  check(await page.locator("img").count() === 0 && !(await page.evaluate(() => window.fixtureXSS)), "command markup is displayed as text");

  for (const flag of ["omitArguments", "mismatchId", "badDigest"]) {
    await page.evaluate(flag => { window.toolReviewFixture[flag] = true; }, flag);
    await refresh(); await inspect();
    check(await page.getByRole("button", {name: "只允许这一次", exact: true}).count() === 0, "malformed detail " + flag + " cannot be approved");
    await page.evaluate(flag => { window.toolReviewFixture[flag] = false; }, flag);
  }

  await page.evaluate(() => { window.toolReviewFixture.active = false; });
  await refresh(); await inspect();
  check(await page.getByRole("button", {name: "只允许这一次", exact: true}).count() === 0, "revoked task cannot present an approval control");
  await page.evaluate(() => { window.toolReviewFixture.active = true; window.toolReviewFixture.review.status = "blocked"; });
  await refresh(); await inspect();
  check(await page.getByRole("button", {name: "只允许这一次", exact: true}).count() === 0 && (await page.locator("#protection-dialog").innerText()).includes("防护检查已拦截"), "blocked candidates cannot be approved from history");

  await page.evaluate(() => { window.toolReviewFixture.review.status = "pending"; window.toolReviewFixture.loss = true; });
  await refresh(); await inspect();
  await page.getByRole("checkbox", {name: "我已核对这次操作及完整参数，只允许执行一次", exact: true}).check();
  await page.getByRole("button", {name: "只允许这一次", exact: true}).click();
  await page.getByText(/首次响应丢失/).waitFor();
  await refresh(); await inspect();
  check(await page.getByRole("button", {name: "只允许这一次", exact: true}).count() === 0, "refresh after uncertain response cannot enable a second approval POST");
  check(await page.getByRole("button", {name: "查询这一次确认的结果", exact: true}).isVisible(), "uncertain approval exposes only original-request lookup");
  const stored = await page.evaluate(() => sessionStorage.getItem("yuanxingmu.protection.requests"));
  check(!stored.includes("SYNTHETIC-INPUT") && !stored.includes("printf"), "pending storage keeps request identity without command content");
  await page.evaluate(() => { window.toolReviewFixture.rebuild(); });
  await open(); await inspect();
  check(await page.getByRole("button", {name: "只允许这一次", exact: true}).count() === 0 && await page.getByRole("button", {name: "查询这一次确认的结果", exact: true}).isVisible(), "component reconstruction preserves the uncertain original request");
  await page.evaluate(() => {
    const fixture = window.toolReviewFixture;
    for (const job of fixture.jobs.values()) job.status = "succeeded";
    fixture.review.status = "approved";
  });
  await page.getByRole("button", {name: "查询这一次确认的结果", exact: true}).click();
  await page.getByRole("button", {name: "查看这一次操作", exact: true}).waitFor();
  const reconciled = await page.evaluate(() => ({posts: window.toolReviewFixture.calls.filter(call => call.options.method === "POST"),
    gets: window.toolReviewFixture.calls.filter(call => call.path.startsWith("/api/requests/"))}));
  check(reconciled.posts.length === 1 && reconciled.posts[0].options.noRetry === true && reconciled.gets[0].path.endsWith(reconciled.posts[0].options.key), "lost acknowledgement uses original key and never repeats the POST");
  await inspect();
  check((await page.locator("#protection-dialog").innerText()).includes("已允许一次，等待领取"), "approval is described as permission, not completed execution");

  await page.evaluate(() => { const fixture = window.toolReviewFixture; fixture.review.id = "e".repeat(32); fixture.review.status = "pending"; fixture.reject = true; });
  await refresh(); await inspect();
  await page.getByRole("checkbox", {name: "我已核对这次操作及完整参数，只允许执行一次", exact: true}).check();
  await page.getByRole("button", {name: "只允许这一次", exact: true}).click();
  await page.getByText(/这项工作正在处理其他操作/).waitFor();
  await page.evaluate(() => { window.toolReviewFixture.reject = false; });
  await refresh(); await inspect();
  check(await page.getByRole("button", {name: "只允许这一次", exact: true}).isVisible() && await page.getByRole("button", {name: "查询这一次确认的结果", exact: true}).count() === 0, "definite HTTP rejection does not strand a nonexistent request key");
  check(await page.getByRole("button", {name: "只允许这一次", exact: true}).isDisabled(), "retry after definite rejection still requires fresh review");

  const beforeStorageFailure = await page.evaluate(() => window.toolReviewFixture.calls.filter(call => call.options.method === "POST").length);
  await page.evaluate(() => {
    const fixture = window.toolReviewFixture;
    fixture.originalStorageSet = Storage.prototype.setItem;
    Storage.prototype.setItem = function (key, value) {
      if (key === "yuanxingmu.protection.requests") throw new DOMException("fixture unavailable storage", "QuotaExceededError");
      return fixture.originalStorageSet.call(this, key, value);
    };
  });
  await page.getByRole("checkbox", {name: "我已核对这次操作及完整参数，只允许执行一次", exact: true}).check();
  await page.getByRole("button", {name: "只允许这一次", exact: true}).click();
  await page.getByText(/浏览器无法保存这次操作标识，尚未提交/).waitFor();
  check(await page.evaluate(() => window.toolReviewFixture.calls.filter(call => call.options.method === "POST").length) === beforeStorageFailure, "local request-identity storage failure happens before any approval POST");
  await page.evaluate(() => { Storage.prototype.setItem = window.toolReviewFixture.originalStorageSet; });
  await refresh(); await inspect();
  check(await page.getByRole("button", {name: "只允许这一次", exact: true}).isVisible() && await page.getByRole("button", {name: "查询这一次确认的结果", exact: true}).count() === 0, "storage recovery does not leave an unsent pending request");

  await page.getByText("修改防护开关", {exact: true}).click();
  await page.evaluate(() => { window.toolReviewFixture.loss = true; });
  await page.getByRole("button", {name: "保存防护设置", exact: true}).click();
  await page.getByText(/首次响应丢失/).waitFor();
  await refresh();
  await page.getByText("修改防护开关", {exact: true}).click();
  check(await page.getByRole("button", {name: "保存防护设置", exact: true}).isDisabled() && await page.getByRole("button", {name: "查询上次保存的结果", exact: true}).isVisible(), "uncertain protection-setting change also prevents resubmission");
  await page.evaluate(() => { for (const job of window.toolReviewFixture.jobs.values()) job.status = "succeeded"; });
  await page.getByRole("button", {name: "查询上次保存的结果", exact: true}).click();
  await page.getByRole("button", {name: "查看这一次操作", exact: true}).waitFor();
  const settingsRecovery = await page.evaluate(() => ({posts: window.toolReviewFixture.calls.filter(call => call.options.method === "POST" && call.path.endsWith("/protection")),
    reads: window.toolReviewFixture.calls.filter(call => call.path.startsWith("/api/requests/"))}));
  check(settingsRecovery.posts.length === 1 && settingsRecovery.reads.some(call => call.path.endsWith(settingsRecovery.posts[0].options.key)), "protection settings recover using the original key without another write");
  await inspect();

  await page.setViewportSize({width: 390, height: 844});
  await page.locator("#protection-dialog").ariaSnapshot();
  check(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), "mobile approval page has no horizontal overflow");
  check(await page.locator("#protection-dialog pre").first().evaluate(element => element.scrollWidth <= element.clientWidth + 1), "mobile command text wraps inside the actual review block");
  await page.screenshot({path: "../output/playwright/tool-review-v1/review-mobile.png", fullPage: true});
  await page.setViewportSize({width: 1180, height: 920});
  await page.screenshot({path: "../output/playwright/tool-review-v1/review-desktop.png", fullPage: true});
  await page.evaluate(() => { window.toolReviewFixture.authorized = false; window.toolReviewFixture.widget.reset(); });
  check(await page.locator("#protection-dialog pre").count() === 0, "reset clears displayed command content");
  return {scope: "Browser approval UI fixture; no real ledger, model or command executed", total: passed.length, passed};
}
