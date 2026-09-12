// Browser UI contract fixture only. No actual settings service, model, external
// endpoint or file effect is exercised here. Run with playwright-cli run-code.
async (page) => {
  const passed = [];
  const check = (value, name) => { if (!value) throw Error(name); passed.push(name); };
  await page.route("**/*", route => route.abort());
  await page.setViewportSize({width: 1180, height: 940});
  await page.setContent('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>操作对象设置测试</title></head><body><main class="wrap"><section class="work-section"><h2>工作台设置</h2><div id="action-target-settings"></div></section></main></body></html>');
  await page.addStyleTag({path: "yuanxingmu/dashboard/web/styles.css"});
  await page.addStyleTag({content: ".work-section { max-width: 650px; margin: 32px auto; }"});
  await page.addScriptTag({path: "yuanxingmu/dashboard/web/targets.js"});
  await page.evaluate(() => {
    const fixture = window.targetsFixture = {authorized: true, calls: [], serial: 0, keys: new Map(), jobs: new Map(),
      loseResponse: false, dropBeforeAccept: false, reject: false, hold: false, release: null,
      targets: [{id: "existing-chat", kind: "message", label: '<img src=x onerror=window.fixtureXSS=true> 项目群',
        provider: "slack", destination: "https://chat.example.test/SECRET-PATH?token=SECRET-QUERY", form_fields: [],
        url: "https://chat.example.test/SHOULD-NOT-RENDER", headers: {Authorization: "SHOULD-NOT-RENDER"}}]};
    const copy = value => structuredClone(value);
    const failure = (text, uncertain, status = 500) => { const error = Error(text); error.uncertain = uncertain; error.status = status; return error; };
    const api = async (path, options = {}) => {
      fixture.calls.push({path, options: copy(options)});
      if (path.startsWith("/api/requests/")) {
        const id = fixture.keys.get(path.split("/").at(-1));
        if (!id) throw failure("no such request", false, 404);
        return {job: copy(fixture.jobs.get(id))};
      }
      if (path.startsWith("/api/jobs/")) return {job: copy(fixture.jobs.get(path.split("/").at(-1)))};
      if (path === "/api/action-targets" && options.method !== "POST") return {targets: copy(fixture.targets)};
      if (options.method !== "POST" || !["/api/action-targets", "/api/action-targets/remove"].includes(path)) throw failure("unexpected route", false, 404);
      if (fixture.hold) await new Promise(resolve => { fixture.release = resolve; });
      if (fixture.dropBeforeAccept) throw failure("lost before acceptance", true);
      if (fixture.reject) throw failure("invalid configuration with SECRET-MUST-NOT-ECHO", false, 400);
      const id = options.body.id;
      if (path.endsWith("/remove")) fixture.targets = fixture.targets.filter(target => target.id !== id);
      else {
        const target = options.body.target;
        const saved = {id, kind: target.kind, label: target.label, provider: target.provider || "standard", form_fields: target.form_fields || [],
          destination: target.url ? new URL(target.url).origin : target.workspace + "/" + target.relative_path,
          ...(target.workspace ? {workspace: target.workspace, relative_path: target.relative_path} : {})};
        fixture.targets = fixture.targets.filter(target => target.id !== id);
        fixture.targets.push(saved);
      }
      const jobId = (++fixture.serial).toString(16).padStart(32, "0");
      const job = {id: jobId, status: "succeeded", result: {}};
      fixture.jobs.set(jobId, job); fixture.keys.set(options.key, jobId);
      if (fixture.loseResponse) { fixture.loseResponse = false; throw failure("lost response", true); }
      return {job: copy(job)};
    };
    const node = (tag, className, text) => { const element = document.createElement(tag); element.className = className || ""; if (text !== undefined) element.textContent = text; return element; };
    fixture.widget = window.createYuanxingmuTargets({api, node, authorized: () => fixture.authorized});
    fixture.widget.boot(); fixture.widget.boot();
  });
  check(await page.locator("#action-target-settings > details").count() === 1, "boot is idempotent");
  await page.locator("body").ariaSnapshot();
  await page.getByText("可确认的操作对象", {exact: true}).click();
  await page.locator('button[data-target-edit="existing-chat"]').waitFor();
  await page.locator("body").ariaSnapshot();
  check(await page.locator("img").count() === 0 && !(await page.evaluate(() => window.fixtureXSS)), "target labels are text, not executable markup");
  const rendered = await page.locator("body").innerText();
  check(!rendered.includes("SECRET-PATH") && !rendered.includes("SECRET-QUERY") && !rendered.includes("SHOULD-NOT-RENDER"), "list renders only endpoint origin and discards secret fields");
  check(await page.evaluate(() => window.targetsFixture.calls.every(call => call.path === "/api/action-targets" && !call.options.method)), "opening settings performs only a settings read");

  await page.locator('button[data-target-edit="existing-chat"]').click();
  check(await page.locator("#targets-url").inputValue() === "", "editing never refills a saved secret URL");
  check(await page.locator("#targets-id").getAttribute("readonly") !== null, "editing keeps the fixed target identifier");
  await page.getByRole("button", {name: "取消编辑", exact: true}).click();

  const begin = async (kind, id) => {
    await page.getByRole("button", {name: "添加操作对象", exact: true}).click();
    await page.locator("#targets-label").fill({message: "项目群消息", upload: "报告接收端", form: "活动报名表", overwrite: "正式报告", delete: "旧版备忘"}[kind]);
    await page.locator("#targets-id").fill(id);
    await page.locator("#targets-kind").selectOption(kind);
    await page.locator("#targets-form").ariaSnapshot();
  };

  check(await page.locator("#targets-id").getAttribute("maxlength") === "64" &&
    await page.locator("#targets-label").getAttribute("maxlength") === "128", "identifier limit matches the 64-character backend limit while label stays 128");
  await begin("message", "id-length-check");
  await page.locator("#targets-url").fill("https://example.test/id-length-check");
  await page.evaluate(() => {
    document.getElementById("targets-id").value = "a".repeat(65);
    document.getElementById("targets-form").dispatchEvent(new Event("submit", {bubbles: true, cancelable: true}));
  });
  await page.getByText("对象代号请使用 1–64 个英文字母、数字、下划线或短横线，并以字母或数字开头。", {exact: true}).waitFor();
  check(await page.evaluate(() => window.targetsFixture.calls.every(call => call.options.method !== "POST")), "oversized identifier rejected by submission validation before POST");
  await page.locator("#targets-id").fill("_bad-prefix");
  await page.locator("#targets-save").click();
  check(await page.evaluate(() => window.targetsFixture.calls.every(call => call.options.method !== "POST")), "identifier must start with a letter or digit like the backend");
  await page.getByRole("button", {name: "取消编辑", exact: true}).click();

  for (const kind of ["message", "upload", "form", "overwrite", "delete"]) {
    await begin(kind, "fixture-" + kind);
    if (["message", "upload", "form"].includes(kind)) {
      await page.locator("#targets-url").fill("https://receiver.example.test/SECRET-" + kind);
      if (kind === "message") await page.locator("#targets-provider").selectOption("feishu");
      if (kind === "form") await page.locator("#targets-form-fields").fill("name\nnote");
    } else {
      await page.locator("#targets-workspace").fill("/home/fixture/reviewed-files");
      await page.locator("#targets-relative-path").fill(kind + ".txt");
      check((await page.locator("#targets-form").innerText()).includes("Linux / WSL"), "file kind " + kind + " explains its host requirement");
    }
    await page.locator("#targets-save").click();
    await page.getByText("对象设置已保存，将用于之后创建的工作。实际操作仍需逐项核对。", {exact: true}).waitFor();
    check(await page.locator("#targets-url").inputValue() === "", "submitted secret URL cleared for " + kind);
    check(await page.locator('button[data-target-edit="fixture-' + kind + '"]').count() === 1, "saved kind " + kind + " appears after service read");
  }
  const saved = await page.evaluate(() => window.targetsFixture.calls.filter(call => call.options.method === "POST"));
  check(saved.length === 5 && saved.every(call => call.options.noRetry === true && /^[0-9a-f]{32}$/.test(call.options.key)), "every save is a single keyed POST with automatic retry disabled");
  check(new Set(saved.map(call => call.options.key)).size === 5, "each deliberate save gets a distinct request identity");
  check(JSON.stringify(saved.find(call => call.options.body.target?.kind === "form").options.body.target.form_fields) === '["name","note"]', "form names reach the API as an explicit allowlist");
  check(saved.filter(call => ["overwrite", "delete"].includes(call.options.body.target?.kind)).every(call => !Object.hasOwn(call.options.body.target, "url")), "file target requests do not carry network URLs");
  check(await page.evaluate(() => window.targetsFixture.calls.every(call => call.path.startsWith("/api/"))), "saving settings never runs a receiver connection test");

  await begin("message", "reject-http");
  await page.locator("#targets-url").fill("http://remote.example.test/insecure");
  await page.locator("#targets-save").click();
  await page.getByText("接收地址须使用 HTTPS；HTTP 仅支持明确的本机回环地址，不能包含账号或页面锚点。", {exact: true}).waitFor();
  check(await page.evaluate(() => window.targetsFixture.calls.filter(call => call.options.method === "POST").length) === 5, "nonlocal plaintext URL rejected before POST");
  await page.locator("#targets-url").fill("http://127.0.0.1:18888/local-fixture");
  await page.locator("#targets-save").click();
  await page.getByText("对象设置已保存，将用于之后创建的工作。实际操作仍需逐项核对。", {exact: true}).waitFor();
  check(await page.locator('button[data-target-edit="reject-http"]').count() === 1, "literal loopback target accepted as configuration only");

  await begin("form", "duplicate-form");
  await page.locator("#targets-url").fill("https://example.test/form");
  await page.locator("#targets-form-fields").fill("name\nname");
  await page.locator("#targets-save").click();
  await page.getByText(/表单需填写 1–16 个不重复的字段名/).waitFor();
  check(await page.evaluate(() => window.targetsFixture.calls.filter(call => call.options.method === "POST").length) === 6, "duplicate form fields rejected before POST");
  await page.getByRole("button", {name: "取消编辑", exact: true}).click();

  await begin("delete", "path-traversal");
  await page.locator("#targets-workspace").fill("/home/fixture/reviewed-files");
  await page.locator("#targets-relative-path").fill("../outside.txt");
  await page.locator("#targets-save").click();
  await page.getByText("文件名应位于指定文件夹内，不能含有返回上级目录的 ..。", {exact: true}).waitFor();
  check(await page.evaluate(() => window.targetsFixture.calls.filter(call => call.options.method === "POST").length) === 6, "parent-directory file target rejected before POST");
  await page.getByRole("button", {name: "取消编辑", exact: true}).click();

  await begin("message", "lost-response");
  await page.locator("#targets-url").fill("https://example.test/SECRET-LOST");
  await page.evaluate(() => { window.targetsFixture.loseResponse = true; });
  await page.locator("#targets-save").click();
  await page.locator("#targets-check-request").waitFor({state: "visible"});
  check(await page.locator("#targets-save").isDisabled() && await page.locator("#targets-url").inputValue() === "", "lost response disables resubmit and clears URL");
  await page.locator("#targets-check-request").click();
  await page.getByText("对象设置已保存，将用于之后创建的工作。实际操作仍需逐项核对。", {exact: true}).waitFor();
  const reconciled = await page.evaluate(() => ({posts: window.targetsFixture.calls.filter(call => call.options.body?.id === "lost-response"),
    lookups: window.targetsFixture.calls.filter(call => call.path.startsWith("/api/requests/"))}));
  check(reconciled.posts.length === 1 && reconciled.lookups[0].path.endsWith(reconciled.posts[0].options.key), "lost response recovered by read-only lookup using original key");

  await page.locator('button[data-target-remove="fixture-delete"]').click();
  check(await page.getByRole("button", {name: "确认移除配置", exact: true}).isVisible(), "removing configuration requires its explicit confirmation");
  await page.getByRole("button", {name: "保留配置", exact: true}).click();
  check(await page.evaluate(() => window.targetsFixture.calls.filter(call => call.path.endsWith("/remove")).length) === 0, "keeping configuration makes no removal request");
  await page.locator('button[data-target-remove="fixture-delete"]').click();
  await page.getByRole("button", {name: "确认移除配置", exact: true}).click();
  await page.getByText("对象配置已移除。已有工作的绑定保持不变。", {exact: true}).waitFor();
  check(await page.locator('button[data-target-remove="fixture-delete"]').count() === 0, "confirmed configuration removal refreshes the list");

  await begin("message", "known-failure");
  await page.locator("#targets-url").fill("https://example.test/SECRET-FAILED");
  await page.evaluate(() => { window.targetsFixture.reject = true; });
  await page.locator("#targets-save").click();
  await page.getByText("这次设置未能完成，请重新读取并核对后再试。", {exact: true}).waitFor();
  check(await page.locator("#targets-url").inputValue() === "" && !(await page.locator("body").innerText()).includes("SECRET-MUST-NOT-ECHO"), "known API failure clears secret and does not echo its raw error");
  await page.evaluate(() => { window.targetsFixture.reject = false; });
  await page.getByRole("button", {name: "取消编辑", exact: true}).click();

  await begin("message", "unknown-request");
  await page.locator("#targets-url").fill("https://example.test/SECRET-UNKNOWN");
  await page.evaluate(() => { window.targetsFixture.dropBeforeAccept = true; });
  await page.locator("#targets-save").click();
  await page.locator("#targets-check-request").waitFor({state: "visible"});
  await page.locator("#targets-check-request").click();
  await page.getByText("还无法确认原请求的结果，请稍后再次查询；不会重新提交。", {exact: true}).waitFor();
  check(await page.locator("#targets-save").isDisabled() && await page.evaluate(() => window.targetsFixture.calls.filter(call => call.options.body?.id === "unknown-request").length) === 1, "missing original request remains blocked without a second POST");

  await page.evaluate(async () => { window.targetsFixture.dropBeforeAccept = false; window.targetsFixture.widget.reset(); await window.targetsFixture.widget.refresh(); });
  await begin("message", "double-submit");
  await page.locator("#targets-url").fill("https://example.test/SECRET-IN-FLIGHT");
  await page.evaluate(() => {
    window.targetsFixture.hold = true;
    document.getElementById("targets-form").requestSubmit();
    document.getElementById("targets-form").requestSubmit();
  });
  check(await page.evaluate(() => window.targetsFixture.calls.filter(call => call.options.body?.id === "double-submit").length) === 1, "concurrent submit events produce one POST");
  check(await page.locator("#targets-url").inputValue() === "" && await page.locator("#targets-save").isDisabled(), "in-flight save clears the secret before its response");
  await page.evaluate(() => { window.targetsFixture.hold = false; window.targetsFixture.release(); });
  await page.getByText("对象设置已保存，将用于之后创建的工作。实际操作仍需逐项核对。", {exact: true}).waitFor();

  await page.locator('button[data-target-edit="fixture-overwrite"]').click();
  check(await page.locator("#targets-workspace").inputValue() === "/home/fixture/reviewed-files", "available safe file settings can be edited without guessing");
  await page.setViewportSize({width: 390, height: 844});
  await page.locator("body").ariaSnapshot();
  check(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), "mobile settings have no horizontal overflow");
  await page.screenshot({path: "../output/playwright/targets-v1/file-settings-mobile.png", fullPage: true});
  await page.setViewportSize({width: 1180, height: 940});
  await page.screenshot({path: "../output/playwright/targets-v1/file-settings-desktop.png", fullPage: true});
  await page.getByRole("button", {name: "取消编辑", exact: true}).click();
  await begin("message", "stale-response");
  await page.locator("#targets-url").fill("https://example.test/SECRET-STALE");
  await page.evaluate(() => { window.targetsFixture.hold = true; });
  await page.locator("#targets-save").click();
  await page.evaluate(async () => {
    const fixture = window.targetsFixture;
    fixture.authorized = false; fixture.widget.reset();
    fixture.hold = false; fixture.release();
    await new Promise(resolve => window.setTimeout(resolve, 25));
  });
  check(await page.locator("#targets-feedback").isHidden() && await page.locator('button[data-target-edit="stale-response"]').count() === 0, "response from an old authorization generation cannot refill the UI");
  check(await page.locator("#targets-url").inputValue() === "" && await page.getByRole("button", {name: "添加操作对象", exact: true}).isDisabled(), "authorization reset clears secret inputs and disables mutation");
  return {scope: "Browser settings UI fixture only; no real backend, model, delivery or file effect", total: passed.length, passed};
}
