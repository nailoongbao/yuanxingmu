// Real browser / production create form; all HTTP routes are local fixtures.
// No Workbench, native Agent, model inference or external endpoint is exercised.
// Run with playwright-cli run-code from the repository root.
async (page) => {
  const passed = [], posts = [], jobs = new Map(), unexpected = [];
  const check = (condition, label) => { if (!condition) throw Error(label); passed.push(label); };
  const origin = "http://127.0.0.1:29667";
  const agentKey = "SYNTHETIC-WORKING-KEY-UI", judgeKey = "SYNTHETIC-JUDGE-KEY-UI";
  let mode = "success", serial = 0;
  const publicInfo = {runtime:{available:true}, frameworks:{openclaw:{available:true},hermes:{available:true}},
    limits:{document_bytes:262144,document_count:32,total_document_bytes:1048576},skills:[]};
  await page.unroute("**/*");
  await page.route("**/*", async route => {
    const request = route.request(), address = request.url();
    if (!address.startsWith(origin+"/")) { unexpected.push(address); return route.abort(); }
    const pathname = address.slice(origin.length).split(/[?#]/)[0];
    const json = (value, status=200) => route.fulfill({status,contentType:"application/json",body:JSON.stringify(value)});
    if (pathname === "/") return route.fulfill({path:"yuanxingmu/dashboard/web/index.html",contentType:"text/html"});
    if (["/app.js","/styles.css","/mark.svg"].includes(pathname)) return route.fulfill({path:"yuanxingmu/dashboard/web"+pathname});
    // Optional management widgets are outside this create-form contract.
    if (["/mail.js","/actions.js","/protection.js","/targets.js","/alerts.js"].includes(pathname)) return route.fulfill({contentType:"text/javascript",body:"/* unrelated widget omitted by UI fixture */"});
    if (pathname === "/api/info") return json(publicInfo);
    if (pathname === "/api/profiles" && request.method() === "GET") return json({profiles:[]});
    if (pathname.startsWith("/api/jobs/")) return json({job:jobs.get(pathname.split("/").at(-1))});
    if (pathname === "/api/profiles" && request.method() === "POST") {
      posts.push({body:request.postDataJSON(),key:request.headers()["idempotency-key"]});
      if (mode === "reject") return json({error:{message:"合成配置拒绝"}},400);
      if (mode === "uncertain") return json({error:{message:"合成服务中断，接收状态不确定"}},503);
      if (mode === "unauthorized") return json({error:{message:"合成会话失效"}},401);
      const id = (++serial).toString(16).padStart(32,"0");
      const job = {id,profile_id:"b".repeat(32),action:"create",status:"succeeded",result:{}};
      jobs.set(id,job); return json({job},202);
    }
    unexpected.push(pathname); return json({error:{message:"unexpected fixture route"}},404);
  });
  await page.setViewportSize({width:1250,height:1000});
  await page.goto(origin+"/#access=synthetic-ui-management-token");
  await page.locator("#create-submit").waitFor({state:"visible"});
  await page.waitForFunction(() => !document.querySelector("#create-fields").disabled);
  await page.locator("body").ariaSnapshot();
  await page.getByText("用另一个模型做防护检查（可选）",{exact:true}).click();
  check(await page.locator("#judge-url").isDisabled(),"independent fields start disabled");
  check(await page.locator("#judge-api-key").getAttribute("type") === "password","judge credential uses a password input");
  check(await page.locator("#judge-api-key").getAttribute("autocomplete") === "off","judge credential does not request browser persistence");
  await page.locator("#separate-judge").check();
  check(await page.locator("#judge-url").isEnabled(),"selecting independent judge enables its fields");
  await page.locator("#judge-api-key").fill(judgeKey);
  await page.locator("#separate-judge").uncheck();
  check(await page.locator("#judge-api-key").inputValue() === "","deselecting independent judge clears its credential");

  const fillWork = async label => {
    await page.locator("#work-name").fill(label);
    await page.locator("#work-objective").fill("读取资料并保存本地摘要，不得外发。");
    await page.locator("#model-url").fill("http://127.0.0.1:29881/v1");
    await page.locator("#model-id").fill("working-model-fixture");
    await page.locator("#api-key").fill(agentKey);
  };
  const finished = () => page.waitForFunction(() => !document.querySelector("#create-fields").disabled);
  await fillWork("使用原模型检查");
  await page.locator("#create-submit").click();
  await finished();
  check(posts.length===1 && !("judge" in posts[0].body),"unchecked form omits independent configuration entirely");
  check(posts[0].body.api_key===agentKey,"working credential reaches only the create request body");
  check(await page.locator("#api-key").inputValue()==="","working credential clears after submission");

  await fillWork("使用独立检查模型");
  await page.locator("#separate-judge").check();
  await page.locator("#judge-url").fill("http://127.0.0.1:29882/v1");
  await page.locator("#judge-model-id").fill("independent-judge-fixture");
  await page.locator("#judge-api-key").fill(judgeKey);
  await page.locator("#judge-timeout").fill("41");
  await page.locator("#create-submit").click();
  await finished();
  const independent=posts[1].body;
  check(independent.judge.url==="http://127.0.0.1:29882/v1" && independent.judge.id==="independent-judge-fixture" && independent.judge.api_key===judgeKey && independent.judge.timeout_seconds===41,
    "enabled form submits distinct URL/model/key and numeric timeout");
  check(independent.model_id==="working-model-fixture" && independent.api_key===agentKey,"independent settings preserve working-model fields");
  check(await page.locator("#judge-api-key").inputValue()==="" && await page.locator("#api-key").inputValue()==="","successful submission clears both credential inputs");

  mode="reject";
  await fillWork("被拒绝的配置");
  await page.locator("#judge-api-key").fill(judgeKey);
  await page.locator("#create-submit").click();
  await page.getByText("合成配置拒绝",{exact:true}).waitFor();
  await finished();
  check(await page.locator("#judge-api-key").inputValue()==="","definitive server rejection leaves the judge input empty");
  const rejectedKey=posts.at(-1).key;
  mode="success";
  await page.locator("#api-key").fill(agentKey);
  await page.locator("#create-submit").click();
  await finished();
  check(posts.at(-1).body.judge.api_key==="" && posts.at(-1).key!==rejectedKey,"fresh request after rejection cannot reuse the old judge credential");

  mode="uncertain";
  await fillWork("接收情况待确认");
  await page.locator("#judge-api-key").fill(judgeKey);
  await page.locator("#create-submit").click();
  await page.locator("#retry-create").waitFor({state:"visible"});
  check(await page.locator("#judge-api-key").inputValue()==="","uncertain receipt keeps the visible credential empty");
  const uncertain=posts.at(-1);
  mode="success";
  await page.locator("#retry-create").click();
  await finished();
  check(posts.at(-1).key===uncertain.key && JSON.stringify(posts.at(-1).body)===JSON.stringify(uncertain.body),
    "uncertain receipt retries the original body and idempotency key");

  const publicText=await page.locator("body").innerText();
  const storage=await page.evaluate(()=>({local:{...localStorage},session:{...sessionStorage}}));
  check(!publicText.includes(agentKey) && !publicText.includes(judgeKey),"neither credential appears in visible page text");
  check(!JSON.stringify(storage).includes(agentKey) && !JSON.stringify(storage).includes(judgeKey),"neither credential is persisted in browser storage");
  check(unexpected.length===0,"browser only used the isolated fixture routes");
  await page.evaluate(()=>window.scrollTo(0,0));
  await page.screenshot({path:"output/playwright/judge-workbench-desktop.png",fullPage:true});
  await page.setViewportSize({width:390,height:844});
  await page.evaluate(()=>window.scrollTo(0,0));
  await page.screenshot({path:"output/playwright/judge-workbench-mobile.png",fullPage:true});
  return {status:"passed",checks:passed.length,passed,create_requests:posts.length,
    scope:"production HTML/app.js with synthetic routed API; no native Agent or model inference"};
}
