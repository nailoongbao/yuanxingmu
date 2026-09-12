// Production Workbench HTML/app/alerts, synthetic same-origin HTTP responses.
// This tests browser interaction, not native Agents, inference or delivery.
async (page) => {
  const passed = [], posts = [], unexpected = [], errors = [], jobs = new Map();
  const check = (ok, label) => { if (!ok) throw Error(label); passed.push(label); };
  const origin = "http://127.0.0.1:29668", secret = "SYNTHETIC-ALERT-UI-SECRET", pathSecret = "PRIVATE-UI-HOOK";
  let mode = "success", serial = 0;
  const emptyCounts = () => ({pending:0,in_flight:0,delivered:0,failed:0});
  let report = {enabled:false,generation:null,configuration:null,has_credential:false,counts:emptyCounts(),events:[],
    storage_fault:false,full:false,scanner_error:null,source_errors:[],worker_running:false,worker_error:null,scanner_running:false,
    last_scan_at:null,stopped:[],delivery_semantics:"at_least_once",starts_with:"new_events",requires_workbench_process:true};
  await page.goto("about:blank");
  await page.unroute("**/*");
  page.on("pageerror", error => errors.push(error.message));
  await page.route("**/*", async route => {
    const request = route.request(), address = request.url();
    if (!address.startsWith(origin+"/")) { unexpected.push(address); return route.abort(); }
    const pathname = address.slice(origin.length).split(/[?#]/)[0];
    const json = (body, status=200) => route.fulfill({status,contentType:"application/json",body:JSON.stringify(body)});
    if (pathname === "/") return route.fulfill({path:"yuanxingmu/dashboard/web/index.html",contentType:"text/html"});
    if (["/app.js","/alerts.js","/styles.css","/mark.svg"].includes(pathname)) return route.fulfill({path:"yuanxingmu/dashboard/web"+pathname});
    if (["/mail.js","/actions.js","/protection.js","/targets.js"].includes(pathname)) return route.fulfill({contentType:"text/javascript",body:"/* unrelated widget omitted */"});
    if (pathname === "/api/info") return json({runtime:{available:true},frameworks:{openclaw:{available:true},hermes:{available:true}},limits:{document_bytes:262144,total_document_bytes:1048576},skills:[]});
    if (pathname === "/api/profiles") return json({profiles:[]});
    if (pathname === "/api/notifications" && request.method() === "GET") {
      if (mode === "unauthorized") return json({error:{message:"Synthetic access expired"}},401);
      return json(report);
    }
    if (pathname === "/api/notifications" && request.method() === "POST") {
      const body = request.postDataJSON(), key = request.headers()["idempotency-key"];
      posts.push({body,key});
      if (mode === "reject") return json({error:{message:"Synthetic configuration rejected"}},400);
      const id = (++serial).toString(16).padStart(32,"0");
      const job = {id,profile_id:null,action:"notifications_set",status:"succeeded",result:{notifications_updated:true,enabled:body.enabled}};
      jobs.set(key, job); jobs.set(id, job);
      report = {...report,enabled:body.enabled,generation:body.enabled?id:null,counts:emptyCounts(),events:[],
        configuration:body.enabled?{destination_origin:"https://notify.example.test",strict_receipt:body.config.strict_receipt,
          timeout_seconds:body.config.timeout_seconds,max_attempts:body.config.max_attempts,queue_capacity:body.config.queue_capacity}:null,
        has_credential:Boolean(body.config?.api_key),worker_running:body.enabled,scanner_running:body.enabled};
      if (mode === "uncertain") return json({error:{message:"Synthetic response lost after save"}},503);
      return json({job});
    }
    if (pathname.startsWith("/api/requests/") || pathname.startsWith("/api/jobs/")) {
      const job = jobs.get(pathname.split("/").at(-1));
      return job ? json({job}) : json({error:{message:"not found"}},404);
    }
    unexpected.push(pathname); return json({error:{message:"unexpected route"}},404);
  });
  await page.setViewportSize({width:1360,height:1000});
  await page.goto(origin+"/#access=synthetic-alert-ui-management-token");
  await page.waitForFunction(() => document.querySelector("#alerts-edit") && !document.querySelector("#alerts-edit").disabled);
  await page.locator("body").ariaSnapshot();
  await page.locator("#alerts-panel > summary").click();
  await page.locator("#alerts-edit").click();
  check(await page.locator("#alerts-url").getAttribute("type")==="password","receiver URL is not exposed as a visible text field");
  check(await page.locator("#alerts-key").getAttribute("autocomplete")==="off","receiver credential does not request browser storage");
  await page.locator("#alerts-url").fill("https://notify.example.test/"+pathSecret);
  await page.locator("#alerts-key").fill(secret);
  await page.locator("#alerts-cancel").click();
  check(await page.locator("#alerts-key").inputValue()==="" && await page.locator("#alerts-url").inputValue()==="","cancel clears both receiver URL and key");
  const fill = async () => {
    await page.locator("#alerts-edit").click();
    await page.locator("#alerts-url").fill("https://notify.example.test/"+pathSecret);
    await page.locator("#alerts-key").fill(secret);
  };
  await fill();
  await page.locator("#alerts-save").click();
  await page.waitForFunction(() => document.querySelector("#alerts-status").textContent==="后台已启用");
  check(posts.length===1 && posts[0].body.enabled && posts[0].body.config.api_key===secret,"host configuration receives the fixed endpoint and credential once");
  check(await page.locator("#alerts-key").inputValue()==="" && await page.locator("#alerts-url").inputValue()==="","successful submission clears secrets");
  check(!(await page.locator("#alerts-report").innerText()).includes(pathSecret),"status shows the receiver origin without its private path");
  check((await page.locator("#alerts-panel").innerText()).includes("进程必须保持运行"),"ordinary users see the Workbench process requirement");
  check((await page.locator("#alerts-panel").innerText()).includes("不附带资料、指令或工作名称"),"notification payload privacy is explained");
  mode="reject";
  await fill(); await page.locator("#alerts-save").click();
  await page.getByText("这次设置未完成，请核对当前状态后重新填写。",{exact:true}).waitFor();
  check(await page.locator("#alerts-key").inputValue()==="" && await page.locator("#alerts-url").inputValue()==="","definitive rejection does not retain secrets");
  mode="uncertain";
  await fill(); await page.locator("#alerts-save").click();
  await page.locator("#alerts-check").waitFor({state:"visible"});
  const before = posts.length;
  check(await page.locator("#alerts-key").inputValue()==="" && await page.locator("#alerts-url").inputValue()==="","unknown save result also clears secrets");
  await page.locator("#alerts-check").click();
  await page.waitForFunction(() => document.querySelector("#alerts-check").hidden);
  check(posts.length===before,"unknown save is resolved by receipt query without re-submitting configuration");
  check(new Set(posts.map(item=>item.key)).size===posts.length,"distinct settings actions have distinct request IDs");
  mode="success";
  report = {...report,counts:{pending:2,in_flight:1,delivered:6,failed:1},events:[
    {status:"paused",delivery:"failed",created_at:1789187400,attempts:3},
    {status:"approval_required",delivery:"pending",created_at:1789187460,attempts:0}],full:true,
    source_errors:[{profile_id:"c".repeat(32),code:"notification_queue_full"}]};
  await page.locator("#alerts-refresh").click();
  await page.getByText("提醒记录已满，新提醒正在等待。已发送记录也占用名额，以避免重复发送。关闭后重新启用会建立新记录，旧提醒不再补发。",{exact:true}).waitFor();
  const text = await page.locator("#alerts-report").innerText();
  check(text.includes("发送失败 1") && text.includes("等待发送 2") && text.includes("等待本人确认"),"pending, failure, capacity and action-confirmation states render distinctly");
  await page.evaluate(()=>window.scrollTo(0,0));
  await page.screenshot({path:"output/playwright/alerts-workbench-desktop.png",fullPage:true});
  await page.setViewportSize({width:390,height:844});
  await page.evaluate(()=>window.scrollTo(0,0));
  await page.screenshot({path:"output/playwright/alerts-workbench-mobile.png",fullPage:true});
  check(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),"notification settings fit a narrow screen without horizontal overflow");
  report={...report,counts:null,events:[],storage_fault:true,full:false,source_errors:[],worker_running:false,scanner_running:false};
  await page.locator("#alerts-refresh").click();
  await page.getByText("提醒记录无法核对，发送数量未知。请保留本机记录并检查工作台；这不会恢复被暂停的工作。",{exact:true}).waitFor();
  check(await page.locator("#alerts-report .alert-counts").count()===0,"storage fault shows unknown counts instead of invented zeros");
  report={...report,counts:emptyCounts(),storage_fault:false,worker_running:true,scanner_running:true};
  check(report.enabled,"fixture still enabled before requesting notification shutdown");
  await page.locator("#alerts-refresh").click();
  await page.locator("#alerts-disable").click();
  check(await page.locator("#alerts-confirm-disable").isVisible(),"turning off reminders explains the pending-delivery effect before submission");
  await page.locator("#alerts-confirm-disable").click();
  await page.waitForFunction(()=>document.querySelector("#alerts-status").textContent==="未启用");
  check(JSON.stringify(posts.at(-1).body)==='{"enabled":false}',"disable request contains no old secret or endpoint");
  await fill();
  await page.locator("#alerts-panel > summary").click();
  await page.waitForFunction(()=>document.querySelector("#alerts-key").value==="" && document.querySelector("#alerts-url").value==="");
  check(await page.locator("#alerts-key").inputValue()==="" && await page.locator("#alerts-url").inputValue()==="","closing the settings panel clears secrets");
  await page.locator("#alerts-panel > summary").click();
  await fill(); mode="unauthorized";
  await page.locator("#alerts-refresh").click();
  await page.waitForFunction(()=>document.querySelector("#alerts-edit").disabled && document.querySelector("#alerts-status").textContent==="等待连接");
  check(await page.locator("#alerts-key").inputValue()==="" && await page.locator("#alerts-url").inputValue()==="","expired management authentication clears secrets and disables settings");
  const storage = await page.evaluate(()=>JSON.stringify({local:Object.entries(localStorage),session:Object.entries(sessionStorage)}));
  check(!storage.includes(secret) && !storage.includes(pathSecret),"receiver URL and key are absent from browser local/session storage");
  check(unexpected.length===0 && errors.length===0,"only expected local UI routes were used and no page errors occurred");
  return {status:"passed",checks:passed.length,passed,posts:posts.length,
    scope:"production Workbench HTML/app/alerts with synthetic same-origin API; no native Agent or real webhook"};
}
