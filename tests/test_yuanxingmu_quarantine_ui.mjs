// Browser-only fixture for the real protection component. No actual Broker,
// model, native command, desktop notification or external effect is run here.
async (page) => {
  const passed = [], failures = [];
  const check = (value, name) => (value ? passed : failures).push(name);
  await page.route("**/*", route => route.abort());
  await page.route("http://127.0.0.1:18989/quarantine-fixture", route => route.fulfill({contentType: "text/html", body:
    '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>暂停恢复界面检查</title></head><body><main class="wrap"><div id="fixture-controls"></div></main></body></html>'}));
  await page.goto("http://127.0.0.1:18989/quarantine-fixture");
  await page.setViewportSize({width: 1180, height: 940});
  await page.addStyleTag({path: "yuanxingmu/dashboard/web/styles.css"});
  await page.addScriptTag({path: "yuanxingmu/dashboard/web/protection.js"});
  await page.evaluate(() => {
    sessionStorage.removeItem("yuanxingmu.protection.requests");
    const fixture = window.quarantineFixture = {profileId: "a".repeat(32), calls: [], keys: new Map(), jobs: new Map(), serial: 0,
      lose: false, reject: false, missingOriginal: false, authorized: true, permissionRequests: 0, notifications: []};
    class NotificationFixture {
      static permission = "default";
      static async requestPermission() { fixture.permissionRequests++; this.permission = "granted"; return "granted"; }
      constructor(title, options) {fixture.notifications.push({title, options});}
    }
    Object.defineProperty(window, "Notification", {value: NotificationFixture, configurable: true});
    fixture.fresh = (epoch = 3, character = "b") => {
      const incident = {id: character.repeat(32), epoch, layer: "input", code: "fixture_instruction",
        reason: '<img src=x onerror=window.fixtureXSS=true> 合成资料试图改变任务 SECRET-REASON', resolved_at: null};
      return {scope: "task_family", state: "paused", paused: true, can_resume: true, revoked: false, epoch,
        incident_id: incident.id, incident: structuredClone(incident), incidents: [incident], unresolved_count: 1,
        has_more: false, storage_fault: false, admitted_effects: {consumed_tool_permits: 0, sending_mail: 0, executing_actions: 0}};
    };
    fixture.quarantine = fixture.fresh();
    const error = (message, uncertain, status) => Object.assign(Error(message), {uncertain, status});
    fixture.finish = () => {
      fixture.quarantine = {...fixture.quarantine, paused: false, state: "active", can_resume: false,
        epoch: fixture.quarantine.epoch + 1, unresolved_count: 0};
      for (const row of fixture.quarantine.incidents) row.resolved_at = "fixture-resolved";
      for (const job of fixture.jobs.values()) job.status = "succeeded";
    };
    fixture.api = async (path, options = {}) => {
      fixture.calls.push({path, options: structuredClone(options)});
      if(path.startsWith("/api/requests/")) {
        const key = path.split("/").at(-1), id = fixture.keys.get(key);
        if(!id || fixture.missingOriginal) throw error("原请求尚无法确认", false, 404);
        return {job: structuredClone(fixture.jobs.get(id))};
      }
      if(path.startsWith("/api/jobs/")) return {job: structuredClone(fixture.jobs.get(path.split("/").at(-1)))};
      const base = "/api/profiles/" + fixture.profileId;
      if(path === base + "/protection" && !options.method) return {supported:true,objective:"本机核对合成资料",mode:"enforce",editable:false,
        layers:{foundation:true,input:true,memory:true,alignment:true,command:true},events:[],quarantine:structuredClone(fixture.quarantine)};
      if(path === base + "/tools" && !options.method) return {supported:true,active:!fixture.quarantine.paused,reviews:[]};
      if(path !== base + "/quarantine/resume" || options.method !== "POST") throw error("unexpected route", false, 404);
      if(fixture.reject) throw error("本次恢复未被接受", false, 409);
      const q = fixture.quarantine, body = options.body;
      if(body.epoch !== q.epoch || body.incident_id !== q.incident_id || body.confirm !== "resume") throw error("暂停记录已经改变", false, 409);
      const id = (++fixture.serial).toString(16).padStart(32,"0");
      const job = {id,status:fixture.lose ? "running" : "succeeded",result:{}};
      fixture.keys.set(options.key,id);fixture.jobs.set(id,job);
      if(fixture.lose) {fixture.lose=false;throw error("恢复响应丢失",true,0);}
      fixture.finish();return {job:structuredClone(job)};
    };
    fixture.node = (tag,className,text) => {const result=document.createElement(tag);result.className=className||"";if(text!==undefined)result.textContent=text;return result;};
    fixture.rebuild = () => {
      fixture.widget?.reset();document.getElementById("protection-dialog")?.remove();
      fixture.widget=window.createYuanxingmuProtection({api:fixture.api,node:fixture.node,authorized:()=>fixture.authorized});
      fixture.widget.boot();document.getElementById("fixture-controls").replaceChildren(fixture.widget.profileButton({id:fixture.profileId,name:"暂停检查"}));
    };
    fixture.rebuild();
  });
  const open = async () => {await page.getByRole("button",{name:"防护记录",exact:true}).click();await page.getByText("你确定的工作目标",{exact:true}).waitFor();};
  const refresh = async () => {await page.getByRole("button",{name:"刷新记录",exact:true}).click();await page.getByText("你确定的工作目标",{exact:true}).waitFor();};
  const consent = () => page.getByRole("checkbox",{name:"我已核对全部未处理原因，并处理了可疑内容",exact:true});
  const resume = () => page.getByRole("button",{name:"恢复这份工作",exact:true});
  const posts = () => page.evaluate(() => window.quarantineFixture.calls.filter(call=>call.options.method==="POST"));
  await open();
  check(await resume().isDisabled(),"resume needs explicit review of all unresolved reasons");
  check(await page.locator("img").count()===0 && !(await page.evaluate(()=>window.fixtureXSS)),"incident reason markup stays plain text");
  check((await page.locator("#protection-dialog").innerText()).includes("已经开始的操作仍需核对结果"),"pause wording preserves uncertainty about already-started effects");
  check((await page.locator("#protection-dialog").innerText()).includes("恢复不会自动重试旧操作"),"resume wording never promises automatic retry of old operations");
  check(await page.evaluate(()=>window.quarantineFixture.permissionRequests)===0,"opening the component never requests notification permission");
  await page.evaluate(()=>{const f=window.quarantineFixture;f.widget.profilesChanged([{id:f.profileId,paused:true,revoked:false,pause_epoch:1,name:"SECRET-PROFILE"}]);});
  check(await page.evaluate(()=>window.quarantineFixture.notifications.length)===0,"profile updates never send a notification before permission");
  await page.getByRole("button",{name:"开启本机桌面提醒",exact:true}).click();
  check(await page.evaluate(()=>window.quarantineFixture.permissionRequests)===1,"notification permission is requested only by explicit button click");
  await page.evaluate(()=>{
    const f=window.quarantineFixture,p={id:f.profileId,paused:true,revoked:false,pause_epoch:2,name:"SECRET-PROFILE",reason:"SECRET-REASON"};
    f.widget.profilesChanged([p]);f.widget.profilesChanged([p]);
  });
  check(await page.evaluate(()=>window.quarantineFixture.notifications.length)===1,"repeated same-epoch updates produce one generic notification");
  check(!(await page.evaluate(()=>JSON.stringify(window.quarantineFixture.notifications))).includes("SECRET"),"notification title and body contain neither task name nor incident content");
  check((await page.title()).includes("1 项暂停"),"document title shows the number of paused tasks");
  await page.evaluate(()=>{const f=window.quarantineFixture;f.widget.profilesChanged([{id:f.profileId,paused:true,revoked:false,pause_epoch:3}]);});
  check(await page.evaluate(()=>window.quarantineFixture.notifications.length)===2,"a new pause epoch produces a new notification");
  await page.evaluate(()=>{const f=window.quarantineFixture;f.widget.profilesChanged([{id:f.profileId,paused:true,revoked:true,pause_epoch:4}]);});
  check(await page.evaluate(()=>window.quarantineFixture.notifications.length)===2 && !(await page.title()).includes("项暂停"),"revoked profiles neither notify nor inflate active pause counts");

  await page.evaluate(()=>{
    const f=window.quarantineFixture,q=f.quarantine;
    q.incidents.push({id:"c".repeat(32),epoch:2,layer:"memory",reason:"第二条独立的合成原因",resolved_at:null});q.unresolved_count=2;
  });
  await refresh();
  check((await page.locator("#protection-dialog").innerText()).includes("第二条独立的合成原因") &&
    (await page.locator("#protection-dialog").innerText()).includes("全部 2 条"),"all unresolved incidents and their count are shown before family recovery");

  for(const variant of ["missingIncident","wrongId","wrongEpoch","wrongReason","countMismatch","duplicateIncident","truncatedUnresolved"]) {
    await page.evaluate(variant=>{
      const f=window.quarantineFixture,q=f.quarantine=f.fresh();
      if(variant==="missingIncident")delete q.incident;
      if(variant==="wrongId")q.incident.id="d".repeat(32);
      if(variant==="wrongEpoch")q.incident.epoch=2;
      if(variant==="wrongReason")q.incident.reason="未展示的另一段原因";
      if(variant==="countMismatch")q.unresolved_count=2;
      if(variant==="duplicateIncident"){q.incidents.push(structuredClone(q.incidents[0]));q.unresolved_count=2;}
      if(variant==="truncatedUnresolved"){q.has_more=true;q.unresolved_count=101;}
    },variant);
    await refresh();
    check(await resume().count()===0,"incomplete or mismatched incident state cannot be resumed: "+variant);
  }
  await page.evaluate(()=>{const f=window.quarantineFixture;f.quarantine={...f.fresh(),storage_fault:true};});
  await refresh();
  check(await resume().count()===0 && (await page.locator("#protection-dialog").innerText()).includes("防护状态写入失败"),"backend storage fault offers no resume even with an otherwise valid pause");
  await page.evaluate(()=>{const f=window.quarantineFixture;f.quarantine={...f.fresh(),paused:false,storage_fault:true};});
  await refresh();
  check((await page.locator("#protection-dialog").innerText()).includes("防护状态写入失败") && !(await page.locator("#protection-dialog").innerText()).includes("目前没有暂停工作"),"failed pause persistence is not described as normal active work");
  await page.evaluate(()=>{const f=window.quarantineFixture;f.quarantine={...f.fresh(),revoked:true,can_resume:false};});
  await refresh();
  check(await resume().count()===0,"revoked task has no resume control");

  await page.evaluate(()=>{const f=window.quarantineFixture;f.quarantine=f.fresh();});
  await refresh();
  await consent().check();
  await page.evaluate(()=>{const f=window.quarantineFixture;f.quarantine=f.fresh(4,"d");});
  await resume().click();
  await page.getByText(/暂停记录已经改变/).waitFor();
  let sent=await posts();
  check(sent.length===1 && sent[0].options.body.epoch===3 && sent[0].options.body.incident_id==="b".repeat(32),"a concurrent new incident cannot silently replace the snapshot the person reviewed");
  await refresh();
  check(await resume().isDisabled() && !(await consent().isChecked()),"a changed incident requires fresh explicit review");
  await consent().check();await resume().click();
  await page.getByText("目前没有暂停工作",{exact:true}).waitFor();
  sent=await posts();
  check(sent[1].options.body.epoch===4 && sent[1].options.body.incident_id==="d".repeat(32) && sent[1].options.noRetry===true,"confirmed recovery sends the exact new epoch and incident in one keyed POST");

  await page.evaluate(()=>{const f=window.quarantineFixture;f.quarantine=f.fresh(6,"e");f.lose=true;});
  await refresh();await consent().check();await resume().click();
  await page.getByText(/恢复响应丢失/).waitFor();
  await refresh();
  check(await resume().count()===0 && await page.getByRole("button",{name:"查询这次恢复的结果",exact:true}).isVisible(),"unknown recovery result permits only querying the original request");
  check(!(await page.evaluate(()=>sessionStorage.getItem("yuanxingmu.protection.requests"))).includes("SECRET-REASON"),"pending recovery storage contains no incident reason or document content");
  await page.evaluate(()=>window.quarantineFixture.rebuild());await open();
  check(await resume().count()===0,"component reconstruction preserves the unknown original recovery");
  const beforeQuery=await posts();
  await page.evaluate(()=>{window.quarantineFixture.missingOriginal=true;});
  await page.getByRole("button",{name:"查询这次恢复的结果",exact:true}).click();
  await page.getByText(/原请求尚无法确认/).waitFor();
  check(await resume().count()===0 && (await posts()).length===beforeQuery.length,"an unavailable original request never enables a second recovery POST");
  await page.evaluate(()=>{window.quarantineFixture.missingOriginal=false;});
  await page.evaluate(()=>window.quarantineFixture.finish());
  await page.getByRole("button",{name:"查询这次恢复的结果",exact:true}).click();
  await page.getByText("目前没有暂停工作",{exact:true}).waitFor();
  const requests=await page.evaluate(()=>window.quarantineFixture.calls.filter(call=>call.path.startsWith("/api/requests/")));
  check((await posts()).length===beforeQuery.length && requests.some(call=>call.path.endsWith(beforeQuery.at(-1).options.key)),"unknown recovery is reconciled with original-key GET and no second POST");

  await page.evaluate(()=>{const f=window.quarantineFixture;f.quarantine=f.fresh(8,"f");f.originalSetItem=Storage.prototype.setItem;
    Storage.prototype.setItem=function(key,value){if(key==="yuanxingmu.protection.requests")throw new DOMException("fixture storage failure","QuotaExceededError");return f.originalSetItem.call(this,key,value);};});
  await refresh();await consent().check();const beforeStorage=(await posts()).length;await resume().click();
  await page.getByText(/浏览器无法保存这次操作标识，尚未提交/).waitFor();
  check((await posts()).length===beforeStorage,"browser storage failure prevents resume POST before dispatch");
  await page.evaluate(()=>{Storage.prototype.setItem=window.quarantineFixture.originalSetItem;});
  await refresh();
  check(await resume().isDisabled() && await page.getByRole("button",{name:"查询这次恢复的结果",exact:true}).count()===0,"storage recovery does not strand an unsubmitted request and still requires consent");

  await page.setViewportSize({width:390,height:844});
  await page.locator("#protection-dialog").ariaSnapshot();
  check(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),"mobile quarantine page has no body overflow");
  check(await page.locator("#protection-dialog").evaluate(el=>el.scrollWidth<=el.clientWidth+1),"mobile quarantine reasons fit inside the actual dialog");
  await page.screenshot({path:"../output/playwright/quarantine-v1/pause-mobile.png",fullPage:true});
  await page.setViewportSize({width:1180,height:940});
  await page.screenshot({path:"../output/playwright/quarantine-v1/pause-desktop.png",fullPage:true});
  await page.evaluate(()=>{const q=window.quarantineFixture.quarantine;q.incident.reason=q.incidents[0].reason="X".repeat(700);});
  await refresh();await page.setViewportSize({width:390,height:844});
  check(await page.locator("#protection-dialog").evaluate(el=>el.scrollWidth<=el.clientWidth+1),"a long unbroken incident reason wraps within the mobile review dialog");
  await page.evaluate(()=>{window.quarantineFixture.authorized=false;window.quarantineFixture.widget.reset();});
  check(await page.locator("#protection-dialog").isHidden() && !(await page.locator("#protection-dialog").innerText()).includes("SECRET-REASON"),"authorization reset closes and clears the paused incident view");
  if(failures.length) throw Error(JSON.stringify({scope:"Quarantine browser fixture only",passed:passed.length,failures}));
  return {scope:"Quarantine browser fixture only; no actual service, model, command or notification",total:passed.length,passed};
}
