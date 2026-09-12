// Real protection component in a browser, with an in-memory host API fixture.
// No actual profile, model, command, native Agent or outbound effect is run.
async (page) => {
  const passed = [];
  const check = (value, name) => { if (!value) throw Error(name); passed.push(name); };
  await page.route("**/*", route => route.abort());
  await page.route("http://127.0.0.1:18989/layer-settings-fixture", route => route.fulfill({contentType:"text/html", body:
    '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>逐层防护设置测试</title></head><body><main class="wrap"><div id="fixture-controls"></div></main></body></html>'}));
  await page.goto("http://127.0.0.1:18989/layer-settings-fixture");
  await page.setViewportSize({width:1180,height:920});
  await page.addStyleTag({path:"yuanxingmu/dashboard/web/styles.css"});
  await page.addScriptTag({path:"yuanxingmu/dashboard/web/protection.js"});
  await page.evaluate(() => {
    sessionStorage.removeItem("yuanxingmu.protection.requests");
    const f = window.layerSettingsFixture = {id:"a".repeat(32), posts:[], supported:true, skillSupport:true, editable:true,
      settings:{mode:"enforce",input_enabled:true,memory_enabled:true,command_enabled:true,alignment_enabled:true,foundation_enabled:true,
        input_mode:"observe",memory_mode:"inherit",command_mode:"inherit",alignment_mode:"inherit",foundation_mode:"inherit",
        foundation_config_enabled:true,skill_semantic_enabled:false,skill_rules_enabled:true}};
    f.baseline=structuredClone(f.settings);f.events=[];f.revision=0;
    const node=(tag,className,text)=>{const e=document.createElement(tag);e.className=className||"";if(text!==undefined)e.textContent=text;return e;};
    const api=async(path,options={})=>{
      if(options.method === "POST") {
        f.posts.push(structuredClone(options.body));
        const changes={};for(const [name,after] of Object.entries(options.body.settings))if(f.settings[name]!==after)changes[name]={before:f.settings[name],after};
        f.events.unshift({time:"2026-09-12T00:00:00Z",code:"operator_settings_changed",layer:"foundation",reason:"本人保存了设置",settings_history:{source:"workbench",intent:options.body.intent||"set",changes}});
        Object.assign(f.settings,options.body.settings);f.revision++;return {job:{id:"b".repeat(32),status:"succeeded"}};
      }
      if(path.endsWith("/tools")) return {supported:false};
      if(!path.endsWith("/protection")) throw Error("Unexpected fixture endpoint");
      const layers={},layer_modes={},effective_modes={};
      for(const name of ["input","memory","command","alignment","foundation"]) {
        layers[name]=f.settings[name+"_enabled"];layer_modes[name]=f.settings[name+"_mode"];
        effective_modes[name]=!layers[name] ? "disabled" : layer_modes[name]==="inherit" ? f.settings.mode : layer_modes[name];
      }
      const changes={};for(const [name,after] of Object.entries(f.baseline))if(f.settings[name]!==after)changes[name]={before:f.settings[name],after};
      return {supported:true,objective:"整理本机资料，外发先由本人核对。",editable:f.editable,live_settings:true,
        per_layer_settings:f.supported,mode:f.settings.mode,layers,layer_modes,effective_modes,
        skill_rules_settings:f.skillSupport,skill_purpose:f.skillSupport,
        settings_history:f.supported,policy_sha256:String(f.revision).padStart(64,"0"),
        baseline:f.supported?{supported:true,sha256:"d".repeat(64),settings:f.baseline,changes}:{supported:false,reason:"这份旧工作没有创建时设置"},
        foundation_scans:{configuration:f.settings.foundation_config_enabled,skill_semantic:f.settings.skill_semantic_enabled,
          ...(f.skillSupport?{skill_rules:f.settings.skill_rules_enabled}:{})},events:structuredClone(f.events)};
    };
    const widget=window.createYuanxingmuProtection({api,node,authorized:()=>true});widget.boot();
    document.getElementById("fixture-controls").append(widget.profileButton({id:f.id,name:"逐层设置"}));
  });
  await page.getByRole("button",{name:"防护记录",exact:true}).click();
  await page.locator("#protection-dialog").ariaSnapshot();
  const content=await page.locator("#protection-dialog").innerText();
  check(content.includes("外部内容检查 · 只记录，不拦截") && content.includes("危险命令检查 · 拦截或等本人确认"),"summary displays each layer's effective intervention");
  check(!content.includes("当前仅记录检查结果，不阻断操作"),"mixed policy is never described as global observation");
  await page.getByText("修改防护开关",{exact:true}).click();
  check(await page.getByLabel("外部内容检查的处理方式",{exact:true}).inputValue()==="observe","layer override is loaded into its control");
  check(!(await page.getByLabel("技能语义检查",{exact:true}).isChecked()) && await page.getByLabel("基础配置检查（规则与语义）",{exact:true}).isChecked(),"configuration and skill semantic controls are independent");
  check(await page.getByLabel("技能规则检查",{exact:true}).isChecked(),"new profiles load the independent skill rules control");
  await page.getByLabel("技能规则检查",{exact:true}).uncheck();
  await page.getByLabel("危险命令检查的处理方式",{exact:true}).selectOption("enforce");
  await page.getByLabel("默认处理方式",{exact:true}).selectOption("observe");
  await page.getByRole("button",{name:"保存防护设置",exact:true}).click();
  await page.getByText("危险命令检查 · 拦截或等本人确认",{exact:true}).waitFor();
  check((await page.evaluate(()=>window.layerSettingsFixture.posts))[0].settings.command_mode==="enforce","saved payload keeps explicit enforcement under an observe default");
  check((await page.evaluate(()=>window.layerSettingsFixture.posts))[0].settings.skill_rules_enabled===false,"saving a rules change does not enable skill semantics");
  check((await page.locator("#protection-dialog").innerText()).includes("记忆防投毒 · 只记录，不拦截"),"inherited layers follow the new default");
  await page.getByText("修改防护开关",{exact:true}).click();
  await page.getByRole("button",{name:"恢复全部开启",exact:true}).click();
  check(await page.evaluate(()=>window.layerSettingsFixture.posts.length)===1,"restore button prepares the form without writing settings");
  check(await page.getByLabel("危险命令检查的处理方式",{exact:true}).inputValue()==="inherit" && await page.getByLabel("技能语义检查",{exact:true}).isChecked(),"restore clears overrides and enables both scan options");
  check(await page.getByLabel("技能规则检查",{exact:true}).isChecked(),"recommended defaults restore skill rules independently");
  await page.getByRole("button",{name:"保存防护设置",exact:true}).click();
  await page.getByText("记忆防投毒 · 拦截或等本人确认",{exact:true}).waitFor();
  check((await page.evaluate(()=>window.layerSettingsFixture.posts))[1].settings.mode==="enforce","restored defaults become effective only after save");
  await page.getByText("修改防护开关",{exact:true}).click();
  await page.getByRole("button",{name:"恢复创建时设置",exact:true}).click();
  check(await page.evaluate(()=>window.layerSettingsFixture.posts.length)===2,"creation restore previews values without a write");
  check((await page.locator(".settings-preview").innerText()).includes("技能语义检查：开启 → 关闭"),"restore preview displays specific before and after values");
  await page.getByRole("button",{name:"保存防护设置",exact:true}).click();
  await page.getByText("外部内容检查 · 只记录，不拦截",{exact:true}).waitFor();
  const restored=await page.evaluate(()=>window.layerSettingsFixture.posts[2]);
  check(restored.intent==="restore_creation" && restored.baseline_sha256==="d".repeat(64) && restored.expected_policy_sha256==="2".padStart(64,"0"),"restore submits the reviewed baseline and current-policy hashes");
  check((await page.locator("#protection-dialog").innerText()).includes("工作台 · 恢复创建时设置"),"history identifies the real entry and restore action");
  await page.getByText("修改防护开关",{exact:true}).click();
  await page.getByRole("button",{name:"恢复创建时设置",exact:true}).click();
  await page.getByLabel("技能语义检查",{exact:true}).check();
  await page.getByRole("button",{name:"保存防护设置",exact:true}).click();
  const edited=await page.evaluate(()=>window.layerSettingsFixture.posts[3]);
  check(edited.intent==="set" && !("baseline_sha256" in edited) && edited.expected_policy_sha256==="3".padStart(64,"0"),"editing a restore preview keeps the read version while becoming an ordinary change");
  await page.getByText("修改防护开关",{exact:true}).click();
  await page.setViewportSize({width:390,height:844});
  await page.locator("#protection-dialog").ariaSnapshot();
  check(await page.locator("#protection-dialog").evaluate(el=>el.scrollWidth<=el.clientWidth+1),"settings fit within the mobile dialog");
  await page.screenshot({path:"output/playwright/layer-settings-mobile.png",fullPage:true});
  await page.getByRole("button",{name:"保存防护设置",exact:true}).scrollIntoViewIfNeeded();
  await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
  await page.screenshot({path:"output/playwright/layer-settings-controls-mobile.png",fullPage:true});
  await page.evaluate(()=>{window.layerSettingsFixture.skillSupport=false;});
  await page.getByRole("button",{name:"刷新记录",exact:true}).click();
  await page.getByText("修改防护开关",{exact:true}).click();
  check(await page.getByLabel("技能规则检查",{exact:true}).count()===0 && await page.getByLabel("技能语义检查",{exact:true}).count()===1,"earlier per-layer profiles retain their controls without gaining an unsupported skill switch");
  await page.getByRole("button",{name:"保存防护设置",exact:true}).click();
  check(!("skill_rules_enabled" in await page.evaluate(()=>window.layerSettingsFixture.posts.at(-1).settings)),"earlier per-layer saves omit the new skill field");
  await page.evaluate(()=>{window.layerSettingsFixture.supported=false;});
  await page.getByRole("button",{name:"刷新记录",exact:true}).click();
  await page.getByText("修改防护开关",{exact:true}).click();
  check(await page.getByLabel("外部内容检查的处理方式",{exact:true}).count()===0,"legacy profiles do not offer unsupported per-layer controls");
  await page.getByRole("button",{name:"保存防护设置",exact:true}).click();
  const old=await page.evaluate(()=>window.layerSettingsFixture.posts.at(-1).settings);
  check(Object.keys(old).length===6 && !("input_mode" in old) && !("skill_semantic_enabled" in old),"legacy save sends only the original five flags and mode");
  return {scope:"Browser UI fixture, not native Agent validation",total:passed.length,passed};
}
