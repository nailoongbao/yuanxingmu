/* Show observed host decisions, not a guessed safety score. */
(() => {
  "use strict";
  window.createYuanxingmuProtection = function ({api, node, authorized}) {
    let dialog, content, title, selected, generation = 0;
    const names = {foundation:"安装与技能检查",input:"外部内容检查",memory:"记忆防投毒",alignment:"任务偏移检查",command:"危险命令检查"};
    const modeNames = {enforce:"拦截或等本人确认",observe:"只记录，不拦截",disabled:"已关闭，不检查"};
    const settingLabels={mode:"默认处理方式",foundation_config_enabled:"基础配置检查",skill_semantic_enabled:"技能语义检查",skill_rules_enabled:"技能规则检查"};
    for(const [name,label] of Object.entries(names)){settingLabels[name+"_enabled"]=label;settingLabels[name+"_mode"]=label+"的处理方式";}
    const settingValue=value=>value===true?"开启":value===false?"关闭":value==="inherit"?"跟随默认":modeNames[value]||"未知";
    function appendChanges(parent,changes) {
      const list=node("ul","");
      for(const [name,pair] of Object.entries(changes||{})) if(settingLabels[name] && pair && "before" in pair && "after" in pair) {
        list.append(node("li","",settingLabels[name]+"："+settingValue(pair.before)+" → "+settingValue(pair.after)));
      }
      parent.append(list.childElementCount?list:node("p","field-note","设置值没有变化。"));
    }
    const resultNames = {allow:"允许继续",block:"已拦截",review:"需要本人核对"};
    const reviewNames = {pending:"等待你确认",approved:"已允许一次，等待领取",consumed:"这一次许可已使用",denied:"你已拒绝",blocked:"防护检查已拦截",expired:"等待已超时",interrupted:"审批服务已重启，本次许可失效"};
    const storageKey="yuanxingmu.protection.requests",pending=new Map();
    const alerts=new Map(),baseTitle=document.title;
    try {
      const stored=JSON.parse(sessionStorage.getItem(storageKey) || "[]");
      if(Array.isArray(stored)) for(const [slot,item] of stored.slice(-256)) {
        if(/^[a-f0-9]{32}:(?:settings|resume|[a-f0-9]{32})$/.test(slot) && /^[a-f0-9]{32}$/.test(item?.key)
            && (!item.jobId || /^[a-f0-9]{32}$/.test(item.jobId))) pending.set(slot,item);
      }
    } catch { /* A corrupt browser cache never creates an approval. */ }
    function remember() {sessionStorage.setItem(storageKey,JSON.stringify([...pending]));}
    async function submitOnce(slot,path,body) {
      let saved=pending.get(slot),job;
      if(!saved) {
        if(!path) throw new Error("上次操作已结束，请刷新记录。");
        saved={key:crypto.randomUUID().replaceAll("-","")};pending.set(slot,saved);
        try {remember();} catch(error) {pending.delete(slot);throw new Error("浏览器无法保存这次操作标识，尚未提交。请恢复本标签页存储后重试。");}
        try {job=(await api(path,{method:"POST",key:saved.key,noRetry:true,body})).job;}
        catch(error) {if(error.uncertain === false && error.status >= 400 && error.status < 500){pending.delete(slot);remember();}throw error;}
      } else job=(await api(saved.jobId ? "/api/jobs/"+saved.jobId : "/api/requests/"+saved.key)).job;
      if(!/^[a-f0-9]{32}$/.test(job?.id)) throw new Error("没有收到可核对的原操作记录。");
      saved.jobId=job.id;remember();
      for(let i=0;i<60 && job.status === "running";i++) {
        await new Promise(resolve=>setTimeout(resolve,500));job=(await api("/api/jobs/"+saved.jobId)).job;
      }
      if(["succeeded","failed"].includes(job.status)){pending.delete(slot);remember();}
      if(job.status !== "succeeded") throw new Error(job.error?.message || "处理结果尚未确认，请查询原操作记录。");
    }
    function settings(value,id,own) {
      const panel=node("details","prompt-details");panel.append(node("summary","","修改防护开关"));
      panel.append(node("p","field-note",value.editable ? value.live_settings ? "可以在工作运行时修改。后续操作使用新设置，未使用的审批和草稿会作废；安装检查下次启动时重做。暂停状态和已开始的操作不会因此改变。" : "修改只影响后续操作，已积累的资料权限和检查记录会保留。未使用的审批和草稿会作废。" : "当前不能修改设置。旧版本工作需先暂时关闭；存储故障需先处理。"));
      const form=node("form",""),group=node("fieldset","mail-drafts"),inputs={},layerModes={},scans={};group.disabled=!value.editable;
      let intent="set";
      const preview=node("div","settings-preview");preview.setAttribute("aria-live","polite");
      const slot=id+":settings";
      for(const [name,labelText] of Object.entries(names)) {
        const label=node("label",""),input=node("input","");input.type="checkbox";input.checked=Boolean(value.layers[name]);
        inputs[name]=input;label.append(input,node("span","",labelText));group.append(label);
        if(value.per_layer_settings) {
          const select=node("select","");select.setAttribute("aria-label",labelText+"的处理方式");
          for(const [key,text] of [["inherit","跟随默认处理方式"],...Object.entries(modeNames).filter(([key])=>key!=="disabled")]) {const option=node("option","",text);option.value=key;select.append(option);}
          select.value=value.layer_modes?.[name] || "inherit";select.disabled=!input.checked;layerModes[name]=select;
          input.addEventListener("change",()=>{select.disabled=!input.checked;});group.append(select);
        }
      }
      const mode=node("select","");mode.setAttribute("aria-label","默认处理方式");
      for(const [key,label] of [["enforce","拦截或等本人确认"],["observe","只记录，不拦截"]]) {const option=node("option","",label);option.value=key;mode.append(option);}
      mode.value=value.mode;
      group.append(node("p","field-note",value.per_layer_settings ? "默认处理方式只影响选择“跟随默认”的层；关闭的层不会检查。" : "这个旧版本工作支持五层开关和全局处理方式。新建工作可分别设置每层的处理方式。"),mode);
      if(value.per_layer_settings) {
        group.append(node("h4","","安装检查的内容"));
        const scanOptions=[["foundation_config_enabled","基础配置检查（规则与语义）",value.foundation_scans?.configuration],["skill_semantic_enabled","技能语义检查",value.foundation_scans?.skill_semantic]];
        if(value.skill_rules_settings)scanOptions.push(["skill_rules_enabled","技能规则检查",value.foundation_scans?.skill_rules]);
        for(const [key,text,enabled] of scanOptions) {
          const label=node("label",""),input=node("input","");input.type="checkbox";input.checked=enabled!==false;
          input.setAttribute("aria-label",text);scans[key]=input;label.append(input,node("span","",text));group.append(label);
        }
        group.append(node("p","field-note",value.skill_rules_settings ? "规则与语义可分别关闭；文件安全读取和固定快照仍保留。语义检查同时核对技能说明与所属文件的行为。缺少用途说明不能算完成检查。" : "安装与技能检查开启时，技能规则和安全快照仍会检查。这个旧版本不支持独立技能规则开关。"));
      }
      const reset=node("button","button button-quiet","恢复全部开启"),save=node("button","button button-secondary","保存防护设置");reset.type="button";save.type="submit";
      reset.addEventListener("click",()=>{for(const input of [...Object.values(inputs),...Object.values(scans)]) input.checked=true;for(const select of Object.values(layerModes)){select.value="inherit";select.disabled=false;}mode.value="enforce";
        intent="reset_defaults";preview.replaceChildren(node("p","field-note","已填入全部开启、默认拦截的推荐设置。保存后生效；这不是恢复创建时设置。"));});
      if(value.baseline?.supported && /^[a-f0-9]{64}$/.test(value.baseline.sha256) && /^[a-f0-9]{64}$/.test(value.policy_sha256)) {
        const restore=node("button","button button-quiet","恢复创建时设置");restore.type="button";
        restore.addEventListener("click",()=>{
          const saved=value.baseline.settings;
          for(const [name,input] of Object.entries(inputs))input.checked=saved[name+"_enabled"];
          for(const [name,select] of Object.entries(layerModes)){select.value=saved[name+"_mode"];select.disabled=!inputs[name].checked;}
          for(const [name,input] of Object.entries(scans))input.checked=saved[name];mode.value=saved.mode;
          intent="restore_creation";preview.replaceChildren(node("p","field-note","已填入创建时确认的设置，请核对下面的变化。点击保存后才生效；这不会解除暂停或撤权。"));
          appendChanges(preview,value.baseline.changes);
        });group.append(restore);
      } else group.append(node("p","field-note",value.baseline?.reason || "这份工作没有可核对的创建时设置快照。"));
      form.addEventListener("change",()=>{if(intent!=="set"){intent="set";preview.replaceChildren(node("p","field-note","预览已手动改动，将按普通设置修改保存。"));}});
      const feedback=node("p","form-message");feedback.setAttribute("role","status");
      group.append(reset,preview,save);form.append(group,feedback);panel.append(form);
      if(pending.has(slot)) {
        group.disabled=true;
        const query=node("button","button button-secondary","查询上次保存的结果");query.type="button";
        query.addEventListener("click",async()=>{query.disabled=true;try{await submitOnce(slot);if(own===generation && id===selected) await load();}catch(error){feedback.textContent=error.message+" 不会重新保存。";query.disabled=false;}});
        form.append(query);
      }
      form.addEventListener("submit",async event=>{
        event.preventDefault();if(!value.editable || group.disabled) return;group.disabled=true;
        const changes={mode:mode.value,...Object.fromEntries(Object.entries(inputs).map(([name,input])=>[name+"_enabled",input.checked]))};
        for(const [name,select] of Object.entries(layerModes)) changes[name+"_mode"]=select.value;
        for(const [name,input] of Object.entries(scans)) changes[name]=input.checked;
        try {
          const body={settings:changes};
          if(value.settings_history) {body.intent=intent;body.expected_policy_sha256=value.policy_sha256;}
          if(intent==="restore_creation") {body.intent=intent;body.baseline_sha256=value.baseline.sha256;body.expected_policy_sha256=value.policy_sha256;}
          await submitOnce(slot,"/api/profiles/"+id+"/protection",body);
          if(own===generation && id===selected) await load();
        } catch(error) {feedback.textContent=error.message+" 此页面不会重复提交，请刷新后核对实际设置。";}
      });
      return panel;
    }
    function quarantine(value,id,own) {
      const panel=node("section","mail-draft-card");
      if(!value) return panel;
      panel.append(node("h3","",value.paused ? "工作已暂停，需要你处理" : "目前没有暂停工作"));
      if(value.storage_fault) {
        panel.replaceChildren(node("h3","","防护状态写入失败，后续操作已停止"),node("p","","请保留防护记录，检查本机存储并重启服务。此页面暂不能恢复执行。"));
        panel.setAttribute("role","alert");return panel;
      }
      if(!value.paused) return panel;
      panel.setAttribute("role","alert");
      const incidents=Array.isArray(value.incidents) ? value.incidents.filter(item=>item && item.resolved_at===null) : [];
      const complete=Number.isSafeInteger(value.unresolved_count) && value.unresolved_count > 0 && incidents.length===value.unresolved_count
        && new Set(incidents.map(item=>item.id)).size===incidents.length
        && incidents.every(item=>/^[a-f0-9]{32}$/.test(item.id) && Number.isSafeInteger(item.epoch) && item.epoch>0 && item.epoch<=value.epoch && typeof item.reason==="string" && item.reason.trim())
        && value.incident?.id===value.incident_id && value.incident?.epoch===value.epoch
        && incidents.some(item=>item.id===value.incident_id && item.epoch===value.epoch && item.reason===value.incident.reason);
      if(!complete) {
        panel.append(node("p","form-message error","暂停记录不完整或已改变，当前不能恢复。请重新读取全部未处理原因。"));return panel;
      }
      panel.append(node("p","", "请核对全部 "+incidents.length+" 条未处理原因："));
      for(const item of incidents) panel.append(node("p","",(names[item.layer] || "防护")+"："+item.reason));
      panel.append(node("p","field-note","暂停期间，这份工作及它分出的任务不能再取得新的工具执行许可。未使用的审批和待确认操作已作废；已经开始的操作仍需核对结果。"));
      panel.append(node("p","field-note","先移除可疑资料或修正任务内容，再恢复。恢复不会自动重试旧操作；需要回到聊天页重新发起。"));
      if(!value.can_resume || !Number.isSafeInteger(value.epoch) || value.epoch < 1 || !/^[a-f0-9]{32}$/.test(value.incident_id)) return panel;
      const slot=id+":resume",feedback=node("p","form-message");feedback.setAttribute("role","status");
      if(pending.has(slot)) {
        const query=node("button","button button-secondary","查询这次恢复的结果");query.type="button";
        query.addEventListener("click",async()=>{query.disabled=true;try{await submitOnce(slot);if(own===generation && id===selected)await load();}catch(error){feedback.textContent=error.message+" 不会再次提交恢复。";query.disabled=false;}});
        panel.append(query,feedback);return panel;
      }
      const label=node("label",""),check=node("input","");check.type="checkbox";
      label.append(check,node("span","","我已核对全部未处理原因，并处理了可疑内容"));
      const resume=node("button","button button-primary","恢复这份工作");resume.type="button";resume.disabled=true;
      check.addEventListener("change",()=>{resume.disabled=!check.checked;});
      resume.addEventListener("click",async()=>{
        if(!check.checked)return;resume.disabled=check.disabled=true;
        try{await submitOnce(slot,"/api/profiles/"+id+"/quarantine/resume",{epoch:value.epoch,incident_id:value.incident_id,confirm:"resume"});if(own===generation&&id===selected)await load();}
        catch(error){feedback.textContent=error.message+" 请刷新后核对最新状态，此页面不会重复恢复。";}
      });
      panel.append(label,resume,feedback);return panel;
    }
    function reviewDisplay(entry) {
      const args=entry.arguments,object=value=>value!==null && typeof value==="object" && !Array.isArray(value);
      const source=args.source_tool,submitted=object(source)?source.arguments:null;
      // Source is the host-stored candidate, not the model's explanation or a
      // guess derived from its shell command. Unknown shapes stay generic.
      const fileRequest=["terminal","exec"].includes(entry.tool) && object(source)
        && Object.keys(source).length===3 && source.tool==="file_write" && source.name==="write_file"
        && object(submitted) && Object.keys(submitted).length===2
        && typeof submitted.path==="string" && submitted.path.trim() && !submitted.path.includes("\0")
        && typeof submitted.content==="string";
      const summary=node("section","tool-review-summary");
      function field(label,value,kind,missing) {
        summary.append(node("h4","",label));
        if(typeof value==="string") {
          summary.append(node("pre",(kind==="file-content"?"mail-full-body ":"")+"tool-review-"+kind,value));
          if(value.length===0)summary.append(node("p","field-note","此项为空。"));
        } else summary.append(node("p","field-note",missing));
      }
      if(fileRequest) {
        summary.append(node("h3","","文件工具申请"),node("p","field-note","工具：写文件（write_file）"),
          node("p","field-note","下面是文件工具提交的路径和内容。本次待批准的实际命令与输入，请展开完整原始参数一并核对。"));
        field("请求的目标路径",submitted.path,"file-path","");
        field("请求写入的全文",submitted.content,"file-content","");
      } else {
        summary.append(node("h3","",["terminal","exec"].includes(entry.tool)?"终端执行申请":"工具执行申请"));
        field("实际命令",args.command,"command","没有可直接显示的命令文本，请核对完整原始参数。");
        field("工作目录",args.cwd,"cwd","本次参数未提供可直接显示的工作目录。");
        field("标准输入",args.stdin_data,"stdin",Object.hasOwn(args,"stdin_data")?"输入格式无法直接显示，请核对完整原始参数。":"本次未提供标准输入。");
      }
      const raw=node("details","prompt-details tool-review-original");
      raw.append(node("summary","","查看完整原始参数（命令、目录、来源和输入）"),
        node("pre","mail-full-body tool-review-raw",JSON.stringify({tool:entry.tool,arguments:entry.arguments},null,2)));
      if(typeof entry.reason==="string" && entry.reason) {
        raw.append(node("h4","","检查说明原文"),node("pre","mail-full-body",entry.reason));
      }
      return [summary,raw];
    }
    async function reviews(id, own) {
      const value = await api("/api/profiles/" + id + "/tools");
      if (own !== generation || id !== selected || !value.supported) return;
      const section=node("section", "mail-drafts");
      section.append(node("h3","","需要你确认的工具操作"),node("p","field-note","只允许这一次，不会记成以后都允许。五分钟内没有处理，操作就会停止；允许后仍受资料和联网权限限制。"));
      if (!value.reviews.length) section.append(node("p","field-note","目前没有等待确认的工具操作。"));
      for (const item of value.reviews) {
        const row=node("article","mail-draft-card");
        row.append(node("strong","",(item.tool === "terminal" || item.tool === "exec" ? "工具执行" : item.tool)+" · "+(reviewNames[item.status] || "状态待确认")));
        const inspect=node("button","button button-secondary","查看这一次操作");inspect.type="button";
        inspect.addEventListener("click", async()=>{
          inspect.disabled=true;
          try {
            const detail=await api("/api/profiles/"+id+"/tools/"+item.id);
            if (own !== generation || id !== selected) return;
            const entry=detail.review;
            if(!entry || entry.id !== item.id || !/^[a-f0-9]{64}$/.test(entry.digest) || typeof entry.tool !== "string" || !entry.tool
                || !entry.arguments || typeof entry.arguments !== "object" || Array.isArray(entry.arguments)
                || !Object.hasOwn(reviewNames,entry.status) || typeof detail.active !== "boolean") throw new Error("操作详情不完整，无法确认。请重新读取完整参数。");
            row.replaceChildren(node("strong","",reviewNames[entry.status] || "状态待确认"),...reviewDisplay(entry));
            if (entry.status !== "pending" || !detail.active) return;
            const slot=id+":"+entry.id;
            if(pending.has(slot)) {
              const query=node("button","button button-secondary","查询这一次确认的结果"),feedback=node("p","form-message");query.type="button";
              query.addEventListener("click",async()=>{query.disabled=true;try{await submitOnce(slot);if(own===generation && id===selected) await load();}catch(error){feedback.textContent=error.message+" 不会再次提交确认。";query.disabled=false;}});
              row.append(query,feedback);return;
            }
            const label=node("label",""),check=node("input","");check.type="checkbox";
            label.append(check,node("span","","我已核对这次操作及完整参数，只允许执行一次"));
            const approve=node("button","button button-primary","只允许这一次"),deny=node("button","button button-outline-danger","拒绝这一次");
            approve.type=deny.type="button";approve.disabled=true;
            check.addEventListener("change",()=>{approve.disabled=!check.checked;});
            const feedback=node("p","form-message");feedback.setAttribute("role","status");
            async function decide(action) {
              approve.disabled=deny.disabled=check.disabled=true;
              try {
                await submitOnce(slot,"/api/profiles/"+id+"/tools/"+entry.id+"/"+action,{digest:entry.digest,confirm:action});
                if (own === generation && id === selected) await load();
              } catch(error) {
                // Never retry an approval POST after an uncertain response.
                feedback.textContent=error.message+" 请刷新记录核对；此页面不会重复提交。";
              }
            }
            approve.addEventListener("click",()=>{if(check.checked) void decide("approve");});
            deny.addEventListener("click",()=>void decide("deny"));
            const confirmation=node("div","mail-review-confirmation"),actions=node("div","dialog-actions");
            actions.append(approve,deny);confirmation.append(label,actions);row.append(confirmation,feedback);
          } catch(error) {row.append(node("p","form-message error",error.message));inspect.disabled=false;}
        });
        row.append(inspect);section.append(row);
      }
      content.prepend(section);
    }
    async function load() {
      const own = ++generation, id = selected;
      content.replaceChildren(node("p","field-note","正在读取本机防护记录…"));
      try {
        const value = await api("/api/profiles/" + id + "/protection");
        if (own !== generation || id !== selected) return;
        content.replaceChildren();
        if (!value.supported) {content.append(node("p","field-note",value.message));return;}
        if(value.quarantine) content.append(quarantine(value.quarantine,id,own));
        content.append(node("h3","","你确定的工作目标"),node("p","mail-full-body",value.objective));
        if(value.judge) content.append(node("p","field-note",(value.judge.independent ? "独立检查模型：" : "检查与工作使用同一模型：")+value.judge.id+"；每次最多等待 "+value.judge.timeout_seconds+" 秒。"));
        content.append(node("p","field-note","默认处理方式："+(modeNames[value.mode] || value.mode)+(value.per_layer_settings ? "。每层实际采用的方式见下方。" : "。")));
        if(value.buffered_response && value.layers?.alignment) content.append(node("p","field-note","回答会收齐后检查，再显示到聊天页，因此不会逐字实时出现。"));
        if(value.input_containment) content.append(node("p","field-note","可疑外部资料会被整段扣留，其他已授权工作继续，不需要你反复恢复。危险操作、记忆投毒与回答越界仍会暂停工作。"));
        const layers = node("div","mail-drafts");
        for (const [name,label] of Object.entries(names)) {
          const effective=value.effective_modes?.[name] || (value.layers?.[name] ? value.mode : "disabled");
          layers.append(node("p","",label + " · " + (modeNames[effective] || "状态未知")));
        }
        if(value.foundation_scans) layers.append(node("p","field-note","基础配置检查："+(value.foundation_scans.configuration ? "开启" : "关闭")+"；技能语义检查："+(value.foundation_scans.skill_semantic ? "开启" : "关闭")+"。安装与技能检查整层关闭时，这些检查均不执行。"));
        if(value.skill_rules_settings)layers.append(node("p","field-note","技能规则检查："+(value.foundation_scans?.skill_rules ? "开启" : "关闭")+"。"));
        layers.append(node("p","field-note",value.skill_purpose ? "技能用途对照：随技能语义检查执行，比较固定 SKILL.md 与所属文件；用途缺失会要求先补充说明。" : "这份旧工作没有本版的技能用途对照；原有技能检查保持原版本范围。"));
        content.append(layers,node("h3","","最近发生的检查"));
        layers.append(node("p","field-note","选中的技能："+(value.skills?.names?.join("、") || "无")+"；固定文件 "+(value.skills?.files || 0)+" 份。"),settings(value,id,own));
        if (!value.events.length) content.append(node("p","field-note","还没有本次检查记录。开启功能不等于已经验证每个场景。"));
        for (const event of value.events) {
          const row = node("article","mail-draft-card");
          const observed = event.code === "operator_settings_changed" ? "防护设置已更新" : event.assessed === false ? "未检查（已关闭）" : event.enforced === false && event.would_verdict ? "仅观察：原本会" + (resultNames[event.would_verdict] || event.would_verdict) : resultNames[event.verdict] || "检查未完成";
          row.append(node("strong","",(names[event.layer] || event.layer || "防护") + " · " + observed));
          row.append(node("p","",event.reason || ""));
          if(event.settings_history) {
            const history=event.settings_history;
            const sources={workbench:"工作台",cli:"命令行",host:"主机管理入口"},intents={set:"修改设置",reset_defaults:"恢复全部开启",restore_creation:"恢复创建时设置"};
            row.append(node("p","field-note",(sources[history.source]||"主机")+" · "+(intents[history.intent]||"修改设置")));
            appendChanges(row,history.changes);
          }
          row.append(node("small","field-note",new Date(event.time).toLocaleString("zh-CN") + (event.evidence?.judge_valid ? " · 收到有效模型判定" : "")));
          content.append(row);
        }
        if (value.foundation) {
          if(value.foundation.current_policy === false) content.append(node("p","form-message","下面的安装检查使用的是旧设置；当前设置尚未完成启动检查。"));
          const details=node("details","prompt-details");details.append(node("summary","","查看安装检查原始记录"),node("pre","mail-full-body",JSON.stringify(value.foundation,null,2)));content.append(details);
        }
        await reviews(id,own);
      } catch(error) {if (own === generation) content.replaceChildren(node("p","form-message error",error.message));}
    }
    function boot() {
      dialog=node("dialog","mail-dialog");dialog.id="protection-dialog";dialog.setAttribute("aria-labelledby","protection-title");
      const body=node("div","dialog-body"), head=node("div","mail-dialog-heading");
      title=node("h2","","防护记录");title.id="protection-title";
      const close=node("button","button button-quiet","关闭");close.type="button";close.addEventListener("click",()=>dialog.close());
      const refresh=node("button","button button-secondary","刷新记录");refresh.type="button";refresh.addEventListener("click",()=>void load());
      const notifications=node("button","button button-secondary","开启本机桌面提醒");notifications.type="button";
      notifications.disabled=!("Notification" in window);
      notifications.addEventListener("click",async()=>{
        try{const permission=await Notification.requestPermission();notifications.textContent=permission==="granted"?"已开启本机桌面提醒":"浏览器未允许桌面提醒";}catch{notifications.textContent="浏览器不支持桌面提醒";}
      });
      content=node("div","");head.append(title,close);body.append(head,refresh,notifications,node("p","field-note","保留工作台标签页即可接收暂停提醒。提醒不包含资料内容；页面关闭或浏览器休眠时不能保证及时通知。"),content);dialog.append(body);document.body.append(dialog);
      dialog.addEventListener("close",()=>{generation++;selected=null;content.replaceChildren();});
    }
    function profileButton(profile) {
      const button=node("button","button button-secondary","防护记录");button.type="button";button.disabled=!authorized();
      button.addEventListener("click",()=>{selected=profile.id;title.textContent=profile.name+" · 防护记录";dialog.showModal();void load();});return button;
    }
    function notificationsEnabled(){return "Notification" in window && Notification.permission === "granted";}
    function profilesChanged(profiles) {
      const paused=profiles.filter(p=>p.paused===true && p.revoked!==true);
      document.title=paused.length ? "（"+paused.length+" 项暂停）"+baseTitle : baseTitle;
      for(const profile of paused) {
        if(!Number.isSafeInteger(profile.pause_epoch) || profile.pause_epoch < 1 || alerts.get(profile.id) === profile.pause_epoch)continue;
        alerts.set(profile.id,profile.pause_epoch);
        if(notificationsEnabled())try{const notice=new Notification("元星木已暂停一份工作",{body:"请回到本机工作台查看原因，并核对已经开始的操作。",tag:"yuanxingmu-"+profile.id});notice.onclick=()=>{window.focus();};}catch{/* The persistent work card still shows the pause. */}
      }
    }
    function reset() {generation++;selected=null;alerts.clear();document.title=baseTitle;if(dialog){dialog.close();content.replaceChildren();}}
    return {boot,profileButton,reset,profilesChanged,notificationsEnabled};
  };
})();
