/* Show observed host decisions, not a guessed safety score. */
(() => {
  "use strict";
  window.createYuanxingmuProtection = function ({api, node, authorized}) {
    let dialog, content, title, selected, generation = 0;
    const names = {foundation:"安装与技能检查",input:"外部内容检查",memory:"记忆防投毒",alignment:"任务偏移检查",command:"危险命令检查"};
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
      const form=node("form",""),group=node("fieldset","mail-drafts"),inputs={};group.disabled=!value.editable;
      const slot=id+":settings";
      for(const [name,labelText] of Object.entries(names)) {
        const label=node("label",""),input=node("input","");input.type="checkbox";input.checked=Boolean(value.layers[name]);
        inputs[name]=input;label.append(input,node("span","",labelText));group.append(label);
      }
      const mode=node("select","");mode.setAttribute("aria-label","检查后怎么处理");
      for(const [key,label] of [["enforce","拦截或等本人确认"],["observe","只记录，不拦截"]]) {const option=node("option","",label);option.value=key;mode.append(option);}
      mode.value=value.mode;
      const reset=node("button","button button-quiet","恢复全部开启"),save=node("button","button button-secondary","保存防护设置");reset.type="button";save.type="submit";
      reset.addEventListener("click",()=>{for(const input of Object.values(inputs)) input.checked=true;mode.value="enforce";});
      const feedback=node("p","form-message");feedback.setAttribute("role","status");
      group.append(mode,reset,save);form.append(group,feedback);panel.append(form);
      if(pending.has(slot)) {
        group.disabled=true;
        const query=node("button","button button-secondary","查询上次保存的结果");query.type="button";
        query.addEventListener("click",async()=>{query.disabled=true;try{await submitOnce(slot);if(own===generation && id===selected) await load();}catch(error){feedback.textContent=error.message+" 不会重新保存。";query.disabled=false;}});
        form.append(query);
      }
      form.addEventListener("submit",async event=>{
        event.preventDefault();if(!value.editable || group.disabled) return;group.disabled=true;
        const changes={mode:mode.value,...Object.fromEntries(Object.entries(inputs).map(([name,input])=>[name+"_enabled",input.checked]))};
        try {
          await submitOnce(slot,"/api/profiles/"+id+"/protection",{settings:changes});
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
    async function reviews(id, own) {
      const value = await api("/api/profiles/" + id + "/tools");
      if (own !== generation || id !== selected || !value.supported) return;
      const section=node("section", "mail-drafts");
      section.append(node("h3","","需要你确认的代码操作"),node("p","field-note","只允许这一次，不会记成以后都允许。五分钟内没有处理，操作就会停止；允许后仍受资料和联网权限限制。"));
      if (!value.reviews.length) section.append(node("p","field-note","目前没有等待确认的代码操作。"));
      for (const item of value.reviews) {
        const row=node("article","mail-draft-card");
        row.append(node("strong","",(item.tool === "terminal" || item.tool === "exec" ? "执行代码" : item.tool)+" · "+(reviewNames[item.status] || "状态待确认")),node("p","",item.reason));
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
            row.replaceChildren(node("strong","",reviewNames[entry.status] || "状态待确认"),node("p","",entry.reason),node("pre","mail-full-body",JSON.stringify({tool:entry.tool,arguments:entry.arguments},null,2)));
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
            row.append(label,approve,deny,feedback);
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
        content.append(node("p","field-note",value.mode === "observe" ? "当前仅记录检查结果，不阻断操作。" : "检查未通过的操作会停止或进入本人确认。"));
        if(value.buffered_response && value.layers?.alignment) content.append(node("p","field-note","回答会收齐后检查，再显示到聊天页，因此不会逐字实时出现。"));
        const layers = node("div","mail-drafts");
        for (const [name,label] of Object.entries(names)) {
          layers.append(node("p","",label + " · " + (value.layers?.[name] ? "已开启" : "未开启")));
        }
        content.append(layers,node("h3","","最近发生的检查"));
        layers.append(node("p","field-note","选中的技能："+(value.skills?.names?.join("、") || "无")+"；固定文件 "+(value.skills?.files || 0)+" 份。"),settings(value,id,own));
        if (!value.events.length) content.append(node("p","field-note","还没有本次检查记录。开启功能不等于已经验证每个场景。"));
        for (const event of value.events) {
          const row = node("article","mail-draft-card");
          const observed = event.code === "operator_settings_changed" ? "防护设置已更新" : event.assessed === false ? "未检查（已关闭）" : event.enforced === false && event.would_verdict ? "仅观察：原本会" + (resultNames[event.would_verdict] || event.would_verdict) : resultNames[event.verdict] || "检查未完成";
          row.append(node("strong","",(names[event.layer] || event.layer || "防护") + " · " + observed));
          row.append(node("p","",event.reason || ""));
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
