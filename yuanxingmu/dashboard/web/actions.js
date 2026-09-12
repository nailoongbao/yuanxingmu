/* Host action records distinguish fixed-scope automation from individual confirmation. */
(() => {
  "use strict";

  window.createYuanxingmuActions = function ({api, newKey, node, authorized, getProfile, upsertProfile, refreshProfiles}) {
    const e = {};
    const state = {profileId: null, actionId: null, action: null, actions: [], targets: [], active: false,
      supported: false, verified: false, stale: false, editing: false, cancelling: false,
      listLoading: false, detailLoading: false, generation: 0, selection: 0, requests: new Map()};
    const names = {message: "发送消息", upload: "上传文件", form: "提交表单", overwrite: "覆盖文件", delete: "删除文件"};
    const statuses = {pending: ["待核对", ""], executing: ["正在执行", "working"],
      acknowledged: ["已完成提交", "ready"], unconfirmed: ["结果不明", "uncertain"],
      not_started: ["未开始执行", "uncertain"], cancelled: ["已弃用", ""]};
    const idOK = value => typeof value === "string" && /^[0-9a-f]{32}$/.test(value);
    const digestOK = value => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
    const timeOK = value => typeof value === "string" && value.length <= 128 && Number.isFinite(Date.parse(value));
    const executionFields = ["attempt_id", "approved_at", "authorized_at", "execution_mode", "authorization_source", "authorization_sha256"];
    const record = value => value !== null && typeof value === "object" && !Array.isArray(value);
    const exactKeys = (value, keys) => record(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
    const keyFor = (profile, action) => profile + "/" + action;
    const current = () => state.requests.get(keyFor(state.profileId, state.actionId));
    const base = profile => "/api/profiles/" + encodeURIComponent(profile) + "/actions";
    const detailPath = (profile, action) => base(profile) + "/" + encodeURIComponent(action);
    const errorText = error => error instanceof Error ? error.message : "暂时无法确认，请重新读取。";
    const pause = ms => new Promise(resolve => window.setTimeout(resolve, ms));
    const clearReview = () => { if (e.reviewed) e.reviewed.checked = false; };
    const selectedRequest = request => request.generation === state.generation && state.requests.get(keyFor(request.profileId, request.actionId)) === request;
    const shownRequest = request => state.profileId === request.profileId && state.actionId === request.actionId;

    function message(text, error = false) {
      e.feedback.textContent = text;
      e.feedback.hidden = !text;
      e.feedback.classList.toggle("error", error);
    }

    function executionInfo(action) {
      if (action?.execution_mode === "automatic" && action.authorization_source === "frozen_task_scope"
          && action.approved_at === null && timeOK(action.authorized_at) && digestOK(action.authorization_sha256)) {
        return {label: "本次授权范围内自动执行", timeLabel: "授权时间", time: action.authorized_at};
      }
      if ((action?.execution_mode === "manual" && action.authorization_source === "host_confirmation"
          || action?.execution_mode == null && action?.authorization_source == null) && timeOK(action?.approved_at)) {
        return {label: "本人确认后执行", timeLabel: "确认时间", time: action.approved_at};
      }
      return null;
    }

    function validateAction(action, id) {
      const fail = () => { throw new Error("操作内容返回不完整，暂时不能确认。请重新读取。"); };
      if (!record(action) || action.id !== id || !idOK(id) || !Object.hasOwn(names, action.kind) || !Object.hasOwn(statuses, action.status) ||
          !Number.isSafeInteger(action.revision) || action.revision < 1 || !digestOK(action.digest) ||
          !record(action.target) || typeof action.target.label !== "string" || typeof action.target.destination !== "string" ||
          action.target.target_id !== action.target_id || action.target.kind !== action.kind ||
          !exactKeys(action.proposal, ["kind", "target_id", "payload"]) || action.proposal.kind !== action.kind ||
          action.proposal.target_id !== action.target_id) fail();
      const p = action.proposal.payload;
      if (action.kind === "message" && (!exactKeys(p, ["body"]) || typeof p.body !== "string")) fail();
      if (action.kind === "upload" && (!exactKeys(p, ["filename", "content"]) || typeof p.filename !== "string" || typeof p.content !== "string")) fail();
      if (action.kind === "overwrite" && (!exactKeys(p, ["content"]) || typeof p.content !== "string")) fail();
      if (action.kind === "delete" && !exactKeys(p, [])) fail();
      if (action.kind === "form" && (!exactKeys(p, ["fields"]) || !record(p.fields) ||
          !Array.isArray(action.target.form_fields) || !exactKeys(p.fields, action.target.form_fields) ||
          !Object.values(p.fields).every(value => typeof value === "string"))) fail();
      if (["overwrite", "delete"].includes(action.kind) &&
          (!record(action.before) || typeof action.before.content !== "string" || !digestOK(action.before.sha256))) fail();
      if (action.execution_mode === "automatic" && (!executionInfo(action) || !idOK(action.attempt_id)
          || ["pending", "cancelled"].includes(action.status) || ["overwrite", "delete"].includes(action.kind))) fail();
      let destination = action.target.destination;
      if (!["overwrite", "delete"].includes(action.kind)) {
        try {
          const url = new URL(destination);
          if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) fail();
          destination = url.origin;
        } catch { fail(); }
      }
      return {...action, target: {target_id: action.target_id, kind: action.kind, label: action.target.label,
        destination, form_fields: action.target.form_fields ? [...action.target.form_fields] : []}};
    }

    function canChange() {
      const profile = getProfile(state.profileId);
      return Boolean(authorized() && state.supported && state.active && state.verified && !state.stale &&
        !state.detailLoading && !current() && !profile?.pending && profile?.revoked === false && state.action?.status === "pending");
    }

    function stateNote(action) {
      if (!action) return "读取完整内容后才能核对。";
      if (action.status === "pending") return action.kind === "delete"
        ? "确认后将删除下方指定文件。请核对文件位置和原有全文。"
        : action.kind === "overwrite" ? "确认后，新内容会替换这份文件的原有内容。请核对前后全文。"
        : "这项操作还没有执行，请核对接收对象和完整内容。";
      if (action.status === "executing") return "正在执行这一次操作。关闭窗口不会取消已经开始的提交。";
      if (action.status === "acknowledged") return ["overwrite", "delete"].includes(action.kind)
        ? "这一次文件操作已完成，记录已保留。" : "接收服务已确认这次提交；这不代表对方已经查看或处理。";
      if (action.status === "unconfirmed") return "暂时无法确认操作是否完成。请先核对接收端或目标文件；这份记录不会再次执行。";
      if (action.status === "not_started") return "这一次操作没有开始，原因已保留。这份记录不会再次执行；处理原因后需另行提出并核对。";
      return "这项提案已弃用，不能执行。";
    }

    function updateControls() {
      if (!e.dialog) return;
      const allowed = authorized(), request = current(), action = state.action, change = canChange();
      for (const button of document.querySelectorAll("button[data-yuanxingmu-actions-profile]")) button.disabled = !allowed;
      e.listRefresh.disabled = !allowed || state.listLoading;
      e.listRefresh.textContent = state.listLoading ? "正在读取…" : "刷新操作";
      e.reload.disabled = !allowed || state.detailLoading || Boolean(request);
      e.reload.textContent = state.stale ? "读取最新版" : "重新读取完整内容";
      e.editFields.disabled = !change;
      e.editSave.disabled = !change || !state.editing;
      e.editDiscard.disabled = Boolean(request);
      e.editStart.hidden = !action || action.status !== "pending" || state.editing;
      e.editStart.disabled = !change || state.cancelling;
      e.cancelStart.hidden = !action || action.status !== "pending";
      e.cancelStart.disabled = !change || state.editing;
      e.cancelConfirm.disabled = !change;
      e.cancelKeep.disabled = Boolean(request);
      const review = change && !state.editing && !state.cancelling;
      e.reviewed.disabled = !review;
      if (!review) clearReview();
      e.reviewBox.hidden = !action || action.status !== "pending";
      e.commit.hidden = !action || action.status !== "pending" || Boolean(request);
      e.commit.textContent = action?.kind === "delete" ? "确认删除这个文件" : action?.kind === "overwrite" ? "确认覆盖这个文件"
        : action?.kind === "upload" ? "确认上传这份文件" : action?.kind === "form" ? "确认提交这份表单" : "确认发送这条消息";
      e.commit.disabled = !review || !e.reviewed.checked;
      e.commit.className = "button " + (["overwrite", "delete"].includes(action?.kind) ? "button-danger" : "button-primary");
      e.checkRequest.hidden = !request || request.phase !== "uncertain";
      e.checkRequest.disabled = !allowed || Boolean(request?.watching);
      e.reason.textContent = !allowed ? "访问凭证已失效，请重新打开工作台。"
        : request ? "这次提交还未确认结果，只能查询原记录，不能再次执行。"
        : state.detailLoading ? "正在读取完整内容…"
        : state.stale ? "内容已经改变，请重新读取并核对。"
        : getProfile(state.profileId)?.pending ? "这份工作还有操作未结束，请先等待结果。"
        : !state.active || getProfile(state.profileId)?.revoked !== false ? "这份工作的权限未确认或已收回，不能执行新的操作。"
        : state.editing ? "请保存修改，再核对保存后的对象和全文。"
        : !state.verified ? "暂时无法确认内容，请重新读取。" : "";
    }

    function field(label, content, full = false) {
      const wrapper = node("div", full ? "mail-body-field" : "");
      wrapper.append(node("dt", "", label), node("dd", full ? "mail-full-body" : "", content));
      return wrapper;
    }

    function renderDetail() {
      const action = state.action;
      e.read.replaceChildren();
      e.read.hidden = !action || state.editing;
      e.editForm.hidden = !action || !state.editing;
      e.cancelBox.hidden = !state.cancelling;
      e.note.textContent = stateNote(action);
      e.title.textContent = action && action.status !== "pending" ? "操作记录" : "核对操作";
      e.badge.textContent = action ? statuses[action.status][0] : "正在读取";
      e.badge.className = "status-badge " + (action ? statuses[action.status][1] : "");
      e.version.textContent = action ? "第 " + action.revision + " 版" : "";
      if (action) {
        const execution = executionInfo(action);
        if (execution) e.read.append(field("执行方式", execution.label),
          field(execution.timeLabel, new Date(execution.time).toLocaleString("zh-CN", {hour12: false})));
        e.read.append(field("操作", names[action.kind]), field("对象", action.target.label),
          field(["overwrite", "delete"].includes(action.kind) ? "文件位置" : "接收服务", action.target.destination));
        const p = action.proposal.payload;
        if (action.kind === "message") e.read.append(field("消息全文", p.body, true));
        if (action.kind === "upload") e.read.append(field("文件名", p.filename), field("上传全文", p.content, true));
        if (action.kind === "form") for (const key of action.target.form_fields) e.read.append(field(key, p.fields[key], true));
        if (["overwrite", "delete"].includes(action.kind)) e.read.append(field("原有全文", action.before.content, true));
        if (action.kind === "overwrite") e.read.append(field("替换为", p.content, true));
      }
      updateControls();
    }

    function renderList() {
      const fragment = document.createDocumentFragment();
      if (!state.actions.length) {
        const empty = node("div", "mail-empty");
        empty.append(node("h3", "", state.listLoading ? "正在读取操作" : !state.supported ? "这份工作尚未启用操作核对"
          : !state.targets.length ? "尚未登记操作对象" : "还没有待核对的操作"),
          node("p", "field-note", !state.targets.length ? "请先在宿主设置中登记接收位置或可修改的文件，再让 AI 提出操作。"
            : "已授权范围内的自动操作和需要本人核对的操作，都会在这里列出。"));
        fragment.append(empty);
      }
      for (const action of state.actions) {
        if (!idOK(action.id) || !Object.hasOwn(names, action.kind) || !Object.hasOwn(statuses, action.status)) continue;
        const row = node("article", "mail-draft-row"), heading = node("div", "mail-draft-heading");
        heading.append(node("h3", "", names[action.kind]), node("span", "status-badge " + statuses[action.status][1], statuses[action.status][0]));
        const open = button("查看完整内容", "button-secondary", () => { void select(action.id); });
        open.dataset.actionId = action.id;
        open.disabled = !authorized();
        row.append(heading, node("p", "mail-draft-recipient", action.target_label || "已登记对象"));
        const execution = executionInfo(action);
        if (execution) row.append(node("p", "field-note", execution.label));
        row.append(open);
        fragment.append(row);
      }
      e.list.replaceChildren(fragment);
      e.list.setAttribute("aria-busy", String(state.listLoading));
    }

    async function refreshList() {
      if (!state.profileId || !authorized() || state.listLoading) return;
      const profile = state.profileId, generation = state.generation;
      state.listLoading = true;
      updateControls();
      try {
        const data = await api(base(profile));
        if (generation !== state.generation || profile !== state.profileId) return;
        if (!Array.isArray(data.actions) || !Array.isArray(data.targets) || typeof data.supported !== "boolean" || typeof data.active !== "boolean")
          throw new Error("操作列表返回不完整，请重新读取。");
        state.actions = data.actions; state.targets = data.targets;
        state.active = data.active; state.supported = data.supported;
        if (state.action) {
          const latest = data.actions.find(action => action.id === state.actionId);
          if (!latest || latest.digest !== state.action.digest || latest.revision !== state.action.revision) {
            state.stale = true; state.verified = false; clearReview();
            message("操作内容已更新，请重新读取最新版并核对。", true);
          } else if (latest.status !== state.action.status || executionFields.some(key => latest[key] !== state.action[key])) {
            state.action = validateAction({...state.action, status: latest.status,
              ...Object.fromEntries(executionFields.filter(key => Object.hasOwn(latest, key)).map(key => [key, latest[key]]))}, state.actionId);
            clearReview(); renderDetail();
          }
        }
      } catch (error) {
        if (generation === state.generation && profile === state.profileId) {
          state.verified = false; clearReview(); message(errorText(error), true);
        }
      } finally {
        if (generation === state.generation && profile === state.profileId) {
          state.listLoading = false; renderList(); updateControls();
        }
      }
    }

    function accept(data, id) {
      state.action = validateAction(data.action, id);
      if (typeof data.active !== "boolean") throw new Error("暂时无法确认这份工作的权限。");
      state.active = data.active; state.verified = true; state.stale = false;
      state.editing = false; state.cancelling = false;
      clearReview(); renderDetail();
    }

    async function select(id) {
      if (!idOK(id) || !state.profileId || !authorized()) return;
      const selection = ++state.selection, generation = state.generation, profile = state.profileId;
      state.actionId = id; state.action = null; state.verified = false; state.detailLoading = true;
      state.editing = false; state.cancelling = false;
      e.listPanel.hidden = true; e.detailPanel.hidden = false;
      e.title.textContent = "核对操作"; clearReview(); message(""); renderDetail();
      try {
        const data = await api(detailPath(profile, id));
        if (generation !== state.generation || selection !== state.selection || profile !== state.profileId) return;
        accept(data, id);
      } catch (error) {
        if (generation === state.generation && selection === state.selection) message(errorText(error), true);
      } finally {
        if (generation === state.generation && selection === state.selection) { state.detailLoading = false; updateControls(); }
      }
    }

    async function open(profile) {
      if (!authorized() || !profile || !idOK(profile.id) || !profile.features?.includes("reviewed_actions_v1")) return;
      boot(); state.selection += 1;
      state.profileId = profile.id; state.actionId = null; state.action = null; state.actions = []; state.targets = [];
      state.active = false; state.supported = true; state.verified = false; state.listLoading = false;
      state.editing = false; state.cancelling = false;
      e.workName.textContent = profile.name || "当前工作"; e.title.textContent = "操作与记录";
      e.listPanel.hidden = false; e.detailPanel.hidden = true; clearReview(); message(""); renderList();
      if (!e.dialog.open) e.dialog.showModal();
      e.close.focus(); await refreshList();
    }

    function input(label, value, multiline = false) {
      const wrapper = node("div", "field"), control = node(multiline ? "textarea" : "input", "");
      const id = "actions-input-" + e.editPayload.children.length;
      control.id = id; control.value = value; control.autocomplete = "off"; control.spellcheck = false;
      if (multiline) control.rows = 9; else control.type = "text";
      const caption = node("label", "", label); caption.htmlFor = id;
      wrapper.append(caption, control); e.editPayload.append(wrapper);
      return control;
    }

    function editorPayload(proposal) {
      e.editPayload.replaceChildren(); e.inputs = {};
      const p = proposal.payload, kind = proposal.kind;
      if (kind === "message") e.inputs.body = input("消息全文", p.body || "", true);
      if (kind === "upload") e.inputs.filename = input("上传文件名", p.filename || "report.txt");
      if (["upload", "overwrite"].includes(kind)) e.inputs.content = input(kind === "upload" ? "上传全文" : "替换后的完整内容", p.content || "", true);
      if (kind === "form") {
        const target = state.targets.find(target => target.target_id === e.targetSelect.value) || state.action.target;
        e.inputs.fields = new Map();
        for (const key of target.form_fields || []) e.inputs.fields.set(key, input(key, p.fields?.[key] || "", true));
      }
      if (kind === "delete") e.editPayload.append(node("p", "field-note", "保存后会重新读取所选文件；请核对最新的文件位置和原有全文，再确认删除。"));
    }

    function startEditing(proposal = null) {
      if (!canChange()) return;
      state.editing = true; state.cancelling = false; clearReview();
      const selected = proposal || state.action.proposal;
      const targets = state.targets.filter(target => target.kind === state.action.kind);
      e.targetSelect.replaceChildren();
      for (const target of targets) {
        const option = node("option", "", target.label); option.value = target.target_id; e.targetSelect.append(option);
      }
      e.targetSelect.value = selected.target_id;
      if (!e.targetSelect.value) e.targetSelect.selectedIndex = -1;
      editorPayload(selected); message(""); renderDetail(); e.targetSelect.focus();
    }

    function editedProposal() {
      const payload = {}, kind = state.action.kind;
      if (!e.targetSelect.value) throw new Error("请选择一个已登记的操作对象。");
      if (kind === "message") payload.body = e.inputs.body.value;
      if (["upload", "overwrite"].includes(kind)) payload.content = e.inputs.content.value;
      if (kind === "upload") {
        payload.filename = e.inputs.filename.value;
        if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(payload.filename)) throw new Error("文件名请使用英文字母、数字、点、短横线或下划线，最多 128 个字符。");
      }
      if (kind === "form") {
        payload.fields = Object.fromEntries(Array.from(e.inputs.fields, ([key, control]) => [key, control.value]));
        if (Object.values(payload.fields).some(value => new TextEncoder().encode(value).byteLength > 8192))
          throw new Error("表单的每个字段最多 8 KB，请缩短后再保存。");
      }
      if ([payload.body, payload.content].some(value => typeof value === "string" && new TextEncoder().encode(value).byteLength > 65536))
        throw new Error("内容最多 64 KB，请缩短后再保存。");
      return {kind, target_id: e.targetSelect.value, payload};
    }

    async function finish(request, job) {
      const data = await api(detailPath(request.profileId, request.actionId));
      if (!selectedRequest(request)) return true;
      const action = validateAction(data.action, request.actionId);
      if (action.status === "executing" || (request.op === "commit" && action.status === "pending" && job.status !== "failed")) return false;
      state.requests.delete(keyFor(request.profileId, request.actionId));
      if (job.result?.profile) upsertProfile(job.result.profile);
      if (shownRequest(request)) {
        accept(data, request.actionId);
        if (job.status === "failed" && request.op === "edit" && action.status === "pending" &&
            action.revision === request.body.revision && action.digest === request.body.digest) startEditing(request.body.proposal);
        message(job.status === "failed" ? (job.error?.message || "这次操作没有完成，请核对当前记录。")
          : request.op === "edit" ? "修改已保存，请重新核对对象和保存后的全文。" : "", job.status === "failed");
      }
      if (state.profileId === request.profileId) await refreshList();
      try { await refreshProfiles(); } catch { /* The action outcome above remains authoritative. */ }
      return true;
    }

    async function watch(request) {
      if (request.watching || !selectedRequest(request) || !authorized()) return;
      request.watching = true;
      try {
        // A missing first response is reconciled by a GET using the SAME key.
        // This code never repeats a mutation POST, even when lookup returns 404.
        if (!request.jobId) {
          const found = await api("/api/requests/" + encodeURIComponent(request.key));
          if (!selectedRequest(request)) return;
          if (!idOK(found.job?.id)) throw new Error("暂时未找到这次提交的记录，请稍后继续查询。");
          request.jobId = found.job.id;
        }
        request.phase = "working";
        for (let count = 0; count < 30 && selectedRequest(request) && authorized(); count += 1) {
          const result = await api("/api/jobs/" + encodeURIComponent(request.jobId));
          if (!selectedRequest(request)) return;
          const job = result.job;
          if (!job || job.id !== request.jobId) throw new Error("返回的操作记录不一致，请稍后继续查询。");
          if (["succeeded", "failed"].includes(job.status) && await finish(request, job)) return;
          updateControls(); await pause(2000);
        }
        if (selectedRequest(request)) request.phase = "uncertain";
      } catch (error) {
        if (selectedRequest(request)) {
          request.phase = "uncertain";
          if (shownRequest(request)) message(errorText(error) + " 只会查询这一次提交，不会重新执行。", true);
        }
      } finally { request.watching = false; if (request.generation === state.generation) updateControls(); }
    }

    async function mutate(op) {
      if (!canChange() || current() || (op === "commit" && (!e.reviewed.checked || state.editing || state.cancelling))) return;
      if ((op === "edit" && !state.editing) || (op === "cancel" && !state.cancelling)) return;
      const action = state.action, body = {revision: action.revision, digest: action.digest};
      if (op === "edit") {
        try { body.proposal = editedProposal(); } catch (error) { message(errorText(error), true); return; }
      }
      if (op === "commit") body.confirm = "commit";
      const request = {profileId: state.profileId, actionId: action.id, op, body, key: newKey(), generation: state.generation,
        phase: "posting", jobId: null, watching: false};
      state.requests.set(keyFor(request.profileId, request.actionId), request);
      state.cancelling = false; clearReview(); message(""); renderDetail();
      try {
        const result = await api(detailPath(request.profileId, request.actionId) + "/" + op,
          {method: "POST", body, key: request.key, noRetry: true});
        if (!selectedRequest(request)) return;
        if (!idOK(result.job?.id)) {
          const error = new Error("暂时未收到这次操作的记录。"); error.uncertain = true; throw error;
        }
        request.jobId = result.job.id; request.phase = "working"; void watch(request);
      } catch (error) {
        if (!selectedRequest(request)) return;
        request.phase = "uncertain";
        if (shownRequest(request)) message(errorText(error) + " 请查询这次操作的结果。", true);
        if (error.uncertain === false) {
          try { await finish(request, {status: "failed", error: {message: errorText(error)}}); }
          catch { /* Preserve the key until the existing outcome can be read. */ }
        }
      } finally { if (request.generation === state.generation) updateControls(); }
    }

    function button(label, style, handler) {
      const result = node("button", "button " + style, label); result.type = "button";
      result.addEventListener("click", handler); return result;
    }

    function boot() {
      if (e.dialog) return;
      e.dialog = node("dialog", "mail-dialog"); e.dialog.id = "actions-dialog";
      e.dialog.setAttribute("aria-labelledby", "actions-title");
      const body = node("div", "dialog-body"), heading = node("div", "mail-dialog-heading"), headingText = node("div", "");
      e.workName = node("p", "section-index"); e.title = node("h2", "", "待核对的操作"); e.title.id = "actions-title";
      e.close = button("关闭", "button-quiet", () => e.dialog.close());
      headingText.append(e.workName, e.title); heading.append(headingText, e.close);
      e.feedback = node("p", "form-message"); e.feedback.setAttribute("role", "status"); e.feedback.setAttribute("aria-live", "polite"); e.feedback.hidden = true;
      e.listPanel = node("section", ""); const toolbar = node("div", "mail-list-toolbar");
      e.listRefresh = button("刷新操作", "button-secondary", () => { void refreshList(); });
      toolbar.append(node("p", "field-note", "查看目标和完整内容，决定是否执行。"), e.listRefresh);
      e.list = node("div", "mail-drafts"); e.listPanel.append(toolbar, e.list);
      e.detailPanel = node("section", ""); e.detailPanel.hidden = true;
      const nav = node("div", "mail-detail-toolbar"), meta = node("div", "mail-detail-meta");
      e.back = button("返回操作列表", "button-quiet", () => {
        state.selection += 1; state.actionId = null; state.action = null; state.verified = false; state.editing = false;
        clearReview(); message(""); e.title.textContent = "操作与记录"; e.listPanel.hidden = false; e.detailPanel.hidden = true; void refreshList();
      });
      e.reload = button("重新读取完整内容", "button-quiet", () => { if (state.actionId) void select(state.actionId); }); nav.append(e.back, e.reload);
      e.badge = node("span", "status-badge"); e.version = node("span", "field-note"); meta.append(e.badge, e.version);
      e.note = node("p", "mail-state-note"); e.read = node("dl", "mail-read");
      e.editForm = node("form", "mail-edit-form"); e.editForm.autocomplete = "off"; e.editForm.hidden = true;
      e.editFields = node("fieldset", ""); e.editFields.append(node("legend", "visually-hidden", "修改待核对操作"));
      const targetField = node("div", "field"), targetLabel = node("label", "", "操作对象"); targetLabel.htmlFor = "actions-edit-target";
      e.targetSelect = node("select", ""); e.targetSelect.id = "actions-edit-target";
      targetField.append(targetLabel, e.targetSelect); e.editPayload = node("div", ""); e.editFields.append(targetField, e.editPayload);
      e.targetSelect.addEventListener("change", () => { if (state.action) editorPayload(state.action.proposal); clearReview(); });
      const editButtons = node("div", "mail-edit-actions"); e.editSave = button("保存修改", "button-secondary", () => { void mutate("edit"); });
      e.editDiscard = button("放弃修改", "button-quiet", () => { state.editing = false; clearReview(); renderDetail(); });
      editButtons.append(e.editSave, e.editDiscard); e.editForm.append(e.editFields, editButtons);
      e.editForm.addEventListener("submit", event => { event.preventDefault(); void mutate("edit"); });
      e.cancelBox = node("div", "mail-cancel-confirmation"); e.cancelBox.hidden = true;
      const cancelButtons = node("div", "mail-edit-actions");
      e.cancelConfirm = button("确认弃用提案", "button-outline-danger", () => { void mutate("cancel"); });
      e.cancelKeep = button("保留提案", "button-secondary", () => { state.cancelling = false; renderDetail(); });
      cancelButtons.append(e.cancelConfirm, e.cancelKeep); e.cancelBox.append(node("p", "", "弃用后，这项提案不能再执行。"), cancelButtons);
      e.reviewBox = node("div", "mail-review-confirmation"); const reviewLabel = node("label", "");
      e.reviewed = node("input", ""); e.reviewed.type = "checkbox"; e.reviewed.id = "actions-reviewed";
      reviewLabel.append(e.reviewed, node("span", "", "我已核对对象和完整内容")); e.reason = node("p", "field-note"); e.reviewBox.append(reviewLabel, e.reason);
      e.reviewed.addEventListener("change", updateControls);
      const controls = node("div", "mail-detail-actions"), controlsLeft = node("div", "");
      e.editStart = button("修改提案", "button-secondary", () => startEditing());
      e.cancelStart = button("弃用提案", "button-quiet", () => { if (canChange()) { state.cancelling = true; clearReview(); renderDetail(); } });
      e.commit = button("确认执行", "button-primary", () => { void mutate("commit"); }); e.commit.id = "actions-commit";
      e.checkRequest = button("只查询这次操作", "button-secondary", () => { const request = current(); if (request) void watch(request); });
      e.checkRequest.id = "actions-check-request"; e.checkRequest.hidden = true;
      controlsLeft.append(e.editStart, e.cancelStart); controls.append(controlsLeft, e.commit, e.checkRequest);
      e.detailPanel.append(nav, meta, e.note, e.read, e.editForm, e.cancelBox, e.reviewBox, controls);
      body.append(heading, e.feedback, e.listPanel, e.detailPanel); e.dialog.append(body); document.body.append(e.dialog);
      e.dialog.addEventListener("close", () => {
        state.selection += 1; state.profileId = null; state.actionId = null; state.action = null; state.verified = false;
        state.actions = []; state.targets = []; clearReview(); e.read.replaceChildren(); e.editPayload.replaceChildren(); e.list.replaceChildren();
      });
      updateControls();
    }

    function reset() {
      state.generation += 1; state.selection += 1; state.requests.clear(); state.profileId = null; state.actionId = null;
      state.action = null; state.actions = []; state.targets = []; state.active = false; state.verified = false;
      state.listLoading = false; state.detailLoading = false; state.editing = false; state.cancelling = false;
      if (e.dialog) { e.dialog.close(); e.read.replaceChildren(); e.editPayload.replaceChildren(); e.list.replaceChildren(); message(""); updateControls(); }
    }

    function profileButton(profile) {
      if (!profile?.features?.includes("reviewed_actions_v1")) return null;
      const result = button("核对操作", "button-secondary", () => { void open(getProfile(profile.id) || profile); });
      result.dataset.yuanxingmuActionsProfile = profile.id; result.disabled = !authorized(); return result;
    }

    return {boot, reset, updateControls, profileButton, profilesChanged: updateControls, open};
  };
})();
