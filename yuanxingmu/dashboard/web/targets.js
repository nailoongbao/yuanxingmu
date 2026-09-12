/* Host-owned target settings. Saving settings never runs a connection test. */
(() => {
  "use strict";

  window.createYuanxingmuTargets = function ({api, node, authorized}) {
    const e = {};
    const state = {targets: [], loaded: false, loading: false, editing: null, removing: null,
      pending: null, checking: false, generation: 0};
    const names = {message: "发送消息", upload: "上传文本文件", form: "提交表单", overwrite: "覆盖指定文件", delete: "删除指定文件"};
    const providers = {standard: "普通消息接口（body）", text: "普通消息接口（text）", slack: "Slack 群聊", feishu: "飞书群聊"};
    const network = kind => ["message", "upload", "form"].includes(kind);
    const record = value => value !== null && typeof value === "object" && !Array.isArray(value);
    const idOK = value => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(value);
    const fieldOK = value => typeof value === "string" && /^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(value) && !["constructor", "prototype"].includes(value);
    const freshKey = () => Array.from(window.crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, "0")).join("");
    const selected = request => state.pending === request && request.generation === state.generation;

    function message(text, error = false) {
      e.feedback.textContent = text;
      e.feedback.hidden = !text;
      e.feedback.classList.toggle("error", error);
    }

    function button(text, className, action) {
      const result = node("button", "button " + className, text);
      result.type = "button";
      result.addEventListener("click", action);
      return result;
    }

    function safeDestination(target) {
      if (!network(target.kind)) return target.destination;
      try {
        const value = new URL(target.destination);
        if (["https:", "http:"].includes(value.protocol)) return value.origin;
      } catch { /* Do not render a malformed server-supplied endpoint. */ }
      return "已保存接收服务";
    }

    function validateTargets(data) {
      if (!record(data) || !Array.isArray(data.targets) || data.targets.length > 256) throw new Error("对象设置返回不完整，请重新读取。");
      const seen = new Set();
      return data.targets.map(target => {
        if (!record(target) || !idOK(target.id) || seen.has(target.id) || !Object.hasOwn(names, target.kind) ||
            typeof target.label !== "string" || typeof target.destination !== "string" ||
            !Object.hasOwn(providers, target.provider) || !Array.isArray(target.form_fields) ||
            !target.form_fields.every(fieldOK)) throw new Error("对象设置返回不完整，请重新读取。");
        seen.add(target.id);
        // Deliberately discard unknown fields, including url and headers.
        return {id: target.id, kind: target.kind, label: target.label, provider: target.provider,
          destination: safeDestination(target), form_fields: [...target.form_fields],
          workspace: typeof target.workspace === "string" ? target.workspace : "",
          relative_path: typeof target.relative_path === "string" ? target.relative_path : ""};
      });
    }

    function updateControls() {
      if (!e.panel) return;
      const allowed = authorized(), busy = Boolean(state.pending), ready = allowed && state.loaded && !state.loading && !busy;
      e.fields.disabled = !ready;
      e.add.disabled = !ready;
      e.save.disabled = !ready;
      e.cancel.disabled = busy;
      e.refresh.disabled = !allowed || state.loading || state.pending?.phase === "sending";
      e.refresh.textContent = state.loading ? "正在读取…" : "重新读取设置";
      e.check.hidden = !busy || state.pending.phase === "sending";
      e.check.disabled = !allowed || state.checking;
      e.check.textContent = state.checking ? "正在查询…" : "只查询这次保存";
      e.removeConfirm.disabled = !ready || !state.removing;
      e.removeKeep.disabled = busy;
      for (const control of e.list.querySelectorAll("button")) control.disabled = !ready;
      e.status.textContent = !allowed ? "等待连接" : state.loading ? "正在读取" : state.loaded ? state.targets.length + " 个对象" : "尚未读取";
      e.save.textContent = state.pending?.phase === "sending" ? "正在保存…" : state.editing ? "保存对象修改" : "保存操作对象";
      if (!allowed) e.url.value = "";
    }

    function renderList() {
      const fragment = document.createDocumentFragment();
      if (!state.targets.length) {
        const empty = node("div", "mail-empty");
        empty.append(node("h3", "", state.loaded ? "还没有操作对象" : "等待读取操作对象"),
          node("p", "field-note", "登记接收位置或指定文件后，新工作中的 AI 才能为它提出操作。"));
        fragment.append(empty);
      }
      for (const target of state.targets) {
        const row = node("article", "mail-draft-row"), heading = node("div", "mail-draft-heading");
        heading.append(node("h3", "", target.label), node("span", "status-badge", names[target.kind]));
        const actions = node("div", "mail-edit-actions");
        const edit = button("修改对象", "button-secondary", () => startEditing(target));
        const remove = button("移除配置", "button-quiet", () => startRemoving(target));
        edit.dataset.targetEdit = target.id;
        remove.dataset.targetRemove = target.id;
        actions.append(edit, remove);
        row.append(heading, node("p", "mail-draft-recipient", "对象代号：" + target.id),
          node("p", "field-note", target.destination));
        if (target.kind === "form") row.append(node("p", "field-note", "表单字段：" + target.form_fields.join("、")));
        row.append(actions);
        fragment.append(row);
      }
      e.list.replaceChildren(fragment);
      e.list.setAttribute("aria-busy", String(state.loading));
      updateControls();
    }

    async function refresh() {
      if (!e.panel || !authorized() || state.loading) return;
      const generation = state.generation;
      state.loading = true;
      updateControls();
      try {
        const data = await api("/api/action-targets");
        if (generation !== state.generation) return;
        state.targets = validateTargets(data);
        state.loaded = true;
      } catch (error) {
        if (generation === state.generation) {
          state.loaded = false;
          message(error?.status === 404 ? "当前本机服务还未提供对象设置，请更新后重新打开。" : "暂时无法读取对象设置，请重新连接后再试。", true);
        }
      } finally {
        if (generation === state.generation) { state.loading = false; renderList(); }
      }
    }

    function changeKind() {
      const kind = e.kind.value, isNetwork = network(kind);
      e.network.hidden = !isNetwork;
      e.providerField.hidden = kind !== "message";
      e.formFields.hidden = kind !== "form";
      e.fileFields.hidden = isNetwork;
      e.url.required = isNetwork;
      e.workspace.required = !isNetwork;
      e.path.required = !isNetwork;
      e.formNames.required = kind === "form";
      e.urlNote.textContent = state.editing && isNetwork
        ? "完整地址不会回显。修改这个对象时，请重新填写接收地址。提交后输入框会清空。"
        : "填写服务提供的完整 HTTPS 接收地址。本机测试可用 127.0.0.1 或 [::1] 的 HTTP 地址。提交后输入框会清空。";
      e.fileNote.textContent = kind === "delete"
        ? "选择 Linux / WSL 上现有的 UTF-8 文本文件，最多 64 KB。实际删除前，仍需核对文件位置和原有全文。"
        : "选择 Linux / WSL 上现有的 UTF-8 文本文件，最多 64 KB。实际覆盖前，仍需核对原文和替换后的全文。";
    }

    function clearForm() {
      state.editing = null;
      e.form.reset();
      e.url.value = "";
      e.id.readOnly = false;
      e.title.textContent = "添加操作对象";
      changeKind();
    }

    function startEditing(target = null) {
      if (!authorized() || !state.loaded || state.pending || state.loading) return;
      clearForm();
      state.removing = null;
      e.removeBox.hidden = true;
      if (target) {
        state.editing = target.id;
        e.id.value = target.id;
        e.id.readOnly = true;
        e.label.value = target.label;
        e.kind.value = target.kind;
        e.provider.value = target.provider;
        e.formNames.value = target.form_fields.join("\n");
        e.workspace.value = target.workspace;
        e.path.value = target.relative_path;
        e.title.textContent = "修改操作对象";
      }
      e.form.hidden = false;
      message("");
      changeKind();
      updateControls();
      e.label.focus();
    }

    function startRemoving(target) {
      if (!authorized() || !state.loaded || state.pending || state.loading) return;
      state.removing = target;
      e.url.value = "";
      e.form.hidden = true;
      e.removeText.textContent = "移除「" + target.label + "」的配置？新工作将不能再选择这个对象；已有工作仍保留原来的绑定。";
      e.removeBox.hidden = false;
      message("");
      updateControls();
      e.removeKeep.focus();
    }

    function collect() {
      const id = e.id.value.trim(), label = e.label.value.trim(), kind = e.kind.value;
      if (!idOK(id)) throw new Error("对象代号请使用 1–64 个英文字母、数字、下划线或短横线，并以字母或数字开头。");
      if (!label || new TextEncoder().encode(label).length > 512 || /[\u0000-\u001f\u007f]/.test(label)) throw new Error("请填写简短、单行的对象名称。");
      if (!Object.hasOwn(names, kind)) throw new Error("请选择操作类型。");
      if (!state.editing && state.targets.some(target => target.id === id)) throw new Error("这个对象代号已存在，请选择修改对象，或换一个代号。");
      const target = {kind, label};
      if (network(kind)) {
        const raw = e.url.value.trim();
        let url;
        try { url = new URL(raw); } catch { throw new Error("请填写完整的接收地址。"); }
        const ipv4 = url.hostname.split(".");
        const loopback = url.hostname === "[::1]" || (ipv4.length === 4 && ipv4[0] === "127" &&
          ipv4.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255));
        if (!/^[\x21-\x7e]+$/.test(raw) || !["https:", "http:"].includes(url.protocol) || url.username || url.password || url.hash ||
            (url.protocol === "http:" && !loopback)) throw new Error("接收地址须使用 HTTPS；HTTP 仅支持明确的本机回环地址，不能包含账号或页面锚点。");
        target.url = url.href;
        if (kind === "message") target.provider = e.provider.value;
        if (kind === "form") {
          const fields = e.formNames.value.split(/[\r\n,，]+/).map(value => value.trim()).filter(Boolean);
          if (!fields.length || fields.length > 16 || !fields.every(fieldOK) || new Set(fields).size !== fields.length) {
            throw new Error("表单需填写 1–16 个不重复的字段名。以英文字母开头，可用数字、下划线或短横线，每个最多 64 字符。");
          }
          target.form_fields = fields;
        }
      } else {
        const workspace = e.workspace.value.trim(), relative = e.path.value.trim();
        if (!workspace.startsWith("/") || /[\u0000-\u001f\u007f\\]/.test(workspace)) throw new Error("请填写 Linux / WSL 中的完整文件夹路径，例如 /home/me/reviewed-files。");
        if (!relative || relative.startsWith("/") || /[\u0000-\u001f\u007f\\]/.test(relative) ||
            relative.split("/").some(part => !part || part === "." || part === "..")) throw new Error("文件名应位于指定文件夹内，不能含有返回上级目录的 ..。");
        target.workspace = workspace;
        target.relative_path = relative;
      }
      return {id, target};
    }

    async function finish(request, success) {
      if (!selected(request)) return;
      state.pending = null;
      state.removing = null;
      e.removeBox.hidden = true;
      if (success) { clearForm(); e.form.hidden = true; }
      message(success ? (request.operation === "remove" ? "对象配置已移除。已有工作的绑定保持不变。" : "对象设置已保存，将用于之后创建的工作。实际操作仍需逐项核对。")
        : "这次设置未能完成，请重新读取并核对后再试。", !success);
      await refresh();
      updateControls();
    }

    async function accept(request, data) {
      if (!selected(request)) return;
      if (data?.job) {
        const job = data.job;
        if (!record(job) || typeof job.id !== "string" || !/^[0-9a-f]{32}$/.test(job.id)) throw new Error("invalid_job");
        request.jobId = job.id;
        if (job.status === "succeeded") return finish(request, true);
        if (job.status === "failed") return finish(request, false);
        if (!["queued", "running"].includes(job.status)) throw new Error("invalid_job_status");
        request.phase = "waiting";
        message("本机服务正在保存设置。可以查询这一次保存的结果。");
      } else {
        if (!record(data)) throw new Error("invalid_settings_response");
        return finish(request, true);
      }
      updateControls();
    }

    async function submit(operation) {
      if (!authorized() || !state.loaded || state.pending || state.loading) return;
      let payload;
      if (operation === "remove") {
        if (!state.removing) return;
        payload = {id: state.removing.id};
      } else {
        if (e.form.hidden || !e.form.reportValidity()) return;
        try { payload = collect(); } catch (error) { message(error.message, true); return; }
      }
      const request = {key: freshKey(), operation, phase: "sending", generation: state.generation};
      state.pending = request;
      e.url.value = "";
      message("");
      updateControls();
      try {
        const data = await api(operation === "remove" ? "/api/action-targets/remove" : "/api/action-targets",
          {method: "POST", key: request.key, body: payload, noRetry: true});
        await accept(request, data);
      } catch (error) {
        if (!selected(request)) return;
        if (error?.uncertain === false) {
          await finish(request, false);
        } else {
          request.phase = "uncertain";
          message("暂时无法确认这次保存的结果。请查询原请求，设置不会自动重发。", true);
        }
      } finally {
        if (payload.target) delete payload.target.url;
        if (request.generation === state.generation) updateControls();
      }
    }

    async function checkRequest() {
      const request = state.pending;
      if (!request || request.phase === "sending" || !authorized() || state.checking) return;
      state.checking = true;
      updateControls();
      try {
        const data = await api(request.jobId ? "/api/jobs/" + encodeURIComponent(request.jobId)
          : "/api/requests/" + encodeURIComponent(request.key));
        if (!data?.job) throw new Error("missing_job");
        await accept(request, data);
      } catch {
        if (selected(request)) message("还无法确认原请求的结果，请稍后再次查询；不会重新提交。", true);
      } finally {
        if (request.generation === state.generation) { state.checking = false; updateControls(); }
      }
    }

    function field(label, id, type = "text", note = "") {
      const wrapper = node("div", "field"), caption = node("label", "", label);
      caption.htmlFor = id;
      const input = node(type === "textarea" ? "textarea" : "input", "");
      input.id = id;
      input.autocomplete = "off";
      input.spellcheck = false;
      if (type !== "textarea") input.type = type;
      wrapper.append(caption, input);
      if (note) { const help = node("p", "field-note", note); help.id = id + "-note"; input.setAttribute("aria-describedby", help.id); wrapper.append(help); }
      return {wrapper, input};
    }

    function selectField(label, id, options) {
      const wrapper = node("div", "field"), caption = node("label", "", label), select = node("select", "");
      caption.htmlFor = id;
      select.id = id;
      for (const [value, text] of Object.entries(options)) { const option = node("option", "", text); option.value = value; select.append(option); }
      wrapper.append(caption, select);
      return {wrapper, input: select};
    }

    function boot() {
      if (e.panel) return true;
      const mount = document.getElementById("action-target-settings");
      if (!mount) return false;
      e.panel = node("details", "mail-account-panel");
      const summary = node("summary", "");
      e.status = node("span", "mail-account-status", "尚未读取");
      summary.append(node("span", "", "可确认的操作对象"), e.status);
      const content = node("div", "mail-account-content");
      content.append(node("p", "field-note", "登记允许发送消息、上传文本、提交表单或修改的具体对象。这里的修改只用于之后创建的工作；已有工作保留创建时的设置。"));
      const controls = node("div", "mail-account-actions");
      e.add = button("添加操作对象", "button-secondary", () => startEditing());
      e.refresh = button("重新读取设置", "button-quiet", () => { void refresh(); });
      controls.append(e.add, e.refresh);
      e.feedback = node("p", "form-message"); e.feedback.id = "targets-feedback"; e.feedback.hidden = true;
      e.feedback.setAttribute("role", "status"); e.feedback.setAttribute("aria-live", "polite");
      e.check = button("只查询这次保存", "button-secondary", () => { void checkRequest(); }); e.check.hidden = true; e.check.id = "targets-check-request";
      e.list = node("div", "mail-drafts field-group"); e.list.id = "targets-list";
      e.form = node("form", "field-group"); e.form.id = "targets-form"; e.form.autocomplete = "off"; e.form.hidden = true;
      e.title = node("h3", "", "添加操作对象");
      e.fields = node("fieldset", ""); e.fields.append(node("legend", "visually-hidden", "操作对象设置"));
      const label = field("对象名称", "targets-label"); e.label = label.input; e.label.required = true; e.label.maxLength = 128; e.label.placeholder = "例如：项目群、报名表、正式报告";
      const id = field("对象代号", "targets-id", "text", "给 AI 引用的固定代号。可用英文字母、数字、下划线或短横线，例如 project-chat。"); e.id = id.input; e.id.required = true; e.id.maxLength = 64;
      const kind = selectField("操作类型", "targets-kind", names); e.kind = kind.input;
      e.fields.append(label.wrapper, id.wrapper, kind.wrapper);
      e.network = node("div", "");
      const provider = selectField("消息服务", "targets-provider", providers); e.provider = provider.input; e.providerField = provider.wrapper;
      const url = field("完整接收地址", "targets-url", "password"); e.url = url.input; e.url.maxLength = 16384; e.url.autocomplete = "new-password";
      e.urlNote = node("p", "field-note"); e.urlNote.id = "targets-url-note"; e.url.setAttribute("aria-describedby", e.urlNote.id); url.wrapper.append(e.urlNote);
      const formNames = field("表单字段名", "targets-form-fields", "textarea", "每行一个字段名，最多 16 个。例如 name 和 note。保存的是允许填写的字段，具体内容由每次提案提供。");
      e.formNames = formNames.input; e.formNames.rows = 3; e.formNames.maxLength = 1100; e.formFields = formNames.wrapper;
      e.network.append(provider.wrapper, url.wrapper, formNames.wrapper);
      e.fileFields = node("div", "");
      const workspace = field("文件所在文件夹", "targets-workspace", "text", "使用由本机服务管理、AI 无法直接改写的独立文件夹。");
      e.workspace = workspace.input; e.workspace.maxLength = 4096; e.workspace.placeholder = "/home/me/reviewed-files";
      const relative = field("文件夹内的文件名", "targets-relative-path"); e.path = relative.input; e.path.maxLength = 1024; e.path.placeholder = "report.txt";
      e.fileNote = node("p", "field-note"); e.fileFields.append(workspace.wrapper, relative.wrapper, e.fileNote);
      const formControls = node("div", "mail-account-actions");
      e.save = node("button", "button button-secondary", "保存操作对象"); e.save.type = "submit"; e.save.id = "targets-save";
      e.cancel = button("取消编辑", "button-quiet", () => { if (!state.pending) { clearForm(); e.form.hidden = true; message(""); updateControls(); } });
      formControls.append(e.save, e.cancel); e.fields.append(e.network, e.fileFields, formControls);
      const formHeading = node("div", "group-heading"); formHeading.append(e.title);
      e.form.append(formHeading, e.fields);
      e.form.addEventListener("submit", event => { event.preventDefault(); void submit("save"); });
      e.kind.addEventListener("change", () => { e.url.value = ""; changeKind(); });
      e.removeBox = node("div", "mail-cancel-confirmation"); e.removeBox.hidden = true;
      e.removeText = node("p", "");
      const removeControls = node("div", "mail-edit-actions");
      e.removeKeep = button("保留配置", "button-secondary", () => { state.removing = null; e.removeBox.hidden = true; });
      e.removeConfirm = button("确认移除配置", "button-outline-danger", () => { void submit("remove"); });
      removeControls.append(e.removeKeep, e.removeConfirm); e.removeBox.append(e.removeText, removeControls);
      content.append(controls, e.feedback, e.check, e.form, e.removeBox, e.list);
      e.panel.append(summary, content); mount.append(e.panel);
      changeKind(); renderList();
      e.panel.addEventListener("toggle", () => { if (e.panel.open && !state.loaded) void refresh(); });
      updateControls();
      return true;
    }

    function reset() {
      state.generation += 1; state.targets = []; state.loaded = false; state.loading = false;
      state.pending = null; state.checking = false; state.removing = null;
      if (e.panel) { clearForm(); e.form.hidden = true; e.removeBox.hidden = true; message(""); renderList(); }
    }

    return {boot, refresh, reset, updateControls};
  };
})();
