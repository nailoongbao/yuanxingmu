/* Browser controls only: collection, persistence and delivery run on the host. */
(() => {
  "use strict";
  window.createYuanxingmuAlerts = function ({api, node, authorized}) {
    const e = {}, state = {data: null, loading: false, pending: null, checking: false, generation: 0};
    const phases = {pending: "等待发送", in_flight: "正在发送", delivered: "接收服务已确认", failed: "发送失败"};
    const kinds = {paused: "工作已暂停", resumed: "本人已恢复工作", revoked: "权限已收回", approval_required: "等待本人确认"};
    const record = value => value !== null && typeof value === "object" && !Array.isArray(value);
    const current = request => state.pending === request && request.generation === state.generation;
    const freshKey = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), value => value.toString(16).padStart(2, "0")).join("");
    const countsOK = counts => record(counts) && Object.keys(phases).every(name => Number.isSafeInteger(counts[name]) && counts[name] >= 0);

    function feedback(text, error = false) {
      e.feedback.textContent = text; e.feedback.hidden = !text; e.feedback.classList.toggle("error", error);
    }
    function clearSecrets() { if (e.url) { e.url.value = ""; e.key.value = ""; } }
    function button(text, id, action, kind = "button-secondary") {
      const element = node("button", "button " + kind, text); element.id = id; element.type = "button";
      element.addEventListener("click", action); return element;
    }
    function field(text, id, type, note = "") {
      const wrapper = node("div", "field"), label = node("label", "", text), input = node("input", "");
      label.htmlFor = id; input.id = id; input.type = type; input.autocomplete = "off"; input.spellcheck = false;
      wrapper.append(label, input);
      if (note) { const help = node("p", "field-note", note); help.id = id + "-note"; input.setAttribute("aria-describedby", help.id); wrapper.append(help); }
      return {wrapper, input};
    }
    function validate(data) {
      if (!record(data) || typeof data.enabled !== "boolean" || typeof data.storage_fault !== "boolean" ||
          typeof data.full !== "boolean" || !(data.counts === null || countsOK(data.counts)) ||
          !Array.isArray(data.events) || data.events.length > 100 || !Array.isArray(data.source_errors) ||
          !Array.isArray(data.stopped) || data.stopped.length > 20 ||
          (data.enabled && (!record(data.configuration) || typeof data.configuration.destination_origin !== "string"))) throw Error("invalid_notification_status");
      for (const item of data.events) if (!record(item) || !Object.hasOwn(kinds, item.status) || !Object.hasOwn(phases, item.delivery) ||
          !Number.isFinite(item.created_at) || !Number.isSafeInteger(item.attempts) || item.attempts < 0) throw Error("invalid_notification_event");
      for (const item of data.stopped) if (!record(item) || !(item.counts === null || countsOK(item.counts))) throw Error("invalid_notification_history");
      return data;
    }
    function updateControls() {
      if (!e.panel) return;
      const ready = authorized() && Boolean(state.data) && !state.loading && !state.pending;
      e.fields.disabled = !ready; e.edit.disabled = !ready; e.disable.disabled = !ready || !state.data?.enabled;
      e.confirmDisable.disabled = !ready; e.cancel.disabled = Boolean(state.pending);
      e.refresh.disabled = !authorized() || state.loading || state.pending?.phase === "sending";
      e.check.hidden = !state.pending || state.pending.phase === "sending";
      e.check.disabled = !authorized() || state.checking;
      e.save.textContent = state.pending?.phase === "sending" ? "正在保存…" : "保存并启用后台提醒";
      if (!authorized()) clearSecrets();
    }
    function render() {
      if (!e.panel) return;
      const data = state.data;
      e.status.textContent = !authorized() ? "等待连接" : state.loading ? "正在读取" : !data ? "尚未读取" :
        data.storage_fault || data.worker_error || data.source_errors.length ? "提醒异常" : data.full ? "记录已满" :
        data.counts?.failed ? "有发送失败" : data.enabled ? "后台已启用" : "未启用";
      const children = [];
      if (data?.enabled) {
        let destination = "已保存接收服务";
        try { const parsed = new URL(data.configuration.destination_origin); if (["https:", "http:"].includes(parsed.protocol)) destination = parsed.origin; } catch { /* Do not echo a malformed endpoint. */ }
        children.push(node("p", "field-note", "接收服务：" + destination + "。完整地址和凭证只保存在本机。"));
      }
      if (data?.storage_fault) children.push(node("p", "notice notice-error", "提醒记录无法核对，发送数量未知。请保留本机记录并检查工作台；这不会恢复被暂停的工作。"));
      if (data?.full) children.push(node("p", "notice notice-error", "提醒记录已满，新提醒正在等待。已发送记录也占用名额，以避免重复发送。关闭后重新启用会建立新记录，旧提醒不再补发。"));
      if (data?.source_errors.length) children.push(node("p", "notice notice-error", "部分工作的新事件还没有进入提醒记录，后台会继续尝试。请同时查看各项工作的状态。"));
      if (data?.enabled && (!data.worker_running || !data.scanner_running || data.worker_error)) children.push(node("p", "notice notice-error", "后台提醒尚未正常运行，请检查本机服务；不要将已保存设置当作已送达提醒。"));
      if (data?.counts) {
        const counts = node("div", "alert-counts");
        for (const [key, label] of Object.entries(phases)) counts.append(node("span", "status-badge", label + " " + data.counts[key]));
        children.push(counts);
      }
      if (data?.counts?.failed) children.push(node("p", "field-note", "发送失败的提醒已停止自动重试，请在工作台查看对应状态。接收服务确认不代表本人已经读到。"));
      const retired = (data?.stopped || []).reduce((sum, item) => sum + (item.counts ? item.counts.pending + item.counts.in_flight + item.counts.failed : 0), 0);
      if (retired) children.push(node("p", "field-note", "最近停用的提醒记录中有 " + retired + " 条未确认送达，已停止补发；旧记录仍保留在本机。"));
      const list = node("div", "alert-event-list");
      for (const event of data?.events || []) {
        const row = node("div", "alert-event-row");
        row.append(node("span", "", kinds[event.status]), node("span", "field-note", phases[event.delivery] + " · 尝试 " + event.attempts + " 次"),
          node("time", "field-note", new Date(event.created_at * 1000).toLocaleString()));
        list.append(row);
      }
      children.push(list); e.report.replaceChildren(...children); updateControls();
    }
    async function refresh() {
      if (!authorized() || state.loading) return;
      const generation = state.generation; state.loading = true; render();
      try {
        const data = validate(await api("/api/notifications"));
        if (generation === state.generation) state.data = data;
      } catch {
        if (generation === state.generation) { state.data = null; feedback("暂时无法读取后台提醒，请重新连接本机工作台。", true); }
      } finally { if (generation === state.generation) { state.loading = false; render(); } }
    }
    function collect() {
      const raw = e.url.value.trim(); let url;
      try { url = new URL(raw); } catch { throw Error("请填写完整的提醒接收地址。"); }
      const parts = url.hostname.split(".");
      const loopback = url.hostname === "[::1]" || parts.length === 4 && parts[0] === "127" && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255);
      if (!/^[\x21-\x7e]+$/.test(raw) || raw.includes("\\") || !["http:", "https:"].includes(url.protocol) ||
          url.username || url.password || url.search || url.hash || (url.protocol === "http:" && !loopback)) throw Error("接收地址须为 HTTPS；HTTP 只支持明确的本机地址，不能含账号、查询参数或页面锚点。");
      if (!/^[\x21-\x7e]*$/.test(e.key.value)) throw Error("凭证不能含空格、换行或中文。");
      return {enabled: true, config: {url: url.href, api_key: e.key.value, strict_receipt: e.strict.checked,
        timeout_seconds: Number(e.timeout.value), max_attempts: Number(e.attempts.value), queue_capacity: Number(e.capacity.value)}};
    }
    async function finish(request, success) {
      if (!current(request)) return;
      state.pending = null; clearSecrets(); e.form.hidden = true; e.disableBox.hidden = true;
      feedback(success ? "设置已保存。启用或更换接收服务后，只提醒随后发生的新事件。" : "这次设置未完成，请核对当前状态后重新填写。", !success);
      await refresh(); updateControls();
    }
    async function accept(request, data) {
      if (!current(request)) return;
      const job = data?.job;
      if (!record(job) || typeof job.id !== "string" || !/^[0-9a-f]{32}$/.test(job.id) || job.action !== "notifications_set") throw Error("invalid_notification_job");
      request.jobId = job.id;
      if (job.status === "succeeded" || job.status === "failed") return finish(request, job.status === "succeeded");
      if (!["queued", "running"].includes(job.status)) throw Error("invalid_notification_job_status");
      request.phase = "waiting"; feedback("本机正在保存设置，可以查询这一次保存的结果。"); updateControls();
    }
    async function submit(enabled) {
      if (!authorized() || !state.data || state.pending || state.loading) return;
      let payload;
      try {
        if (enabled && !e.form.reportValidity()) return;
        payload = enabled ? collect() : {enabled: false};
      } catch (error) { clearSecrets(); feedback(error.message, true); return; }
      const request = {key: freshKey(), generation: state.generation, phase: "sending"};
      state.pending = request; clearSecrets(); feedback(""); updateControls();
      try { await accept(request, await api("/api/notifications", {method: "POST", key: request.key, body: payload, noRetry: true})); }
      catch (error) {
        if (!current(request)) return;
        if (error?.uncertain === false) await finish(request, false);
        else { request.phase = "uncertain"; feedback("暂时无法确认保存结果。请只查询原请求；完整地址和凭证不会自动重发。", true); }
      } finally {
        if (payload.config) { delete payload.config.url; delete payload.config.api_key; }
        if (request.generation === state.generation) updateControls();
      }
    }
    async function checkRequest() {
      const request = state.pending;
      if (!request || request.phase === "sending" || !authorized() || state.checking) return;
      state.checking = true; updateControls();
      try { await accept(request, await api(request.jobId ? "/api/jobs/" + request.jobId : "/api/requests/" + request.key)); }
      catch { if (current(request)) feedback("原请求的结果仍未确认，请稍后再查；后台提醒设置不会重新提交。", true); }
      finally { if (request.generation === state.generation) { state.checking = false; updateControls(); } }
    }
    function edit() {
      if (!state.data || state.pending || state.loading || !authorized()) return;
      clearSecrets(); e.form.reset(); e.form.hidden = false; e.disableBox.hidden = true; feedback("");
      const config = state.data.configuration;
      e.strict.checked = Boolean(config?.strict_receipt); e.timeout.value = config?.timeout_seconds ?? 5;
      e.attempts.value = config?.max_attempts ?? 5; e.capacity.value = config?.queue_capacity ?? 10000;
      updateControls(); e.url.focus();
    }
    function boot() {
      const mount = document.getElementById("notification-settings"); if (!mount || e.panel) return;
      e.panel = node("details", "mail-account-panel"); e.panel.id = "alerts-panel";
      const summary = node("summary", ""); e.status = node("span", "mail-account-status", "尚未读取"); e.status.id = "alerts-status";
      summary.append(node("span", "", "后台提醒"), e.status);
      const content = node("div", "mail-account-content");
      content.append(node("p", "field-note", "工作暂停、恢复、收回权限，或邮件、消息、文件操作等待本人确认时，发送状态提醒。提醒不附带资料、指令或工作名称。"),
        node("p", "field-note", "关闭浏览器后仍可提醒，但启动工作台的进程必须保持运行。进程重启后补发停机期间的新事件；接收服务确认不代表本人已读。"));
      const controls = node("div", "mail-account-actions");
      e.edit = button("设置接收服务", "alerts-edit", edit); e.refresh = button("刷新提醒状态", "alerts-refresh", () => { void refresh(); }, "button-quiet");
      e.disable = button("关闭后台提醒", "alerts-disable", () => { clearSecrets(); e.form.hidden = true; e.disableBox.hidden = false; }, "button-quiet");
      controls.append(e.edit, e.refresh, e.disable);
      e.feedback = node("p", "form-message"); e.feedback.id = "alerts-feedback"; e.feedback.hidden = true;
      e.feedback.setAttribute("role", "status"); e.feedback.setAttribute("aria-live", "polite");
      e.check = button("只查询这次保存", "alerts-check", () => { void checkRequest(); }); e.check.hidden = true;
      e.form = node("form", "field-group"); e.form.id = "alerts-form"; e.form.autocomplete = "off"; e.form.hidden = true;
      e.fields = node("fieldset", ""); e.fields.append(node("legend", "visually-hidden", "后台提醒设置"));
      const url = field("完整接收地址", "alerts-url", "password", "接收服务需要接受通用 JSON 状态提醒。完整地址不会回显；修改设置时需重新填写。"),
        key = field("接收凭证（可留空）", "alerts-key", "password", "本机使用 Bearer 方式发送。提交、取消或连接失效时清空，浏览器不保存。"),
        timeout = field("每次等待秒数", "alerts-timeout", "number"), attempts = field("最多尝试次数", "alerts-attempts", "number"),
        capacity = field("提醒记录上限", "alerts-capacity", "number", "包括已发送的记录。达到上限后保留新事件，不会悄悄丢弃。" );
      e.url = url.input; e.url.required = true; e.url.maxLength = 2048;
      e.key = key.input; e.key.maxLength = 8192;
      e.timeout = timeout.input; e.timeout.min = .01; e.timeout.max = 30; e.timeout.step = .01; e.timeout.value = 5; e.timeout.required = true;
      e.attempts = attempts.input; e.attempts.min = 1; e.attempts.max = 20; e.attempts.step = 1; e.attempts.value = 5; e.attempts.required = true;
      e.capacity = capacity.input; e.capacity.min = 1; e.capacity.max = 100000; e.capacity.step = 1; e.capacity.value = 10000; e.capacity.required = true;
      const strictLabel = node("label", "alert-check"); e.strict = node("input", ""); e.strict.type = "checkbox"; e.strict.id = "alerts-strict";
      strictLabel.append(e.strict, node("span", "", "要求接收服务逐条确认事件编号（需服务支持）"));
      const advanced = node("details", ""); advanced.append(node("summary", "", "重试与记录设置"), timeout.wrapper, attempts.wrapper, capacity.wrapper, strictLabel);
      const note = node("p", "field-note", "首次启用只提醒随后发生的事。更换设置或关闭提醒会停止旧记录的补发；已经发出的请求无法撤回。再次启用从新的事件开始，旧记录留在本机。" );
      e.save = node("button", "button button-secondary", "保存并启用后台提醒"); e.save.id = "alerts-save"; e.save.type = "submit";
      e.cancel = button("取消编辑", "alerts-cancel", () => { clearSecrets(); e.form.hidden = true; feedback(""); }, "button-quiet");
      const formControls = node("div", "mail-account-actions"); formControls.append(e.save, e.cancel);
      e.fields.append(url.wrapper, key.wrapper, advanced, note, formControls); e.form.append(e.fields);
      e.form.addEventListener("submit", event => { event.preventDefault(); void submit(true); });
      e.disableBox = node("div", "mail-cancel-confirmation"); e.disableBox.hidden = true;
      e.confirmDisable = button("确认关闭提醒", "alerts-confirm-disable", () => { void submit(false); }, "button-outline-danger");
      e.disableBox.append(node("p", "", "关闭后停止补发旧提醒，已有请求可能已经到达接收服务。任务的防护和暂停状态保持独立。"), e.confirmDisable,
        button("保持提醒", "alerts-keep", () => { e.disableBox.hidden = true; }, "button-quiet"));
      e.report = node("div", "field-group"); e.report.id = "alerts-report";
      content.append(controls, e.feedback, e.check, e.form, e.disableBox, e.report); e.panel.append(summary, content); mount.append(e.panel);
      e.panel.addEventListener("toggle", () => { if (e.panel.open) void refresh(); else { clearSecrets(); e.form.hidden = true; } });
      window.addEventListener("pagehide", clearSecrets);
      window.setInterval(() => { if (e.panel.open && document.visibilityState === "visible" && authorized() && !state.pending) void refresh(); }, 6500);
      render(); if (authorized()) void refresh();
    }
    function reset() {
      state.generation += 1; state.pending = null; state.checking = false; state.loading = false; state.data = null;
      if (e.panel) { clearSecrets(); e.form.hidden = true; e.disableBox.hidden = true; feedback(""); render(); }
    }
    return {boot, reset, refresh, updateControls};
  };
})();
