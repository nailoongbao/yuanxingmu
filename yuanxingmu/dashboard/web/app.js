/* The management token is removed before any UI is initialized. */
(() => {
  "use strict";

  const SESSION_KEY = "yuanxingmu.workbench.access";
  let fragment = window.location.hash;
  if (fragment) {
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
  }
  let accessToken = "";
  let storageAvailable = true;
  const access = new URLSearchParams(fragment.slice(1));
  fragment = "";
  try {
    if (access.has("access")) {
      accessToken = access.get("access") || "";
      window.sessionStorage.removeItem(SESSION_KEY);
      if (accessToken) window.sessionStorage.setItem(SESSION_KEY, accessToken);
    } else {
      accessToken = window.sessionStorage.getItem(SESSION_KEY) || "";
    }
  } catch {
    storageAvailable = false;
    accessToken = access.get("access") || accessToken;
  }
  access.delete("access");

  const state = {
    info: null,
    profiles: [],
    profilesLoaded: false,
    documents: [],
    nextDocument: 1,
    importing: false,
    refreshing: false,
    createAttempt: null,
    createJob: null,
    createSending: false,
    requests: new Map(),
    jobs: new Map(),
    jobErrors: new Map(),
    dashboardURLs: new Map(),
    createdProfiles: new Set(),
    revokeTarget: null,
    authRejected: false,
    profilesError: "",
    infoError: ""
  };
  const elements = {};
  let mail = null;
  let actionReview = null;
  let protection = null;
  let targets = null;
  let alerts = null;
  let lastProfileRender = "";
  const profileID = /^[a-f0-9]{32}$/;
  const resourceName = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
  const statusLabels = {
    stopped: ["已停止", ""],
    starting: ["正在启动", "working"],
    ready: ["正在运行", "ready"],
    stopping: ["正在停止", "working"],
    interrupted: ["运行中断", "uncertain"],
    unconfirmed: ["状态待确认", "uncertain"],
    failed: ["运行异常", "failed"],
    creation_failed: ["创建未完成", "failed"]
  };
  const actionLabels = {create: "创建", start: "启动", stop: "暂时关闭", revoke: "收回权限"};
  const frameworkLabel = name => name === "hermes" ? "Hermes" : "OpenClaw";
  const frameworkReady = name => Boolean((state.info?.frameworks?.[name || "openclaw"] || state.info?.runtime)?.available);
  const anyFrameworkReady = () => state.info?.frameworks
    ? Object.values(state.info.frameworks).some(item => item.available) : Boolean(state.info?.runtime?.available);
  const delay = milliseconds => new Promise(resolve => window.setTimeout(resolve, milliseconds));

  class APIError extends Error {
    constructor(message, status = 0, uncertain = false) {
      super(message);
      this.status = status;
      this.uncertain = uncertain;
    }
  }

  function node(tag, className, content) {
    const result = document.createElement(tag);
    if (className) result.className = className;
    if (content !== undefined) result.textContent = String(content);
    return result;
  }

  function button(label, className, handler, focusKey) {
    const result = node("button", "button " + className, label);
    result.type = "button";
    result.addEventListener("click", handler);
    if (focusKey) result.dataset.focusKey = focusKey;
    return result;
  }

  function sizeLabel(bytes) {
    if (!Number.isFinite(bytes)) return "";
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1048576) return (bytes / 1024).toFixed(bytes % 1024 ? 1 : 0) + " KB";
    return (bytes / 1048576).toFixed(bytes % 1048576 ? 1 : 0) + " MB";
  }

  function errorText(error) {
    return error instanceof Error ? error.message : "这次操作未完成，请刷新状态后重试。";
  }

  function setConnection(connected, message) {
    elements.connectionText.textContent = message;
    elements.connectionDot.className = "connection-dot " + (connected ? "connected" : "disconnected");
  }

  function updateNotice() {
    let message = "";
    if (!accessToken || state.authRejected) {
      message = state.authRejected
        ? "本机服务已拒绝这次访问凭证。请从启动工作台的终端重新打开完整启动链接。"
        : "请从启动工作台的终端打开完整启动链接，才能查看和管理本机工作。";
    } else if (state.infoError) {
      message = state.infoError;
    } else if (state.profilesError) {
      message = "暂时无法刷新工作状态。下方若有内容，是上一次收到的结果。" + state.profilesError;
    } else if (state.info && !anyFrameworkReady()) {
      message = "本机运行环境尚未就绪，暂时不能创建或启动工作。" + (state.info.runtime.reason || "");
    } else if (!storageAvailable) {
      message = "浏览器未允许在本标签页保存访问凭证。刷新网页后，请重新打开终端中的完整启动链接。";
    }
    elements.globalNotice.textContent = message;
    elements.globalNotice.hidden = !message;
    elements.globalNotice.classList.toggle("notice-error", !accessToken || state.authRejected);
  }

  function rejectToken() {
    accessToken = "";
    state.authRejected = true;
    state.createAttempt = null;
    state.requests.clear();
    state.dashboardURLs.clear();
    mail?.reset();
    actionReview?.reset();
    protection?.reset();
    targets?.reset();
    alerts?.reset();
    try { window.sessionStorage.removeItem(SESSION_KEY); } catch { /* Storage may be unavailable. */ }
    if (elements.apiKey) {
      elements.apiKey.value = "";
      if(elements.judgeKey) elements.judgeKey.value="";
      elements.runtimeStatus.textContent = "访问凭证已失效";
      setConnection(false, "需要重新打开");
      updateControls();
      updateNotice();
      renderProfiles();
    }
  }

  async function api(path, options = {}) {
    if (!accessToken) throw new APIError("请重新打开终端中的完整启动链接。", 401);
    const requestToken = accessToken;
    const isPost = options.method === "POST";
    for (let attempt = 0; attempt < 2; attempt += 1) {
      if (requestToken !== accessToken) throw new APIError("访问链接已更新，正在重新连接。", 401);
      const controller = new AbortController();
      const timeout = window.setTimeout(() => controller.abort(), 20000);
      try {
        const headers = {Accept: "application/json", Authorization: "Bearer " + requestToken};
        if (isPost) {
          headers["Content-Type"] = "application/json";
          headers["Idempotency-Key"] = options.key;
        }
        const response = await fetch(path, {
          method: options.method || "GET",
          headers,
          body: isPost ? JSON.stringify(options.body) : undefined,
          mode: "same-origin",
          credentials: "omit",
          redirect: "error",
          cache: "no-store",
          referrerPolicy: "no-referrer",
          signal: controller.signal
        });
        if (requestToken !== accessToken) throw new APIError("访问链接已更新，正在重新连接。", 401);
        if (response.status === 401) {
          rejectToken();
          throw new APIError("访问凭证已失效，请重新打开终端中的完整启动链接。", 401);
        }
        let data;
        try { data = await response.json(); } catch {
          throw new APIError("后台返回的内容无法读取，请重试确认这次操作。", response.status, isPost);
        }
        if (!response.ok) {
          throw new APIError(data.error?.message || "本机服务未能完成这次请求。", response.status, isPost && response.status >= 500);
        }
        return data;
      } catch (error) {
        if (error instanceof APIError) throw error;
        if (attempt === 0 && accessToken && !(isPost && options.noRetry)) {
          await delay(700);
          continue;
        }
        throw new APIError("无法连接本机服务，请确认启动工作台的终端仍在运行。", 0, isPost);
      } finally {
        window.clearTimeout(timeout);
      }
    }
  }

  function newKey() {
    return window.crypto.randomUUID().replaceAll("-", "");
  }

  function updateControls() {
    const authorized = Boolean(accessToken) && !state.authRejected;
    const runtimeReady = anyFrameworkReady();
    const createBusy = Boolean(state.createAttempt || state.createJob || state.importing || state.createSending);
    elements.createFields.disabled = !authorized || !runtimeReady || createBusy;
    elements.createSubmit.disabled = !frameworkReady(elements.framework.value) || createBusy;
    elements.createSubmit.textContent = state.importing ? "正在读取文本…" : state.createJob ? "正在创建，请稍候…" : state.createSending ? "正在提交…" : "创建独立工作 ↗";
    elements.refreshButton.disabled = !authorized || state.refreshing;
    elements.refreshButton.textContent = state.refreshing ? "正在刷新…" : "刷新状态 ↻";
    elements.retryCreate.hidden = !(state.createAttempt && !state.createSending);
    elements.retryCreate.disabled = !authorized || state.createSending;
    elements.confirmRevoke.disabled = !authorized;
    mail?.updateControls();
    actionReview?.updateControls();
    targets?.updateControls();
    alerts?.updateControls();
  }

  function setCreateMessage(message, isError = false) {
    elements.createMessage.textContent = message;
    elements.createMessage.hidden = !message;
    elements.createMessage.classList.toggle("error", isError);
  }

  function renderInfo(info) {
    state.info = info;
    elements.runtimeStatus.textContent = anyFrameworkReady() ? "可以开始工作" : "尚未就绪";
    elements.runtimeVersion.textContent = ["openclaw", "hermes"].filter(frameworkReady).map(frameworkLabel).join(" · ");
    for (const option of elements.framework.options) {
      option.disabled = !frameworkReady(option.value);
      option.textContent = frameworkLabel(option.value) + (option.disabled ? "（尚未安装）" : "");
    }
    if (!frameworkReady(elements.framework.value)) {
      const first = Array.from(elements.framework.options).find(option => !option.disabled);
      if (first) elements.framework.value = first.value;
    }
    elements.fileLimitNote.textContent = "UTF-8 文本，每份最多 " + sizeLabel(info.limits.document_bytes);
    const skills=document.getElementById("create-skills");
    const chosen=new Set(Array.from(skills.querySelectorAll("input:checked")).map(input=>input.value));
    skills.replaceChildren();
    for(const item of info.skills || []) {
      const label=node("label",""),input=node("input","");input.type="checkbox";input.value=item.id;input.checked=chosen.has(item.id);
      label.append(input,node("span","",item.label));skills.append(label);
    }
    if(!(info.skills || []).length) skills.append(node("p","field-note","本机还没有登记可选技能，将使用不加载额外技能的工作环境。"));
    renderDocuments();
    updateControls();
  }

  async function refreshProfiles() {
    if (!accessToken) return;
    try {
      const data = await api("/api/profiles");
      if (!Array.isArray(data.profiles)) throw new APIError("工作列表返回不完整，请重新刷新。", 500);
      state.profiles = data.profiles;
      state.profilesLoaded = true;
      state.profilesError = "";
      for (const profile of state.profiles) {
        if (profile.status !== "ready") state.dashboardURLs.delete(profile.id);
      }
      elements.profileList.setAttribute("aria-busy", "false");
      elements.refreshTime.textContent = "状态更新于 " + new Date().toLocaleTimeString("zh-CN", {hour12: false});
      setConnection(true, "已连接本机");
      renderProfiles();
      mail?.profilesChanged();
      protection?.profilesChanged(state.profiles);
    } catch (error) {
      if (error.status !== 401) {
        state.profilesError = errorText(error);
        setConnection(false, "连接暂时中断");
        elements.profileList.setAttribute("aria-busy", "false");
        renderProfiles();
      }
    }
    updateNotice();
  }

  async function refreshAll() {
    if (state.refreshing || !accessToken) return;
    state.refreshing = true;
    updateControls();
    const results = await Promise.allSettled([api("/api/info"), refreshProfiles(), mail?.refreshAccount()]);
    if (results[0].status === "fulfilled") {
      const info = results[0].value;
      if (info.runtime && info.limits) {
        state.infoError = "";
        renderInfo(info);
      } else {
        state.infoError = "运行环境信息返回不完整，请重新刷新。";
        elements.runtimeStatus.textContent = "暂时无法确认";
      }
    } else if (results[0].reason.status !== 401) {
      state.infoError = errorText(results[0].reason);
      elements.runtimeStatus.textContent = "暂时无法确认";
      setConnection(false, "连接暂时中断");
    }
    if (results[1].status === "rejected") state.profilesError = errorText(results[1].reason);
    state.refreshing = false;
    updateNotice();
    updateControls();
    renderProfiles();
  }

  function renderDocuments() {
    const total = state.documents.reduce((sum, item) => sum + item.bytes, 0);
    elements.documentCount.textContent = state.documents.length ? state.documents.length + " 份 · " + sizeLabel(total) : "尚未导入";
    const fragmentNode = document.createDocumentFragment();
    for (const item of state.documents) {
      const row = node("div", "document-item");
      const file = node("div", "document-file");
      const filename = node("span", "document-file-name", item.filename);
      filename.append(node("span", "document-size", sizeLabel(item.bytes)));
      const remove = button("移除", "remove-file", () => {
        state.documents = state.documents.filter(documentItem => documentItem.id !== item.id);
        renderDocuments();
        elements.documentFiles.focus();
      });
      remove.className = "remove-file";
      remove.setAttribute("aria-label", "移除 " + item.filename);
      file.append(filename, remove);
      const resource = node("div", "resource-row");
      const label = node("label", "", "对话中叫它");
      label.htmlFor = "resource-name-" + item.id;
      const input = node("input");
      input.id = label.htmlFor;
      input.type = "text";
      input.value = item.name;
      input.required = true;
      input.maxLength = 64;
      input.pattern = "[A-Za-z0-9][A-Za-z0-9_\\-]{0,63}";
      input.autocomplete = "off";
      input.spellcheck = false;
      input.setAttribute("aria-label", item.filename + " 的资料名称");
      input.addEventListener("input", () => { item.name = input.value; input.setCustomValidity(""); });
      resource.append(label, input);
      row.append(file, resource);
      fragmentNode.append(row);
    }
    if (state.documents.length) {
      fragmentNode.append(node("p", "resource-hint", "资料名称用于在对话中点名读取，只能使用英文字母、数字、下划线或短横线，以字母或数字开头。"));
    }
    elements.documentList.replaceChildren(fragmentNode);
  }

  function nextResourceName() {
    let index = state.documents.length + 1;
    let proposed = index === 1 ? "quote" : "doc" + index;
    while (state.documents.some(item => item.name === proposed)) {
      index += 1;
      proposed = "doc" + index;
    }
    return proposed;
  }

  async function importDocuments() {
    const files = Array.from(elements.documentFiles.files || []);
    elements.documentFiles.value = "";
    if (!files.length || !state.info || state.importing) return;
    state.importing = true;
    updateControls();
    const errors = [];
    const limits = state.info.limits;
    for (const file of files) {
      const filename = file.name.split(/[\\/]/).pop() || "document.txt";
      const total = state.documents.reduce((sum, item) => sum + item.bytes, 0);
      if (state.documents.length >= limits.documents) {
        errors.push("最多导入 " + limits.documents + " 份资料，其余文件未导入。");
        break;
      }
      if (file.size > limits.document_bytes) {
        errors.push(filename + "：超过单份 " + sizeLabel(limits.document_bytes) + " 的限制。");
        continue;
      }
      if (total + file.size > limits.total_document_bytes) {
        errors.push(filename + "：导入后会超过总计 " + sizeLabel(limits.total_document_bytes) + " 的限制。");
        continue;
      }
      try {
        const content = new TextDecoder("utf-8", {fatal: true}).decode(await file.arrayBuffer());
        if (content.includes("\u0000")) throw new Error("not-text");
        state.documents.push({id: state.nextDocument++, name: nextResourceName(), filename, content, bytes: file.size});
      } catch {
        errors.push(filename + "：无法按 UTF-8 文本读取，请先转存为 UTF-8 文本文件。");
      }
    }
    elements.fileError.textContent = errors.join("\n");
    elements.fileError.hidden = !errors.length;
    state.importing = false;
    renderDocuments();
    updateControls();
  }

  function validateCreate() {
    for (const input of [elements.workName, elements.modelURL, elements.modelID, elements.apiKey]) input.setCustomValidity("");
    if (!elements.workName.value.trim()) elements.workName.setCustomValidity("请填写工作名称。");
    if (!elements.modelID.value.trim()) elements.modelID.setCustomValidity("请填写模型名称。");
    try {
      const url = new URL(elements.modelURL.value.trim());
      if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) throw new Error("invalid-url");
      if (url.protocol === "https:" && !elements.apiKey.value.trim()) {
        elements.apiKey.setCustomValidity("使用 HTTPS 模型服务时，请填写连接密钥。");
      }
    } catch { elements.modelURL.setCustomValidity("请填写完整的 http:// 或 https:// 模型地址，密钥请放在连接密钥一栏。"); }
    if (elements.apiKey.value && !/^[\x21-\x7e]+$/.test(elements.apiKey.value)) {
      elements.apiKey.setCustomValidity("密钥不能含空格、换行或中文，请核对后重新填写。");
    }
    const names = new Set();
    for (const item of state.documents) {
      const input = document.getElementById("resource-name-" + item.id);
      input.setCustomValidity("");
      if (!resourceName.test(item.name)) input.setCustomValidity("资料名称须以字母或数字开头，仅使用字母、数字、下划线和短横线，最多 64 个字符。");
      else if (names.has(item.name)) input.setCustomValidity("每份资料的名称需要不同。");
      names.add(item.name);
    }
    return elements.createForm.reportValidity();
  }

  async function submitCreate(event) {
    if (event) event.preventDefault();
    if (state.createSending || state.createJob || state.importing || !accessToken) return;
    if (!state.createAttempt) {
      if (!validateCreate()) return;
      state.createAttempt = {
        key: newKey(),
        body: {
          framework: elements.framework.value,
          objective: elements.objective.value.trim(),
          defense: {mode:document.getElementById("create-defense-mode").value,
            ...Object.fromEntries(Array.from(document.querySelectorAll("#create-defense-layers input[data-layer]")).map(input=>[input.dataset.layer+"_enabled",input.checked]))},
          skills: Array.from(document.querySelectorAll("#create-skills input:checked")).map(input=>input.value),
          name: elements.workName.value.trim(),
          model_url: elements.modelURL.value.trim(),
          model_id: elements.modelID.value.trim(),
          api_key: elements.apiKey.value,
          documents: state.documents.map(item => ({name: item.name, filename: item.filename, content: item.content}))
        }
      };
      if(elements.separateJudge.checked) state.createAttempt.body.judge={url:elements.judgeURL.value.trim(),id:elements.judgeID.value.trim(),api_key:elements.judgeKey.value,timeout_seconds:Number(elements.judgeTimeout.value)};
      elements.apiKey.value = "";
      elements.judgeKey.value = "";
    }
    const attempt = state.createAttempt;
    state.createSending = true;
    setCreateMessage("正在提交创建请求。收到后台结果后，会在右侧显示这份工作。");
    updateControls();
    try {
      const result = await api("/api/profiles", {method: "POST", body: attempt.body, key: attempt.key});
      if (!result.job?.id) throw new APIError("尚未收到创建结果，请重试确认同一次操作。", 0, true);
      state.createAttempt = null;
      attempt.body.api_key = "";
      if(attempt.body.judge) attempt.body.judge.api_key="";
      state.createJob = result.job.id;
      setCreateMessage("本机正在创建工作，请稍候。关闭网页不会取消已经提交的操作。");
      registerJob(result.job);
      await refreshProfiles();
    } catch (error) {
      if (!error.uncertain) {
        attempt.body.api_key = "";
        if(attempt.body.judge) attempt.body.judge.api_key="";
        state.createAttempt = null;
      }
      setCreateMessage(errorText(error) + (error.uncertain ? " 创建是否收到暂未确认；下方按钮会继续确认同一次操作。" : ""), true);
    } finally {
      state.createSending = false;
      updateControls();
    }
  }

  function acceptedDashboardURL(value) {
    if (typeof value !== "string") return null;
    try {
      const url = new URL(value);
      if (!["http:", "https:"].includes(url.protocol) || !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) return null;
      if (url.username || url.password || (accessToken && value.includes(accessToken))) return null;
      return url.href;
    } catch { return null; }
  }

  function upsertProfile(profile) {
    if (!profile || !profileID.test(profile.id)) return;
    const index = state.profiles.findIndex(item => item.id === profile.id);
    if (index < 0) state.profiles.unshift(profile);
    else state.profiles[index] = profile;
    state.profilesLoaded = true;
  }

  function registerJob(job) {
    if (typeof job.id !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(job.id)) return;
    state.jobs.set(job.id, job);
    state.jobErrors.delete(job.profile_id);
    renderProfiles();
    void watchJob(job.id);
  }

  async function watchJob(id) {
    while (accessToken && state.jobs.has(id)) {
      try {
        const result = await api("/api/jobs/" + encodeURIComponent(id));
        const job = result.job;
        if (!job || job.id !== id) throw new APIError("暂未取得这次操作的结果，正在重新确认。");
        state.jobs.set(id, job);
        if (job.result?.profile) upsertProfile(job.result.profile);
        if (job.status === "succeeded" || job.status === "failed") {
          state.jobs.delete(id);
          state.requests.delete(job.profile_id);
          if (job.status === "succeeded") {
            state.jobErrors.delete(job.profile_id);
            if (job.action === "start") {
              const url = acceptedDashboardURL(job.result?.dashboard_url);
              if (url) state.dashboardURLs.set(job.profile_id, url);
              else state.jobErrors.set(job.profile_id, "启动操作已完成，但没有收到可用的本机聊天入口。请刷新状态后重新获取入口。");
            }
            if (job.action === "stop") state.dashboardURLs.delete(job.profile_id);
          } else {
            state.jobErrors.set(job.profile_id, job.error?.message || "这次操作未完成，请检查工作状态。");
          }
          if (state.createJob === id) {
            state.createJob = null;
            if (job.status === "succeeded") {
              state.createdProfiles.add(job.profile_id);
              const name = job.result?.profile?.name;
              setCreateMessage((name ? "“" + name + "”" : "工作") + "已创建。请在工作卡片中启动，再进入聊天界面对话。");
              elements.workName.value = "";
              elements.objective.value = "";
              state.documents = [];
              elements.fileError.hidden = true;
              renderDocuments();
            } else {
              setCreateMessage("创建未完成。" + (job.error?.message || "请查看工作卡片中的结果。") + " 已留下的工作记录会继续显示。", true);
            }
          }
          updateControls();
          renderProfiles();
          await refreshProfiles();
          return;
        }
        renderProfiles();
      } catch (error) {
        if (error.status === 401 || !accessToken) return;
        const job = state.jobs.get(id);
        if (job) {
          job.pollError = errorText(error) + " 正在重新确认操作结果。";
          renderProfiles();
        }
        await delay(3000);
      }
      await delay(1500);
    }
  }

  async function runMutation(profile, action) {
    if (!profileID.test(profile.id) || !accessToken) return;
    let request = state.requests.get(profile.id);
    if (request && (request.sending || request.action !== action)) return;
    if (!request) {
      request = {action, key: newKey(), body: action === "revoke" ? {confirm: "revoke"} : {}, sending: false, error: ""};
      state.requests.set(profile.id, request);
    }
    request.sending = true;
    request.error = "";
    state.jobErrors.delete(profile.id);
    renderProfiles();
    try {
      const result = await api("/api/profiles/" + profile.id + "/" + action, {method: "POST", body: request.body, key: request.key});
      if (!result.job?.id) throw new APIError("尚未收到操作结果，请重试确认同一次操作。", 0, true);
      state.requests.delete(profile.id);
      registerJob(result.job);
      await refreshProfiles();
    } catch (error) {
      if (error.uncertain) {
        request.sending = false;
        request.error = errorText(error) + " 提交结果尚未确认，重试会继续同一次操作。";
      } else {
        state.requests.delete(profile.id);
        state.jobErrors.set(profile.id, errorText(error));
      }
      renderProfiles();
    }
  }

  function pendingFor(profile) {
    return Array.from(state.jobs.values()).find(job => job.profile_id === profile.id) || null;
  }

  function showRevoke(profile) {
    state.revokeTarget = profile.id;
    elements.revokeWorkName.textContent = profile.name;
    elements.revokeDialog.showModal();
    elements.cancelRevoke.focus();
  }

  function renderProfile(profile) {
    const card = node("article", "profile-card" + (state.createdProfiles.has(profile.id) ? " created" : ""));
    const heading = node("div", "profile-heading");
    const titleGroup = node("div");
    if (state.createdProfiles.has(profile.id)) titleGroup.append(node("p", "created-note", "刚刚创建"));
    const title = node("h3", "", profile.name);
    title.id = "work-title-" + profile.id;
    card.setAttribute("aria-labelledby", title.id);
    titleGroup.append(title);
    const model = node("p", "model-line", "模型 · ");
    model.append(node("span", "", profile.model_id || "尚未配置完成"));
    titleGroup.append(model);
    const status = statusLabels[profile.status] || ["状态待确认", "uncertain"];
    heading.append(titleGroup, node("span", "status-badge " + status[1], status[0]));
    card.append(heading);
    if(profile.paused === true) {
      const warning=node("p","job-notice error","工作已暂停，后续工具操作已停止。请打开防护记录，核对原因后恢复。");
      warning.setAttribute("role","alert");card.append(warning);
    }

    const permission = node("div", "permission" + (profile.revoked === true ? " revoked" : profile.revoked !== false ? " unknown" : ""));
    const permissionText = node("div");
    permissionText.append(node("p", "", profile.revoked === true ? "资料权限已永久收回" : profile.paused === true ? "本次资料权限已暂停使用" : profile.revoked === false ? "本次资料权限仍有效" : "资料权限尚未确认"));
    if (profile.revoked === true) permissionText.append(node("p", "", "这份工作不能重新启动。已读到的内容不会被清除；是否仍在运行，请看上方状态。"));
    if (profile.revoked === null) permissionText.append(node("p", "", "请刷新查看结果，当前不能确认资料是否仍可读取。"));
    permission.append(node("span", "permission-indicator", profile.revoked === true ? "−" : profile.revoked === false ? "◇" : "?"), permissionText);
    card.append(permission);

    const documents = Array.isArray(profile.documents) ? profile.documents : [];
    if (documents.length) {
      const files = node("div", "saved-documents");
      files.append(node("h4", "", "已导入的资料 · " + documents.length + " 份"));
      const list = node("ul");
      for (const item of documents) {
        const row = node("li");
        row.append(node("code", "resource-tag", item.name), node("span", "saved-filename", item.filename), node("span", "document-size", sizeLabel(item.bytes)));
        list.append(row);
      }
      files.append(list);
      card.append(files);
      if (profile.revoked === false) {
        const details = node("details", "prompt-details");
        details.dataset.detailKey = profile.id;
        details.open = state.createdProfiles.has(profile.id);
        details.append(node("summary", "", "进入聊天后，可以这样开始"));
        const names = documents.map(item => item.name).join("、");
        details.append(node("p", "prompt-example", "请阅读资源 " + names + "，用中文总结主要内容，并注明资料来源。"));
        details.append(node("p", "prompt-footnote", "把这句话发到 " + frameworkLabel(profile.framework) + " 中；资料名称需要与上方一致。"));
        card.append(details);
      }
    } else card.append(node("p", "no-documents", "这份工作没有导入资料。"));

    const mailEntry = mail?.profileEntry(profile);
    if (mailEntry) card.append(mailEntry);
    const extraActions = node("div", "profile-actions");
    const reviewButton = actionReview?.profileButton(profile);
    const protectionButton = protection?.profileButton(profile);
    if (reviewButton) extraActions.append(reviewButton);
    if (protectionButton) extraActions.append(protectionButton);
    if (extraActions.childElementCount) card.append(extraActions);

    const request = state.requests.get(profile.id);
    const job = pendingFor(profile);
    const busy = Boolean(request || job || profile.pending || ["starting", "stopping"].includes(profile.status));
    const pending = request ? "正在提交" + actionLabels[request.action] + "请求…" : job ? "本机正在" + (actionLabels[job.action] || "处理") + "，请稍候。" : profile.pending ? "本机正在" + (actionLabels[profile.pending] || "处理操作") + "，请稍候。" : "";
    if (pending) {
      const notice = node("div", "job-notice", request?.error || job?.pollError || pending);
      if (request?.error) {
        notice.classList.add("error");
        const retry = button("重新确认这次操作", "button-secondary", () => { void runMutation(profile, request.action); }, profile.id + "-retry");
        retry.disabled = !accessToken;
        notice.append(document.createElement("br"), retry);
      }
      if (!request?.error && !job?.pollError && (request?.action === "start" || job?.action === "start" || profile.status === "starting")) {
        notice.append(node("p", "", "启动可能需要几十秒，完成后会显示聊天入口。"));
      }
      card.append(notice);
    }
    const error = state.jobErrors.get(profile.id) || profile.error?.message;
    if (error) card.append(node("p", "job-notice error", error));

    const actions = node("div", "profile-actions");
    const url = state.dashboardURLs.get(profile.id);
    if (url && profile.status === "ready") {
      const open = node("a", "button button-primary", "进入 " + frameworkLabel(profile.framework) + " ↗");
      open.href = url;
      open.target = "_blank";
      open.rel = "noopener noreferrer";
      open.dataset.focusKey = profile.id + "-open";
      actions.append(open);
    } else {
      const start = button(profile.status === "ready" ? "获取聊天入口" : "启动工作", "button-primary", () => { void runMutation(profile, "start"); }, profile.id + "-start");
      start.disabled = busy || !accessToken || profile.revoked === true || !frameworkReady(profile.framework) || ["creation_failed", "unconfirmed"].includes(profile.status);
      actions.append(start);
    }
    const stop = button("暂时关闭", "button-secondary", () => { void runMutation(profile, "stop"); }, profile.id + "-stop");
    stop.disabled = busy || !accessToken || profile.status === "stopped";
    actions.append(stop, node("span", "action-divider"));
    if (profile.revoked !== true) {
      const revoke = button("收回权限", "button-outline-danger", () => showRevoke(profile), profile.id + "-revoke");
      revoke.disabled = busy || !accessToken;
      actions.append(revoke);
    }
    card.append(actions);
    return card;
  }

  function renderProfiles() {
    if (!elements.profileList) return;
    const renderKey = JSON.stringify({
      profiles: state.profiles,
      loaded: state.profilesLoaded,
      error: state.profilesError,
      authorized: Boolean(accessToken),
      runtimeAvailable: state.info?.frameworks || state.info?.runtime,
      createDisabled: elements.createFields.disabled,
      created: Array.from(state.createdProfiles),
      requests: Array.from(state.requests, ([id, request]) => [id, request.action, request.sending, request.error]),
      jobs: Array.from(state.jobs, ([id, job]) => [id, job.profile_id, job.action, job.status, job.pollError]),
      errors: Array.from(state.jobErrors),
      urls: Array.from(state.dashboardURLs)
    });
    if (renderKey === lastProfileRender) return;
    lastProfileRender = renderKey;
    const focused = elements.profileList.contains(document.activeElement) ? document.activeElement.dataset.focusKey : null;
    const openDetails = new Map(Array.from(elements.profileList.querySelectorAll("details[data-detail-key]"), detail => [detail.dataset.detailKey, detail.open]));
    const fragmentNode = document.createDocumentFragment();
    const validProfiles = state.profiles.filter(profile => profileID.test(profile.id));
    if (validProfiles.length) {
      for (const profile of validProfiles) fragmentNode.append(renderProfile(profile));
    } else {
      const empty = node("div", "empty-state");
      empty.append(node("span", "empty-symbol", "◇"));
      if (!accessToken) {
        empty.append(node("h3", "", "等待连接本机工作台"), node("p", "", "请使用启动终端给出的完整链接，访问你自己的工作。"));
      } else if (state.profilesLoaded) {
        empty.append(node("h3", "", "从第一份资料开始"), node("p", "", "创建一份真实工作后，它会出现在这里。你可以查看资料范围、开始对话，或暂时关闭这份工作。"));
        const first = button("创建第一份工作", "button-secondary", () => {
          elements.workName.focus();
          elements.createForm.scrollIntoView({behavior: "auto", block: "start"});
        }, "first-work");
        first.disabled = elements.createFields.disabled;
        empty.append(first);
      } else {
        empty.append(node("h3", "", state.profilesError ? "暂时无法读取工作" : "正在读取本机工作"), node("p", "", state.profilesError ? "请确认启动终端仍在运行，然后刷新状态。" : "这里只显示本机实际创建的工作。"));
      }
      fragmentNode.append(empty);
    }
    elements.profileList.replaceChildren(fragmentNode);
    elements.workCount.textContent = String(validProfiles.length);
    elements.workCount.hidden = !state.profilesLoaded;
    for (const detail of elements.profileList.querySelectorAll("details[data-detail-key]")) {
      if (openDetails.has(detail.dataset.detailKey)) detail.open = openDetails.get(detail.dataset.detailKey);
    }
    if (focused) {
      const next = Array.from(elements.profileList.querySelectorAll("[data-focus-key]")).find(item => item.dataset.focusKey === focused);
      if (next && !next.disabled) next.focus({preventScroll: true});
    }
  }

  function boot() {
    const ids = {
      connectionText: "connection-text", connectionDot: "connection-dot", globalNotice: "global-notice",
      runtimeStatus: "runtime-status", runtimeVersion: "runtime-version", createForm: "create-form",
      createFields: "create-fields", framework: "framework", objective: "work-objective", workName: "work-name", modelURL: "model-url", modelID: "model-id",
      apiKey: "api-key", documentFiles: "document-files", documentList: "document-list", documentCount: "document-count",
      separateJudge:"separate-judge",judgeFields:"judge-fields",judgeURL:"judge-url",judgeID:"judge-model-id",judgeKey:"judge-api-key",judgeTimeout:"judge-timeout",
      fileLimitNote: "file-limit-note", fileError: "file-error", createSubmit: "create-submit", createMessage: "create-message",
      retryCreate: "retry-create", refreshButton: "refresh-button", profileList: "profile-list", workCount: "work-count",
      refreshTime: "refresh-time", revokeDialog: "revoke-dialog", revokeWorkName: "revoke-work-name",
      cancelRevoke: "cancel-revoke", confirmRevoke: "confirm-revoke"
    };
    for (const [key, id] of Object.entries(ids)) elements[key] = document.getElementById(id);
    if (typeof window.createYuanxingmuMail === "function") {
      mail = window.createYuanxingmuMail({
        api, newKey, node,
        authorized: () => Boolean(accessToken) && !state.authRejected,
        getProfile: id => state.profiles.find(profile => profile.id === id),
        upsertProfile, refreshProfiles
      });
      mail.boot();
    }
    if (typeof window.createYuanxingmuActions === "function") {
      actionReview = window.createYuanxingmuActions({api,newKey,node,authorized:()=>Boolean(accessToken)&&!state.authRejected,
        getProfile:id=>state.profiles.find(profile=>profile.id===id),upsertProfile,refreshProfiles});
      actionReview.boot();
    }
    if (typeof window.createYuanxingmuProtection === "function") {
      protection = window.createYuanxingmuProtection({api,node,authorized:()=>Boolean(accessToken)&&!state.authRejected});
      protection.boot();
    }
    if (typeof window.createYuanxingmuTargets === "function") {
      targets = window.createYuanxingmuTargets({api,node,authorized:()=>Boolean(accessToken)&&!state.authRejected});
      targets.boot();
    }
    if (typeof window.createYuanxingmuAlerts === "function") {
      alerts = window.createYuanxingmuAlerts({api,node,authorized:()=>Boolean(accessToken)&&!state.authRejected});
      alerts.boot();
    }
    elements.documentFiles.addEventListener("change", () => { void importDocuments(); });
    elements.framework.addEventListener("change", updateControls);
    elements.createForm.addEventListener("submit", event => { void submitCreate(event); });
    elements.retryCreate.addEventListener("click", () => { void submitCreate(); });
    elements.refreshButton.addEventListener("click", () => { void refreshAll(); });
    elements.separateJudge.addEventListener("change",()=>{elements.judgeFields.disabled=!elements.separateJudge.checked;if(!elements.separateJudge.checked)elements.judgeKey.value="";});
    for (const input of [elements.workName, elements.modelURL, elements.modelID, elements.apiKey]) {
      input.addEventListener("input", () => { input.setCustomValidity(""); elements.apiKey.setCustomValidity(""); });
    }
    elements.cancelRevoke.addEventListener("click", () => elements.revokeDialog.close());
    elements.revokeDialog.addEventListener("close", () => { state.revokeTarget = null; });
    elements.confirmRevoke.addEventListener("click", () => {
      const profile = state.profiles.find(item => item.id === state.revokeTarget);
      elements.revokeDialog.close();
      if (profile && profile.revoked !== true) void runMutation(profile, "revoke");
    });
    updateControls();
    updateNotice();
    if (accessToken) void refreshAll();
    else {
      elements.runtimeStatus.textContent = "等待完整启动链接";
      elements.profileList.setAttribute("aria-busy", "false");
      setConnection(false, "等待连接");
      renderProfiles();
    }
    window.setInterval(() => {
      if (accessToken && !state.refreshing && (document.visibilityState === "visible" || protection?.notificationsEnabled())) void refreshProfiles();
    }, 6500);
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible" && accessToken) void refreshAll();
    });
  }

  window.addEventListener("hashchange", () => {
    const incoming = new URLSearchParams(window.location.hash.slice(1));
    if (!incoming.has("access")) return;
    if(elements.apiKey) elements.apiKey.value="";
    if(elements.judgeKey) elements.judgeKey.value="";
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
    accessToken = incoming.get("access") || "";
    incoming.delete("access");
    try {
      window.sessionStorage.removeItem(SESSION_KEY);
      if (accessToken) window.sessionStorage.setItem(SESSION_KEY, accessToken);
      window.location.reload();
    } catch {
      storageAvailable = false;
      state.authRejected = false;
      state.createAttempt = null;
      state.createJob = null;
      state.requests.clear();
      state.jobs.clear();
      state.jobErrors.clear();
      state.dashboardURLs.clear();
      state.profiles = [];
      state.profilesLoaded = false;
      state.refreshing = false;
      state.infoError = "";
      state.profilesError = "";
      mail?.reset();
      actionReview?.reset();
      protection?.reset();
      targets?.reset();
      alerts?.reset();
      updateControls();
      updateNotice();
      renderProfiles();
      if (accessToken) void refreshAll();
    }
  });

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot, {once: true});
  else boot();
})();
