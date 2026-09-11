/* Mail content and credentials stay in memory; the server authorizes every mutation. */
(() => {
  "use strict";

  window.createYuanxingmuMail = function ({api, newKey, node, authorized, getProfile, upsertProfile, refreshProfiles}) {
    const elements = {};
    const state = {
      account: null, accountLoading: null, accountSaving: false, accountDirty: false, accountError: "", accountRevision: 0,
      profileId: null, draftId: null, draft: null, drafts: [], active: false, supported: false,
      view: "list", listLoading: false, listLoaded: false, detailLoading: false, verified: false, stale: false,
      editing: false, cancelling: false, message: "", messageError: false,
      generation: 0, selection: 0, requests: new Map()
    };
    let lastListRender = "";
    const editable = draft => draft && draft.status === "pending";
    const safeID = value => typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value);
    const pause = milliseconds => new Promise(resolve => window.setTimeout(resolve, milliseconds));
    const statusLabels = {
      pending: ["待核对", "", "这封邮件还没有发送，请核对收件人、主题和全文。"],
      sending: ["发送中", "working", "正在提交给邮箱服务。关闭窗口不会取消这次发送。"],
      acknowledged: ["已提交邮箱服务", "ready", "邮箱服务已接收这封邮件。这不代表收件人已经收到或阅读。"],
      unconfirmed: ["结果不明", "uncertain", "暂时无法确认邮箱服务是否已接收。请先到邮箱中核对发送情况，确认前不要重复发送。"],
      not_started: ["尚未开始发送", "uncertain", "这次发送尚未开始，请检查邮箱设置。这份草稿已保留记录，不会再次发送。"],
      cancelled: ["已弃用", "", "这份草稿已弃用，不能再发送。"]
    };
    const requestKey = (profile, draft) => profile + "/" + draft;
    const currentRequest = () => state.requests.get(requestKey(state.profileId, state.draftId));
    const pathFor = profile => "/api/profiles/" + encodeURIComponent(profile) + "/mail";
    const detailPath = (profile, draft) => pathFor(profile) + "/" + encodeURIComponent(draft);
    const messageOf = error => error instanceof Error ? error.message : "暂时无法读取结果，请重新确认。";
    const dateLabel = value => {
      if (typeof value !== "string") return "";
      const date = new Date(value);
      return Number.isNaN(date.getTime()) ? "" : date.toLocaleString("zh-CN", {hour12: false});
    };

    function validateDraft(draft, id) {
      if (!draft || draft.id !== id || !safeID(draft.id) || !Number.isInteger(draft.revision) || draft.revision < 1 ||
          typeof draft.digest !== "string" || !draft.digest ||
          ![draft.recipient, draft.subject, draft.body].every(value => typeof value === "string") || !statusLabels[draft.status]) {
        throw new Error("草稿内容返回不完整，暂时不能发送。请重新读取。");
      }
      return draft;
    }

    function feedback(message, isError = false) {
      state.message = message;
      state.messageError = isError;
      elements.feedback.textContent = message;
      elements.feedback.hidden = !message;
      elements.feedback.classList.toggle("error", isError);
    }

    function accountMessage(message, isError = false) {
      elements.accountMessage.textContent = message;
      elements.accountMessage.hidden = !message;
      elements.accountMessage.classList.toggle("error", isError);
    }

    function clearReview() {
      elements.reviewed.checked = false;
    }

    function reconcileRecordedOutcome(draft) {
      const request = currentRequest();
      if (request?.phase === "uncertain" && !request.jobId &&
          ["acknowledged", "unconfirmed", "not_started", "cancelled"].includes(draft?.status)) {
        state.requests.delete(requestKey(request.profileId, request.draftId));
        feedback("");
      }
    }

    function fillAccount(account) {
      elements.from.value = account?.from_address || "";
      elements.username.value = account?.username || "";
      elements.host.value = account?.host || "";
      elements.port.value = String(account?.port || 465);
      elements.password.value = "";
    }

    function receiveAccount(account, forceFill = false) {
      if (!account || typeof account.configured !== "boolean" ||
          (account.configured && (!safeID(account.account_id) || typeof account.from_address !== "string"))) {
        throw new Error("邮箱设置返回不完整，请重新读取。");
      }
      const previous = state.account?.account_id;
      const previousAddress = state.account?.from_address;
      if (state.accountError) accountMessage("");
      state.account = account;
      state.accountError = "";
      if (previous !== account.account_id || previousAddress !== account.from_address) {
        clearReview();
        if (previous && state.draft && editable(state.draft) && !currentRequest()) feedback("发件邮箱已更新，请重新核对发件人和邮件全文。");
      }
      if (!state.accountDirty || forceFill) fillAccount(account);
      renderSender();
      updateControls();
    }

    async function refreshAccount(forceFill = false) {
      if (!authorized()) return;
      if (state.accountLoading) return state.accountLoading;
      const generation = state.generation;
      const accountRevision = state.accountRevision;
      const operation = (async () => {
        try {
          const account = await api("/api/mail-account");
          if (generation !== state.generation || accountRevision !== state.accountRevision) return;
          receiveAccount(account, forceFill);
        } catch (error) {
          if (generation !== state.generation || accountRevision !== state.accountRevision) return;
          state.accountError = messageOf(error);
          clearReview();
          accountMessage("暂时无法确认发件邮箱设置。" + state.accountError, true);
        } finally {
          if (generation === state.generation) {
            state.accountLoading = null;
            updateControls();
          }
        }
      })();
      state.accountLoading = operation;
      updateControls();
      return operation;
    }

    async function saveAccount(event) {
      event.preventDefault();
      if (!authorized() || state.accountSaving || !elements.accountForm.reportValidity()) return;
      const generation = state.generation;
      const body = {
        host: elements.host.value.trim(), port: Number(elements.port.value),
        username: elements.username.value.trim(), password: elements.password.value,
        from_address: elements.from.value.trim()
      };
      state.accountSaving = true;
      state.accountRevision += 1;
      elements.password.value = "";
      clearReview();
      accountMessage("正在保存发件邮箱设置…");
      updateControls();
      try {
        const account = await api("/api/mail-account", {method: "POST", body, key: newKey()});
        if (generation !== state.generation) return;
        state.accountDirty = false;
        receiveAccount(account, true);
        accountMessage("发件邮箱设置已保存。每封邮件仍需单独核对并确认；保存设置不会发送邮件。");
      } catch (error) {
        if (generation !== state.generation) return;
        state.accountError = messageOf(error);
        accountMessage(messageOf(error) + (error.uncertain ? " 保存结果暂时无法确认，请重新读取设置。" : " 请核对设置后重新填写授权码。"), true);
      } finally {
        body.password = "";
        if (generation === state.generation) {
          state.accountSaving = false;
          elements.password.value = "";
          updateControls();
        }
      }
    }

    function renderSender() {
      const draft = state.draft;
      const request = currentRequest();
      const submittingFrom = request?.action === "send" ? request.fromAddress : null;
      const historical = draft && ["sending", "acknowledged", "unconfirmed", "not_started"].includes(draft.status) && draft.from_address;
      elements.readFrom.textContent = submittingFrom || historical || (state.account?.configured ? state.account.from_address : "尚未设置发件邮箱");
    }

    function renderDetail() {
      const draft = state.draft;
      elements.read.hidden = !draft || state.editing;
      elements.editForm.hidden = !draft || !state.editing;
      elements.cancelConfirmation.hidden = !state.cancelling;
      if (draft) {
        elements.readRecipient.textContent = draft.recipient;
        elements.readSubject.textContent = draft.subject;
        elements.readBody.textContent = draft.body;
        const updated = dateLabel(draft.updated_at || draft.created_at);
        elements.version.textContent = "第 " + draft.revision + " 版" + (updated ? " · " + updated : "");
      } else {
        for (const field of [elements.readRecipient, elements.readSubject, elements.readBody, elements.version]) field.textContent = "";
      }
      renderSender();
      updateControls();
    }

    function updateControls() {
      if (!elements.dialog) return;
      const allowed = authorized();
      elements.accountFields.disabled = !allowed || state.accountSaving;
      elements.accountSave.textContent = state.accountSaving ? "正在保存…" : "保存发件邮箱";
      elements.accountRefresh.disabled = !allowed || state.accountSaving || Boolean(state.accountLoading);
      elements.accountStatus.textContent = !allowed ? "等待连接" : state.accountError ? "设置待确认" : state.account?.configured ? state.account.from_address : state.accountLoading ? "正在读取" : "尚未设置";
      elements.listRefresh.disabled = !allowed || state.listLoading;
      elements.listRefresh.textContent = state.listLoading ? "正在读取…" : "刷新草稿";
      elements.reload.disabled = !allowed || state.detailLoading || Boolean(currentRequest());
      elements.reload.textContent = state.editing ? "放弃修改并读取最新版" : state.stale ? "读取最新版" : "重新读取草稿";
      const draft = state.draft;
      const request = currentRequest();
      const profile = getProfile(state.profileId);
      const profilePending = Boolean(profile?.pending);
      const permissionUncertain = profile?.revoked !== true && profile?.revoked !== false;
      const canChange = Boolean(allowed && state.active && state.supported && state.verified && !state.stale &&
        !state.detailLoading && !request && !profilePending && !permissionUncertain && profile.revoked === false && editable(draft));
      let reason = "";
      if (!allowed) reason = "访问凭证已失效，请重新打开完整启动链接。";
      else if (state.detailLoading || !draft) reason = "正在读取完整草稿，请稍候。";
      else if (request) reason = request.phase === "uncertain" ? "提交结果尚未确认，暂时不能再次发送。" : "这次操作尚未结束，请等待结果。";
      else if (profilePending) reason = "这份工作还有操作尚未结束，请等待结果。";
      else if (!state.supported) reason = "这份工作暂不支持邮件核对。";
      else if (state.stale) reason = "草稿已更新，请重新读取最新版并核对。";
      else if (permissionUncertain) reason = "暂时无法确认这份工作的权限，请刷新状态后再核对。";
      else if (!state.verified) reason = "暂时无法确认草稿和权限状态，请重新读取。";
      else if (!state.active && editable(draft)) reason = "这份工作的权限已收回，尚未发送的草稿不能再发送。";
      else if (!editable(draft)) reason = statusLabels[draft.status]?.[2] || "暂时不能发送。";
      else if (state.editing) reason = "请先保存修改，再核对保存后的完整草稿。";
      else if (state.accountSaving || state.accountError) reason = "请先确认发件邮箱设置。";
      else if (!state.account?.configured) reason = "还没有设置发件邮箱。请关闭窗口，在“发件邮箱设置”中完成配置。";
      else if (state.cancelling) reason = "请先决定是否弃用这份草稿。";
      elements.sendReason.textContent = reason;
      const canReview = Boolean(canChange && !state.editing && !state.cancelling && !state.accountSaving && !state.accountError && state.account?.configured);
      elements.reviewed.disabled = !canReview;
      if (!canReview) clearReview();
      elements.send.disabled = !canReview || !elements.reviewed.checked;
      elements.send.hidden = Boolean(draft && !editable(draft)) || Boolean(request);
      elements.reviewConfirmation.hidden = Boolean(draft && !editable(draft));
      elements.editStart.hidden = state.editing || Boolean(draft && !editable(draft));
      elements.cancelStart.hidden = Boolean(draft && !editable(draft));
      elements.editStart.disabled = !canChange || state.cancelling;
      elements.cancelStart.disabled = !canChange || state.editing || state.cancelling;
      elements.editFields.disabled = !canChange;
      elements.editSave.disabled = !canChange;
      elements.cancelConfirm.disabled = !canChange;
      elements.retry.hidden = !request || request.phase !== "uncertain" || Boolean(request.jobId);
      elements.retry.disabled = !allowed || request?.posting;
      elements.close.textContent = state.editing ? "放弃修改并关闭" : "关闭";
      elements.back.textContent = state.editing ? "放弃修改并返回列表" : "返回草稿列表";
      let status = statusLabels[draft?.status] || ["正在读取", "working", "正在读取完整草稿。"];
      if (!draft && !state.detailLoading) status = ["读取未完成", "uncertain", "尚未取得完整草稿，请重新读取。"];
      if (request) {
        status = request.phase === "uncertain" || request.pollError
          ? ["结果待确认", "uncertain", "暂时无法确认这次操作的结果。请继续查询，不要另行发送同一封邮件。"]
          : [request.action === "send" ? "发送中" : "正在处理", "working", request.action === "send" ? "正在提交给邮箱服务。关闭窗口不会取消这次发送。" : "正在保存这次操作，请稍候。"];
      }
      elements.draftStatus.textContent = status[0];
      elements.draftStatus.className = "status-badge " + status[1];
      elements.stateNote.textContent = status[2];
    }

    function renderList() {
      const renderKey = JSON.stringify([state.drafts, state.listLoading, state.listLoaded, state.supported, state.messageError, authorized()]);
      if (renderKey === lastListRender && elements.drafts.childNodes.length) return;
      lastListRender = renderKey;
      const focusedDraft = elements.drafts.contains(document.activeElement) ? document.activeElement.dataset.draftId : null;
      const fragment = document.createDocumentFragment();
      if (!state.drafts.length) {
        const empty = node("div", "mail-empty");
        empty.append(node("h3", "", !state.listLoaded ? state.messageError ? "暂时无法读取草稿" : "正在读取邮件草稿" : state.supported ? "还没有邮件草稿" : "暂时没有可用草稿"));
        empty.append(node("p", "field-note", !state.listLoaded ? "收到这份工作的草稿后，会在这里展示。" : state.supported ? "到 OpenClaw 里对 AI 说：“请帮我拟一封邮件，把草稿放到工作台让我核对。”记得告诉它收件人的邮箱和要写的内容。" : "这份工作暂时没有可查看的邮件草稿。"));
        fragment.append(empty);
      }
      for (const draft of state.drafts) {
        if (!safeID(draft.id)) continue;
        const row = node("article", "mail-draft-row");
        const heading = node("div", "mail-draft-heading");
        const status = statusLabels[draft.status] || ["状态待确认", "uncertain"];
        heading.append(node("h3", "", draft.subject || "（未填写主题）"), node("span", "status-badge " + status[1], status[0]));
        const open = node("button", "button button-secondary", editable(draft) ? "核对邮件" : "查看全文");
        open.type = "button";
        open.dataset.draftId = draft.id;
        open.disabled = !authorized();
        open.addEventListener("click", () => { void selectDraft(draft.id); });
        row.append(heading, node("p", "mail-draft-recipient", "收件人：" + (draft.recipient || "尚未填写")));
        const created = dateLabel(draft.created_at);
        if (created) row.append(node("p", "mail-draft-time", "创建于 " + created));
        row.append(open);
        fragment.append(row);
      }
      elements.drafts.replaceChildren(fragment);
      elements.drafts.setAttribute("aria-busy", String(state.listLoading));
      if (focusedDraft) {
        const next = Array.from(elements.drafts.querySelectorAll("button[data-draft-id]")).find(item => item.dataset.draftId === focusedDraft);
        if (next && !next.disabled) next.focus({preventScroll: true});
      }
    }

    async function refreshList() {
      if (!state.profileId || state.listLoading || !authorized()) return;
      const profileId = state.profileId;
      const generation = state.generation;
      state.listLoading = true;
      updateControls();
      try {
        const data = await api(pathFor(profileId));
        if (generation !== state.generation || profileId !== state.profileId) return;
        if (!Array.isArray(data.drafts) || typeof data.active !== "boolean" || typeof data.supported !== "boolean") throw new Error("草稿列表返回不完整，请重新读取。");
        state.drafts = data.drafts;
        state.listLoaded = true;
        state.active = data.active;
        state.supported = data.supported;
        if (state.draft) {
          const latest = state.drafts.find(draft => draft.id === state.draftId);
          reconcileRecordedOutcome(latest);
          if (!latest || latest.digest !== state.draft.digest || latest.revision !== state.draft.revision) {
            state.stale = true;
            clearReview();
            feedback("草稿已更新，请读取最新版并重新核对。" + (state.editing ? "正在编辑的内容会保留在窗口中。" : ""), true);
          } else {
            if (latest.status !== state.draft.status) clearReview();
            state.draft = {...state.draft, ...latest};
            state.verified = true;
            renderSender();
          }
        }
      } catch (error) {
        if (generation !== state.generation || profileId !== state.profileId) return;
        state.verified = false;
        clearReview();
        feedback(messageOf(error), true);
      } finally {
        if (generation === state.generation && profileId === state.profileId) {
          state.listLoading = false;
          renderList();
          updateControls();
        }
      }
    }

    function acceptDetail(data, id) {
      state.draft = validateDraft(data.draft, id);
      reconcileRecordedOutcome(state.draft);
      state.active = data.active === true;
      state.verified = typeof data.active === "boolean";
      state.stale = false;
      state.editing = false;
      state.cancelling = false;
      clearReview();
      renderDetail();
    }

    async function selectDraft(id) {
      if (!safeID(id) || !state.profileId || !authorized()) return;
      const selection = ++state.selection;
      const generation = state.generation;
      const profileId = state.profileId;
      state.draftId = id;
      state.draft = null;
      state.editing = false;
      state.cancelling = false;
      state.verified = false;
      state.detailLoading = true;
      state.view = "detail";
      clearReview();
      feedback("");
      elements.listPanel.hidden = true;
      elements.detailPanel.hidden = false;
      elements.title.textContent = "核对邮件";
      renderDetail();
      try {
        const [data] = await Promise.all([api(detailPath(profileId, id)), refreshAccount()]);
        if (generation !== state.generation || selection !== state.selection) return;
        acceptDetail(data, id);
      } catch (error) {
        if (generation === state.generation && selection === state.selection) feedback(messageOf(error), true);
      } finally {
        if (generation === state.generation && selection === state.selection) {
          state.detailLoading = false;
          updateControls();
        }
      }
    }

    async function open(profile) {
      if (!authorized() || !Array.isArray(profile.features) || !profile.features.includes("reviewed_email_v1")) return;
      state.profileId = profile.id;
      state.drafts = [];
      state.active = false;
      state.supported = true;
      state.view = "list";
      state.draft = null;
      state.draftId = null;
      state.listLoading = false;
      state.listLoaded = false;
      elements.workName.textContent = profile.name;
      elements.title.textContent = "邮件草稿";
      elements.listPanel.hidden = false;
      elements.detailPanel.hidden = true;
      feedback("");
      renderList();
      elements.dialog.showModal();
      elements.close.focus();
      await Promise.all([refreshList(), refreshAccount()]);
    }

    function startEditing() {
      if (elements.editStart.disabled || !state.draft) return;
      state.editing = true;
      state.cancelling = false;
      clearReview();
      elements.editRecipient.value = state.draft.recipient;
      elements.editSubject.value = state.draft.subject;
      elements.editBody.value = state.draft.body;
      feedback("");
      renderDetail();
      elements.editRecipient.focus();
    }

    function requestIsCurrent(request) {
      return request.generation === state.generation && state.requests.get(requestKey(request.profileId, request.draftId)) === request;
    }

    async function finishRequest(request, job) {
      const data = await api(detailPath(request.profileId, request.draftId));
      if (!requestIsCurrent(request)) return true;
      validateDraft(data.draft, request.draftId);
      if (request.action === "send" && (data.draft.status === "sending" || (data.draft.status === "pending" && job.status !== "failed"))) return false;
      state.requests.delete(requestKey(request.profileId, request.draftId));
      if (job.result?.profile) upsertProfile(job.result.profile);
      if (state.profileId === request.profileId && state.draftId === request.draftId) {
        acceptDetail(data, request.draftId);
        if (job.status === "failed" && request.action === "edit" && editable(data.draft) &&
            data.draft.digest === request.body.digest && data.draft.revision === request.body.revision) {
          state.editing = true;
          elements.editRecipient.value = request.body.draft.recipient;
          elements.editSubject.value = request.body.draft.subject;
          elements.editBody.value = request.body.draft.body;
          renderDetail();
        }
        feedback(job.status === "failed" ? (job.error?.message || "这次操作未完成，请核对当前草稿状态。") : request.action === "edit" ? "草稿已保存，请重新核对收件人、主题和全文。" : "", job.status === "failed");
      }
      if (state.profileId === request.profileId) await refreshList();
      await refreshProfiles();
      return true;
    }

    async function watchRequest(request) {
      if (request.watching) return;
      request.watching = true;
      while (authorized() && requestIsCurrent(request)) {
        try {
          const result = await api("/api/jobs/" + encodeURIComponent(request.jobId));
          if (!requestIsCurrent(request)) return;
          const job = result.job;
          if (!job || job.id !== request.jobId) throw new Error("暂未取得这次操作的结果，正在继续确认。");
          request.pollError = "";
          if (["succeeded", "failed"].includes(job.status) && await finishRequest(request, job)) return;
          updateControls();
        } catch (error) {
          if (!requestIsCurrent(request) || !authorized()) return;
          request.pollError = messageOf(error);
          if (state.profileId === request.profileId && state.draftId === request.draftId) {
            feedback(messageOf(error) + " 正在继续查询这次操作的结果。", true);
            updateControls();
          }
        }
        await pause(2000);
      }
    }

    async function submitRequest(request) {
      if (request.posting || !requestIsCurrent(request) || !authorized()) return;
      request.posting = true;
      request.phase = "posting";
      clearReview();
      updateControls();
      try {
        const result = await api(pathFor(request.profileId) + "/" + request.action, {method: "POST", body: request.body, key: request.key});
        if (!requestIsCurrent(request)) return;
        if (!safeID(result.job?.id)) {
          const error = new Error("尚未收到可查询的操作结果，请继续确认这次提交。");
          error.uncertain = true;
          throw error;
        }
        request.jobId = result.job.id;
        request.phase = "working";
        void watchRequest(request);
      } catch (error) {
        if (!requestIsCurrent(request)) return;
        request.phase = "uncertain";
        if (state.profileId === request.profileId && state.draftId === request.draftId) feedback(messageOf(error) + (error.uncertain ? " 提交结果暂时无法确认，请继续确认这次提交。" : " 正在重新读取草稿状态。"), true);
        if (!error.uncertain) {
          try { await finishRequest(request, {status: "failed", error: {message: messageOf(error)}}); }
          catch { /* Keep the same request key until its outcome can be checked. */ }
        }
      } finally {
        request.posting = false;
        if (request.generation === state.generation) updateControls();
      }
    }

    function beginMutation(action) {
      const control = action === "send" ? elements.send : action === "edit" ? elements.editSave : elements.cancelConfirm;
      if (control.disabled || !state.draft || !authorized() || currentRequest() || !state.active || !state.supported ||
          !state.verified || state.stale || state.detailLoading || !editable(state.draft) || getProfile(state.profileId)?.pending) return;
      if (action === "edit") {
        elements.editBody.setCustomValidity(new TextEncoder().encode(elements.editBody.value).byteLength > 65536 ? "正文超过 64 KB，请缩短后再保存。" : "");
        if (!elements.editForm.reportValidity()) return;
      }
      const draft = state.draft;
      const body = {draft_id: draft.id, revision: draft.revision, digest: draft.digest};
      if (action === "send") {
        if (!elements.reviewed.checked || !state.account?.configured) return;
        body.account_id = state.account.account_id;
        body.confirm = "send";
      }
      if (action === "edit") body.draft = {recipient: elements.editRecipient.value.trim(), subject: elements.editSubject.value, body: elements.editBody.value};
      const request = {profileId: state.profileId, draftId: draft.id, action, body, key: newKey(), fromAddress: action === "send" ? state.account.from_address : null, generation: state.generation, phase: "ready", posting: false, watching: false, jobId: null, pollError: ""};
      state.requests.set(requestKey(state.profileId, draft.id), request);
      feedback("");
      state.cancelling = false;
      renderDetail();
      void submitRequest(request);
    }

    function profilesChanged() {
      if (!state.profileId) return;
      const profile = getProfile(state.profileId);
      if (!profile || profile.revoked !== false) {
        state.active = false;
        clearReview();
      }
      updateControls();
    }

    function reset() {
      state.generation += 1;
      state.selection += 1;
      state.requests.clear();
      state.account = null;
      state.accountLoading = null;
      state.accountSaving = false;
      state.accountDirty = false;
      state.accountError = "";
      state.profileId = null;
      state.draftId = null;
      state.draft = null;
      state.drafts = [];
      state.active = false;
      if (elements.dialog) {
        elements.dialog.close();
        elements.accountForm.reset();
        elements.password.value = "";
        accountMessage("");
        updateControls();
      }
    }

    function boot() {
      const ids = {
        accountPanel: "account-panel", accountStatus: "account-status", accountForm: "account-form", accountFields: "account-fields",
        from: "from", username: "username", password: "password", host: "host", port: "port", accountSave: "account-save",
        accountRefresh: "account-refresh", accountMessage: "account-message", dialog: "dialog", workName: "work-name", title: "title",
        close: "close", feedback: "feedback", listPanel: "list-panel", listRefresh: "list-refresh", drafts: "drafts", detailPanel: "detail-panel",
        back: "back", reload: "reload", draftStatus: "draft-status", version: "version", stateNote: "state-note", read: "read",
        readFrom: "read-from", readRecipient: "read-recipient", readSubject: "read-subject", readBody: "read-body",
        editForm: "edit-form", editFields: "edit-fields", editRecipient: "edit-recipient", editSubject: "edit-subject", editBody: "edit-body",
        editSave: "edit-save", editDiscard: "edit-discard", editStart: "edit-start", cancelStart: "cancel-start",
        cancelConfirmation: "cancel-confirmation", cancelConfirm: "cancel-confirm", cancelKeep: "cancel-keep",
        reviewConfirmation: "review-confirmation", reviewed: "reviewed", sendReason: "send-reason", send: "send", retry: "retry"
      };
      for (const [key, id] of Object.entries(ids)) elements[key] = document.getElementById("mail-" + id);
      elements.accountForm.addEventListener("submit", event => { void saveAccount(event); });
      elements.accountForm.addEventListener("input", () => { state.accountDirty = true; });
      elements.accountRefresh.addEventListener("click", () => {
        state.accountDirty = false;
        elements.password.value = "";
        accountMessage("");
        void refreshAccount(true);
      });
      elements.close.addEventListener("click", () => elements.dialog.close());
      elements.dialog.addEventListener("close", () => {
        state.selection += 1;
        state.profileId = null;
        state.draftId = null;
        state.draft = null;
        state.drafts = [];
        state.editing = false;
        state.cancelling = false;
        state.detailLoading = false;
        elements.editForm.reset();
        clearReview();
        renderDetail();
        elements.drafts.replaceChildren();
      });
      elements.listRefresh.addEventListener("click", () => { void Promise.all([refreshList(), refreshAccount()]); });
      elements.reload.addEventListener("click", () => { if (state.draftId) void selectDraft(state.draftId); });
      elements.back.addEventListener("click", () => {
        state.selection += 1;
        state.draft = null;
        state.draftId = null;
        state.editing = false;
        state.cancelling = false;
        state.detailLoading = false;
        state.view = "list";
        elements.title.textContent = "邮件草稿";
        elements.listPanel.hidden = false;
        elements.detailPanel.hidden = true;
        elements.editForm.reset();
        clearReview();
        feedback("");
        renderDetail();
        void refreshList();
      });
      elements.editStart.addEventListener("click", startEditing);
      elements.editDiscard.addEventListener("click", () => { state.editing = false; elements.editForm.reset(); clearReview(); renderDetail(); });
      elements.editForm.addEventListener("submit", event => { event.preventDefault(); beginMutation("edit"); });
      elements.editBody.addEventListener("input", () => elements.editBody.setCustomValidity(""));
      elements.cancelStart.addEventListener("click", () => { state.cancelling = true; clearReview(); renderDetail(); });
      elements.cancelKeep.addEventListener("click", () => { state.cancelling = false; renderDetail(); });
      elements.cancelConfirm.addEventListener("click", () => beginMutation("cancel"));
      elements.reviewed.addEventListener("change", updateControls);
      elements.send.addEventListener("click", () => beginMutation("send"));
      elements.retry.addEventListener("click", () => { const request = currentRequest(); if (request) void submitRequest(request); });
      window.setInterval(() => {
        if (authorized() && elements.dialog.open && document.visibilityState === "visible") void Promise.all([refreshList(), refreshAccount()]);
      }, 6500);
      updateControls();
    }

    function profileEntry(profile) {
      if (!Array.isArray(profile.features) || !profile.features.includes("reviewed_email_v1")) return null;
      const entry = node("div", "mail-profile-entry");
      const text = node("div");
      text.append(node("h4", "", "邮件草稿"), node("p", "field-note", "AI 先拟稿，由你核对后发送。"));
      const openButton = node("button", "button button-secondary", "查看邮件草稿");
      openButton.type = "button";
      openButton.dataset.focusKey = profile.id + "-mail";
      openButton.disabled = !authorized();
      openButton.addEventListener("click", () => { void open(profile); });
      entry.append(text, openButton);
      return entry;
    }

    return {boot, refreshAccount, updateControls, profilesChanged, profileEntry, reset};
  };
})();
