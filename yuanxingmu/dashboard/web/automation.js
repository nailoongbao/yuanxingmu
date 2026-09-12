/* Creation-time consent for fixed, host-registered action destinations. */
(() => {
  "use strict";

  const kinds = Object.freeze({message: "发送消息", upload: "上传资料", form: "提交表单"});
  const targetID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
  const digest = /^[a-f0-9]{64}$/;
  const maximumTargets = 32;
  const limits = Object.freeze({attempts: 8, perBody: 8192, totalBody: 65536});

  function safeOrigin(value) {
    if (typeof value !== "string" || value.length > 8192) throw new Error("invalid_target");
    const url = new URL(value);
    if (url.username || url.password || !["https:", "http:"].includes(url.protocol)
        || (url.protocol === "http:" && !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname))) {
      throw new Error("invalid_target");
    }
    return url.origin;
  }

  function projectTargets(value) {
    if (!value || !Array.isArray(value.targets) || value.targets.length > maximumTargets) throw new Error("invalid_targets");
    const projected = new Map();
    const seen = new Set();
    for (const item of value.targets) {
      if (!item || typeof item !== "object" || typeof item.id !== "string" || !targetID.test(item.id)
          || seen.has(item.id)) throw new Error("invalid_target");
      seen.add(item.id);
      if (["delete", "overwrite"].includes(item.kind)) continue;
      if (!Object.hasOwn(kinds, item.kind) || typeof item.label !== "string" || !item.label.trim()
          || item.label.length > 128 || typeof item.binding_digest !== "string" || !digest.test(item.binding_digest)) {
        throw new Error("invalid_target");
      }
      // Keep only the public origin and reviewed binding; never retain a webhook path or credentials.
      projected.set(item.id, Object.freeze({id: item.id, kind: item.kind, label: item.label,
        origin: safeOrigin(item.destination), bindingDigest: item.binding_digest}));
    }
    return projected;
  }

  window.createYuanxingmuAutomation = ({api, node, authorized, busy = () => false}) => {
    const state = {targets: new Map(), selected: new Map(), enabled: false, loaded: false,
      loading: false, generation: 0, request: 0};
    const elements = {};
    let mounted = false;

    function feedback(message, isError = false) {
      if (!mounted) return;
      elements.feedback.textContent = message;
      elements.feedback.hidden = !message;
      elements.feedback.classList.toggle("error", isError);
    }

    function updateControls() {
      if (!mounted) return;
      const unavailable = !authorized() || busy();
      elements.enabled.checked = state.enabled;
      elements.enabled.disabled = unavailable || !state.loaded || !state.targets.size || state.loading;
      elements.refresh.disabled = unavailable || state.loading;
      elements.refresh.textContent = state.loading ? "正在读取对象…" : "刷新可选对象";
      elements.choices.hidden = !state.enabled;
      elements.status.textContent = !authorized() ? "等待连接" : state.loading ? "正在读取" :
        !state.loaded ? "暂不可用" : !state.targets.size ? "尚无可选对象" : state.selected.size ?
          "已选择 " + state.selected.size + " 个对象" : "未开启自动提交";
      for (const input of elements.list.querySelectorAll("input[data-automation-target]")) {
        input.checked = state.selected.has(input.dataset.automationTarget);
        input.disabled = unavailable || !state.enabled || state.loading || !state.loaded;
      }
    }

    function renderTargets() {
      if (!mounted) return;
      const fragment = document.createDocumentFragment();
      for (const target of state.targets.values()) {
        const row = node("div", "mail-draft-row");
        const heading = node("div", "mail-draft-heading");
        heading.append(node("h3", "", target.label), node("span", "status-badge", kinds[target.kind]));
        const origin = node("p", "mail-draft-recipient", target.origin);
        const consent = node("div", "mail-review-confirmation");
        const label = node("label");
        const input = node("input");
        input.type = "checkbox";
        input.dataset.automationTarget = target.id;
        input.addEventListener("change", () => {
          if (!authorized() || busy() || state.loading || !state.enabled || !state.loaded
              || state.targets.get(target.id)?.bindingDigest !== target.bindingDigest) {
            updateControls();
            return;
          }
          if (input.checked) {
            if (state.selected.size >= maximumTargets && !state.selected.has(target.id)) {
              feedback("每份工作最多选择 32 个自动提交对象。", true);
              updateControls();
              return;
            }
            state.selected.set(target.id, target.bindingDigest);
          } else state.selected.delete(target.id);
          feedback("");
          updateControls();
        });
        label.append(input, node("span", "", "允许「" + target.label + "」接收本次工作的资料，并在限额内自动提交"));
        consent.append(label);
        row.append(heading, origin, consent);
        fragment.append(row);
      }
      elements.list.replaceChildren(fragment);
      elements.empty.hidden = Boolean(state.targets.size);
      updateControls();
    }

    async function refresh() {
      if (!mounted || !authorized()) return;
      const generation = state.generation;
      const request = ++state.request;
      state.loading = true;
      updateControls();
      try {
        const result = await api("/api/action-targets");
        if (generation !== state.generation || request !== state.request || !authorized()) return;
        const next = projectTargets(result);
        let changed = false;
        for (const [id, binding] of state.selected) {
          if (next.get(id)?.bindingDigest !== binding) {
            state.selected.delete(id);
            changed = true;
          }
        }
        state.targets = next;
        state.loaded = true;
        if (!next.size) state.enabled = false;
        feedback(changed ? "部分对象配置已变化，相关勾选已清除。请重新核对后选择。" : "", changed);
      } catch {
        if (generation !== state.generation || request !== state.request || !authorized()) return;
        state.targets.clear();
        state.selected.clear();
        state.enabled = false;
        state.loaded = false;
        feedback("暂时无法读取自动提交对象。这次创建不会开启自动提交，仍可按原方式逐项核对操作。", true);
      } finally {
        if (generation === state.generation && request === state.request) {
          state.loading = false;
          renderTargets();
        }
      }
    }

    function collect() {
      if (!authorized() || !state.enabled || !state.selected.size) return {};
      if (!state.loaded || state.loading || state.selected.size > maximumTargets) {
        throw new Error("请等待操作对象读取完成，再核对自动执行范围。");
      }
      const scopes = [];
      const bindings = [];
      for (const [id, binding] of state.selected) {
        if (state.targets.get(id)?.bindingDigest !== binding || !digest.test(binding)) {
          throw new Error("自动提交对象已变化，请刷新并重新选择。");
        }
        scopes.push([id, {accepted_labels: ["private"], max_body_bytes: limits.perBody}]);
        bindings.push([id, binding]);
      }
      // New objects only: the create attempt owns this snapshot throughout any retry.
      return {action_automation: {version: 1, max_attempts: limits.attempts,
        max_total_body_bytes: limits.totalBody, targets: Object.fromEntries(scopes)},
      action_automation_bindings: Object.fromEntries(bindings)};
    }

    function reset() {
      state.generation += 1;
      state.request += 1;
      state.targets.clear();
      state.selected.clear();
      state.enabled = false;
      state.loaded = false;
      state.loading = false;
      feedback("");
      renderTargets();
    }

    function boot() {
      if (mounted) return;
      const mount = document.getElementById("create-action-automation");
      if (!mount) return;
      mounted = true;
      const heading = node("div", "group-heading");
      elements.status = node("span", "", "等待连接");
      heading.append(node("h3", "", "自动执行范围"), elements.status);
      const introduction = node("p", "field-note", "创建时选一次。通过防护检查后，本次授权范围内的消息、上传和表单由 AI 自动完成，后续无需逐项确认。");
      const toggle = node("div", "mail-review-confirmation");
      const label = node("label");
      elements.enabled = node("input");
      elements.enabled.id = "automation-enabled";
      elements.enabled.type = "checkbox";
      label.append(elements.enabled, node("span", "", "让 AI 在选定范围内自动完成"));
      toggle.append(label);
      elements.choices = node("div");
      elements.choices.id = "automation-choices";
      elements.choices.hidden = true;
      const limitNote = node("p", "field-note", "本工作合计最多 8 次 · 每次最多 8 KB · 本工作总计 64 KB。每个接收对象都需要你明确勾选。");
      limitNote.id = "automation-limits";
      elements.list = node("div", "mail-drafts");
      elements.list.id = "automation-targets";
      elements.choices.append(limitNote, elements.list);
      elements.empty = node("p", "field-note", "尚无可自动提交的对象。可先在“可确认的操作对象”中登记消息、上传或表单接收端。未选择对象时，仍按原方式逐项核对。");
      elements.empty.id = "automation-empty";
      const details = node("details", "prompt-details");
      details.append(node("summary", "", "这次授权包含什么"), node("p", "field-note", "自动提交仅限选中的固定对象，这些对象可以接收本次工作的资料。没有授权的操作、邮件、删除和覆盖仍待你核对。发送结果不明确时不会自动重发。超出次数或大小限制的操作也会转为待核对。"));
      const actions = node("div", "mail-account-actions");
      elements.refresh = node("button", "button button-quiet", "刷新可选对象");
      elements.refresh.type = "button";
      elements.refresh.id = "automation-refresh";
      elements.refresh.addEventListener("click", () => { void refresh(); });
      actions.append(elements.refresh);
      elements.feedback = node("p", "form-message");
      elements.feedback.id = "automation-feedback";
      elements.feedback.setAttribute("role", "status");
      elements.feedback.setAttribute("aria-live", "polite");
      elements.feedback.hidden = true;
      mount.append(heading, introduction, toggle, elements.choices, elements.empty, details, actions, elements.feedback);
      elements.enabled.addEventListener("change", () => {
        if (authorized() && !busy() && state.loaded && !state.loading && state.targets.size) {
          state.enabled = elements.enabled.checked;
          if (!state.enabled) state.selected.clear();
          feedback("");
        }
        updateControls();
      });
      updateControls();
    }

    return Object.freeze({boot, refresh, collect, reset, updateControls});
  };
})();
