const state = {
  config: null,
  districts: [],
  departments: [],
  visibleDepartments: [],
  calendar: [],
  sources: [],
  selectedDept: null,
  taskTimer: null,
  setupUserExpanded: false,
  validation: null,
};

const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await res.json();
  if (!res.ok || data.ok === false) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

function setStatus(text, running = false, cooling = false) {
  $("taskState").textContent = text;
  $("taskState").classList.toggle("running", running);
  $("taskState").classList.toggle("cooling", cooling);
}

function remainingCooldownSeconds(task) {
  if (!task || !task.cooldownUntil) return Number(task?.cooldownSeconds || 0);
  const remaining = Math.ceil((new Date(task.cooldownUntil).getTime() - Date.now()) / 1000);
  return Math.max(0, remaining);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function selectedDistrictCode() {
  return $("districtSelect").value || "001";
}

function selectedDeptCode() {
  return $("deptSelect").value || "";
}

function selectedDeptName() {
  const option = $("deptSelect").selectedOptions[0];
  return option ? option.dataset.name : "";
}

function taskPayload() {
  return {
    districtCode: selectedDistrictCode(),
    deptCode: selectedDeptCode(),
    deptName: selectedDeptName(),
    visitDate: $("dateSelect").value,
    periodType: $("periodSelect").value,
    doctorMode: $("doctorModeSelect").value,
    startAt: $("startAt").value,
    endAfterSeconds: Number($("endAfter").value || 240),
    intervalSeconds: Number($("interval").value || 1),
  };
}

function periodText(value) {
  return { AM: "上午", PM: "下午", "": "不限" }[value || ""] || value;
}

function doctorModeText(value) {
  return { any: "不限医生", prefer: "专家优先", required: "必须专家" }[value || ""] || value || "默认";
}

function shortDateTime(value) {
  if (!value) return "";
  const normalized = String(value).replace("T", " ");
  return normalized.length >= 16 ? normalized.slice(5, 16) : normalized;
}

function renderDistricts() {
  const current = state.config?.target?.district_code || "001";
  $("districtSelect").innerHTML = state.districts
    .map((item) => {
      const selected = item.districtCode === current ? "selected" : "";
      return `<option value="${item.districtCode}" ${selected}>${item.districtName}</option>`;
    })
    .join("");
}

function renderDepartments() {
  const keyword = $("deptSearch").value.trim();
  state.visibleDepartments = state.departments.filter((item) => !keyword || item.path.includes(keyword));
  const current = state.config?.target?.dept_code;
  $("deptSelect").innerHTML = state.visibleDepartments
    .map((item) => {
      const selected = item.deptCode === current ? "selected" : "";
      return `<option value="${item.deptCode}" data-name="${item.deptName}" ${selected}>${item.path}</option>`;
    })
    .join("");
  state.selectedDept = state.visibleDepartments.find((item) => item.deptCode === $("deptSelect").value) || null;
}

function renderCalendar() {
  $("dateSelect").innerHTML = state.calendar
    .map((item) => {
      return `<option value="${item.visitDate}">${calendarOptionLabel(item)}</option>`;
    })
    .join("");
  const defaultItem = state.calendar.find((item) => item.defaultSelected) || state.calendar[state.calendar.length - 1];
  if (defaultItem) {
    $("dateSelect").value = defaultItem.visitDate;
  }
  renderDateDetail();
}

function calendarOptionLabel(item) {
  const windowMark = item.withinCurrentWindow === false ? "提前监控" : "当前窗口";
  const sourceStatus = item.sourceStatusView || "可查";
  return [item.visitDate, item.weekView, sourceStatus, windowMark].filter(Boolean).join(" · ");
}

function renderDateDetail() {
  const selected = state.calendar.find((item) => item.visitDate === $("dateSelect").value);
  if (!selected) {
    $("dateDetail").textContent = "";
    $("dateDetail").className = "date-detail";
    return;
  }
  const pending = selected.withinCurrentWindow === false;
  $("dateDetail").className = pending ? "date-detail pending" : "date-detail ready";
  $("dateDetail").textContent =
    pending && selected.estimatedReleaseAt
      ? `辅助信息：预计放号 ${shortDateTime(selected.estimatedReleaseAt)}，可提前开启监控`
      : "辅助信息：已进入当前可查窗口";
}

function renderDoctorMode() {
  const mode = state.config?.target?.expert_mode || "prefer";
  $("doctorModeSelect").value = mode;
}

function configReadyForQueries() {
  return Boolean(state.config?.setup?.authImported);
}

function renderSetup() {
  const warnings = state.config?.warnings || [];
  const setup = state.config?.setup || {};
  const needsSetup = !setup.ready;
  const collapsed = !needsSetup && !state.setupUserExpanded;
  $("setupPanel").classList.toggle("collapsed", collapsed);
  $("setupPanel").classList.toggle("needs-setup", needsSetup);
  $("hideSetupButton").textContent = collapsed ? "展开" : "收起";
  const auth = state.config?.auth || {};
  const headers = auth.headers || [];
  const headerRows = headers.length
    ? headers.map((item) => `<span>${escapeHtml(item.name)}</span><span>${escapeHtml(item.value)}</span>`).join("")
    : "<span>headers</span><span>未导入</span>";
  const qrText = auth.qrAuthSupported ? "扫码登录" : "需在微信中打开医院小程序";
  $("qrBox").textContent = qrText;
  const authVerified = state.validation?.ok ? true : setup.authVerified;
  const checklist = [
    ["登录态", setup.authImported, "已导入", "待导入"],
    ["登录验证", authVerified, "通过", "待验证"],
    ["就诊人", setup.patientSelected, "已识别", "待识别"],
    ["提交接口", setup.submitEndpoint, "已识别", "待识别"],
    ["本地配置", setup.localConfigSaved, "已保存", "待保存"],
  ];
  $("setupChecklist").innerHTML = checklist
    .map(([label, ok, good, bad]) => {
      const klass = ok ? "ok" : "pending";
      return `<span class="${klass}">${escapeHtml(label)}：${ok ? good : bad}</span>`;
    })
    .join("");
  $("setupMessage").textContent =
    state.validation?.message || (warnings.length ? warnings.join("；") : "授权配置已完成，可以进入监控。");
  $("configDetail").innerHTML = `
    <div class="config-summary">
      <span>配置文件：${escapeHtml(auth.configPath || "config.local.json")}</span>
      <span>扫码直连：${auth.qrAuthSupported ? "已支持" : "医院未提供公开回调，暂需导入 cURL"}</span>
      <span>提交接口：${escapeHtml(state.config?.endpoints?.submit || "未配置")}</span>
      <span>就诊人编码：${state.config?.target?.patient_code && !String(state.config.target.patient_code).includes("REPLACE_") ? "已配置" : "未配置"}</span>
    </div>
    <div class="headers-table">${headerRows}</div>
  `;
}

function renderNotify() {
  const notify = state.config?.notify || {};
  const channel = (notify.channels || [])[0] || {};
  const type = channel.type || "bark";
  const enabled = Boolean(notify.enabled);
  const configured = Boolean(notify.configured);
  $("notifyEnabled").checked = Boolean(notify.enabled);
  $("notifyType").value = type;
  $("notifyName").value = channel.name || "手机通知";
  $("notifyMethod").value = channel.method || "POST";
  $("notifyUrl").placeholder = channel.url === "CONFIGURED" ? "已配置，填写新 URL 可替换" : "https://example.com/webhook";
  $("notifyUrl").value = "";
  $("barkServerUrl").value = channel.serverUrl || "https://api.day.app";
  $("barkDeviceKey").placeholder = channel.deviceKey === "CONFIGURED" ? "已配置，填写新 Key 可替换" : "从 Bark App 复制 Device Key";
  $("barkDeviceKey").value = "";
  $("serverChanSendKey").placeholder = channel.sendKey === "CONFIGURED" ? "已配置，填写新 SendKey 可替换" : "从 Server 酱复制 SendKey";
  $("serverChanSendKey").value = "";
  $("telegramBotToken").placeholder = channel.botToken === "CONFIGURED" ? "已配置，填写新 Token 可替换" : "从 BotFather 获取 Bot Token";
  $("telegramBotToken").value = "";
  $("telegramChatId").placeholder = channel.chatId === "CONFIGURED" ? "已配置，填写新 Chat ID 可替换" : "Chat ID 或 @channelusername";
  $("telegramChatId").value = "";
  renderNotifyStatus(enabled, configured, type);
  renderNotifyFields();
}

function notifyChannelLabel(type) {
  const labels = {
    bark: "Bark",
    serverchan: "Server 酱",
    telegram: "Telegram",
    webhook: "自定义 Webhook",
  };
  return labels[type] || "未选择";
}

function renderNotifyStatus(enabled, configured, type) {
  const channelLabel = notifyChannelLabel(type || $("notifyType").value || "bark");
  const status = enabled ? "已启用" : configured ? "已配置，未启用" : "待配置";
  $("notifyState").textContent = `${channelLabel} · ${status}`;
  $("notifyState").classList.toggle("ok", enabled);
  $("notifyState").classList.toggle("warning", !enabled);
  $("notifyToggleTitle").textContent = `当前渠道：${channelLabel}`;
  $("notifyToggleDetail").textContent = `${status}；开启后，命中号源、待支付和监控启停会发送提醒`;
}

function renderNotifyFields() {
  const type = $("notifyType").value || "bark";
  for (const el of document.querySelectorAll(".notify-field")) {
    el.classList.add("hidden");
  }
  for (const el of document.querySelectorAll(`.notify-${type}`)) {
    el.classList.remove("hidden");
  }
}

function sourceMatchesControls(src) {
  const period = $("periodSelect").value;
  if (period && src.period_type !== period) return false;
  if ($("doctorModeSelect").value === "required" && !isExpertSource(src)) return false;
  return true;
}

function isExpertSource(src) {
  const text = `${src.source_name || ""} ${src.label || ""}`;
  return text.includes("专家门诊") || text.includes("专家");
}

function renderSources(items = state.sources, fromMonitor = false) {
  const filtered = items.filter(sourceMatchesControls);
  if (!filtered.length) {
    $("sourcesList").className = "list empty";
    $("sourcesList").textContent = fromMonitor ? "监控中暂未命中号源" : "当前条件下暂无可用号源";
    return;
  }
  $("sourcesList").className = "list";
  $("sourcesList").innerHTML = filtered
    .map((src, index) => {
      const encoded = encodeURIComponent(JSON.stringify(src));
      return `
        <article class="source-item ${fromMonitor ? "hit" : ""}">
          <div class="source-main">
            <span>${src.doctor_name || "未知医生"}</span>
            <span>${src.price || "-"} 元</span>
          </div>
          <div class="source-meta">
            <span>${src.visit_date}</span>
            <span>${src.period_view || src.period_type}</span>
            <span>${src.source_name || "号源"}</span>
            <span>余号 ${src.count}</span>
            ${src.time_interval_view ? `<span>${src.time_interval_view}</span>` : ""}
          </div>
          <div class="source-actions">
            <button data-source="${encoded}" data-index="${index}" class="submit-button">提交预约</button>
          </div>
        </article>
      `;
    })
    .join("");
  for (const button of document.querySelectorAll(".submit-button")) {
    button.addEventListener("click", () => submitSource(JSON.parse(decodeURIComponent(button.dataset.source))));
  }
}

function renderTaskSummary(task) {
  const settings = task?.settings || {};
  const hasTask = Boolean(settings.deptCode || settings.visitDate || task?.startedAt);
  if (!hasTask) {
    $("taskSummary").className = "task-summary muted";
    $("taskSummary").textContent = "暂无监控任务";
    return;
  }
  const cooldownSeconds = remainingCooldownSeconds(task);
  const stateText =
    task.running && cooldownSeconds > 0
      ? `冷却中 ${cooldownSeconds}s`
      : task.running
        ? "监控中"
        : "已停止";
  const stateClass = task.running && cooldownSeconds > 0 ? "cooling" : task.running ? "running" : "muted";
  const hitText = task.hits?.length ? `命中 ${task.hits.length} 个` : "暂无命中";
  const intervalText = task.pollIntervalSeconds || settings.intervalSeconds || 1;
  $("taskSummary").className = `task-summary ${stateClass}`;
  $("taskSummary").innerHTML = `
    <div class="task-summary-main">
      <strong>${escapeHtml(stateText)}</strong>
      <span>${escapeHtml(settings.deptName || settings.deptCode || "未选择科室")}</span>
      <span>${escapeHtml(settings.visitDate || "未选择日期")}</span>
      <span>${escapeHtml(periodText(settings.periodType))}</span>
      <span>${escapeHtml(doctorModeText(settings.doctorMode))}</span>
    </div>
    <div class="task-summary-meta">
      <span>${escapeHtml(hitText)}</span>
      ${task.releaseAt ? `<span>预计放号：${escapeHtml(shortDateTime(task.releaseAt))}</span>` : ""}
      <span>开始：${escapeHtml(settings.startAt || task.startedAt || "立即")}</span>
      <span>时长：${escapeHtml(settings.endAfterSeconds || 240)} 秒</span>
      <span>间隔：${escapeHtml(intervalText)} 秒</span>
      ${task.rateLimitCount ? `<span>连续限流：${escapeHtml(task.rateLimitCount)} 次</span>` : ""}
    </div>
  `;
}

function renderLogs(task) {
  renderTaskSummary(task);
  const logs = (task.logs || []).slice().reverse();
  $("logs").textContent = logs.join("\n");
  if (task.hits && task.hits.length) {
    renderSources(task.hits, true);
  }
  const cooldownSeconds = remainingCooldownSeconds(task);
  if (task.running && cooldownSeconds > 0) {
    setStatus(`冷却中 ${cooldownSeconds}s`, true, true);
    return;
  }
  setStatus(task.running ? "监控中" : "未启动", task.running);
}

function renderLocalLog(message, payload = null, running = false) {
  renderLogs({
    running,
    logs: [`[${new Date().toLocaleTimeString()}] ${message}`],
    hits: [],
    startedAt: running ? new Date().toISOString() : null,
    settings: payload || {},
    cooldownUntil: null,
    cooldownSeconds: 0,
    rateLimitCount: 0,
    releaseAt: null,
    pollIntervalSeconds: payload?.intervalSeconds || null,
  });
}

async function loadConfig() {
  const data = await api("/api/config");
  state.config = data.config;
  const warnings = state.config.warnings || [];
  renderConfigStatus();
  $("endAfter").value = state.config.polling?.end_after_seconds || 240;
  $("interval").value = state.config.polling?.interval_after_release || 1;
  $("startAt").value = state.config.polling?.start_at || "";
  renderDoctorMode();
  renderSetup();
  renderNotify();
}

function renderConfigStatus() {
  const warnings = state.config?.warnings || [];
  const setup = state.config?.setup || {};
  const status = $("configStatus");
  status.className = "config-status";
  if (setup.ready) {
    status.classList.add("ok");
    status.textContent = "配置可用";
    return;
  }
  status.classList.add("warning");
  const missing = [];
  if (!setup.authImported) missing.push("登录态");
  if (!setup.patientSelected) missing.push("就诊人");
  if (!setup.submitEndpoint) missing.push("提交接口");
  status.textContent = missing.length ? `配置未完成：缺少${missing.join("、")}` : warnings.join("；");
}

async function loadDistricts() {
  const data = await api("/api/districts");
  state.districts = data.items;
  renderDistricts();
}

async function loadDepartments() {
  const data = await api(`/api/departments?districtCode=${encodeURIComponent(selectedDistrictCode())}`);
  state.departments = data.items;
  renderDepartments();
}

async function loadCalendar() {
  const deptCode = selectedDeptCode();
  if (!deptCode) return;
  const data = await api(`/api/calendar?deptCode=${encodeURIComponent(deptCode)}&days=10`);
  state.calendar = data.items;
  renderCalendar();
}

async function loadSources() {
  const deptCode = selectedDeptCode();
  const visitDate = $("dateSelect").value;
  if (!deptCode || !visitDate) return;
  const params = new URLSearchParams({ deptCode, visitDate, doctorMode: $("doctorModeSelect").value });
  const data = await api(`/api/sources?${params.toString()}`);
  state.sources = data.items;
  renderSources();
}

async function refreshAll() {
  await loadConfig();
  if (!configReadyForQueries()) {
    $("sourcesList").className = "list empty";
    $("sourcesList").textContent = "请先完成授权与配置";
    return;
  }
  try {
    await loadDistricts();
    await loadDepartments();
    await loadCalendar();
    await loadSources();
    await refreshTask();
  } catch (err) {
    showQueryError(err);
  }
}

function showQueryError(err) {
  const message = err.message || String(err);
  $("sourcesList").className = "list empty";
  $("sourcesList").textContent = message.includes("请求过于频繁")
    ? `${message} 医院接口正在限流，页面会保留已有配置，请稍后再刷新。`
    : message;
}

async function startTask() {
  const button = $("startButton");
  const payload = taskPayload();
  if (!payload.deptCode) {
    alert("请先选择门诊科室");
    return;
  }
  button.disabled = true;
  button.textContent = "启动中";
  setStatus("启动中", true);
  renderLocalLog("正在启动监控任务...", payload, true);
  try {
    remindNotifyIfMissing("监控会继续启动");
    await api("/api/config/target", {
      method: "POST",
      body: JSON.stringify({
        districtCode: payload.districtCode,
        deptCode: payload.deptCode,
        deptName: payload.deptName,
        doctorMode: payload.doctorMode,
      }),
    });
    const data = await api("/api/tasks/start", { method: "POST", body: JSON.stringify(payload) });
    renderLogs(data.task);
    startPolling();
  } catch (err) {
    setStatus("启动失败", false);
    renderLocalLog(`启动失败：${err.message}`, payload, false);
  } finally {
    button.disabled = false;
    button.textContent = "开启监控";
  }
}

async function stopTask() {
  const button = $("stopButton");
  button.disabled = true;
  button.textContent = "停止中";
  setStatus("停止中", false);
  try {
    remindNotifyIfMissing("监控会继续停止");
    const data = await api("/api/tasks/stop", { method: "POST", body: "{}" });
    renderLogs(data.task);
  } catch (err) {
    renderLocalLog(`停止失败：${err.message}`, null, false);
  } finally {
    button.disabled = false;
    button.textContent = "停止监控";
  }
}

function remindNotifyIfMissing(prefix) {
  const notify = state.config?.notify || {};
  if (!notify.enabled || !notify.configured) {
    $("notifyMessage").textContent = `未配置或未启用消息通知，${prefix}。`;
  }
}

async function refreshTask() {
  const data = await api("/api/tasks/status");
  renderLogs(data.task);
}

function startPolling() {
  if (state.taskTimer) clearInterval(state.taskTimer);
  state.taskTimer = setInterval(refreshTask, 1500);
}

async function submitSource(source) {
  const phrase = prompt("输入确认词才会提交预约，成功后请到小程序内支付。");
  if (!phrase) return;
  const data = await api("/api/submit", {
    method: "POST",
    body: JSON.stringify({ confirmPhrase: phrase, source }),
  });
  alert(`提交完成：${JSON.stringify(data.result)}`);
  await refreshTask();
}

async function importCurl() {
  const curl = $("curlInput").value.trim();
  if (!curl) {
    alert("请先粘贴 cURL");
    return;
  }
  const data = await api("/api/config/import-curl", {
    method: "POST",
    body: JSON.stringify({ curl }),
  });
  state.config = data.config;
  $("curlInput").value = "";
  renderConfigStatus();
  renderSetup();
  await refreshAll();
}

function readSelectedFile(input) {
  const file = input.files && input.files[0];
  if (!file) {
    throw new Error("请先选择 HAR 文件");
  }
  return file.text();
}

async function importHar() {
  try {
    const har = await readSelectedFile($("harInput"));
    const data = await api("/api/config/import-har", {
      method: "POST",
      body: JSON.stringify({ har }),
    });
    state.config = data.config;
    state.validation = null;
    $("setupMessage").textContent = `已从 HAR 导入 ${data.imported.candidates} 条医院请求`;
    renderSetup();
    await refreshAll();
  } catch (err) {
    $("setupMessage").textContent = err.message;
  }
}

async function validateAuth() {
  try {
    const data = await api("/api/config/validate-auth", { method: "POST", body: "{}" });
    state.validation = data.validation;
    state.config = data.config;
    renderSetup();
  } catch (err) {
    state.validation = { ok: false, message: err.message };
    renderSetup();
  }
}

function notifyPayload() {
  const type = $("notifyType").value || "bark";
  return {
    enabled: $("notifyEnabled").checked,
    type,
    name: $("notifyName").value.trim() || "手机通知",
    method: $("notifyMethod").value || "POST",
    url: $("notifyUrl").value.trim(),
    serverUrl: $("barkServerUrl").value.trim() || "https://api.day.app",
    deviceKey: $("barkDeviceKey").value.trim(),
    sendKey: $("serverChanSendKey").value.trim(),
    botToken: $("telegramBotToken").value.trim(),
    chatId: $("telegramChatId").value.trim(),
  };
}

async function saveNotify(options = {}) {
  const payload = notifyPayload();
  const type = payload.type;
  const existing = state.config?.notify?.channels?.[0] || {};
  const hasExistingSecret =
    (type === "webhook" && existing.url === "CONFIGURED") ||
    (type === "bark" && existing.deviceKey === "CONFIGURED") ||
    (type === "serverchan" && existing.sendKey === "CONFIGURED") ||
    (type === "telegram" && existing.botToken === "CONFIGURED" && existing.chatId === "CONFIGURED");
  const hasNewSecret =
    (type === "webhook" && payload.url) ||
    (type === "bark" && payload.deviceKey) ||
    (type === "serverchan" && payload.sendKey) ||
    (type === "telegram" && payload.botToken && payload.chatId);
  if (payload.enabled && !hasExistingSecret && !hasNewSecret) {
    $("notifyMessage").textContent = "启用通知前请填写当前渠道需要的密钥";
    renderNotify();
    return;
  }
  if (options.statusOnly) {
    $("notifyMessage").textContent = payload.enabled ? "正在启用通知..." : "正在关闭通知...";
  }
  try {
    const data = await api("/api/config/notify", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    state.config = data.config;
    $("notifyMessage").textContent = payload.enabled ? "通知已启用并保存" : "通知已关闭并保存";
    renderNotify();
  } catch (err) {
    $("notifyMessage").textContent = `通知配置保存失败：${err.message}`;
    renderNotify();
  }
}

async function testNotify() {
  const button = $("testNotifyButton");
  const started = performance.now();
  button.disabled = true;
  button.textContent = "发送中";
  $("notifyMessage").textContent = "正在发送测试通知，请稍候";
  try {
    const data = await api("/api/notify/test", { method: "POST", body: "{}" });
    const seconds = ((performance.now() - started) / 1000).toFixed(1);
    if (data.notification.sent) {
      $("notifyMessage").textContent = `测试通知已发送，用时 ${seconds}s`;
    } else {
      const detail = (data.notification.results || [])
        .map((item) => item.error || `HTTP ${item.status || "-"}`)
        .join("；");
      $("notifyMessage").textContent = detail ? `测试通知发送失败：${detail}` : "没有可用的通知通道";
    }
  } catch (err) {
    $("notifyMessage").textContent = err.message;
  } finally {
    button.disabled = false;
    button.textContent = "发送测试";
  }
}

function wireEvents() {
  $("refreshButton").addEventListener("click", refreshAll);
  $("hideSetupButton").addEventListener("click", () => {
    const setup = state.config?.setup || {};
    if (!setup.ready) {
      state.setupUserExpanded = true;
    } else {
      state.setupUserExpanded = !state.setupUserExpanded;
    }
    renderSetup();
  });
  $("importHarButton").addEventListener("click", importHar);
  $("validateAuthButton").addEventListener("click", validateAuth);
  $("importCurlButton").addEventListener("click", importCurl);
  $("notifyEnabled").addEventListener("change", async () => {
    renderNotifyStatus($("notifyEnabled").checked, Boolean(state.config?.notify?.configured));
    await saveNotify({ statusOnly: true });
  });
  $("notifyType").addEventListener("change", () => {
    renderNotifyFields();
    renderNotifyStatus($("notifyEnabled").checked, Boolean(state.config?.notify?.configured));
  });
  $("saveNotifyButton").addEventListener("click", saveNotify);
  $("testNotifyButton").addEventListener("click", testNotify);
  $("districtSelect").addEventListener("change", async () => {
    await loadDepartments();
    await loadCalendar();
    await loadSources();
  });
  $("deptSearch").addEventListener("input", renderDepartments);
  $("deptSelect").addEventListener("change", async () => {
    await loadCalendar();
    await loadSources();
  });
  $("dateSelect").addEventListener("change", async () => {
    renderDateDetail();
    await loadSources();
  });
  $("periodSelect").addEventListener("change", () => renderSources());
  $("doctorModeSelect").addEventListener("change", async () => {
    await loadSources();
  });
  $("loadSourcesButton").addEventListener("click", loadSources);
  $("startButton").addEventListener("click", startTask);
  $("stopButton").addEventListener("click", stopTask);
  $("clearLogsButton").addEventListener("click", () => {
    $("logs").textContent = "";
  });
}

async function main() {
  wireEvents();
  try {
    await refreshAll();
    startPolling();
  } catch (err) {
    const status = $("configStatus");
    status.className = "config-status error";
    status.textContent = err.message;
  }
}

main();
