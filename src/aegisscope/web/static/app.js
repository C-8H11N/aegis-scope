"use strict";

const translations = {
  "zh-CN": {
    skip: "跳到主要内容",
    navOverview: "总览",
    navValidator: "清单校验",
    navJobs: "审计记录",
    navSafety: "安全边界",
    executionLocked: "执行门已锁定",
    localOnly: "仅本地控制平面",
    workspace: "安全编排工作区",
    pageTitle: "控制台总览",
    apiDocs: "API 文档",
    controlPlaneReady: "控制平面在线",
    heroTitle: "让每一次安全测试都始于明确授权",
    heroDescription: "模型负责提出建议，确定性策略负责范围、速率和停止条件。所有目标执行仍需要独立的人工授权。",
    validateAction: "校验阶段清单",
    viewSafety: "查看安全边界",
    controlPlane: "控制平面",
    checking: "检查中",
    online: "在线",
    unavailable: "不可用",
    modelApi: "模型 API",
    configured: "已配置",
    notConfigured: "未配置",
    proposalOnly: "仅生成待审提案",
    kaliRunner: "Kali Runner",
    configuredUnchecked: "已配置，未连接检测",
    preparedJobs: "本地任务",
    auditStored: "SQLite 审计留痕",
    policyGate: "确定性策略门",
    validatorTitle: "阶段清单校验器",
    validatorDescription: "导入 JSON 清单并在本地检查授权、精确范围、请求上限与停止条件。校验不会访问目标。",
    offlineSafe: "离线安全操作",
    importJson: "导入 JSON",
    loadDemo: "载入安全演示",
    manifestJson: "阶段清单 JSON",
    waitingValidation: "等待校验",
    waitingDescription: "导入或粘贴一份阶段清单。结果会显示允许项、警告和拒绝原因。",
    prepareNote: "“准备任务”只写入本地审计库，不会连接 Kali 或访问目标。",
    clear: "清空",
    validate: "开始校验",
    prepare: "准备本地任务",
    localAudit: "本地审计轨迹",
    jobsTitle: "最近任务",
    jobsDescription: "展示本地任务状态与自动证据研判；只有明确的执行记录才代表曾发送请求。",
    jobId: "任务 ID",
    target: "精确目标",
    stage: "阶段",
    status: "状态",
    analysis: "自动研判",
    noAnalysis: "尚无证据",
    updated: "更新时间",
    noJobs: "暂无本地任务",
    noJobsDescription: "校验并准备一份清单后会显示在这里。",
    safetyByDesign: "默认安全设计",
    safetyTitle: "模型不能越过策略门",
    safetyDescription: "AegisScope 把模型建议与实际执行彻底分离。API 接入不会自动授予任何目标权限。",
    readSecurityModel: "阅读安全模型",
    exactScope: "精确范围",
    exactScopeText: "只接受清单中明确列出的精确主机，不自动扩展资产。",
    conservativeLimits: "保守上限",
    conservativeLimitsText: "单并发、至少五秒间隔、最多二十次请求、不跟随重定向。",
    dualValidation: "双端复核",
    dualValidationText: "Windows 与 Kali 在执行前验证同一份不可扩展清单。",
    footerBoundary: "仅用于合法授权的安全研究",
    validationAllowed: "策略校验通过",
    validationDenied: "策略校验拒绝",
    validationAllowedSummary: "清单满足当前确定性安全策略，可在本地准备审计任务。",
    validationDeniedSummary: "清单未通过安全策略；请先修正列出的原因。",
    noMessages: "没有附加警告。",
    invalidJson: "JSON 格式无效",
    invalidJsonHelp: "请检查括号、逗号和字符串引号后重试。",
    requestFailed: "本地 API 请求失败",
    requestFailedHelp: "请确认 AegisScope 服务仍在运行，然后重试。",
    demoLoaded: "已载入永久 dry-run 的 .invalid 安全演示清单。",
    fileLoaded: "JSON 文件已载入。",
    fileReadFailed: "无法读取所选文件。",
    preparedSuccess: "任务已在本地准备并写入审计库。",
    preparedStatus: "已准备",
    offlineAnalyzedStatus: "已离线研判",
    failedStatus: "失败",
    evidenceTransferFailedStatus: "证据传输失败",
    stoppedStatus: "已安全停止",
    basicObservation: "基础观察",
    parameterBaseline: "公开参数基线",
    refreshFailed: "无法刷新本地任务列表。",
    themeLabel: "切换明暗主题",
    languageLabel: "Switch to English",
    refreshLabel: "刷新任务"
  },
  en: {
    skip: "Skip to main content",
    navOverview: "Overview",
    navValidator: "Manifest validator",
    navJobs: "Audit trail",
    navSafety: "Safety boundary",
    executionLocked: "Execution gate locked",
    localOnly: "Local control plane only",
    workspace: "Security orchestration workspace",
    pageTitle: "Control plane overview",
    apiDocs: "API docs",
    controlPlaneReady: "Control plane online",
    heroTitle: "Make explicit authorization the start of every assessment",
    heroDescription: "The model proposes. Deterministic policy controls scope, rate, and stop conditions. Every target execution still requires separate human authorization.",
    validateAction: "Validate a stage manifest",
    viewSafety: "View safety boundary",
    controlPlane: "Control plane",
    checking: "Checking",
    online: "Online",
    unavailable: "Unavailable",
    modelApi: "Model API",
    configured: "Configured",
    notConfigured: "Not configured",
    proposalOnly: "Unapproved proposals only",
    kaliRunner: "Kali runner",
    configuredUnchecked: "Configured, not connected",
    preparedJobs: "Local jobs",
    auditStored: "SQLite audit trail",
    policyGate: "Deterministic policy gate",
    validatorTitle: "Stage manifest validator",
    validatorDescription: "Import JSON and check authorization, exact scope, request caps, and stop conditions locally. Validation never contacts a target.",
    offlineSafe: "Offline-safe action",
    importJson: "Import JSON",
    loadDemo: "Load safe demo",
    manifestJson: "Stage manifest JSON",
    waitingValidation: "Waiting for validation",
    waitingDescription: "Import or paste a stage manifest. Allowed items, warnings, and denial reasons will appear here.",
    prepareNote: "Prepare job only writes to the local audit database. It does not contact Kali or a target.",
    clear: "Clear",
    validate: "Validate manifest",
    prepare: "Prepare local job",
    localAudit: "Local audit trail",
    jobsTitle: "Recent jobs",
    jobsDescription: "Shows local job state and automatic evidence triage. Only an explicit execution record means requests were sent.",
    jobId: "Job ID",
    target: "Exact target",
    stage: "Stage",
    status: "Status",
    analysis: "Auto triage",
    noAnalysis: "No evidence",
    updated: "Updated",
    noJobs: "No local jobs yet",
    noJobsDescription: "Validate and prepare a manifest to see it here.",
    safetyByDesign: "Safe by design",
    safetyTitle: "The model cannot cross the policy gate",
    safetyDescription: "AegisScope separates model proposals from execution. Connecting an API never grants target authorization.",
    readSecurityModel: "Read the security model",
    exactScope: "Exact scope",
    exactScopeText: "Only exact hosts named in the manifest are accepted. Assets are never expanded automatically.",
    conservativeLimits: "Conservative limits",
    conservativeLimitsText: "One concurrent request, five-second minimum delay, twenty-request cap, and no redirect following.",
    dualValidation: "Two-sided validation",
    dualValidationText: "Windows and Kali validate the same non-extensible manifest before execution.",
    footerBoundary: "For lawful, authorized security research only",
    validationAllowed: "Policy validation passed",
    validationDenied: "Policy validation denied",
    validationAllowedSummary: "The manifest satisfies deterministic safety policy and may be prepared for local audit.",
    validationDeniedSummary: "The manifest failed safety policy. Resolve the listed reasons first.",
    noMessages: "No additional warnings.",
    invalidJson: "Invalid JSON",
    invalidJsonHelp: "Check brackets, commas, and string quotes, then try again.",
    requestFailed: "Local API request failed",
    requestFailedHelp: "Confirm that the AegisScope service is still running, then retry.",
    demoLoaded: "Loaded a permanent dry-run demo using the reserved .invalid namespace.",
    fileLoaded: "JSON file loaded.",
    fileReadFailed: "The selected file could not be read.",
    preparedSuccess: "The job was prepared locally and added to the audit trail.",
    preparedStatus: "Prepared",
    offlineAnalyzedStatus: "Offline triaged",
    failedStatus: "Failed",
    evidenceTransferFailedStatus: "Evidence transfer failed",
    stoppedStatus: "Safely stopped",
    basicObservation: "Basic observation",
    parameterBaseline: "Public parameter baseline",
    refreshFailed: "Could not refresh the local job list.",
    themeLabel: "Toggle light and dark theme",
    languageLabel: "切换到中文",
    refreshLabel: "Refresh jobs"
  }
};

const state = {
  language: localStorage.getItem("aegisscope-language") === "en" ? "en" : "zh-CN",
  theme: localStorage.getItem("aegisscope-theme") || "dark",
  manifest: null,
  decision: null,
  valid: false,
  toastTimer: null
};

const elements = {
  themeToggle: document.querySelector("#theme-toggle"),
  languageToggle: document.querySelector("#language-toggle"),
  manifestInput: document.querySelector("#manifest-json"),
  manifestFile: document.querySelector("#manifest-file"),
  loadDemo: document.querySelector("#load-demo"),
  clearManifest: document.querySelector("#clear-manifest"),
  validateManifest: document.querySelector("#validate-manifest"),
  prepareJob: document.querySelector("#prepare-job"),
  validationEmpty: document.querySelector("#validation-empty"),
  validationResult: document.querySelector("#validation-result"),
  resultIcon: document.querySelector("#result-icon"),
  resultTitle: document.querySelector("#result-title"),
  resultSummary: document.querySelector("#result-summary"),
  resultMessages: document.querySelector("#result-messages"),
  healthStatus: document.querySelector("#health-status"),
  healthDetail: document.querySelector("#health-detail"),
  llmStatus: document.querySelector("#llm-status"),
  runnerStatus: document.querySelector("#runner-status"),
  runnerAlias: document.querySelector("#runner-alias"),
  jobCount: document.querySelector("#job-count"),
  jobsBody: document.querySelector("#jobs-body"),
  jobsEmpty: document.querySelector("#jobs-empty"),
  refreshJobs: document.querySelector("#refresh-jobs"),
  sidebarVersion: document.querySelector("#sidebar-version"),
  toast: document.querySelector("#toast")
};

function t(key) {
  return translations[state.language][key] || key;
}

function applyLanguage() {
  document.documentElement.lang = state.language;
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    node.textContent = t(node.dataset.i18n);
  });
  elements.themeToggle.setAttribute("aria-label", t("themeLabel"));
  elements.languageToggle.setAttribute("aria-label", t("languageLabel"));
  elements.refreshJobs.setAttribute("aria-label", t("refreshLabel"));
  if (state.decision) {
    renderValidation(state.decision);
  }
}

function applyTheme() {
  const safeTheme = state.theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = safeTheme;
}

function showToast(message) {
  window.clearTimeout(state.toastTimer);
  elements.toast.textContent = message;
  elements.toast.classList.add("is-visible");
  state.toastTimer = window.setTimeout(() => {
    elements.toast.classList.remove("is-visible");
  }, 4000);
}

function setBusy(button, busy) {
  button.disabled = busy;
  button.classList.toggle("is-loading", busy);
  button.setAttribute("aria-busy", String(busy));
}

function invalidateManifest() {
  state.manifest = null;
  state.decision = null;
  state.valid = false;
  elements.prepareJob.disabled = true;
  elements.validationEmpty.classList.remove("is-hidden");
  elements.validationResult.classList.add("is-hidden");
}

function parseManifest() {
  const value = elements.manifestInput.value.trim();
  if (!value) {
    throw new SyntaxError("empty manifest");
  }
  return JSON.parse(value);
}

function buildSafeDemo() {
  const now = new Date();
  const expires = new Date(now.getTime() + 60 * 60 * 1000);
  const suffix = typeof crypto.randomUUID === "function"
    ? crypto.randomUUID().slice(0, 8)
    : Math.random().toString(16).slice(2, 10);
  return {
    schema_version: 1,
    job_id: `demo-${suffix}`,
    program_name: "AegisScope Offline Demo",
    stage_type: "basic_observation",
    target_host: "example.invalid",
    allowlist: ["example.invalid"],
    denylist: [],
    authorization: {
      granted: true,
      scope: "stage",
      user_statement: "Local dry-run demo only; no target network access.",
      granted_at: now.toISOString(),
      expires_at: expires.toISOString()
    },
    dry_run: true,
    requests: [{ method: "HEAD", url: "https://example.invalid/" }],
    limits: {
      concurrency: 1,
      request_interval_seconds: 5,
      max_requests: 1,
      per_url_max: 1,
      timeout_seconds: 10,
      max_response_bytes: 1048576,
      max_redirects: 0
    },
    created_at: now.toISOString(),
    expires_at: expires.toISOString(),
    notes: "Reserved .invalid namespace; permanent dry-run demonstration."
  };
}

async function apiRequest(path, options = {}) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(path, {
      ...options,
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {})
      }
    });
    let body = null;
    try {
      body = await response.json();
    } catch (_error) {
      body = null;
    }
    if (!response.ok) {
      const detail = body && body.detail ? String(body.detail) : `HTTP ${response.status}`;
      throw new Error(detail);
    }
    return body;
  } finally {
    window.clearTimeout(timeout);
  }
}

function appendResultMessage(message, type) {
  const row = document.createElement("div");
  row.className = `result-message is-${type}`;
  row.textContent = message;
  elements.resultMessages.appendChild(row);
}

function renderValidation(decision) {
  const allowed = Boolean(decision.allowed);
  elements.validationEmpty.classList.add("is-hidden");
  elements.validationResult.classList.remove("is-hidden");
  elements.resultIcon.className = `result-icon ${allowed ? "is-allowed" : "is-denied"}`;
  elements.resultIcon.textContent = allowed ? "OK" : "!";
  elements.resultTitle.textContent = t(allowed ? "validationAllowed" : "validationDenied");
  elements.resultSummary.textContent = t(allowed ? "validationAllowedSummary" : "validationDeniedSummary");
  elements.resultMessages.replaceChildren();

  const errors = Array.isArray(decision.errors) ? decision.errors : [];
  const warnings = Array.isArray(decision.warnings) ? decision.warnings : [];
  errors.forEach((message) => appendResultMessage(String(message), "error"));
  warnings.forEach((message) => appendResultMessage(String(message), "warning"));
  if (errors.length === 0 && warnings.length === 0) {
    appendResultMessage(t("noMessages"), "ok");
  }

  state.decision = decision;
  state.valid = allowed;
  elements.prepareJob.disabled = !allowed;
}

function renderClientError(titleKey, helpKey, detail = "") {
  elements.validationEmpty.classList.add("is-hidden");
  elements.validationResult.classList.remove("is-hidden");
  elements.resultIcon.className = "result-icon is-denied";
  elements.resultIcon.textContent = "!";
  elements.resultTitle.textContent = t(titleKey);
  elements.resultSummary.textContent = t(helpKey);
  elements.resultMessages.replaceChildren();
  if (detail) {
    appendResultMessage(detail, "error");
  }
  state.valid = false;
  state.decision = null;
  elements.prepareJob.disabled = true;
}

async function validateCurrentManifest() {
  const sourceText = elements.manifestInput.value;
  let payload;
  try {
    payload = parseManifest();
  } catch (error) {
    renderClientError("invalidJson", "invalidJsonHelp", error.message);
    return;
  }

  setBusy(elements.validateManifest, true);
  try {
    const decision = await apiRequest("/api/v1/manifests/validate", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    if (elements.manifestInput.value !== sourceText) {
      invalidateManifest();
      return;
    }
    state.manifest = payload;
    renderValidation(decision);
  } catch (error) {
    renderClientError("requestFailed", "requestFailedHelp", error.message);
  } finally {
    setBusy(elements.validateManifest, false);
  }
}

async function prepareCurrentJob() {
  if (!state.valid || !state.manifest) {
    return;
  }
  elements.prepareJob.disabled = true;
  try {
    await apiRequest("/api/v1/jobs/prepare", {
      method: "POST",
      body: JSON.stringify(state.manifest)
    });
    showToast(t("preparedSuccess"));
    await loadJobs();
  } catch (error) {
    renderClientError("requestFailed", "requestFailedHelp", error.message);
  } finally {
    elements.prepareJob.disabled = !state.valid;
  }
}

function stageName(stage) {
  if (stage === "basic_observation") {
    return t("basicObservation");
  }
  if (stage === "public_parameter_baseline") {
    return t("parameterBaseline");
  }
  return stage || "—";
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "—";
  }
  return new Intl.DateTimeFormat(state.language, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(date);
}

function createCell(value) {
  const cell = document.createElement("td");
  cell.textContent = value;
  return cell;
}

function jobStatusName(status) {
  const names = {
    prepared: "preparedStatus",
    offline_analyzed: "offlineAnalyzedStatus",
    failed: "failedStatus",
    evidence_transfer_failed: "evidenceTransferFailedStatus",
    stopped: "stoppedStatus"
  };
  return names[status] ? t(names[status]) : String(status || "—");
}

function renderJobs(jobs) {
  elements.jobsBody.replaceChildren();
  const safeJobs = Array.isArray(jobs) ? jobs : [];
  elements.jobCount.textContent = String(safeJobs.length);
  elements.jobsEmpty.classList.toggle("is-hidden", safeJobs.length > 0);

  safeJobs.forEach((job) => {
    const row = document.createElement("tr");
    const manifest = job && typeof job.manifest === "object" ? job.manifest : {};
    row.appendChild(createCell(String(job.job_id || "—")));
    row.appendChild(createCell(String(manifest.target_host || "—")));
    row.appendChild(createCell(stageName(manifest.stage_type)));

    const statusCell = document.createElement("td");
    const status = document.createElement("span");
    status.className = "job-status";
    status.textContent = jobStatusName(job.status);
    statusCell.appendChild(status);
    row.appendChild(statusCell);

    const analysis = job && typeof job.analysis === "object" ? job.analysis : null;
    if (analysis) {
      const candidates = Number(analysis.candidate_count || 0);
      const observations = Number(analysis.observation_count || 0);
      const label = state.language === "zh-CN"
        ? `${candidates} 个候选 · ${observations} 个观察`
        : `${candidates} candidates · ${observations} observations`;
      row.appendChild(createCell(label));
    } else {
      row.appendChild(createCell(t("noAnalysis")));
    }
    row.appendChild(createCell(formatDate(job.updated_at)));
    elements.jobsBody.appendChild(row);
  });
}

async function loadJobs(showErrors = false) {
  try {
    const jobs = await apiRequest("/api/v1/jobs?limit=50");
    renderJobs(jobs);
  } catch (_error) {
    elements.jobCount.textContent = "—";
    if (showErrors) {
      showToast(t("refreshFailed"));
    }
  }
}

async function loadSystemStatus() {
  const results = await Promise.allSettled([
    apiRequest("/health"),
    apiRequest("/api/v1/config")
  ]);
  const healthResult = results[0];
  const configResult = results[1];

  if (healthResult.status === "fulfilled") {
    elements.healthStatus.textContent = t("online");
    elements.healthDetail.textContent = `v${healthResult.value.version} · 127.0.0.1`;
    elements.sidebarVersion.textContent = `v${healthResult.value.version}`;
  } else {
    elements.healthStatus.textContent = t("unavailable");
  }

  if (configResult.status === "fulfilled") {
    const config = configResult.value;
    elements.llmStatus.textContent = t(config.llm_configured ? "configured" : "notConfigured");
    elements.runnerStatus.textContent = t("configuredUnchecked");
    elements.runnerAlias.textContent = `${config.ssh_alias} · ${config.remote_root}`;
  } else {
    elements.llmStatus.textContent = t("unavailable");
    elements.runnerStatus.textContent = t("unavailable");
  }
}

function installNavigationObserver() {
  const sections = [...document.querySelectorAll("main section[id]")];
  const links = [...document.querySelectorAll(".nav-item")];
  if (!("IntersectionObserver" in window)) {
    return;
  }
  const observer = new IntersectionObserver((entries) => {
    const visible = entries
      .filter((entry) => entry.isIntersecting)
      .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
    if (!visible) {
      return;
    }
    links.forEach((link) => {
      link.classList.toggle("is-active", link.getAttribute("href") === `#${visible.target.id}`);
    });
  }, { rootMargin: "-20% 0px -65% 0px", threshold: [0.05, 0.25] });
  sections.forEach((section) => observer.observe(section));
}

elements.themeToggle.addEventListener("click", () => {
  state.theme = state.theme === "dark" ? "light" : "dark";
  localStorage.setItem("aegisscope-theme", state.theme);
  applyTheme();
});

elements.languageToggle.addEventListener("click", async () => {
  state.language = state.language === "zh-CN" ? "en" : "zh-CN";
  localStorage.setItem("aegisscope-language", state.language);
  applyLanguage();
  await Promise.all([loadSystemStatus(), loadJobs()]);
});

elements.manifestInput.addEventListener("input", invalidateManifest);
elements.manifestFile.addEventListener("change", async () => {
  const file = elements.manifestFile.files && elements.manifestFile.files[0];
  if (!file) {
    return;
  }
  try {
    elements.manifestInput.value = await file.text();
    invalidateManifest();
    showToast(t("fileLoaded"));
  } catch (_error) {
    showToast(t("fileReadFailed"));
  } finally {
    elements.manifestFile.value = "";
  }
});

elements.loadDemo.addEventListener("click", () => {
  elements.manifestInput.value = JSON.stringify(buildSafeDemo(), null, 2);
  invalidateManifest();
  showToast(t("demoLoaded"));
});

elements.clearManifest.addEventListener("click", () => {
  elements.manifestInput.value = "";
  invalidateManifest();
  elements.manifestInput.focus();
});

elements.validateManifest.addEventListener("click", validateCurrentManifest);
elements.prepareJob.addEventListener("click", prepareCurrentJob);
elements.refreshJobs.addEventListener("click", () => loadJobs(true));

applyTheme();
applyLanguage();
installNavigationObserver();
loadSystemStatus();
loadJobs();
