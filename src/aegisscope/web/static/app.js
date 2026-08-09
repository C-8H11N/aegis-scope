"use strict";

const translations = {
  "zh-CN": {
    skip: "跳到主要内容",
    navOverview: "总览",
    navCampaigns: "智能任务",
    navValidator: "清单校验",
    navJobs: "审计记录",
    navFindings: "线索台账",
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
    findingRecords: "漏洞线索",
    humanReviewedOnly: "确认与报告必须人工审核",
    campaignRecords: "智能任务",
    planningOnly: "离线规划，不自动执行",
    campaignEyebrow: "AUTONOMOUS CAMPAIGN · 自主研究编排",
    campaignsTitle: "让系统记住目标，并自动选择下一步",
    campaignsDescription: "基于已有脱敏证据自动去重、排序假设和控制总预算。系统只生成待授权提案；不会连接 Kali、发送目标请求或自动认定漏洞。",
    offlinePlanner: "离线决策引擎",
    campaignBoundaryTitle: "自动化边界",
    campaignBoundaryText: "“规划下一步”仅处理本地数据。任何生成的阶段提案仍需人工审核、摘要确认和独立授权。",
    programName: "SRC 项目名称",
    exactHost: "精确主机",
    exactHostHelp: "只会加入这个精确主机，不推导子域名。",
    campaignObjective: "研究目标",
    campaignObjectivePlaceholder: "整理已有证据并优先验证最有价值的低影响假设。",
    stageBudget: "阶段预算",
    requestBudget: "总请求预算",
    createCampaign: "创建本地智能任务",
    campaignEmptyTitle: "先创建一个研究任务",
    campaignEmptyText: "创建后点击“规划下一步”，系统会优先使用同项目的离线流量分析；没有证据时只生成两请求公开基线提案。",
    hypotheses: "个假设",
    requestsUsed: "次请求",
    downloadProposal: "下载待授权提案",
    recordOutcome: "完成复核后记录结果",
    reviewStatement: "人工复核说明",
    reviewStatementPlaceholder: "说明证据、判断和停止位置。",
    actualRequests: "本阶段实际请求数",
    keepLead: "保留有效线索",
    rejectLead: "排除该方向",
    duplicateLead: "标记重复",
    exhaustLead: "停止该方向",
    outcomeBoundary: "这里只更新假设队列，不会把线索标记为已确认漏洞或生成报告。",
    campaignDecisionSaved: "人工结论已记录，下一动作已重新计算。",
    recentCampaigns: "最近智能任务",
    noCampaigns: "暂无智能任务。",
    planNext: "规划下一步",
    campaignCreated: "智能任务已在本地创建，没有发送目标请求。",
    campaignPlanned: "离线规划完成，没有发送目标请求。",
    readyCampaignStatus: "待规划",
    planningCampaignStatus: "规划中",
    awaitingAuthorizationStatus: "待阶段授权",
    manualReviewCampaignStatus: "需人工复核",
    completedCampaignStatus: "已完成",
    budgetExhaustedStatus: "预算已耗尽",
    stoppedCampaignStatus: "已安全停止",
    refreshCampaignsLabel: "刷新智能任务",
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
    analystWorkspace: "离线分析工作台",
    findingsTitle: "漏洞候选与生命周期",
    findingsDescription: "HAR 或 Burp XML 先在命令行脱敏导入，再在这里查看候选、人工状态与报告资格。候选默认不可提交。",
    analystBoundary: "这里只展示脱敏派生数据。工具不会自动重放请求、确认漏洞或生成可提交结论。",
    findingTitle: "候选标题",
    endpoint: "归一化接口",
    severity: "风险提示",
    reportEligibility: "报告资格",
    reportable: "可生成报告",
    notReportable: "不可提交",
    noFindings: "暂无候选线索",
    noFindingsDescription: "离线导入并分析授权流量后，候选项会显示在这里。",
    candidateStatus: "待复核",
    needsValidationStatus: "待授权验证",
    confirmedStatus: "已人工确认",
    falsePositiveStatus: "误报",
    duplicateStatus: "重复",
    acceptedRiskStatus: "已接受风险",
    submittedStatus: "已提交",
    fixedStatus: "已修复",
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
    refreshLabel: "刷新任务",
    refreshFindingsLabel: "刷新线索"
  },
  en: {
    skip: "Skip to main content",
    navOverview: "Overview",
    navCampaigns: "Campaigns",
    navValidator: "Manifest validator",
    navJobs: "Audit trail",
    navFindings: "Finding ledger",
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
    findingRecords: "Finding candidates",
    humanReviewedOnly: "Confirmation and reports require human review",
    campaignRecords: "Smart campaigns",
    planningOnly: "Offline planning, no auto execution",
    campaignEyebrow: "AUTONOMOUS CAMPAIGN · RESEARCH ORCHESTRATION",
    campaignsTitle: "Keep research context and choose the next step automatically",
    campaignsDescription: "Deduplicate evidence, rank hypotheses, and enforce a total budget. The engine only creates unapproved proposals; it never contacts Kali, sends a target request, or confirms a vulnerability.",
    offlinePlanner: "Offline decision engine",
    campaignBoundaryTitle: "Automation boundary",
    campaignBoundaryText: "Plan next step processes local data only. Every generated stage proposal still requires human review, digest confirmation, and separate authorization.",
    programName: "SRC program name",
    exactHost: "Exact host",
    exactHostHelp: "Only this exact host is included; subdomains are never inferred.",
    campaignObjective: "Research objective",
    campaignObjectivePlaceholder: "Organize existing evidence and prioritize the highest-value low-impact hypothesis.",
    stageBudget: "Stage budget",
    requestBudget: "Total request budget",
    createCampaign: "Create local smart campaign",
    campaignEmptyTitle: "Create a research campaign first",
    campaignEmptyText: "Then select Plan next step. Matching offline traffic analysis is preferred; without evidence, only a two-request public baseline proposal is created.",
    hypotheses: "hypotheses",
    requestsUsed: "requests",
    downloadProposal: "Download unapproved proposal",
    recordOutcome: "Record the outcome after review",
    reviewStatement: "Human review statement",
    reviewStatementPlaceholder: "Describe the evidence, decision, and stopping point.",
    actualRequests: "Actual requests in this stage",
    keepLead: "Keep as a supported lead",
    rejectLead: "Reject this direction",
    duplicateLead: "Mark duplicate",
    exhaustLead: "Stop this direction",
    outcomeBoundary: "This only updates the hypothesis queue. It never confirms a vulnerability or creates a report.",
    campaignDecisionSaved: "Human decision recorded and the next action recalculated.",
    recentCampaigns: "Recent smart campaigns",
    noCampaigns: "No smart campaigns yet.",
    planNext: "Plan next step",
    campaignCreated: "Campaign created locally. No target request was sent.",
    campaignPlanned: "Offline planning completed. No target request was sent.",
    readyCampaignStatus: "Ready to plan",
    planningCampaignStatus: "Planning",
    awaitingAuthorizationStatus: "Needs stage authorization",
    manualReviewCampaignStatus: "Needs human review",
    completedCampaignStatus: "Completed",
    budgetExhaustedStatus: "Budget exhausted",
    stoppedCampaignStatus: "Safely stopped",
    refreshCampaignsLabel: "Refresh campaigns",
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
    analystWorkspace: "Offline analyst workspace",
    findingsTitle: "Finding candidates and lifecycle",
    findingsDescription: "Import HAR or Burp XML through the redacting CLI, then review candidates, human status, and report eligibility here. Candidates are not reportable by default.",
    analystBoundary: "Only redacted derived data appears here. The tool never replays requests, confirms vulnerabilities, or creates reportable conclusions automatically.",
    findingTitle: "Candidate title",
    endpoint: "Normalized endpoint",
    severity: "Severity hint",
    reportEligibility: "Report eligibility",
    reportable: "Report eligible",
    notReportable: "Not reportable",
    noFindings: "No finding candidates",
    noFindingsDescription: "Candidates appear here after authorized traffic is imported and analyzed offline.",
    candidateStatus: "Needs review",
    needsValidationStatus: "Needs authorized validation",
    confirmedStatus: "Human confirmed",
    falsePositiveStatus: "False positive",
    duplicateStatus: "Duplicate",
    acceptedRiskStatus: "Accepted risk",
    submittedStatus: "Submitted",
    fixedStatus: "Fixed",
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
    refreshLabel: "Refresh jobs",
    refreshFindingsLabel: "Refresh findings"
  }
};

const state = {
  language: localStorage.getItem("aegisscope-language") === "en" ? "en" : "zh-CN",
  theme: localStorage.getItem("aegisscope-theme") || "dark",
  manifest: null,
  decision: null,
  valid: false,
  activeCampaign: null,
  campaignProposal: null,
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
  findingCount: document.querySelector("#finding-count"),
  campaignCount: document.querySelector("#campaign-count"),
  campaignForm: document.querySelector("#campaign-form"),
  campaignProgram: document.querySelector("#campaign-program"),
  campaignTarget: document.querySelector("#campaign-target"),
  campaignObjective: document.querySelector("#campaign-objective"),
  campaignMaxStages: document.querySelector("#campaign-max-stages"),
  campaignMaxRequests: document.querySelector("#campaign-max-requests"),
  createCampaign: document.querySelector("#create-campaign"),
  campaignNextEmpty: document.querySelector("#campaign-next-empty"),
  campaignNextResult: document.querySelector("#campaign-next-result"),
  campaignNextKind: document.querySelector("#campaign-next-kind"),
  campaignNextTitle: document.querySelector("#campaign-next-title"),
  campaignNextExplanation: document.querySelector("#campaign-next-explanation"),
  campaignHypothesisCount: document.querySelector("#campaign-hypothesis-count"),
  campaignBudgetUsed: document.querySelector("#campaign-budget-used"),
  downloadProposal: document.querySelector("#download-proposal"),
  campaignFeedback: document.querySelector("#campaign-feedback"),
  campaignDecisionStatement: document.querySelector("#campaign-decision-statement"),
  campaignConsumedRequests: document.querySelector("#campaign-consumed-requests"),
  campaignList: document.querySelector("#campaign-list"),
  campaignListEmpty: document.querySelector("#campaign-list-empty"),
  refreshCampaigns: document.querySelector("#refresh-campaigns"),
  jobsBody: document.querySelector("#jobs-body"),
  jobsEmpty: document.querySelector("#jobs-empty"),
  refreshJobs: document.querySelector("#refresh-jobs"),
  findingsBody: document.querySelector("#findings-body"),
  findingsEmpty: document.querySelector("#findings-empty"),
  refreshFindings: document.querySelector("#refresh-findings"),
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
  document.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
    node.setAttribute("placeholder", t(node.dataset.i18nPlaceholder));
  });
  elements.themeToggle.setAttribute("aria-label", t("themeLabel"));
  elements.languageToggle.setAttribute("aria-label", t("languageLabel"));
  elements.refreshJobs.setAttribute("aria-label", t("refreshLabel"));
  elements.refreshFindings.setAttribute("aria-label", t("refreshFindingsLabel"));
  elements.refreshCampaigns.setAttribute("aria-label", t("refreshCampaignsLabel"));
  if (state.decision) {
    renderValidation(state.decision);
  }
  if (state.activeCampaign) {
    renderCampaignNext(state.activeCampaign);
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

function findingStatusName(status) {
  const names = {
    candidate: "candidateStatus",
    needs_validation: "needsValidationStatus",
    confirmed: "confirmedStatus",
    false_positive: "falsePositiveStatus",
    duplicate: "duplicateStatus",
    accepted_risk: "acceptedRiskStatus",
    submitted: "submittedStatus",
    fixed: "fixedStatus"
  };
  return names[status] ? t(names[status]) : String(status || "—");
}

function renderFindings(findings) {
  elements.findingsBody.replaceChildren();
  const safeFindings = Array.isArray(findings) ? findings : [];
  elements.findingCount.textContent = String(safeFindings.length);
  elements.findingsEmpty.classList.toggle("is-hidden", safeFindings.length > 0);

  safeFindings.forEach((finding) => {
    const row = document.createElement("tr");
    const title = finding && typeof finding.title === "object"
      ? finding.title[state.language === "zh-CN" ? "zh_cn" : "en"]
      : "—";
    row.appendChild(createCell(String(title || "—")));
    const endpointCell = createCell(String(finding.endpoint_key || "—"));
    endpointCell.className = "endpoint-cell";
    row.appendChild(endpointCell);

    const severityCell = document.createElement("td");
    const severity = document.createElement("span");
    severity.className = `severity-badge severity-${String(finding.severity_hint || "info")}`;
    severity.textContent = String(finding.severity_hint || "info");
    severityCell.appendChild(severity);
    row.appendChild(severityCell);

    const statusCell = document.createElement("td");
    const status = document.createElement("span");
    status.className = `finding-status finding-status-${String(finding.status || "candidate")}`;
    status.textContent = findingStatusName(finding.status);
    statusCell.appendChild(status);
    row.appendChild(statusCell);

    const eligibilityCell = document.createElement("td");
    const eligibility = document.createElement("span");
    eligibility.className = finding.reportable ? "eligibility is-reportable" : "eligibility";
    eligibility.textContent = t(finding.reportable ? "reportable" : "notReportable");
    eligibilityCell.appendChild(eligibility);
    row.appendChild(eligibilityCell);
    row.appendChild(createCell(formatDate(finding.updated_at)));
    elements.findingsBody.appendChild(row);
  });
}

async function loadFindings(showErrors = false) {
  try {
    const findings = await apiRequest("/api/v1/findings?limit=50");
    renderFindings(findings);
  } catch (_error) {
    elements.findingCount.textContent = "—";
    if (showErrors) {
      showToast(t("requestFailed"));
    }
  }
}

function campaignStatusName(status) {
  const names = {
    ready: "readyCampaignStatus",
    planning: "planningCampaignStatus",
    awaiting_stage_authorization: "awaitingAuthorizationStatus",
    manual_review: "manualReviewCampaignStatus",
    completed: "completedCampaignStatus",
    budget_exhausted: "budgetExhaustedStatus",
    stopped: "stoppedCampaignStatus"
  };
  return names[status] ? t(names[status]) : String(status || "—");
}

function localized(value) {
  if (!value || typeof value !== "object") {
    return "—";
  }
  return String(value[state.language === "zh-CN" ? "zh_cn" : "en"] || "—");
}

function renderCampaignNext(campaign) {
  const next = campaign && typeof campaign.next_action === "object"
    ? campaign.next_action
    : null;
  if (!next) {
    elements.campaignNextEmpty.classList.remove("is-hidden");
    elements.campaignNextResult.classList.add("is-hidden");
    return;
  }
  state.activeCampaign = campaign;
  elements.campaignNextEmpty.classList.add("is-hidden");
  elements.campaignNextResult.classList.remove("is-hidden");
  elements.campaignNextKind.textContent = String(next.kind || "NEXT").replaceAll("_", " ");
  elements.campaignNextTitle.textContent = localized(next.title);
  elements.campaignNextExplanation.textContent = localized(next.explanation);
  elements.campaignHypothesisCount.textContent = String(
    Array.isArray(campaign.hypotheses) ? campaign.hypotheses.length : 0
  );
  const budget = campaign && typeof campaign.budget === "object" ? campaign.budget : {};
  elements.campaignBudgetUsed.textContent = `${Number(budget.used_requests || 0)} / ${Number(budget.max_total_requests || 0)}`;
  const downloadable = next.kind === "authorize_stage" && Boolean(next.proposal_id);
  elements.downloadProposal.classList.toggle("is-hidden", !downloadable);
  elements.downloadProposal.disabled = !downloadable;
  const reviewable = ["authorize_stage", "manual_review"].includes(next.kind);
  elements.campaignFeedback.classList.toggle("is-hidden", !reviewable);
}

function renderCampaigns(campaigns) {
  elements.campaignList.replaceChildren();
  const safeCampaigns = Array.isArray(campaigns) ? campaigns : [];
  elements.campaignCount.textContent = String(safeCampaigns.length);
  elements.campaignListEmpty.classList.toggle("is-hidden", safeCampaigns.length > 0);

  safeCampaigns.forEach((campaign) => {
    const card = document.createElement("article");
    card.className = "campaign-row";

    const identity = document.createElement("div");
    identity.className = "campaign-identity";
    const program = document.createElement("strong");
    program.textContent = String(campaign.program_name || "—");
    const target = document.createElement("code");
    target.textContent = String(campaign.target_host || "—");
    identity.append(program, target);

    const status = document.createElement("span");
    status.className = `campaign-status campaign-status-${String(campaign.status || "ready")}`;
    status.textContent = campaignStatusName(campaign.status);

    const budget = document.createElement("div");
    budget.className = "campaign-budget";
    const budgetValue = campaign && typeof campaign.budget === "object" ? campaign.budget : {};
    budget.textContent = `${Number(budgetValue.used_requests || 0)} / ${Number(budgetValue.max_total_requests || 0)}`;

    const next = document.createElement("div");
    next.className = "campaign-next-label";
    next.textContent = localized(campaign.next_action && campaign.next_action.title);

    const actions = document.createElement("div");
    actions.className = "campaign-row-actions";
    const plan = document.createElement("button");
    plan.type = "button";
    plan.className = "button button--secondary campaign-plan-button";
    plan.dataset.campaignId = String(campaign.campaign_id || "");
    plan.textContent = t("planNext");
    actions.appendChild(plan);

    card.append(identity, status, budget, next, actions);
    elements.campaignList.appendChild(card);
  });
}

async function loadCampaigns(showErrors = false) {
  try {
    const campaigns = await apiRequest("/api/v1/campaigns?limit=50");
    renderCampaigns(campaigns);
  } catch (_error) {
    elements.campaignCount.textContent = "—";
    if (showErrors) {
      showToast(t("requestFailed"));
    }
  }
}

async function createCampaign(event) {
  event.preventDefault();
  if (!elements.campaignForm.reportValidity()) {
    return;
  }
  const target = elements.campaignTarget.value.trim().toLowerCase().replace(/\.$/, "");
  const payload = {
    program_name: elements.campaignProgram.value.trim(),
    target_host: target,
    allowlist: [target],
    denylist: [],
    objective: elements.campaignObjective.value.trim(),
    max_stages: Number(elements.campaignMaxStages.value),
    max_total_requests: Number(elements.campaignMaxRequests.value)
  };
  setBusy(elements.createCampaign, true);
  try {
    const campaign = await apiRequest("/api/v1/campaigns", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    renderCampaignNext(campaign);
    showToast(t("campaignCreated"));
    await loadCampaigns();
  } catch (error) {
    showToast(`${t("requestFailed")}: ${error.message}`);
  } finally {
    setBusy(elements.createCampaign, false);
  }
}

async function planCampaign(campaignId, button = null) {
  if (button) {
    setBusy(button, true);
  }
  try {
    const campaign = await apiRequest(`/api/v1/campaigns/${encodeURIComponent(campaignId)}/plan`, {
      method: "POST",
      body: JSON.stringify({ analysis_ids: [] })
    });
    state.campaignProposal = null;
    renderCampaignNext(campaign);
    showToast(t("campaignPlanned"));
    await loadCampaigns();
  } catch (error) {
    showToast(`${t("requestFailed")}: ${error.message}`);
  } finally {
    if (button) {
      setBusy(button, false);
    }
  }
}

async function downloadCampaignProposal() {
  if (!state.activeCampaign) {
    return;
  }
  try {
    const proposal = await apiRequest(
      `/api/v1/campaigns/${encodeURIComponent(state.activeCampaign.campaign_id)}/proposal`
    );
    state.campaignProposal = proposal;
    const blob = new Blob([JSON.stringify(proposal, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${proposal.proposal_id || "campaign-proposal"}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  } catch (error) {
    showToast(`${t("requestFailed")}: ${error.message}`);
  }
}

async function recordCampaignDecision(button) {
  const campaign = state.activeCampaign;
  const next = campaign && campaign.next_action;
  const statement = elements.campaignDecisionStatement.value.trim();
  if (!next || !next.hypothesis_id || statement.length < 8) {
    elements.campaignDecisionStatement.reportValidity();
    elements.campaignDecisionStatement.focus();
    return;
  }
  setBusy(button, true);
  try {
    const updated = await apiRequest(
      `/api/v1/campaigns/${encodeURIComponent(campaign.campaign_id)}/decisions`,
      {
        method: "POST",
        body: JSON.stringify({
          hypothesis_id: next.hypothesis_id,
          disposition: button.dataset.disposition,
          statement,
          consumed_requests: Number(elements.campaignConsumedRequests.value || 0)
        })
      }
    );
    elements.campaignDecisionStatement.value = "";
    elements.campaignConsumedRequests.value = "0";
    elements.campaignFeedback.open = false;
    renderCampaignNext(updated);
    showToast(t("campaignDecisionSaved"));
    await loadCampaigns();
  } catch (error) {
    showToast(`${t("requestFailed")}: ${error.message}`);
  } finally {
    setBusy(button, false);
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
  await Promise.all([loadSystemStatus(), loadJobs(), loadFindings(), loadCampaigns()]);
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
elements.refreshFindings.addEventListener("click", () => loadFindings(true));
elements.campaignForm.addEventListener("submit", createCampaign);
elements.refreshCampaigns.addEventListener("click", () => loadCampaigns(true));
elements.downloadProposal.addEventListener("click", downloadCampaignProposal);
document.querySelectorAll(".campaign-decision-button").forEach((button) => {
  button.addEventListener("click", () => recordCampaignDecision(button));
});
elements.campaignList.addEventListener("click", (event) => {
  const button = event.target.closest(".campaign-plan-button");
  if (!button || !button.dataset.campaignId) {
    return;
  }
  planCampaign(button.dataset.campaignId, button);
});

applyTheme();
applyLanguage();
installNavigationObserver();
loadSystemStatus();
loadJobs();
loadFindings();
loadCampaigns();
