
"use strict";

// ScamShield AI — Analyzer + Scan History + Analytics Dashboard

// ============================================
// MESSAGE ANALYZER
// ============================================

const messageInput = document.getElementById("message");
const analyzeButton = document.getElementById("analyze-btn");
const buttonText = document.getElementById("button-text");
const clearButton = document.getElementById("clear-btn");
const charCount = document.getElementById("char-count");
const errorMessage = document.getElementById("error-message");
const resultsSection = document.getElementById("results");

const riskLevelElement = document.getElementById("risk-level");
const riskScoreElement = document.getElementById("risk-score");
const categoryElement = document.getElementById("category");
const assessmentElement = document.getElementById("assessment");
const indicatorsElement = document.getElementById("indicators");
const aiAnalysisElement = document.getElementById("ai-analysis");
const recommendedActionElement = document.getElementById(
  "recommended-action"
);

// ============================================
// CHARACTER COUNT AND CLEAR
// ============================================

messageInput.addEventListener("input", () => {
  charCount.textContent = `${messageInput.value.length} / 10000`;
});

clearButton.addEventListener("click", () => {
  messageInput.value = "";
  charCount.textContent = "0 / 10000";
  errorMessage.hidden = true;
  resultsSection.hidden = true;
  messageInput.focus();
});

messageInput.addEventListener("keydown", (event) => {
  if (
    event.key === "Enter" &&
    (event.ctrlKey || event.metaKey) &&
    !analyzeButton.disabled
  ) {
    analyzeMessage();
  }
});

analyzeButton.addEventListener("click", analyzeMessage);

// ============================================
// ANALYZER HELPERS
// ============================================

function showError(message) {
  errorMessage.textContent = message;
  errorMessage.hidden = false;
}

function setLoading(isLoading) {
  analyzeButton.disabled = isLoading;
  messageInput.disabled = isLoading;
  clearButton.disabled = isLoading;

  buttonText.textContent = isLoading
    ? "Analyzing message..."
    : "Analyze message →";
}

function getRiskClass(level) {
  const normalized = String(level || "").toUpperCase();

  if (normalized === "HIGH") return "risk-high";
  if (normalized === "MEDIUM") return "risk-medium";
  if (normalized === "LOW") return "risk-low";

  return "risk-safe";
}

function renderIndicators(indicators) {
  indicatorsElement.replaceChildren();

  if (!Array.isArray(indicators) || indicators.length === 0) {
    const item = document.createElement("li");
    item.className = "no-indicators";
    item.textContent = "No specific warning indicators were returned.";
    indicatorsElement.appendChild(item);
    return;
  }

  for (const indicator of indicators) {
    const item = document.createElement("li");
    const reason = String(indicator.reason || "Unspecified indicator");
    const points = Number(indicator.points);

    item.textContent = Number.isFinite(points)
      ? `${reason} (+${points} points)`
      : reason;

    indicatorsElement.appendChild(item);
  }
}

function renderResults(data) {
  if (
    !data ||
    typeof data.final_risk_level !== "string" ||
    !Number.isFinite(Number(data.risk_score))
  ) {
    throw new Error("The API returned an unexpected response format.");
  }

  riskLevelElement.textContent = data.final_risk_level;
  riskScoreElement.textContent = String(data.risk_score);
  categoryElement.textContent = String(
    data.category || "General / Unknown"
  );
  assessmentElement.textContent = String(data.assessment || "");
  aiAnalysisElement.textContent = String(
    data.ai_analysis || "AI explanation is unavailable."
  );
  recommendedActionElement.textContent = String(
    data.recommended_action ||
      "Verify unexpected requests independently."
  );

  renderIndicators(data.warning_indicators);

  const riskPanel = document.querySelector(".risk-panel");

  riskPanel.classList.remove(
    "risk-high",
    "risk-medium",
    "risk-low",
    "risk-safe"
  );

  riskPanel.classList.add(getRiskClass(data.final_risk_level));

  resultsSection.hidden = false;

  resultsSection.scrollIntoView({
    behavior: "smooth",
    block: "start"
  });
}

// ============================================
// ANALYZE MESSAGE API REQUEST
// ============================================

async function analyzeMessage() {
  const message = messageInput.value.trim();

  errorMessage.hidden = true;

  if (!message) {
    showError("Please paste a message before starting the analysis.");
    messageInput.focus();
    return;
  }

  if (message.length > 10000) {
    showError("The message must be 10,000 characters or fewer.");
    return;
  }

  setLoading(true);

  try {
    const response = await fetch("/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ message })
    });

    let data;

    try {
      data = await response.json();
    } catch {
      throw new Error("The server returned an unreadable response.");
    }

    if (!response.ok) {
      const detail = typeof data.detail === "string"
        ? data.detail
        : `Request failed with HTTP ${response.status}.`;

      throw new Error(detail);
    }

    renderResults(data);

    // Refresh history and analytics after a successful scan.
    window.setTimeout(() => {
      loadScanHistory({ quiet: true });
      loadAnalytics({ quiet: true });
    }, 300);
  } catch (error) {
    console.error("ScamShield analysis error:", error);

    showError(
      error instanceof TypeError
        ? "Cannot connect to ScamShield. Check that the backend is running and try again."
        : error.message || "Analysis failed. Please try again."
    );
  } finally {
    setLoading(false);
  }
}

// ============================================
// DAY 49 — SCAN HISTORY DASHBOARD
// ============================================

const historyList = document.getElementById("history-list");
const historySearch = document.getElementById("history-search");
const historyFilter = document.getElementById("history-filter");
const historyRefresh = document.getElementById("history-refresh");
const historyCount = document.getElementById("history-count");
const historyError = document.getElementById("history-error");
const historyEmpty = document.getElementById("history-empty");

const historyDetail = document.getElementById("history-detail");
const historyClose = document.getElementById("history-close");

const detailRisk = document.getElementById("detail-risk");
const detailScore = document.getElementById("detail-score");
const detailDate = document.getElementById("detail-date");
const detailMessage = document.getElementById("detail-message");

let savedScans = [];

function makeElement(tag, className, text) {
  const element = document.createElement(tag);

  if (className) {
    element.className = className;
  }

  if (text !== undefined) {
    element.textContent = String(text);
  }

  return element;
}

function formatScanDate(value) {
  if (!value) return "Date unavailable";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "Date unavailable";
  }

  return date.toLocaleString();
}

function renderHistoryError(message) {
  historyError.textContent = message;
  historyError.hidden = false;
}

function showSavedScan(scan) {
  detailRisk.textContent = scan.risk_level || "Unknown";
  detailScore.textContent = String(scan.risk_score ?? "—");
  detailDate.textContent = formatScanDate(scan.scanned_at);
  detailMessage.textContent = scan.message || "(No saved message)";

  historyDetail.hidden = false;

  historyDetail.scrollIntoView({
    behavior: "smooth",
    block: "nearest"
  });
}

function renderScanHistory() {
  if (!historyList) return;

  const query = historySearch.value.trim().toLowerCase();
  const selectedRisk = historyFilter.value;

  const filteredScans = savedScans.filter((scan) => {
    const message = String(scan.message || "").toLowerCase();
    const risk = String(scan.risk_level || "").toUpperCase();

    const matchesSearch = message.includes(query);
    const matchesRisk =
      selectedRisk === "ALL" || risk === selectedRisk;

    return matchesSearch && matchesRisk;
  });

  historyList.replaceChildren();

  historyCount.textContent =
    `${filteredScans.length} of ${savedScans.length} saved scans`;

  historyEmpty.hidden = filteredScans.length !== 0;

  for (const scan of filteredScans) {
    const item = document.createElement("button");
    item.type = "button";
    item.className = "history-item";

    item.setAttribute(
      "aria-label",
      `View saved scan: ${scan.risk_level || "unknown risk"}`
    );

    const main = makeElement("span", "history-item-main");

    const fullMessage = String(
      scan.message || "(No saved message)"
    );

    const preview = fullMessage.length > 115
      ? `${fullMessage.slice(0, 115)}…`
      : fullMessage;

    const messageElement = makeElement(
      "span",
      "history-item-message",
      preview
    );

    const dateElement = makeElement(
      "span",
      "history-item-date",
      formatScanDate(scan.scanned_at)
    );

    main.append(messageElement, dateElement);

    const meta = makeElement("span", "history-item-meta");

    const riskElement = makeElement(
      "span",
      "history-risk",
      scan.risk_level || "UNKNOWN"
    );

    riskElement.classList.add(getRiskClass(scan.risk_level));

    const scoreElement = makeElement(
      "span",
      "history-score",
      `Score: ${scan.risk_score ?? "—"}`
    );

    meta.append(riskElement, scoreElement);
    item.append(main, meta);

    item.addEventListener("click", () => {
      showSavedScan(scan);
    });

    historyList.appendChild(item);
  }
}

async function loadScanHistory(options = {}) {
  if (!historyList) return;

  const quiet = options.quiet === true;

  if (historyRefresh) historyRefresh.disabled = true;

  if (!quiet) {
    historyError.hidden = true;
    historyCount.textContent = "Loading history...";
  }

  try {
    const response = await fetch("/history?limit=100", {
      headers: {
        Accept: "application/json"
      }
    });

    if (!response.ok) {
      throw new Error(
        `History request failed (HTTP ${response.status}).`
      );
    }

    const data = await response.json();

    if (!Array.isArray(data.scans)) {
      throw new Error("The history API returned an unexpected response.");
    }

    savedScans = data.scans;

    historyError.hidden = true;
    renderScanHistory();
  } catch (error) {
    console.error("ScamShield history error:", error);

    if (!quiet) {
      historyCount.textContent = "Unable to load scan history.";

      renderHistoryError(
        `${error.message} Check that the backend is running.`
      );

      historyEmpty.hidden = true;
    }
  } finally {
    if (historyRefresh) historyRefresh.disabled = false;
  }
}

// Search and risk-level filtering.
if (historySearch && historyFilter && historyRefresh) {
  historySearch.addEventListener("input", renderScanHistory);
  historyFilter.addEventListener("change", renderScanHistory);

  historyRefresh.addEventListener("click", () => {
    loadScanHistory();
  });
}

// Close saved scan details.
if (historyClose && historyDetail) {
  historyClose.addEventListener("click", () => {
    historyDetail.hidden = true;
  });
}

// ============================================
// DAY 50 — SCAN ANALYTICS DASHBOARD
// ============================================

const statsRefresh = document.getElementById("stats-refresh");
const statsError = document.getElementById("stats-error");

const statTotal = document.getElementById("stat-total");
const statHigh = document.getElementById("stat-high");
const statMedium = document.getElementById("stat-medium");
const statLow = document.getElementById("stat-low");

const riskDistribution = document.getElementById("risk-distribution");
const activityChart = document.getElementById("activity-chart");

const RISK_LEVELS = [
  {
    key: "HIGH",
    label: "High risk",
    className: "risk-high"
  },
  {
    key: "MEDIUM",
    label: "Medium risk",
    className: "risk-medium"
  },
  {
    key: "LOW",
    label: "Low risk",
    className: "risk-low"
  },
  {
    key: "NO OBVIOUS INDICATORS",
    label: "No obvious indicators",
    className: "risk-safe"
  }
];

function showStatsError(message) {
  if (!statsError) return;

  statsError.textContent = message;
  statsError.hidden = false;
}

function clearStatsError() {
  if (statsError) {
    statsError.textContent = "";
    statsError.hidden = true;
  }
}

function formatNumber(value) {
  const number = Number(value);

  return Number.isFinite(number) && number >= 0
    ? number.toLocaleString()
    : "0";
}

function renderRiskDistribution(distribution, total) {
  if (!riskDistribution) return;

  riskDistribution.replaceChildren();

  const normalized = {};

  for (const level of RISK_LEVELS) {
    const count = Number(distribution?.[level.key] ?? 0);

    normalized[level.key] =
      Number.isFinite(count) && count >= 0 ? count : 0;
  }

  const unknownCount = Object.entries(distribution || {})
    .filter(([key]) => !RISK_LEVELS.some((level) => level.key === key))
    .reduce((sum, [, value]) => {
      const count = Number(value);
      return sum + (Number.isFinite(count) && count > 0 ? count : 0);
    }, 0);

  const allLevels = [...RISK_LEVELS];

  if (unknownCount > 0) {
    allLevels.push({
      key: "OTHER",
      label: "Other risk levels",
      className: ""
    });
    normalized.OTHER = unknownCount;
  }

  const chartTotal = allLevels.reduce(
    (sum, level) => sum + normalized[level.key],
    0
  );

  if (chartTotal === 0 || total === 0) {
    riskDistribution.appendChild(
      makeElement("p", "muted", "No scan data is available yet.")
    );
    return;
  }

  for (const level of allLevels) {
    const count = normalized[level.key];
    const percentage = (count / chartTotal) * 100;

    const row = makeElement("div", "distribution-row");
    const heading = makeElement("div", "distribution-heading");

    const label = makeElement("span", "distribution-label", level.label);
    const value = makeElement(
      "span",
      "distribution-value",
      `${formatNumber(count)} · ${percentage.toFixed(1)}%`
    );

    heading.append(label, value);

    const track = makeElement("div", "distribution-track");
    track.setAttribute("role", "img");
    track.setAttribute(
      "aria-label",
      `${level.label}: ${count} scans, ${percentage.toFixed(1)} percent`
    );

    const fill = makeElement("div", "distribution-fill");

    if (level.className) {
      fill.classList.add(level.className);
    } else {
      fill.classList.add("risk-other");
    }

    fill.style.width = `${percentage}%`;
    track.appendChild(fill);

    row.append(heading, track);
    riskDistribution.appendChild(row);
  }
}

function getLastSevenDays(activity) {
  const counts = new Map();

  for (const item of Array.isArray(activity) ? activity : []) {
    if (!item || typeof item.date !== "string") continue;

    const count = Number(item.count);

    if (Number.isFinite(count) && count >= 0) {
      counts.set(item.date, (counts.get(item.date) || 0) + count);
    }
  }

  const days = [];
  const today = new Date();

  // Use UTC date keys to match the API's SQLite date() output.
  const todayKey = [
    today.getFullYear(),
    String(today.getMonth() + 1).padStart(2, "0"),
    String(today.getDate()).padStart(2, "0")
  ].join("-");

  // Build calendar dates using local calendar components.
  const base = new Date(
    today.getFullYear(),
    today.getMonth(),
    today.getDate(),
    12
  );

  for (let offset = 6; offset >= 0; offset--) {
    const date = new Date(base);
    date.setDate(base.getDate() - offset);

    const key = [
      date.getFullYear(),
      String(date.getMonth() + 1).padStart(2, "0"),
      String(date.getDate()).padStart(2, "0")
    ].join("-");

    days.push({
      date: key,
      label: date.toLocaleDateString(undefined, {
        month: "short",
        day: "numeric"
      }),
      count: counts.get(key) || 0
    });
  }

  return { days, todayKey };
}

function renderActivityChart(activity) {
  if (!activityChart) return;

  activityChart.replaceChildren();

  const { days } = getLastSevenDays(activity);
  const maxCount = Math.max(1, ...days.map((day) => day.count));

  const chart = makeElement("div", "activity-bars");
  chart.setAttribute("role", "group");
  chart.setAttribute("aria-label", "Scans per day for the last seven days");

  for (const day of days) {
    const column = makeElement("div", "activity-column");

    const count = makeElement(
      "span",
      "activity-count",
      formatNumber(day.count)
    );

    const track = makeElement("div", "activity-bar-track");
    const bar = makeElement("div", "activity-bar");

    const height = day.count === 0
      ? 0
      : Math.max(5, (day.count / maxCount) * 100);

    bar.style.height = `${height}%`;

    track.setAttribute(
      "aria-label",
      `${day.label}: ${day.count} scans`
    );

    track.appendChild(bar);

    const label = makeElement("span", "activity-label", day.label);

    column.append(count, track, label);
    chart.appendChild(column);
  }

  activityChart.appendChild(chart);

  const totalRecent = days.reduce((sum, day) => sum + day.count, 0);

  activityChart.appendChild(
    makeElement(
      "p",
      "activity-summary",
      `${formatNumber(totalRecent)} scans recorded across the displayed seven-day period.`
    )
  );
}

async function loadAnalytics(options = {}) {
  if (!statTotal || !riskDistribution || !activityChart) return;

  const quiet = options.quiet === true;

  if (statsRefresh) statsRefresh.disabled = true;

  if (!quiet) {
    clearStatsError();
  }

  try {
    const response = await fetch("/stats", {
      headers: {
        Accept: "application/json"
      }
    });

    if (!response.ok) {
      throw new Error(
        `Analytics request failed (HTTP ${response.status}).`
      );
    }

    const data = await response.json();

    if (
      !data ||
      !Number.isFinite(Number(data.total_scans)) ||
      !data.risk_distribution ||
      typeof data.risk_distribution !== "object" ||
      Array.isArray(data.risk_distribution) ||
      !Array.isArray(data.recent_activity)
    ) {
      throw new Error("The analytics API returned an unexpected response.");
    }

    const total = Math.max(0, Number(data.total_scans));
    const high = Math.max(0, Number(data.risk_distribution.HIGH || 0));
    const medium = Math.max(0, Number(data.risk_distribution.MEDIUM || 0));
    const low = Math.max(0, Number(data.risk_distribution.LOW || 0));

    statTotal.textContent = formatNumber(total);
    statHigh.textContent = formatNumber(high);
    statMedium.textContent = formatNumber(medium);
    statLow.textContent = formatNumber(low);

    renderRiskDistribution(data.risk_distribution, total);
    renderActivityChart(data.recent_activity);

    clearStatsError();
  } catch (error) {
    console.error("ScamShield analytics error:", error);

    if (!quiet) {
      showStatsError(
        `${error.message || "Could not load analytics."} Check that the backend is running.`
      );
    }
  } finally {
    if (statsRefresh) statsRefresh.disabled = false;
  }
}

// Refresh analytics when requested.
if (statsRefresh) {
  statsRefresh.addEventListener("click", () => {
    loadAnalytics();
  });
}

// Load both dashboards when the page opens.
if (historyList) {
  loadScanHistory();
}

if (statTotal) {
  loadAnalytics();
}