
"use strict";

// ScamShield AI — : Analyzer + Scan History Dashboard

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

const originalButtonText = buttonText.innerHTML;

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

    // Refresh history after a successful scan.
    // A short delay allows the backend request to finish saving.
    window.setTimeout(() => {
      loadScanHistory({ quiet: true });
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

    riskElement.classList.add(
      getRiskClass(scan.risk_level)
    );

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

  historyRefresh.disabled = true;

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
    historyRefresh.disabled = false;
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

// Load history when the page opens.
if (historyList) {
  loadScanHistory();
}
