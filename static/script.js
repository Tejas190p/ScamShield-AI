
"use strict";

// ScamShield AI — Day 48, Step 3

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

    // Use textContent instead of innerHTML for API-provided data.
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
  categoryElement.textContent = String(data.category || "General / Unknown");
  assessmentElement.textContent = String(data.assessment || "");
  aiAnalysisElement.textContent = String(
    data.ai_analysis || "AI explanation is unavailable."
  );
  recommendedActionElement.textContent = String(
    data.recommended_action || "Verify unexpected requests independently."
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