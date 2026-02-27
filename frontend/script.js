const form = document.getElementById("analyze-form");
const refreshMetricsButton = document.getElementById("refresh-metrics");
const demoModeToggle = document.getElementById("demo-mode");
const apiBaseInput = document.getElementById("api-base");
const apiKeyInput = document.getElementById("api-key");

const statusNode = document.getElementById("status");
const riskScoreNode = document.getElementById("risk-score");
const predictionNode = document.getElementById("prediction");
const hashedIdNode = document.getElementById("hashed-id");
const explanationNode = document.getElementById("explanation");
const metricsNode = document.getElementById("metrics");

const DEMO_MODE_KEY = "cde_demo_mode";
const DEMO_METRICS_KEY = "cde_demo_metrics_v1";
const SUSPICIOUS_TOKENS = ["verify", "secure", "update", "password", "login", "bank", "wallet", "urgent"];

let tokenCache = {
  apiBase: "",
  apiKey: "",
  token: "",
  role: "",
};

function setStatus(text, type) {
  statusNode.textContent = text;
  statusNode.className = `status ${type}`;
}

function readForm() {
  return {
    apiBase: apiBaseInput.value.trim().replace(/\/+$/, ""),
    text: document.getElementById("message-text").value.trim(),
    url: document.getElementById("message-url").value.trim(),
    apiKey: apiKeyInput.value.trim(),
    demoMode: Boolean(demoModeToggle.checked),
  };
}

function buildHeaders(apiKey, token) {
  const headers = { "Content-Type": "application/json" };
  if (apiKey) {
    headers["X-API-Key"] = apiKey;
  }
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}

async function postJson(endpoint, apiBase, payload, headers) {
  const response = await fetch(`${apiBase}${endpoint}`, {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`${endpoint} failed (${response.status}): ${body}`);
  }
  return response.json();
}

async function getJson(endpoint, apiBase, headers) {
  const response = await fetch(`${apiBase}${endpoint}`, {
    method: "GET",
    headers,
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`${endpoint} failed (${response.status}): ${body}`);
  }
  return response.json();
}

async function ensureToken(apiBase, apiKey, role = "admin") {
  if (
    tokenCache.token &&
    tokenCache.apiBase === apiBase &&
    tokenCache.apiKey === apiKey &&
    tokenCache.role === role
  ) {
    return tokenCache.token;
  }

  const response = await fetch(`${apiBase}/auth/token`, {
    method: "POST",
    headers: buildHeaders(apiKey, ""),
    body: JSON.stringify({ role }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`/auth/token failed (${response.status}): ${body}`);
  }

  const payload = await response.json();
  tokenCache = {
    apiBase,
    apiKey,
    role,
    token: payload.access_token,
  };
  return tokenCache.token;
}

function setResult(analyzeData) {
  riskScoreNode.textContent = analyzeData.risk_score;
  predictionNode.textContent = `${analyzeData.prediction} (${analyzeData.risk_bucket})`;
  hashedIdNode.textContent = analyzeData.hashed_id;
}

function parseUrl(input) {
  try {
    return new URL(input);
  } catch (error) {
    return null;
  }
}

function toRiskBucket(score) {
  if (score >= 0.85) return "critical";
  if (score >= 0.65) return "high";
  if (score >= 0.35) return "medium";
  return "low";
}

function scoreLocalRisk(text, url) {
  const lowerUrl = url.toLowerCase();
  const lowerText = text.toLowerCase();
  let score = 0.1;
  if (lowerUrl.includes("@")) score += 0.2;
  if (lowerUrl.startsWith("http://")) score += 0.15;
  if (/\d{1,3}(?:\.\d{1,3}){3}/.test(lowerUrl)) score += 0.15;
  if (lowerUrl.length > 75) score += 0.1;
  score += SUSPICIOUS_TOKENS.filter((token) => lowerUrl.includes(token)).length * 0.07;
  score += SUSPICIOUS_TOKENS.filter((token) => lowerText.includes(token)).length * 0.06;
  return Math.min(0.98, Number(score.toFixed(4)));
}

function buildLocalExplanation(text, url, riskScore) {
  const words = (text || "")
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .split(/\s+/)
    .filter((token) => token.length >= 3)
    .slice(0, 20);
  const topTextTokens = words.slice(0, 5).map((token) => ({
    token,
    importance: Number((SUSPICIOUS_TOKENS.includes(token) ? 0.9 : 0.35).toFixed(2)),
  }));
  const normalizedUrl = url.toLowerCase();
  return {
    top_text_tokens: topTextTokens,
    url_features: {
      has_at_symbol: normalizedUrl.includes("@"),
      has_ip: /\d{1,3}(?:\.\d{1,3}){3}/.test(normalizedUrl),
      length: normalizedUrl.length,
    },
    summary:
      riskScore >= 0.5
        ? "Demo-mode heuristic detected suspicious URL/message patterns."
        : "Demo-mode heuristic found low-risk URL/message patterns.",
  };
}

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((item) => item.toString(16).padStart(2, "0"))
    .join("");
}

function readDemoMetrics() {
  try {
    const raw = localStorage.getItem(DEMO_METRICS_KEY);
    if (!raw) {
      return {
        total_requests: 0,
        avg_risk: 0,
        buckets: { low: 0, medium: 0, high: 0, critical: 0 },
      };
    }
    const parsed = JSON.parse(raw);
    return {
      total_requests: Number(parsed.total_requests || 0),
      avg_risk: Number(parsed.avg_risk || 0),
      buckets: {
        low: Number(parsed?.buckets?.low || 0),
        medium: Number(parsed?.buckets?.medium || 0),
        high: Number(parsed?.buckets?.high || 0),
        critical: Number(parsed?.buckets?.critical || 0),
      },
    };
  } catch (error) {
    return {
      total_requests: 0,
      avg_risk: 0,
      buckets: { low: 0, medium: 0, high: 0, critical: 0 },
    };
  }
}

function writeDemoMetrics(nextMetrics) {
  localStorage.setItem(DEMO_METRICS_KEY, JSON.stringify(nextMetrics));
}

function updateDemoMetrics(riskScore, riskBucket) {
  const metrics = readDemoMetrics();
  const nextTotal = metrics.total_requests + 1;
  const nextRiskSum = metrics.avg_risk * metrics.total_requests + riskScore;
  const nextMetrics = {
    total_requests: nextTotal,
    avg_risk: Number((nextRiskSum / nextTotal).toFixed(4)),
    buckets: {
      ...metrics.buckets,
      [riskBucket]: Number(metrics.buckets[riskBucket] || 0) + 1,
    },
  };
  writeDemoMetrics(nextMetrics);
  return nextMetrics;
}

function renderDemoMetrics() {
  const metrics = readDemoMetrics();
  const highRisk = metrics.buckets.high + metrics.buckets.critical;
  const highRiskRate = metrics.total_requests > 0 ? Number((highRisk / metrics.total_requests).toFixed(4)) : 0;
  metricsNode.textContent = JSON.stringify(
    {
      institution_id: "demo-local",
      total_requests: metrics.total_requests,
      avg_risk: metrics.avg_risk,
      high_risk_rate: highRiskRate,
      buckets: metrics.buckets,
      source: "local-demo",
    },
    null,
    2
  );
}

function setDemoModeUi(enabled) {
  apiBaseInput.disabled = false;
  apiKeyInput.disabled = false;
  refreshMetricsButton.textContent = enabled ? "Refresh Demo Metrics/API" : "Refresh Metrics";
  localStorage.setItem(DEMO_MODE_KEY, enabled ? "1" : "0");
  if (enabled) {
    renderDemoMetrics();
  }
}

function loadDemoMode() {
  const persisted = localStorage.getItem(DEMO_MODE_KEY);
  const enabled = persisted == null ? true : persisted === "1";
  demoModeToggle.checked = enabled;
  setDemoModeUi(enabled);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const { apiBase, text, url, apiKey, demoMode } = readForm();
  const parsedUrl = parseUrl(url);

  if (!url || !parsedUrl) {
    setStatus("A valid URL is required", "status-error");
    return;
  }

  if (!demoMode && !apiBase) {
    setStatus("API base is required when demo mode is off", "status-error");
    return;
  }

  setStatus(demoMode ? "Running demo analysis..." : "Running analysis...", "status-idle");
  explanationNode.textContent = "-";

  if (demoMode) {
    const payload = { text, url };
    try {
      if (apiBase) {
        const token = await ensureToken(apiBase, apiKey, "admin").catch(() => "");
        const headers = buildHeaders(apiKey, token);
        const [analyzeData, explainData] = await Promise.all([
          postJson("/analyze", apiBase, payload, headers),
          postJson("/explain", apiBase, payload, headers),
        ]);
        setResult(analyzeData);
        explanationNode.textContent = JSON.stringify(explainData, null, 2);
        try {
          const metricsData = await getJson("/metrics", apiBase, headers);
          metricsNode.textContent = JSON.stringify(metricsData, null, 2);
        } catch (metricsError) {
          metricsNode.textContent = `Demo API metrics unavailable: ${String(metricsError.message || metricsError)}`;
        }
        setStatus("Demo analysis complete (using API base)", "status-ok");
        return;
      }

      const startedAt = performance.now();
      const riskScore = scoreLocalRisk(text, url);
      const riskBucket = toRiskBucket(riskScore);
      const hashedId = await sha256Hex(`${text}|${url}|demo`);
      const analyzeData = {
        risk_score: riskScore,
        prediction: riskScore >= 0.5 ? "phishing" : "benign",
        risk_bucket: riskBucket,
        inference_latency_ms: Number((performance.now() - startedAt).toFixed(3)),
        model_backend: "heuristic",
        hashed_id: hashedId,
      };
      const explainData = buildLocalExplanation(text, url, riskScore);
      setResult(analyzeData);
      explanationNode.textContent = JSON.stringify(explainData, null, 2);
      updateDemoMetrics(riskScore, riskBucket);
      renderDemoMetrics();
      setStatus("Demo analysis complete (local)", "status-ok");
    } catch (error) {
      const startedAt = performance.now();
      const riskScore = scoreLocalRisk(text, url);
      const riskBucket = toRiskBucket(riskScore);
      const hashedId = await sha256Hex(`${text}|${url}|demo`);
      const analyzeData = {
        risk_score: riskScore,
        prediction: riskScore >= 0.5 ? "phishing" : "benign",
        risk_bucket: riskBucket,
        inference_latency_ms: Number((performance.now() - startedAt).toFixed(3)),
        model_backend: "heuristic",
        hashed_id: hashedId,
      };
      const explainData = buildLocalExplanation(text, url, riskScore);
      setResult(analyzeData);
      explanationNode.textContent = JSON.stringify(explainData, null, 2);
      updateDemoMetrics(riskScore, riskBucket);
      renderDemoMetrics();
      setStatus("Demo API failed, switched to local mode", "status-ok");
    }
    return;
  }

  const payload = { text, url };

  try {
    const token = await ensureToken(apiBase, apiKey, "admin").catch(() => "");
    const headers = buildHeaders(apiKey, token);
    const [analyzeData, explainData] = await Promise.all([
      postJson("/analyze", apiBase, payload, headers),
      postJson("/explain", apiBase, payload, headers),
    ]);
    setResult(analyzeData);
    explanationNode.textContent = JSON.stringify(explainData, null, 2);

    try {
      const metricsData = await getJson("/metrics", apiBase, headers);
      metricsNode.textContent = JSON.stringify(metricsData, null, 2);
    } catch (metricsError) {
      metricsNode.textContent = `Metrics unavailable: ${String(metricsError.message || metricsError)}`;
    }
    setStatus("Analysis complete", "status-ok");
  } catch (error) {
    setStatus("Request failed", "status-error");
    explanationNode.textContent = `${String(error.message || error)}\nTip: enable Demo mode for API-free local analysis.`;
  }
});

refreshMetricsButton.addEventListener("click", async () => {
  const { apiBase, apiKey, demoMode } = readForm();
  if (demoMode) {
    if (apiBase) {
      try {
        const token = await ensureToken(apiBase, apiKey, "admin").catch(() => "");
        const metricsData = await getJson("/metrics", apiBase, buildHeaders(apiKey, token));
        metricsNode.textContent = JSON.stringify(metricsData, null, 2);
        setStatus("Demo metrics updated from API", "status-ok");
        return;
      } catch (error) {
        renderDemoMetrics();
        setStatus("Demo API metrics unavailable, showing local metrics", "status-ok");
        return;
      }
    }
    renderDemoMetrics();
    setStatus("Demo metrics updated", "status-ok");
    return;
  }
  try {
    const token = await ensureToken(apiBase, apiKey, "admin").catch(() => "");
    const metricsData = await getJson("/metrics", apiBase, buildHeaders(apiKey, token));
    metricsNode.textContent = JSON.stringify(metricsData, null, 2);
    setStatus("Metrics updated", "status-ok");
  } catch (error) {
    setStatus("Metrics refresh failed", "status-error");
    metricsNode.textContent = String(error.message || error);
  }
});

demoModeToggle.addEventListener("change", () => {
  setDemoModeUi(Boolean(demoModeToggle.checked));
});

loadDemoMode();
