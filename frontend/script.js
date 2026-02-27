const form = document.getElementById("analyze-form");
const refreshMetricsButton = document.getElementById("refresh-metrics");

const statusNode = document.getElementById("status");
const riskScoreNode = document.getElementById("risk-score");
const predictionNode = document.getElementById("prediction");
const hashedIdNode = document.getElementById("hashed-id");
const explanationNode = document.getElementById("explanation");
const metricsNode = document.getElementById("metrics");

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
    apiBase: document.getElementById("api-base").value.trim().replace(/\/+$/, ""),
    text: document.getElementById("message-text").value.trim(),
    url: document.getElementById("message-url").value.trim(),
    apiKey: document.getElementById("api-key").value.trim(),
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
  if (!apiKey) {
    return "";
  }
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
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": apiKey,
    },
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

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const { apiBase, text, url, apiKey } = readForm();

  if (!url || !apiBase) {
    setStatus("API base and URL are required", "status-error");
    return;
  }

  const payload = { text, url };
  setStatus("Running analysis...", "status-idle");
  explanationNode.textContent = "-";

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
    explanationNode.textContent = String(error.message || error);
  }
});

refreshMetricsButton.addEventListener("click", async () => {
  const { apiBase, apiKey } = readForm();
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
