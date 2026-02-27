const BLACKLIST_KEY = "domain_blacklist_cache";
const BLACKLIST_UPDATED_AT_KEY = "domain_blacklist_updated_at";
const SYNC_ALARM = "sync_blacklist_alarm";
const SYNC_INTERVAL_MINUTES = 60;

const SUSPICIOUS_TOKENS = [
  "verify",
  "secure",
  "update",
  "password",
  "login",
  "bank",
  "wallet",
  "urgent",
];

function parseHostname(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (error) {
    return "";
  }
}

function localHeuristic(url) {
  const lower = (url || "").toLowerCase();
  let score = 0.1;
  if (lower.includes("@")) score += 0.2;
  if (lower.startsWith("http://")) score += 0.15;
  if (/\d{1,3}(?:\.\d{1,3}){3}/.test(lower)) score += 0.15;
  score += SUSPICIOUS_TOKENS.filter((token) => lower.includes(token)).length * 0.07;
  if (lower.length > 75) score += 0.1;
  score = Math.min(0.98, score);
  return {
    risk_score: Number(score.toFixed(4)),
    prediction: score >= 0.5 ? "phishing" : "benign",
    risk_bucket: score >= 0.85 ? "critical" : score >= 0.65 ? "high" : score >= 0.35 ? "medium" : "low",
    summary: "Local heuristic fallback was used because backend was unavailable.",
    mode: "heuristic-fallback",
  };
}

async function getCachedBlacklist() {
  const result = await chrome.storage.local.get([BLACKLIST_KEY]);
  const domains = result[BLACKLIST_KEY];
  if (!Array.isArray(domains)) return [];
  return domains.map((item) => String(item).toLowerCase());
}

async function setCachedBlacklist(domains) {
  await chrome.storage.local.set({
    [BLACKLIST_KEY]: domains,
    [BLACKLIST_UPDATED_AT_KEY]: new Date().toISOString(),
  });
}

async function syncBlacklist(apiBase, apiKey) {
  if (!apiBase) return;
  const headers = {};
  if (apiKey) {
    headers["X-API-Key"] = apiKey;
  }
  try {
    const response = await fetch(`${apiBase.replace(/\/+$/, "")}/blacklist`, {
      method: "GET",
      headers,
    });
    if (!response.ok) return;
    const payload = await response.json();
    if (Array.isArray(payload.domains)) {
      await setCachedBlacklist(payload.domains.map((item) => String(item).toLowerCase()));
    }
  } catch (error) {
    // Silent failure: fallback keeps extension available.
  }
}

async function analyzeWithBackend({ url, apiBase, apiKey }) {
  const base = (apiBase || "http://127.0.0.1:8000").replace(/\/+$/, "");
  const headers = { "Content-Type": "application/json" };
  if (apiKey) {
    headers["X-API-Key"] = apiKey;
  }
  const response = await fetch(`${base}/analyze`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      text: "",
      url,
    }),
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Analyze failed (${response.status}): ${body}`);
  }
  const payload = await response.json();
  return {
    risk_score: payload.risk_score,
    prediction: payload.prediction,
    risk_bucket: payload.risk_bucket,
    summary: "Scored by CyberSaarthi backend.",
    mode: "backend",
  };
}

async function scanUrl(payload) {
  const { url, apiBase, apiKey } = payload;
  const hostname = parseHostname(url);
  if (!hostname) {
    return {
      risk_score: 0,
      prediction: "benign",
      risk_bucket: "low",
      summary: "No valid web URL found in active tab.",
      mode: "local",
    };
  }

  await chrome.storage.local.set({
    api_base: apiBase,
    api_key: apiKey,
  });
  await syncBlacklist(apiBase, apiKey);

  const blacklist = await getCachedBlacklist();
  if (blacklist.includes(hostname)) {
    return {
      risk_score: 0.99,
      prediction: "phishing",
      risk_bucket: "critical",
      summary: "Domain is present in locally cached blacklist.",
      mode: "blacklist-cache",
    };
  }

  try {
    return await analyzeWithBackend({ url, apiBase, apiKey });
  } catch (error) {
    return localHeuristic(url);
  }
}

chrome.runtime.onInstalled.addListener(async () => {
  chrome.alarms.create(SYNC_ALARM, { periodInMinutes: SYNC_INTERVAL_MINUTES });
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== SYNC_ALARM) return;
  const config = await chrome.storage.local.get(["api_base", "api_key"]);
  const apiBase = config.api_base || "http://127.0.0.1:8000";
  const apiKey = config.api_key || "";
  await syncBlacklist(apiBase, apiKey);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "scan_url") return false;
  scanUrl(message.payload || {})
    .then((result) => sendResponse(result))
    .catch((error) =>
      sendResponse({
        risk_score: 0.5,
        prediction: "benign",
        risk_bucket: "medium",
        mode: "error",
        summary: `Scan failed: ${String(error.message || error)}`,
      })
    );
  return true;
});
