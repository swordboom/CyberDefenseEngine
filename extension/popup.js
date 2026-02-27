async function loadConfig() {
  const result = await chrome.storage.local.get(["api_base", "api_key", "demo_mode"]);
  document.getElementById("apiBase").value = result.api_base || "http://127.0.0.1:8000";
  document.getElementById("apiKey").value = result.api_key || "";
  const enabled = result.demo_mode !== false;
  document.getElementById("demoMode").checked = enabled;
  setModeUi(enabled);
}

function setModeUi(enabled) {
  document.getElementById("apiBase").disabled = enabled;
  document.getElementById("apiKey").disabled = enabled;
}

async function activeUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url || "";
}

async function scan() {
  const url = await activeUrl();
  const apiBase = document.getElementById("apiBase").value.trim();
  const apiKey = document.getElementById("apiKey").value.trim();
  const demoMode = document.getElementById("demoMode").checked;
  document.getElementById("url").innerText = url || "(No URL found)";
  await chrome.storage.local.set({
    api_base: apiBase,
    api_key: apiKey,
    demo_mode: demoMode,
  });

  chrome.runtime.sendMessage(
    {
      type: "scan_url",
      payload: {
        url,
        apiBase,
        apiKey,
        demoMode,
      },
    },
    (result) => {
      if (chrome.runtime.lastError) {
        document.getElementById("out").innerText = `Scan failed: ${chrome.runtime.lastError.message}`;
        return;
      }
      if (!result) {
        document.getElementById("out").innerText = "Scan failed: empty response";
        return;
      }
      document.getElementById("out").innerText = `Risk: ${result.risk_score}
Prediction: ${result.prediction}
Bucket: ${result.risk_bucket}
Mode: ${result.mode}
Why: ${result.summary}`;
    }
  );
}

document.getElementById("scan").addEventListener("click", scan);
document.getElementById("demoMode").addEventListener("change", (event) => {
  setModeUi(Boolean(event.target.checked));
});
loadConfig();
