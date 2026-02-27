async function activeUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url || "";
}

async function scan() {
  const url = await activeUrl();
  const apiBase = document.getElementById("apiBase").value.trim();
  const apiKey = document.getElementById("apiKey").value.trim();
  document.getElementById("url").innerText = url || "(No URL found)";

  chrome.runtime.sendMessage(
    {
      type: "scan_url",
      payload: {
        url,
        apiBase,
        apiKey,
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
