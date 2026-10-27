const API = "http://127.0.0.1:5000/api/ext_scan";

chrome.runtime.onMessage.addListener((msg, _sender, send) => {
  chrome.storage.local.get("key").then(({ key }) => {
    if (!key) { send({ error: "nokey" }); return; }
    fetch(API, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": key },
      body: JSON.stringify(msg)
    })
      .then(r => r.json())
      .then(send)
      .catch(() => send({ error: true }));
  });
  return true;
});
