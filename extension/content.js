(() => {
  if (location.host === "127.0.0.1:5000") return;   // never scan the PhishNet dashboard itself
  let lastSig = "";

  function esc(s) {
    return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function scanPage() {
    const links = [...document.querySelectorAll("a[href]")].map(a => a.href).filter(h => h.startsWith("http")).slice(0, 40);
    const text = (document.body ? document.body.innerText : "").slice(0, 6000);
    const sig = location.href + links.length + text.length;
    if (sig === lastSig) return;
    lastSig = sig;

    chrome.runtime.sendMessage({ url: location.href, text, links }, res => {
      if (chrome.runtime.lastError || !res || res.error) return;
      document.querySelectorAll("a[href]").forEach(a => {
        if ((res.flagged_links || []).includes(a.href)) {
          a.style.outline = "3px solid #ff4d5e";
          a.title = "PhishNet: dangerous link";
        }
      });
      if (res.level === "High") showBlock(res);
    });
  }

  function showBlock(res) {
    if (document.getElementById("phishnet-block")) return;
    const d = document.createElement("div");
    d.id = "phishnet-block";
    d.style.cssText = "position:fixed;inset:0;background:#2a0910;color:#fff;z-index:2147483647;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:Segoe UI,Arial,sans-serif;text-align:center;padding:30px";
    d.innerHTML =
      '<h1 style="font-size:34px;margin:0 0 8px">PhishNet blocked this page</h1>' +
      '<h2 style="margin:0 0 16px;color:#ff4d5e">High risk (' + esc(res.score) + '/100)</h2>' +
      '<p style="max-width:560px;line-height:1.6">' + (res.reasons || []).map(esc).join("<br>") + "</p>" +
      '<button id="pn-leave" style="padding:12px 28px;font-size:16px;margin:18px;background:#37d6ff;border:0;font-weight:700;cursor:pointer">Leave this site</button>' +
      '<a id="pn-go" href="#" style="color:#ff9aa5;font-size:13px">I understand the risk, continue</a>';
    document.documentElement.appendChild(d);
    d.querySelector("#pn-leave").onclick = () => (location.href = "about:blank");
    d.querySelector("#pn-go").onclick = e => { e.preventDefault(); d.remove(); };
  }

  setTimeout(scanPage, 1200);
  setInterval(scanPage, 30000);   // re-scan when the page content changes
})();
