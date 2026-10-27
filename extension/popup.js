const k = document.getElementById("k"), s = document.getElementById("s");
chrome.storage.local.get("key").then(({ key }) => { if (key) { k.value = key; s.textContent = "Protection is on."; } });
document.getElementById("save").onclick = () => {
  chrome.storage.local.set({ key: k.value.trim() }).then(() => (s.textContent = "Saved. Protection is on."));
};
