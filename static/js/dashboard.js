(() => {
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
const dpr = devicePixelRatio || 1;
const RISKY = { 21: 'FTP', 23: 'Telnet', 135: 'RPC', 139: 'NetBIOS', 445: 'SMB', 3389: 'RDP', 5900: 'VNC' };
const TITLES = { overview: 'Overview', live: 'Live protection', scanner: 'Scanner', firewall: 'Firewall', network: 'Network', history: 'History', extension: 'Browser protection' };
let S = null, kind = 'url', wasScanning = false;

async function api(u, d) {
  try {
    const r = await fetch(u, { method: d ? 'POST' : 'GET', headers: { 'Content-Type': 'application/json' }, body: d ? JSON.stringify(d) : undefined });
    if (r.status === 401) { location.href = '/login'; return {}; }
    return await r.json();
  } catch (e) { return { error: 'Cannot reach the PhishNet server.' }; }
}

/* ---------- icons ---------- */
const P = {
  logo: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
  overview: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/>',
  scanner: '<circle cx="11" cy="11" r="6"/><path d="M16 16l5 5"/>',
  firewall: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>',
  network: '<circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v5M12 12l-6 5M12 12l6 5"/>',
  history: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
  live: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M8 12h2l1.5-3 2 6L15 12h1"/>',
  extension: '<rect x="5" y="5" width="14" height="14" rx="2"/><path d="M9 5V2M15 5V2M9 22v-3M15 22v-3M2 9h3M2 15h3M22 9h-3M22 15h-3"/>'
};
$$('[data-i]').forEach(e => {
  e.innerHTML = `<svg viewBox="0 0 24 24" width="${e.dataset.i === 'logo' ? 34 : 22}" height="${e.dataset.i === 'logo' ? 34 : 22}" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${P[e.dataset.i]}</svg>`;
  e.style.display = 'inline-flex';
});

/* ---------- navigation ---------- */
function show(v) {
  if (!TITLES[v]) v = 'overview';
  $$('.view').forEach(e => e.classList.toggle('on', e.id === 'v-' + v));
  $$('.nav button').forEach(b => b.classList.toggle('on', b.dataset.view === v));
  const h = $('#title'); h.textContent = TITLES[v]; h.classList.remove('in'); void h.offsetWidth; h.classList.add('in');
  history.replaceState(null, '', '#' + v);
  if (v === 'overview') setTimeout(() => { sizeRadar(); if (S) trend(); }, 0);
}
$$('.nav button').forEach(b => b.onclick = () => show(b.dataset.view));

/* ---------- toasts, popups ---------- */
function toast(title, msg, type) {
  const t = document.createElement('div');
  t.className = 'toast ' + (type || '');
  t.innerHTML = `<b>${esc(title)}</b><p>${esc(msg)}</p><span class="bar"></span>`;
  t.onclick = () => t.remove();
  $('#toasts').appendChild(t);
  setTimeout(() => t.remove(), (type === 'info' || type === 'ok') ? 5000 : 12000);
}
function flash() {
  const f = document.createElement('div');
  f.className = 'flash';
  document.body.appendChild(f);
  setTimeout(() => f.remove(), 1400);
}
function notify(m) {
  if ('Notification' in window && Notification.permission === 'granted') new Notification('PhishNet alert', { body: m });
}
document.addEventListener('click', () => {
  if ('Notification' in window && Notification.permission === 'default') Notification.requestPermission();
}, { once: true });

async function poll() {
  const a = await api('/api/alerts');
  (a.alerts || []).forEach(x => {
    if (a.mail_ok === false) toast('Alert (email NOT sent)', x.message + '\n\n' + (a.mail_msg || ''));
    else toast('Alert emailed to you', x.message + '\n\nEmailed to ' + a.email);
    notify(x.message);
    flash();
  });
}

/* ---------- helpers ---------- */
function countTo(el, v) {
  const f = +el.dataset.v || 0;
  el.dataset.v = v;
  if (reduce || f === v) { el.textContent = v; return; }
  const t0 = performance.now();
  (function step(t) {
    const p = Math.min(1, (t - t0) / 700);
    el.textContent = Math.round(f + (v - f) * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(step);
  })(t0);
}
const badge = (lvl, sc) => `<span class="badge ${lvl}">${lvl} ${sc}</span>`;
const hostsOf = () => (S.hosts || []).map(h => ({ host: h.host, ports: JSON.parse(h.ports || '[]') }));

/* ---------- radar ---------- */
const rc = $('#radar'), rx = rc.getContext('2d');
let RW = 0, ang = 0, lastT = 0, blips = [];
function sizeRadar() {
  const s = rc.clientWidth;
  if (!s) return;
  rc.width = rc.height = Math.round(s * dpr);
  RW = rc.width;
  if (reduce) drawRadar(0);
}
function pos(ip) {
  const p = ip.split('.').map(Number);
  return { a: ((p[3] * 47 + p[2] * 13) % 360) * Math.PI / 180, r: 0.22 + ((p[3] * 37) % 70) / 100 };
}
function drawRadar(t) {
  if (!RW || !$('#v-overview').classList.contains('on')) return;
  const w = RW, c = w / 2, R = c - 12 * dpr;
  rx.clearRect(0, 0, w, w);
  rx.lineWidth = dpr;
  for (let i = 1; i <= 4; i++) {
    rx.strokeStyle = `rgba(55,214,255,${i === 4 ? 0.5 : 0.18})`;
    rx.beginPath(); rx.arc(c, c, R * i / 4, 0, 7); rx.stroke();
  }
  rx.strokeStyle = 'rgba(55,214,255,.14)';
  for (let k = 0; k < 4; k++) {
    const a = k * Math.PI / 4;
    rx.beginPath(); rx.moveTo(c - R * Math.cos(a), c - R * Math.sin(a)); rx.lineTo(c + R * Math.cos(a), c + R * Math.sin(a)); rx.stroke();
  }
  if (rx.createConicGradient) {
    const g = rx.createConicGradient(ang, c, c);
    g.addColorStop(0, 'rgba(55,214,255,0)');
    g.addColorStop(0.78, 'rgba(55,214,255,0)');
    g.addColorStop(1, 'rgba(55,214,255,.42)');
    rx.fillStyle = g;
    rx.beginPath(); rx.arc(c, c, R, 0, 7); rx.fill();
  }
  rx.strokeStyle = '#37D6FF'; rx.lineWidth = 2 * dpr;
  rx.beginPath(); rx.moveTo(c, c); rx.lineTo(c + R * Math.cos(ang), c + R * Math.sin(ang)); rx.stroke();

  blips.forEach(b => {
    const diff = (((ang - b.a) % (2 * Math.PI)) + 2 * Math.PI) % (2 * Math.PI);
    const glow = reduce ? 1 : Math.max(0, 1 - diff / (Math.PI * 1.4));
    const x = c + R * b.r * Math.cos(b.a), y = c + R * b.r * Math.sin(b.a);
    const col = b.risky ? '255,77,94' : '76,240,164';
    rx.fillStyle = `rgba(${col},${0.35 + 0.65 * glow})`;
    rx.beginPath(); rx.arc(x, y, (5 + 4 * glow) * dpr, 0, 7); rx.fill();
    if (glow > 0.1) {
      rx.strokeStyle = `rgba(${col},${glow * 0.7})`; rx.lineWidth = dpr;
      rx.beginPath(); rx.arc(x, y, (8 + 10 * (1 - glow)) * dpr, 0, 7); rx.stroke();
    }
    if (glow > 0.45) {
      rx.fillStyle = `rgba(220,235,250,${glow})`;
      rx.font = `${12 * dpr}px JetBrains Mono, Consolas, monospace`;
      rx.fillText(b.ip, x + 10 * dpr, y + 4 * dpr);
    }
  });
  const k = reduce ? 0 : ((t / 30) % 26);
  rx.fillStyle = '#4CF0A4';
  rx.beginPath(); rx.arc(c, c, 5 * dpr, 0, 7); rx.fill();
  rx.strokeStyle = `rgba(76,240,164,${1 - k / 26})`; rx.lineWidth = dpr;
  rx.beginPath(); rx.arc(c, c, (6 + k) * dpr, 0, 7); rx.stroke();
}
function loop(t) {
  const dt = Math.min(0.1, (t - lastT) / 1000) || 0;
  lastT = t;
  ang = (ang + dt * (S && S.scanning ? 2.8 : 0.8)) % (2 * Math.PI);
  drawRadar(t);
  requestAnimationFrame(loop);
}
if (!reduce) requestAnimationFrame(loop);
addEventListener('resize', () => { sizeRadar(); if (S) trend(); });

/* ---------- risk trend ---------- */
function trend() {
  const c = $('#trend');
  if (!c.clientWidth) return;
  const w = c.width = c.clientWidth * dpr, h = c.height = 130 * dpr, x = c.getContext('2d');
  x.clearRect(0, 0, w, h);
  const d = S.timeline;
  if (!d.length) {
    x.fillStyle = '#7C93AB'; x.font = `${14 * dpr}px Chakra Petch, sans-serif`;
    x.fillText('No scans yet. Scan a link to start.', 4 * dpr, h / 2);
    return;
  }
  const bw = w / Math.max(d.length, 12);
  d.forEach((v, i) => {
    const bh = Math.max(3 * dpr, v / 100 * (h - 8 * dpr));
    x.fillStyle = v >= 60 ? '#FF4D5E' : v >= 30 ? '#FFB347' : '#4CF0A4';
    x.fillRect(i * bw + bw * 0.15, h - bh, bw * 0.7, bh);
  });
}

/* ---------- render state ---------- */
function render() {
  const s = S;
  $('#netcidr').textContent = s.network;
  $('#netcidr2').textContent = s.network;
  $$('.js-auto').forEach(c => c.checked = s.auto_scan);
  $('#scanstate').textContent = s.scanning ? ((s.net && s.net.phase) || 'Scanning your network...') : '';
  renderNet(s);
  $$('.js-scan').forEach(b => b.disabled = s.scanning);
  countTo($('#st-total'), s.stats.total);
  countTo($('#st-high'), s.stats.high);
  countTo($('#st-blocked'), s.stats.blocked);
  countTo($('#st-hosts'), s.stats.hosts);
  trend();
  $('#key').textContent = s.api_key;
  $('#histcount').textContent = s.stats.total + ' total';
  renderLive(s.live);
  renderStatus();
  renderTicker();

  $('#alerts').innerHTML = s.alerts.length
    ? s.alerts.map(a => `<div class="alert-item">${esc(a.message)}<small>${esc(a.at)}</small></div>`).join('')
    : '<div class="empty">No alerts yet. High-risk results appear here and are emailed to you.</div>';

  $('#tb-blocked').innerHTML = s.blocked.length
    ? s.blocked.map(b => `<tr><td>${esc(b.kind)}</td><td class="mono">${esc(b.value)}</td><td><button class="btn ghost sm" data-unblock data-k="${esc(b.kind)}" data-v="${esc(b.value)}">Unblock</button></td></tr>`).join('')
    : '<tr><td colspan="3" class="empty">Nothing is blocked yet.</td></tr>';

  const hs = hostsOf();
  blips = hs.filter(h => h.host !== s.me_ip).map(h => ({ ip: h.host, ...pos(h.host), risky: h.ports.some(p => RISKY[p.port]) }));
  $('#tb-hosts').innerHTML = hs.length
    ? hs.map(h => `<tr><td class="mono">${esc(h.host)}${h.host === s.me_ip ? ' <span class="tag me">this PC</span>' : ''}</td><td>${
        h.ports.length ? h.ports.map(p => RISKY[p.port]
          ? `<span class="tag risk" data-block-port="${p.port}" data-host="${esc(h.host)}" title="Click to block">${p.port} ${esc(p.service)}</span>`
          : `<span class="tag">${p.port} ${esc(p.service)}</span>`).join('') : '<span class="mut">No open ports</span>'}</td></tr>`).join('')
    : '<tr><td colspan="2" class="empty">No scan results yet. Press Scan network now.</td></tr>';

  $('#tb-history').innerHTML = s.scans.length
    ? s.scans.map(x => `<tr><td class="mono">${esc(x.target.slice(0, 70))}${x.reasons ? `<div class="mut sm">${esc(x.reasons.slice(0, 170))}</div>` : ''}</td><td>${x.kind === 'auto' ? 'Browser' : esc(x.kind)}</td><td>${badge(x.level, x.score)}</td><td class="mono">${esc(x.at)}</td></tr>`).join('')
    : '<tr><td colspan="4" class="empty">No scans yet.</td></tr>';

  if (wasScanning && !s.scanning) {
    if (s.net && s.net.error) toast('Network scan failed', s.net.error, '');
    else toast('Network scan finished', `${s.stats.hosts} device(s) found on ${s.network}.`, 'info');
  }
  wasScanning = s.scanning;
}
function renderNet(s) {
  const n = s.net || {}, el = $('#netstat'), bar = $('#netbar');
  if (!el) return;
  if (n.error) { el.dataset.s = 'bad'; el.textContent = n.error; bar.classList.remove('on'); return; }
  if (s.scanning) {
    el.dataset.s = 'ok';
    el.textContent = n.phase || 'Scanning...';
    bar.classList.add('on');
    bar.firstChild.style.width = (n.total ? Math.max(4, Math.round(100 * (n.done || 0) / n.total)) : 6) + '%';
    return;
  }
  bar.classList.remove('on');
  if (n.last) { el.dataset.s = 'ok'; el.textContent = `Last scan finished at ${n.last}: ${n.found} device(s) on ${s.network}.`; }
  else { el.dataset.s = 'none'; el.textContent = s.stats.hosts ? `Showing the previous scan of ${s.network}. Press Scan network now to refresh.` : 'No scan yet. Press Scan network now.'; }
}
async function load() {
  const s = await api('/api/state');
  if (s.error) return;
  S = s;
  render();
}

/* ---------- scanner ---------- */
$$('.seg button').forEach(b => b.onclick = () => {
  kind = b.dataset.kind;
  $$('.seg button').forEach(x => x.classList.toggle('on', x === b));
  $('#text').placeholder = kind === 'url'
    ? 'Paste a link to check, for example http://secure-login-paypal.xyz/verify'
    : 'Paste the full text of the suspicious message';
});
function showResult(r) {
  const tx = { High: 'Strong signs of a scam.', Medium: 'Some warning signs found.', Low: 'No major warning signs found.' }[r.level];
  $('#result').className = '';
  $('#result').innerHTML = `
    <div class="res">
      <div class="gauge"><svg viewBox="0 0 120 120"><circle class="bg" cx="60" cy="60" r="54"/><circle class="fg ${r.level}" cx="60" cy="60" r="54"/></svg><div class="v ${r.level}" id="gv" data-v="0">0</div></div>
      <div><div class="lvl ${r.level}">${r.level} risk</div><div class="mut">${tx}</div></div>
    </div>
    ${r.auto_blocked.length ? `<div class="banner">Added to your block list: ${esc(r.auto_blocked.join(', '))}</div>` : ''}
    <h4>Warning signs</h4>
    <ul class="list">${r.reasons.length ? r.reasons.map(x => `<li>${esc(x)}</li>`).join('') : '<li>None found.</li>'}</ul>
    <h4>What to do</h4>
    <ul class="list">${r.tips.map(x => `<li>${esc(x)}</li>`).join('')}</ul>`;
  const fg = $('#result .fg');
  requestAnimationFrame(() => requestAnimationFrame(() => { fg.style.strokeDashoffset = 339.29 * (1 - r.score / 100); }));
  countTo($('#gv'), r.score);
  if (r.level === 'High') flash();
}
$('#scanbtn').onclick = async () => {
  const t = $('#text').value.trim();
  if (!t) { toast('Nothing to scan', 'Paste a link or message first.', 'info'); return; }
  $('#scanbox').classList.add('loading');
  $('#scanbtn').disabled = true;
  const [r] = await Promise.all([api('/api/scan', { kind, text: t }), new Promise(ok => setTimeout(ok, 900))]);
  $('#scanbox').classList.remove('loading');
  $('#scanbtn').disabled = false;
  if (r.error) { toast('Scan failed', r.error, 'info'); return; }
  showResult(r);
  load();
};

/* ---------- firewall ---------- */
$('#presets').innerHTML = Object.entries(RISKY).map(([p, n]) => `<button type="button" data-p="${p}">${p} ${n}</button>`).join('');
$('#presets').onclick = e => { const b = e.target.closest('button'); if (b) $('#port').value = b.dataset.p; };
$('#bport').onclick = async () => {
  const r = await api('/api/block', { kind: 'port', value: $('#port').value });
  if (r.error) toast('Could not block', r.error, 'info');
  else toast(r.ok ? 'Port blocked' : 'Saved, but the firewall rule failed', r.msg, 'info');
  $('#port').value = '';
  load();
};
$('#bdom').onclick = async () => {
  const r = await api('/api/block', { kind: 'domain', value: $('#dom').value });
  toast(r.error ? 'Could not block' : 'Domain blocked', r.error || r.msg, 'info');
  $('#dom').value = '';
  load();
};
document.addEventListener('click', async e => {
  const u = e.target.closest('[data-unblock]');
  if (u) {
    const r = await api('/api/unblock', { kind: u.dataset.k, value: u.dataset.v });
    toast('Unblocked', r.msg, 'info');
    load();
    return;
  }
  const p = e.target.closest('[data-block-port]');
  if (p) {
    const host = p.dataset.host, port = p.dataset.blockPort;
    if (!confirm(`Block port ${port} on ${host}?`)) return;
    const r = await api('/api/block', { kind: 'port', value: port, ip: host === S.me_ip ? '' : host });
    toast(r.error ? 'Could not block' : (r.ok ? 'Port blocked' : 'Saved, but the firewall rule failed'), r.error || r.msg, 'info');
    load();
  }
});

/* ---------- network ---------- */
$$('.js-scan').forEach(b => b.onclick = async () => {
  await api('/api/netscan', {});
  toast('Network scan started', 'Scanning ' + (S ? S.network : 'your network'), 'info');
  setTimeout(load, 700);
});
$$('.js-auto').forEach(c => c.onchange = async () => {
  await api('/api/autoscan', { on: c.checked });
  toast(c.checked ? 'Auto-scan on' : 'Auto-scan off', c.checked ? 'Your network is scanned every 5 minutes and risky ports are blocked.' : 'Automatic scanning stopped.', 'info');
  load();
});

/* ---------- live protection (clipboard) ---------- */
let liveSeen = null, LV = null, lastTicker = '';
function renderLive(L) {
  if (!L) return;
  LV = L;
  document.body.dataset.live = L.on ? 'on' : 'off';
  $$('.js-live').forEach(c => c.checked = !!L.on);
  $('#chip-t').textContent = L.on ? 'ON' : 'OFF';
  $('#coretxt').textContent = L.on ? 'LIVE' : 'OFF';
  $('#livetxt').textContent = L.on
    ? 'Watching your clipboard. Copy a link or message anywhere and it is checked instantly.'
    : 'Turn on live protection to check everything you copy.';
  $('#livewarn').hidden = L.supported !== false;
  countTo($('#lv-checked'), L.checked);
  countTo($('#lv-susp'), L.suspicious);
  countTo($('#lv-threat'), L.threats);
  $('#livecount').textContent = L.feed.length ? L.feed.length + ' recent' : '';

  const maxId = L.feed.reduce((m, f) => Math.max(m, f.id), 0);
  const first = liveSeen === null;
  if (!first && maxId < liveSeen) liveSeen = 0;            // server restarted
  const fresh = new Set(first ? [] : L.feed.filter(f => f.id > liveSeen).map(f => f.id));
  const sig = L.feed.map(f => f.id).join(',');
  if (sig !== renderLive.sig) {
    renderLive.sig = sig;
    $('#livefeed').innerHTML = L.feed.length
      ? L.feed.map(f => `<div class="ev ${f.level}${fresh.has(f.id) ? ' new' : ''}"><span class="t">${esc(f.at)}</span><b class="${f.level}">${f.level.toUpperCase()} ${f.score}</b><span class="pv">${esc(f.preview)}</span>${f.reasons ? `<small>${esc(f.reasons)}</small>` : ''}${f.blocked && f.blocked.length ? `<em>Auto-blocked: ${esc(f.blocked.join(', '))}</em>` : ''}</div>`).join('')
      : '<div class="empty">Nothing yet. Copy a link or message and it shows up here.</div>';
  }
  [...L.feed].filter(f => fresh.has(f.id)).reverse().forEach(f => {
    if (f.level === 'High') { toast('Dangerous content copied', 'Do not open or paste it.\n' + f.preview, ''); flash(); notify('Dangerous content copied: ' + f.preview); }
    else if (f.level === 'Medium') toast('Suspicious content copied', f.preview + '\n' + f.reasons, 'info');
    else toast('Copied link checked', 'Low risk: ' + f.preview, 'ok');
  });
  liveSeen = first ? maxId : Math.max(liveSeen, maxId);
  if (S) renderStatus();
}
async function pollLive() { const L = await api('/api/live'); if (L && !L.error) renderLive(L); }
async function setLive(on) {
  if (LV) renderLive({ ...LV, on });
  const r = await api('/api/liveprotect', { on });
  if (r.supported === false && on) toast('Clipboard access missing', 'Run  pip install pyperclip  in a terminal, then restart PhishNet.', 'info');
  else toast(on ? 'Live protection ON' : 'Live protection OFF', on ? 'Everything you copy is now checked automatically.' : 'Clipboard checking stopped.', on ? 'ok' : 'info');
  pollLive();
}
$$('.js-live').forEach(c => c.onchange = () => setLive(c.checked));
$('#corebtn').onclick = () => setLive(!(LV && LV.on));

/* ---------- status hero + ticker ---------- */
function setPill(id, on, label) {
  const e = $(id);
  e.classList.toggle('on', !!on);
  e.firstChild.textContent = label;
  e.querySelector('b').textContent = on ? 'ON' : 'OFF';
}
function renderStatus() {
  const s = S, L = LV || { feed: [] };
  const recentHigh = L.feed.some(f => f.level === 'High' && (L.now - f.ts) < 90);
  let mode, big, sub;
  if (recentHigh) { mode = 'alert'; big = 'THREAT BLOCKED'; sub = 'A dangerous link was just copied. Do not open it. Its domain is now on your block list.'; }
  else if (L.on && s.auto_scan) { mode = 'full'; big = 'FULLY PROTECTED'; sub = 'The clipboard shield and network auto-scan are both running.'; }
  else if (L.on || s.auto_scan) { mode = 'ok'; big = 'PROTECTED'; sub = L.on ? 'Live protection is checking everything you copy. Turn on auto-scan to guard your network too.' : 'Network auto-scan is running. Turn on live protection to check what you copy.'; }
  else { mode = 'low'; big = 'BASIC MODE'; sub = 'Turn on live protection and auto-scan for full coverage.'; }
  $('#status').dataset.mode = mode;
  $('#sysstate').textContent = big;
  $('#syssub').textContent = sub;
  setPill('#pl-live', L.on, 'Live protection');
  setPill('#pl-auto', s.auto_scan, 'Auto-scan');
  const M = s.mail || {};
  setPill('#pl-mail', M.configured && M.ok !== false, 'Email alerts');
  $('#pl-blk b').textContent = s.stats.blocked;
}
function renderTicker() {
  const s = S, L = LV || {};
  const last = s.scans[0];
  const parts = [
    `LIVE PROTECTION <b class="${L.on ? 'g' : 'r'}">${L.on ? 'ONLINE' : 'OFFLINE'}</b>`,
    `SCANS <b>${s.stats.total}</b>`,
    `HIGH RISK <b class="${s.stats.high ? 'r' : 'g'}">${s.stats.high}</b>`,
    `BLOCKED <b>${s.stats.blocked}</b>`,
    `NETWORK <b>${esc(s.network)}</b>`,
    `DEVICES <b>${s.stats.hosts}</b>`,
    `AUTO-SCAN <b class="${s.auto_scan ? 'g' : 'r'}">${s.auto_scan ? 'ON' : 'OFF'}</b>`,
    last ? `LAST SCAN <b class="${last.level === 'High' ? 'r' : last.level === 'Medium' ? '' : 'g'}">${esc(last.level.toUpperCase())}</b> ${esc(last.target.slice(0, 34))}` : 'NO SCANS YET'
  ].map(x => `<span>${x}</span>`).join('&#9670;');
  const html = parts + parts + parts + parts;
  if (html !== lastTicker) { lastTicker = html; $('#ticker').innerHTML = html; }
}

/* ---------- clear history ---------- */
function openClear() {
  const c = (S && S.counts) || {};
  $('#n-scans').textContent = (c.scans || 0) + ' records';
  $('#n-alerts').textContent = (c.alerts || 0) + ' records';
  $('#n-net').textContent = (c.net || 0) + ' old rows. The latest scan is kept';
  $('#modal').classList.add('on');
}
function closeClear() { $('#modal').classList.remove('on'); }
$('#clearbtn').onclick = openClear;
$('#c-cancel').onclick = closeClear;
$('#modal').onclick = e => { if (e.target.id === 'modal') closeClear(); };
addEventListener('keydown', e => { if (e.key === 'Escape') closeClear(); });
$('#c-go').onclick = async () => {
  const body = { scans: $('#c-scans').checked, alerts: $('#c-alerts').checked, net: $('#c-net').checked };
  if (!body.scans && !body.alerts && !body.net) { toast('Nothing selected', 'Tick at least one item to clear.', 'info'); return; }
  $('#c-prog').classList.add('on'); $('#c-go').disabled = true;
  const [r] = await Promise.all([api('/api/clear_history', body), new Promise(ok => setTimeout(ok, 800))]);
  $('#c-prog').classList.remove('on'); $('#c-go').disabled = false;
  closeClear();
  if (r.error || !r.ok) { toast('Could not clear history', r.error || 'The server did not finish. Try again.', 'info'); return; }
  const c = r.cleared || {}, n = (c.scans || 0) + (c.alerts || 0) + (c.net || 0);
  toast('History cleared', n + ' record(s) removed' + (c.scans != null ? ' (' + c.scans + ' scans)' : '') + '.', 'ok');
  renderLive.sig = null;
  load(); pollLive();
};

/* ---------- ambient effects ---------- */
(function bgfx() {
  const c = $('#bgfx'), x = c.getContext('2d');
  let w = 0, h = 0, N = [], last = 0;
  function size() {
    w = c.width = innerWidth; h = c.height = innerHeight;
    N = Array.from({ length: Math.max(24, Math.round(w * h / 24000)) }, () => ({
      x: Math.random() * w, y: Math.random() * h, vx: (Math.random() - .5) * .45, vy: (Math.random() - .5) * .45, bad: Math.random() < .07, p: Math.random() * 6.28
    }));
  }
  function draw(t) {
    if (!document.hidden && t - last > 32) {
      last = t;
      x.clearRect(0, 0, w, h);
      for (const n of N) {
        if (!reduce) { n.x += n.vx; n.y += n.vy; if (n.x < 0 || n.x > w) n.vx *= -1; if (n.y < 0 || n.y > h) n.vy *= -1; }
      }
      const R = 150;
      for (let i = 0; i < N.length; i++) for (let j = i + 1; j < N.length; j++) {
        const a = N[i], b = N[j], d = Math.hypot(a.x - b.x, a.y - b.y);
        if (d < R) {
          x.strokeStyle = (a.bad || b.bad) ? `rgba(255,77,94,${.2 * (1 - d / R)})` : `rgba(55,214,255,${.16 * (1 - d / R)})`;
          x.beginPath(); x.moveTo(a.x, a.y); x.lineTo(b.x, b.y); x.stroke();
        }
      }
      for (const n of N) {
        x.fillStyle = n.bad ? 'rgba(255,77,94,.8)' : 'rgba(55,214,255,.6)';
        x.beginPath(); x.arc(n.x, n.y, n.bad ? 3 : 2, 0, 7); x.fill();
        if (n.bad) { const k = (t / 1600 + n.p) % 1; x.strokeStyle = `rgba(255,77,94,${.7 * (1 - k)})`; x.beginPath(); x.arc(n.x, n.y, 4 + k * 22, 0, 7); x.stroke(); }
      }
    }
    if (!reduce) requestAnimationFrame(draw);
  }
  size(); addEventListener('resize', size); requestAnimationFrame(draw);
})();
document.addEventListener('mousemove', e => {
  const p = e.target.closest && e.target.closest('.panel');
  if (p) { const r = p.getBoundingClientRect(); p.style.setProperty('--mx', (e.clientX - r.left) + 'px'); p.style.setProperty('--my', (e.clientY - r.top) + 'px'); }
}, { passive: true });
function tick() { $('#clock').textContent = new Date().toLocaleTimeString('en-GB'); }
tick(); setInterval(tick, 1000);

/* ---------- misc ---------- */
$('#testalert').onclick = async () => {
  const b = $('#testalert'); b.disabled = true; b.textContent = 'Sending...';
  const r = await api('/api/test_alert', {});
  b.disabled = false; b.textContent = 'Send test alert';
  if (r.ok) toast('Test email sent', 'Check the inbox of ' + r.email + ' (and the spam folder).', 'ok');
  else toast('Email was not sent', r.msg || r.error || 'Failed', '');
  load();
};
$('#copykey').onclick = () => {
  navigator.clipboard.writeText($('#key').textContent).then(() => toast('Copied', 'API key copied to the clipboard.', 'info'));
};

show(location.hash.slice(1) || 'overview');
sizeRadar();
load();
setInterval(load, 5000);
setInterval(poll, 4000);
setInterval(pollLive, 1500);
})();
