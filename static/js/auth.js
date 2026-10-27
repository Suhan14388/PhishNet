(() => {
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Brand name decodes from random characters once on load
  const brand = document.getElementById('brand');
  if (brand && !reduce) {
    const final = brand.textContent, chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#$%&*';
    let i = 0;
    const iv = setInterval(() => {
      brand.textContent = final.split('').map((c, k) => (k < i ? c : chars[Math.random() * chars.length | 0])).join('');
      i += 0.5;
      if (i > final.length) { brand.textContent = final; clearInterval(iv); }
    }, 45);
  }

  // Show / hide password
  const pw = document.getElementById('password'), tg = document.getElementById('toggle');
  tg.onclick = () => {
    const show = pw.type === 'password';
    pw.type = show ? 'text' : 'password';
    tg.textContent = show ? 'Hide' : 'Show';
  };

  // Button feedback on submit
  document.getElementById('form').addEventListener('submit', () => {
    const b = document.getElementById('submit');
    b.textContent = 'Checking...';
    setTimeout(() => (b.disabled = true), 0);
  });

  // Drifting network graph; a few nodes are flagged red
  const c = document.getElementById('net');
  if (!c) return;
  const x = c.getContext('2d'), dpr = devicePixelRatio || 1;
  let w, h, nodes = [];

  function size() {
    w = c.width = c.offsetWidth * dpr;
    h = c.height = c.offsetHeight * dpr;
    const n = Math.max(22, Math.round((c.offsetWidth * c.offsetHeight) / 14000));
    nodes = Array.from({ length: n }, () => ({
      x: Math.random() * w, y: Math.random() * h,
      vx: (Math.random() - 0.5) * 0.35 * dpr, vy: (Math.random() - 0.5) * 0.35 * dpr,
      bad: Math.random() < 0.1, p: Math.random() * 6.28
    }));
  }

  function draw(t) {
    x.clearRect(0, 0, w, h);
    const R = 150 * dpr;
    for (const n of nodes) {
      if (!reduce) {
        n.x += n.vx; n.y += n.vy;
        if (n.x < 0 || n.x > w) n.vx *= -1;
        if (n.y < 0 || n.y > h) n.vy *= -1;
      }
    }
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j], d = Math.hypot(a.x - b.x, a.y - b.y);
        if (d < R) {
          const bad = a.bad || b.bad;
          x.strokeStyle = bad ? `rgba(255,77,94,${0.28 * (1 - d / R)})` : `rgba(55,214,255,${0.3 * (1 - d / R)})`;
          x.lineWidth = dpr;
          x.beginPath(); x.moveTo(a.x, a.y); x.lineTo(b.x, b.y); x.stroke();
        }
      }
    }
    for (const n of nodes) {
      x.fillStyle = n.bad ? '#FF4D5E' : '#37D6FF';
      x.beginPath(); x.arc(n.x, n.y, (n.bad ? 4.5 : 3) * dpr, 0, 7); x.fill();
      if (n.bad) {
        const k = ((t / 1400 + n.p) % 1);
        x.strokeStyle = `rgba(255,77,94,${1 - k})`;
        x.beginPath(); x.arc(n.x, n.y, (5 + k * 20) * dpr, 0, 7); x.stroke();
      }
    }
    if (!reduce) requestAnimationFrame(draw);
  }

  size();
  addEventListener('resize', size);
  requestAnimationFrame(draw);
})();
