/* Live threat flow: an orb of items from every source, one sector per theme.
   A virtual clock drives it: the rim is "now" on that clock and the core is the start of the
   chosen range, so during a replay items stream in from their source and sink toward the core
   as time passes. Ranges: 48 hours, 1 week (live file), 30/60/90 days (history file).
   Reuses h(), $(), showTip() and hideTip() from app.js. Feed text is untrusted: textContent only. */
"use strict";
(() => {
  const DAY = 864e5, POLL_MS = 5 * 60 * 1000, FLY_MS = 1400, MAX_FLIGHTS = 40;
  const RANGES = [{ days: 2, label: "48 hours", dur: 8000 }, { days: 7, label: "1 week", dur: 12000 },
    { days: 30, label: "30 days", dur: 16000 }, { days: 60, label: "60 days", dur: 20000 }, { days: 90, label: "90 days", dur: 24000 }];
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const fx = {
    live: null, hist: null, histLoadedAt: 0, themes: [], themeIdx: new Map(), range: RANGES[1],
    items: [], pts: [], flights: [], landed: new Set(), shown: new Set(), focus: null,
    vnow: Date.now(), playing: false, following: true, lastFrame: 0, tickerHead: null,
    canvas: null, ctx: null, geo: null, lanes: [], dpr: 1,
  };

  const hash = (s) => { let x = 2166136261; for (let i = 0; i < s.length; i++) { x ^= s.charCodeAt(i); x = Math.imul(x, 16777619); } return ((x >>> 0) % 100000) / 100000; };
  const ago = (ms) => { const m = Math.max(0, Math.round(ms / 60000)); return m < 60 ? `${m}m ago` : m < 2880 ? `${Math.round(m / 60)}h ago` : `${Math.round(m / 1440)}d ago`; };
  const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const fmtClock = (ms) => { const d = new Date(ms); return `${MON[d.getMonth()]} ${d.getDate()}, ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`; };
  const fmtDay = (ms) => { const d = new Date(ms); return `${MON[d.getMonth()]} ${d.getDate()}`; };
  const SOURCE_KEY = (src) => src.endsWith(" status") ? "statuspages" : ({ ransomwatch: "ransomwatch", RansomLook: "ransomlook", Watchlist: "watchlist", "ransomware.live": "ransomware_live", "CISA KEV": "cisa_kev", NVD: "nvd", Upptime: "upptime", INman: "inman" })[src] || "rss";
  const LANE_LABEL = { epss: "EPSS scores", ransomlook: "RansomLook", watchlist: "Site watchlist", ransomwatch: "ransomwatch", ransomware_live: "ransomware.live", cisa_kev: "CISA KEV", nvd: "NVD CVEs", statuspages: "Status pages", upptime: "Upptime", rss: "Advisories & news RSS", inman: "INman curated" };
  const SHORT = { claims: "Extortion claims", kev: "Exploited vulns", cve: "New CVEs", outages: "Outages", advisories: "Advisories & news", incidents: "U.S. incidents" };
  const shortLabel = (th) => th.short || SHORT[th.id] || th.label;
  /* text centred on angle `am` along a circle; flipped on the lower half so it never reads upside down */
  function arcText(c, text, cx, cy, r, am) {
    const bottom = Math.sin(am) > 0.2, dir = bottom ? -1 : 1;
    c.textAlign = "center"; c.textBaseline = "middle";
    let a = am - dir * (c.measureText(text).width / (2 * r));
    for (const ch of text) {
      const half = c.measureText(ch).width / (2 * r);
      a += dir * half;
      c.save(); c.translate(cx + Math.cos(a) * r, cy + Math.sin(a) * r); c.rotate(a + (bottom ? -Math.PI / 2 : Math.PI / 2));
      c.fillText(ch, 0, 0); c.restore();
      a += dir * half;
    }
  }
  const colorOf = (id) => (fx.themes[fx.themeIdx.get(id)] || {}).color || "#9db4d6";
  const rangeMs = () => fx.range.days * DAY;

  async function getJSON(path) {
    try { const r = await fetch(`${path}?t=${Date.now()}`, { cache: "no-cache" }); if (!r.ok) throw new Error(r.status); return await r.json(); }
    catch (e) { return null; }
  }

  /* ---------------- setup ---------------- */
  async function init() {
    const card = $("flowCard"); if (!card) return;
    fx.live = await getJSON("data/flow.json");
    if (!fx.live) { card.classList.add("hidden"); return; }
    fx.canvas = $("orb"); fx.ctx = fx.canvas.getContext("2d");
    setThemes(fx.live.themes);
    buildRangeButtons();
    $("flowPlay").onclick = () => (fx.playing ? pause() : play(fx.vnow >= Date.now() - 1000));
    $("flowScrub").addEventListener("input", (e) => scrubTo(Number(e.target.value)));
    $("flowLive").onclick = goLive;
    fx.canvas.addEventListener("pointermove", hover);
    fx.canvas.addEventListener("pointerleave", hideTip);
    fx.canvas.addEventListener("click", click);
    new ResizeObserver(layout).observe(fx.canvas.parentElement);
    rebuild();
    layout();
    play(true);
    if (!reduce) requestAnimationFrame(frame);
    setInterval(poll, POLL_MS);
  }

  function setThemes(themes) {
    fx.themes = themes || [];
    fx.themeIdx = new Map(fx.themes.map((t, i) => [t.id, i]));
  }

  function buildRangeButtons() {
    $("flowRanges").replaceChildren(...RANGES.map((r) => {
      const b = h("button", { type: "button", class: r === fx.range ? "on" : null, "aria-pressed": String(r === fx.range), text: r.label });
      b.onclick = () => selectRange(r);
      return b;
    }));
  }

  async function selectRange(r) {
    fx.range = r; buildRangeButtons();
    if (r.days > 7 && (!fx.hist || Date.now() - fx.histLoadedAt > POLL_MS * 6)) {
      $("flowClock").textContent = "Loading history…";
      fx.hist = await getJSON("data/flow_history.json"); fx.histLoadedAt = Date.now();
    }
    rebuild(); play(true);
  }

  /* items for the current range: the live file, plus history when the range is longer than a week */
  function rebuild() {
    const byId = new Map();
    if (fx.range.days > 7 && fx.hist) for (const it of fx.hist.items || []) byId.set(it.id, it);
    for (const it of fx.live.items || []) byId.set(it.id, it);
    const from = Date.now() - rangeMs();
    fx.items = [...byId.values()].filter((it) => fx.themeIdx.has(it.theme))
      .map((it) => { it._t = it._t || Date.parse(it.ts); return it; })
      .filter((it) => it._t >= from).sort((a, b) => a._t - b._t);
    fx.pts = fx.items.map((it) => {
      const [a0, a1] = sector(it.theme);
      return { it, a: a0 + 0.04 + hash(it.id) * (a1 - a0 - 0.08), j: (hash(it.id + "r") - 0.5) * 0.08, s: 1.3 + 2.4 * it.severity, x: 0, y: 0 };
    });
    fx.tickerHead = null;
    buildLanes(); renderThemes(); renderSources(); coverageNote(); renderActors(); renderVelocity();
  }

  async function poll() {
    const d = await getJSON("data/flow.json"); if (!d) return;
    const before = new Set((fx.live.items || []).map((i) => i.id));
    fx.live = d; setThemes(d.themes);
    if (fx.range.days > 7 && Date.now() - fx.histLoadedAt > POLL_MS * 6) { const hd = await getJSON("data/flow_history.json"); if (hd) { fx.hist = hd; fx.histLoadedAt = Date.now(); } }
    const keepShown = new Set(fx.shown), keepLanded = new Set(fx.landed);
    rebuild();
    fx.shown = keepShown; fx.landed = keepLanded;
    for (const p of fx.pts) {
      if (before.has(p.it.id) || fx.shown.has(p.it.id) || !fx.following) continue;
      fx.shown.add(p.it.id); launch(p);                       // brand-new items fly in from their source
    }
    if (reduce) draw();
  }

  /* ---------------- clock ---------------- */
  function play(fromStart) {
    if (fromStart) { fx.vnow = Date.now() - rangeMs(); fx.shown = new Set(); fx.landed = new Set(); fx.flights = []; }
    fx.playing = true; fx.following = false; fx.lastFrame = performance.now();
    if (reduce) { fx.vnow = Date.now(); fx.playing = false; fx.following = true; revealUpTo(fx.vnow, false); draw(); maybeTicker(); }
    syncControls();
  }
  function pause() { fx.playing = false; syncControls(); }
  function goLive() { fx.vnow = Date.now(); fx.playing = false; fx.following = true; fx.tickerHead = null; revealUpTo(fx.vnow, false); syncControls(); if (reduce) { draw(); maybeTicker(); } }
  function scrubTo(v) {
    const now = Date.now();
    fx.vnow = now - rangeMs() + (v / 1000) * rangeMs();
    fx.playing = false; fx.following = v >= 1000; fx.flights = [];
    fx.shown = new Set(); fx.landed = new Set(); revealUpTo(fx.vnow, false);
    syncControls(); if (reduce) { draw(); maybeTicker(); }
  }
  function revealUpTo(t, animate) {
    for (const p of fx.pts) {
      if (p.it._t > t || fx.shown.has(p.it.id)) continue;
      fx.shown.add(p.it.id);
      if (animate && fx.flights.length < MAX_FLIGHTS) launch(p); else fx.landed.add(p.it.id);
    }
  }
  function syncControls() {
    const now = Date.now(), live = fx.following && !fx.playing;
    $("flowPlay").textContent = fx.playing ? "Pause" : "Replay";
    $("flowPlay").setAttribute("aria-label", fx.playing ? "Pause replay" : `Replay the last ${fx.range.label}`);
    $("flowScrub").value = String(Math.round(Math.min(1, Math.max(0, (fx.vnow - (now - rangeMs())) / rangeMs())) * 1000));
    $("flowClock").textContent = live ? "Live" : fmtClock(fx.vnow);
    $("flowClock").classList.toggle("live", live);
    $("flowLive").classList.toggle("hidden", live);
  }

  function frame(ts) {
    const dt = Math.min(100, ts - (fx.lastFrame || ts)); fx.lastFrame = ts;
    const now = Date.now();
    if (fx.playing) {
      fx.vnow += dt * (rangeMs() / fx.range.dur);
      if (fx.vnow >= now) { fx.vnow = now; fx.playing = false; fx.following = true; fx.tickerHead = null; }
      revealUpTo(fx.vnow, true);
      syncControls();
    } else if (fx.following) {
      fx.vnow = now;
    }
    draw(); maybeTicker();
    requestAnimationFrame(frame);
  }

  /* ---------------- geometry ---------------- */
  function layout() {
    const W = fx.canvas.parentElement.clientWidth;
    const H = Math.round(Math.max(360, Math.min(560, W * (W < 640 ? 0.95 : 0.56))));
    fx.dpr = Math.min(2, window.devicePixelRatio || 1);
    fx.canvas.width = W * fx.dpr; fx.canvas.height = H * fx.dpr;
    fx.canvas.style.width = `${W}px`; fx.canvas.style.height = `${H}px`;
    const lanesW = W >= 640 ? 190 : 0;
    fx.geo = { W, H, lanesW, cx: lanesW + (W - lanesW) / 2, cy: H / 2 + 6,
      R: Math.min((W - lanesW) / 2 - (W >= 640 ? 100 : 34), H / 2 - (W >= 640 ? 44 : 38)) };
    draw();
    if (fx.velW !== $("flowVelocity").clientWidth) { fx.velW = $("flowVelocity").clientWidth; renderVelocity(); }
  }
  function sector(id) {
    const n = Math.max(1, fx.themes.length), i = fx.themeIdx.get(id), gap = 0.06;
    return [-Math.PI / 2 + (i * 2 * Math.PI) / n + gap, -Math.PI / 2 + ((i + 1) * 2 * Math.PI) / n - gap];
  }
  function position(p) {
    const { cx, cy, R } = fx.geo;
    const age = Math.min(1, Math.max(0, (fx.vnow - p.it._t) / rangeMs()));
    const r = R * Math.min(0.97, Math.max(0.18, 0.22 + 0.74 * (1 - age) + p.j));
    p.x = cx + Math.cos(p.a) * r; p.y = cy + Math.sin(p.a) * r;
  }
  const laneY = (i) => { const n = Math.max(1, fx.lanes.length), top = 64, span = fx.geo.H - 110; return top + (n === 1 ? span / 2 : (i * span) / (n - 1)); };
  function laneAnchor(key) {
    const i = fx.lanes.findIndex((l) => l.key === key);
    if (!fx.geo.lanesW || i < 0) return { x: -10, y: fx.geo.H * (0.2 + 0.6 * Math.random()) };
    return { x: fx.geo.lanesW - 14, y: laneY(i) };
  }
  function launch(p) {
    if (reduce) { fx.landed.add(p.it.id); return; }
    fx.landed.delete(p.it.id);
    fx.flights.push({ p, start: performance.now(), from: laneAnchor(SOURCE_KEY(p.it.source)) });
  }

  /* ---------------- drawing ---------------- */
  function draw() {
    if (!fx.geo) return;
    const c = fx.ctx, { W, H, cx, cy, R, lanesW } = fx.geo, t = performance.now();
    c.setTransform(fx.dpr, 0, 0, fx.dpr, 0, 0); c.clearRect(0, 0, W, H);
    const font = (w, s) => `${w} ${s}px -apple-system, Segoe UI, Roboto, Arial, sans-serif`;

    const g = c.createRadialGradient(cx - R * 0.3, cy - R * 0.35, R * 0.05, cx, cy, R * 1.05);
    g.addColorStop(0, "rgba(64,96,150,0.55)"); g.addColorStop(0.55, "rgba(20,35,64,0.55)"); g.addColorStop(1, "rgba(8,14,28,0.2)");
    c.fillStyle = g; c.beginPath(); c.arc(cx, cy, R * 1.02, 0, Math.PI * 2); c.fill();
    c.strokeStyle = "rgba(157,180,214,0.10)"; c.lineWidth = 1;
    for (let k = 1; k <= 3; k++) { c.beginPath(); c.ellipse(cx, cy, R, R * 0.25 * k, 0, 0, Math.PI * 2); c.stroke(); }
    c.beginPath(); c.ellipse(cx, cy, R * 0.45, R, 0, 0, Math.PI * 2); c.stroke();
    c.setLineDash([2, 5]); c.strokeStyle = "rgba(157,180,214,0.16)";
    [0.96, 0.59, 0.22].forEach((f) => { c.beginPath(); c.arc(cx, cy, R * f, 0, Math.PI * 2); c.stroke(); });
    c.setLineDash([]);

    c.font = font(600, 11.5); c.textBaseline = "middle";
    for (const th of fx.themes) {
      const [a0, a1] = sector(th.id), dim = fx.focus && fx.focus !== th.id;
      c.strokeStyle = th.color; c.globalAlpha = dim ? 0.15 : 0.85; c.lineWidth = 4;
      c.beginPath(); c.arc(cx, cy, R * 1.04, a0, a1); c.stroke(); c.globalAlpha = 1;
      if (!lanesW) {   // narrow screens: short label curved along its own arc, in the sector's colour
        c.fillStyle = dim ? "rgba(223,231,245,0.35)" : th.color; c.font = font(600, 11);
        arcText(c, shortLabel(th), cx, cy, R * 1.04 + 13, (a0 + a1) / 2);
        c.font = font(600, 11.5);
        continue;
      }
      // straight label with a colour key dot, placed just outside the middle of its arc
      const am = (a0 + a1) / 2, lr = R * 1.04 + 16, ax = cx + Math.cos(am) * lr, tw = c.measureText(th.label).width + 13;
      const ly = cy + Math.sin(am) * lr + (Math.abs(Math.sin(am)) > 0.9 ? Math.sign(Math.sin(am)) * 4 : 0);
      const left = Math.cos(am) > 0.25 ? ax : Math.cos(am) < -0.25 ? ax - tw : ax - tw / 2;
      const x0 = Math.max(lanesW + 4, Math.min(W - tw - 8, left));
      c.globalAlpha = dim ? 0.35 : 1;
      c.fillStyle = th.color; c.beginPath(); c.arc(x0 + 4, ly, 4, 0, Math.PI * 2); c.fill();
      c.fillStyle = "#dfe7f5"; c.textAlign = "left"; c.fillText(th.label, x0 + 13, ly);
      c.globalAlpha = 1;
    }

    c.globalCompositeOperation = "lighter";
    const recentCut = fx.vnow - Math.min(DAY, rangeMs() / 7);
    for (const p of fx.pts) {
      if (!fx.landed.has(p.it.id) || p.it._t > fx.vnow) continue;
      position(p);
      const col = colorOf(p.it.theme), dim = fx.focus && fx.focus !== p.it.theme, recent = p.it._t >= recentCut;
      c.globalAlpha = dim ? 0.07 : recent ? 0.95 : 0.5;
      c.strokeStyle = col; c.lineWidth = 1;
      const nl = 3 + 12 * p.it.severity;
      c.beginPath(); c.moveTo(p.x, p.y); c.lineTo(p.x + Math.cos(p.a) * nl, p.y + Math.sin(p.a) * nl); c.stroke();
      c.fillStyle = col; c.beginPath(); c.arc(p.x, p.y, p.s, 0, Math.PI * 2); c.fill();
      if (p.it.seen_on && !dim) { c.strokeStyle = "#ffffff"; c.lineWidth = 1.2; c.beginPath(); c.arc(p.x, p.y, p.s + 2.2, 0, Math.PI * 2); c.stroke(); }
      if (recent && !dim && !reduce) {
        const pulse = (Math.sin(t / 600 + p.a * 7) + 1) / 2;
        c.globalAlpha = 0.16 + 0.2 * pulse; c.beginPath(); c.arc(p.x, p.y, p.s + 3 + 3 * pulse, 0, Math.PI * 2); c.fill();
      }
    }
    const done = [];
    for (const f of fx.flights) {
      const k = (t - f.start) / FLY_MS; if (k < 0) continue;
      if (k >= 1) { fx.landed.add(f.p.it.id); done.push(f); continue; }
      position(f.p);
      const p = f.p, mx = (f.from.x + p.x) / 2, my = Math.min(f.from.y, p.y) - 40;
      const pt = (u) => [(1 - u) ** 2 * f.from.x + 2 * (1 - u) * u * mx + u * u * p.x, (1 - u) ** 2 * f.from.y + 2 * (1 - u) * u * my + u * u * p.y];
      const e = 1 - (1 - k) ** 3, col = colorOf(p.it.theme), s0 = Math.max(0, e - 0.25);
      c.strokeStyle = col; c.lineWidth = 1.5; c.globalAlpha = fx.focus && fx.focus !== p.it.theme ? 0.1 : 0.5; c.beginPath();
      for (let u = s0; u <= e + 1e-9; u += 0.025) { const [x, y] = pt(u); u === s0 ? c.moveTo(x, y) : c.lineTo(x, y); }
      c.stroke();
      const [hx, hy] = pt(e); c.globalAlpha = 1; c.fillStyle = col; c.beginPath(); c.arc(hx, hy, 2.6, 0, Math.PI * 2); c.fill();
    }
    if (done.length) fx.flights = fx.flights.filter((f) => !done.includes(f));
    c.globalCompositeOperation = "source-over"; c.globalAlpha = 1;

    const core = c.createRadialGradient(cx, cy, 0, cx, cy, R * 0.2);
    core.addColorStop(0, "rgba(223,231,245,0.35)"); core.addColorStop(1, "rgba(223,231,245,0)");
    c.fillStyle = core; c.beginPath(); c.arc(cx, cy, R * 0.2, 0, Math.PI * 2); c.fill();
    c.fillStyle = "rgba(223,231,245,0.6)"; c.font = font(400, 10.5); c.textAlign = "center";
    const live = fx.following && !fx.playing;
    c.fillText(live ? "now" : fmtDay(fx.vnow), cx, cy - R * 0.96 + 12);
    c.fillText(fx.range.days <= 2 ? "48 hours earlier" : `${fx.range.days} days earlier`, cx, cy + R * 0.22 + 10);

    if (lanesW) {
      c.textAlign = "left"; c.font = font(600, 11); c.fillStyle = "rgba(223,231,245,0.6)"; c.fillText("SOURCES", 14, 34);
      fx.lanes.forEach((l, i) => {
        const y = laneY(i);
        let n = 0; for (const it of l.items) if (it._t <= fx.vnow) n++;
        c.fillStyle = l.ok ? l.color : "#5b6b85"; c.beginPath(); c.arc(20, y, 4, 0, Math.PI * 2); c.fill();
        c.fillStyle = l.ok ? "#dfe7f5" : "rgba(223,231,245,0.45)"; c.font = font(600, 12); c.fillText(l.label, 32, y - 6);
        c.fillStyle = "rgba(223,231,245,0.55)"; c.font = font(400, 11);
        c.fillText(l.ok || l.items.length ? `${n.toLocaleString()} shown` : "waiting for feed", 32, y + 9);
      });
    }
  }

  /* ---------------- panels ---------------- */
  function buildLanes() {
    const st = (fx.live && fx.live.sources) || {};
    fx.lanes = Object.entries(st).filter(([, v]) => !/^(off|idle)/.test(String(v))).map(([key, v]) => {
      const items = fx.items.filter((i) => SOURCE_KEY(i.source) === key);
      return { key, items, label: LANE_LABEL[key] || key, ok: String(v).startsWith("ok"), color: items[0] ? colorOf(items[0].theme) : "#5b6b85" };
    });
  }

  /* counts per theme over the range: exact daily counts from the history file beyond a week */
  function themeSeries(themeId) {
    const now = Date.now(), from = now - rangeMs();
    const bins = fx.range.days === 2 ? 12 : fx.range.days === 7 ? 7 : 30, size = rangeMs() / bins, per = new Array(bins).fill(0);
    let total = 0;
    const daily = fx.range.days > 7 && fx.hist && fx.hist.daily && fx.hist.daily[themeId];
    if (daily) {
      for (const [d, n] of Object.entries(daily)) {
        const t = Date.parse(d + "T12:00:00Z"); if (t < from || t > now) continue;
        per[Math.min(bins - 1, Math.floor((t - from) / size))] += n; total += n;
      }
    } else {
      for (const it of fx.items) if (it.theme === themeId) { per[Math.min(bins - 1, Math.floor((it._t - from) / size))]++; total++; }
    }
    return { per, total };
  }

  function renderThemes() {
    $("flowThemes").replaceChildren(...fx.themes.map((th) => {
      const { per, total } = themeSeries(th.id), max = Math.max(1, ...per);
      const spark = h("div", { class: "spark", title: `Items per period, last ${fx.range.label}` });
      per.forEach((n) => { const b = h("span"); b.style.height = `${Math.max(2, (n / max) * 22)}px`; b.style.background = th.color; spark.append(b); });
      spark.classList.toggle("dense", per.length > 12);
      const btn = h("button", { type: "button", class: `theme${fx.focus === th.id ? " on" : ""}`, "aria-pressed": String(fx.focus === th.id) },
        h("span", { class: "dot" }), h("span", { class: "tl", text: th.label }),
        h("span", { class: "tn", text: total ? `${total.toLocaleString()} in ${fx.range.label}` : "waiting for feed" }), spark);
      btn.querySelector(".dot").style.background = th.color;
      btn.onclick = () => { fx.focus = fx.focus === th.id ? null : th.id; renderThemes(); if (reduce) draw(); };
      return btn;
    }));
  }

  function maybeTicker() {
    let head = null;
    for (let i = fx.items.length - 1; i >= 0; i--) if (fx.items[i]._t <= fx.vnow && fx.shown.has(fx.items[i].id)) { head = fx.items[i].id; break; }
    if (head === fx.tickerHead) return;
    fx.tickerHead = head;
    const list = [];
    for (let i = fx.items.length - 1; i >= 0 && list.length < 14; i--) { const it = fx.items[i]; if (it._t <= fx.vnow && fx.shown.has(it.id)) list.push(it); }
    $("flowTicker").replaceChildren(...list.map((it, k) => {
      const dot = h("span", { class: "dot" }); dot.style.background = colorOf(it.theme);
      const title = /^https?:\/\//.test(it.url) ? h("a", { href: it.url, target: "_blank", rel: "noopener noreferrer", text: it.title }) : h("span", { text: it.title });
      const when = fx.following && !fx.playing ? ago(Date.now() - it._t) : fmtClock(it._t);
      return h("li", { class: k === 0 && fx.playing ? "new" : null }, dot, h("div", {}, title, h("div", { class: "meta", text: `${it.source} · ${when}` })));
    }));
  }

  function renderSources() {
    const d = fx.live;
    $("flowUpdated").textContent = d.generated_at ? `Feeds checked ${ago(Date.now() - Date.parse(d.generated_at))}` : "";
    $("flowSourceList").textContent = Object.entries({ ...(d.sources || {}), ...(d.enrichment || {}) })
      .map(([k, v]) => `${LANE_LABEL[k] || k}: ${v}`).join(" · ");
  }

  function coverageNote() {
    const el = $("flowCoverage"), from = Date.now() - rangeMs();
    if (!fx.items.length) { el.textContent = "No items in this range yet."; return; }
    let first = Infinity;   // earliest item we hold at all, not just in this range
    for (const it of [...((fx.hist && fx.hist.items) || []), ...(fx.live.items || [])]) first = Math.min(first, it._t || Date.parse(it.ts));
    el.textContent = first - from > 1.5 * DAY
      ? `Items start ${fmtDay(first)}: feeds that only publish recent items build up history from their first scheduled run.`
      : fx.range.days > 7 ? `Beyond the last week, the orb shows the ${fx.hist ? fx.hist.items_per_theme_day : 12} most severe items per theme per day; counts are exact.` : "";
  }

  /* ---------------- interaction ---------------- */
  function nearest(ev) {
    const r = fx.canvas.getBoundingClientRect(), x = ev.clientX - r.left, y = ev.clientY - r.top;
    let best = null, bd = 100;
    for (const p of fx.pts) {
      if (!fx.landed.has(p.it.id) || p.it._t > fx.vnow || (fx.focus && fx.focus !== p.it.theme)) continue;
      const d = (p.x - x) ** 2 + (p.y - y) ** 2; if (d < bd) { bd = d; best = p; }
    }
    return best;
  }
  function hover(ev) {
    const p = nearest(ev); fx.canvas.style.cursor = p ? "pointer" : "default";
    if (!p) return hideTip();
    const th = fx.themes[fx.themeIdx.get(p.it.theme)];
    const att = actorMeta(p.it.actor);
    showTip(ev, [h("b", { text: th ? th.label : p.it.theme }), h("div", { text: p.it.title }),
      p.it.seen_on ? h("div", { class: "orgs", text: `Seen on ${p.it.seen_on.length} trackers: ${p.it.seen_on.join(", ")}` }) : null,
      att ? h("div", { class: "orgs", text: `MITRE ATT&CK: ${att.name} (${att.id})` }) : null,
      typeof p.it.epss === "number" ? h("div", { class: "orgs", text: `EPSS: ${(p.it.epss * 100).toFixed(p.it.epss < 0.1 ? 1 : 0)}% chance of exploitation in the next 30 days (higher than ${Math.round((p.it.epss_pct || 0) * 100)}% of CVEs)` }) : null,
      h("div", { class: "orgs", text: `${p.it.seen_on ? "First seen on " : ""}${p.it.source} · ${fmtClock(p.it._t)}` })].filter(Boolean));
  }
  function click(ev) {
    const p = nearest(ev); if (!p || !/^https?:\/\//.test(p.it.url)) return;
    const a = h("a", { href: p.it.url, target: "_blank", rel: "noopener noreferrer" }); document.body.append(a); a.click(); a.remove();
  }

  /* ---------------- actors + vulnerability velocity ---------------- */
  function actorMeta(name) {
    if (!name) return null;
    const m = (fx.hist && fx.hist.actors && fx.hist.actors[name]) || (fx.live.actors && fx.live.actors[name]);
    return m && /^https:\/\/attack\.mitre\.org\//.test(m.url) ? m : null;
  }

  function renderActors() {
    const counts = new Map(), now = Date.now(), from = now - rangeMs();
    const daily = fx.range.days > 7 && fx.hist && fx.hist.actors_daily;
    if (daily) {
      for (const [a, days] of Object.entries(daily)) {
        let n = 0; for (const [d, c] of Object.entries(days)) { const t = Date.parse(d + "T12:00:00Z"); if (t >= from && t <= now) n += c; }
        if (n) counts.set(a, n);
      }
    } else {
      for (const it of fx.items) if (it.actor) counts.set(it.actor, (counts.get(it.actor) || 0) + 1);
    }
    const top = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 10);
    const max = top.length ? top[0][1] : 1;
    $("flowActors").replaceChildren(...(top.length ? top.map(([name, n]) => {
      const att = actorMeta(name), bar = h("span", { class: "bar" }); bar.style.width = `${Math.max(3, (100 * n) / max)}%`;
      return h("li", {},
        h("span", { class: "an", title: name, text: name }),
        h("span", { class: "track" }, bar),
        h("span", { class: "ac", text: n.toLocaleString() }),
        att ? h("a", { class: "att", href: att.url, target: "_blank", rel: "noopener noreferrer", title: `MITRE ATT&CK ${att.type}: ${att.name}`, text: att.id }) : h("span", { class: "att none", text: "–" }));
    }) : [h("li", { class: "empty", text: "No named groups in this range yet." })]));
    const mapped = top.filter(([a]) => actorMeta(a)).length;
    $("flowActorsNote").textContent = top.length
      ? `Claims and incidents naming a group, last ${fx.range.label}. ${mapped} of ${top.length} link to a MITRE ATT&CK profile.`
      : "";
  }

  function velocitySeries(themeId, bins) {
    const now = Date.now(), from = now - rangeMs(), size = rangeMs() / bins, per = new Array(bins).fill(0);
    const daily = fx.range.days > 7 && fx.hist && fx.hist.daily && fx.hist.daily[themeId];
    if (daily) {
      for (const [d, n] of Object.entries(daily)) { const t = Date.parse(d + "T12:00:00Z"); if (t >= from && t <= now) per[Math.min(bins - 1, Math.floor((t - from) / size))] += n; }
    } else {
      for (const it of fx.items) if (it.theme === themeId) per[Math.min(bins - 1, Math.floor((it._t - from) / size))]++;
    }
    return per;
  }

  function renderVelocity() {
    const bins = fx.range.days === 2 ? 12 : fx.range.days, unit = fx.range.days === 2 ? "4 hours" : "day";
    const rows = [["cve", "New high/critical CVEs"], ["kev", "Added to CISA's exploited list"]];
    const W = Math.max(260, $("flowVelocity").clientWidth || 520), rowH = 64, padL = 4, padR = 4, H = rows.length * (rowH + 28);
    const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `Vulnerabilities per ${unit}, last ${fx.range.label}` });
    rows.forEach(([id, label], r) => {
      const per = velocitySeries(id, bins), max = Math.max(1, ...per), total = per.reduce((a, b) => a + b, 0);
      const y0 = r * (rowH + 28) + 18, bw = (W - padL - padR) / bins;
      svg.append(s("text", { x: padL, y: y0 - 5, "font-size": 12, fill: "#dfe7f5", "font-weight": 600, text: label }));
      svg.append(s("text", { x: W - padR, y: y0 - 5, "font-size": 11.5, fill: "#8fa1bf", "text-anchor": "end",
        text: total ? `${total.toLocaleString()} total · peak ${max.toLocaleString()} per ${unit}` : "waiting for feed" }));
      svg.append(s("line", { x1: padL, x2: W - padR, y1: y0 + rowH, y2: y0 + rowH, stroke: "#2a3b5e" }));
      per.forEach((n, i) => {
        if (!n) return;
        const hgt = (n / max) * rowH;
        const bar = s("rect", { x: padL + i * bw + bw * 0.12, y: y0 + rowH - hgt, width: Math.max(1, bw * 0.76), height: hgt, rx: 1, fill: colorOf(id) });
        bar.append(s("title", { text: `${n} in this ${unit}` }));
        svg.append(bar);
      });
    });
    $("flowVelocity").replaceChildren(svg);
  }

  init();
})();
