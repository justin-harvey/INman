/* Live threat flow: an orb of the last week's items from every source, split into
   theme sectors. New items stream in from their source lane and land at the rim;
   items drift toward the core as they age. Reuses h(), $(), showTip() and hideTip()
   from app.js. All feed text is untrusted: set with textContent only. */
"use strict";
(() => {
  const POLL_MS = 5 * 60 * 1000, FLY_MS = 1500, REPLAY_MS = 9000;
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const fx = { doc: null, items: [], byId: new Map(), themes: [], themeIdx: new Map(), focus: null,
               points: [], flights: [], landed: new Set(), canvas: null, ctx: null, geo: null, lanes: [], dpr: 1 };

  const hash = (s) => { let x = 2166136261; for (let i = 0; i < s.length; i++) { x ^= s.charCodeAt(i); x = Math.imul(x, 16777619); } return ((x >>> 0) % 100000) / 100000; };
  const ago = (ms) => { const m = Math.round(ms / 60000); return m < 60 ? `${m}m ago` : m < 2880 ? `${Math.round(m / 60)}h ago` : `${Math.round(m / 1440)}d ago`; };
  const SOURCE_KEY = (src) => src.endsWith(" status") ? "statuspages" : ({ ransomwatch: "ransomwatch", "ransomware.live": "ransomware_live", "CISA KEV": "cisa_kev", NVD: "nvd", Upptime: "upptime", INman: "inman" })[src] || "rss";
  const LANE_LABEL = { ransomwatch: "ransomwatch", ransomware_live: "ransomware.live", cisa_kev: "CISA KEV", nvd: "NVD CVEs", statuspages: "Status pages", upptime: "Upptime", rss: "Advisories & news RSS", inman: "INman curated" };

  async function load() {
    try {
      const r = await fetch(`data/flow.json?t=${Date.now()}`, { cache: "no-cache" });
      if (!r.ok) throw new Error(r.status);
      return await r.json();
    } catch (e) { return null; }
  }

  async function init() {
    const card = $("flowCard"); if (!card) return;
    const doc = await load();
    if (!doc) { card.classList.add("hidden"); return; }
    fx.canvas = $("orb"); fx.ctx = fx.canvas.getContext("2d");
    ingest(doc, true);
    $("flowReplay").onclick = () => replay();
    fx.canvas.addEventListener("pointermove", hover);
    fx.canvas.addEventListener("pointerleave", hideTip);
    fx.canvas.addEventListener("click", click);
    new ResizeObserver(layout).observe(fx.canvas.parentElement);
    layout();
    replay();
    if (!reduce) requestAnimationFrame(frame);
    setInterval(async () => { const d = await load(); if (d) ingest(d, false); }, POLL_MS);
  }

  /* -------- data -------- */
  function ingest(doc, first) {
    fx.doc = doc;
    fx.themes = doc.themes || [];
    fx.themeIdx = new Map(fx.themes.map((t, i) => [t.id, i]));
    const fresh = [];
    for (const it of doc.items || []) {
      if (!fx.themeIdx.has(it.theme)) continue;
      if (!fx.byId.has(it.id)) { it._t = Date.parse(it.ts); fx.byId.set(it.id, it); if (!first) fresh.push(it); }
    }
    const keep = new Set((doc.items || []).map((i) => i.id));
    for (const id of [...fx.byId.keys()]) if (!keep.has(id)) { fx.byId.delete(id); fx.landed.delete(id); }
    fx.items = [...fx.byId.values()].sort((a, b) => b._t - a._t);
    buildLanes(); place(); renderThemes(); renderTicker(new Set(fresh.map((i) => i.id))); renderSources();
    fresh.sort((a, b) => a._t - b._t).forEach((it, k) => launch(it, k * 350));
    if (reduce) draw();
  }

  function buildLanes() {
    const statuses = (fx.doc && fx.doc.sources) || {};
    fx.lanes = Object.entries(statuses).filter(([, v]) => v !== "off").map(([key, v]) => {
      const items = fx.items.filter((i) => SOURCE_KEY(i.source) === key);
      const day = items.filter((i) => Date.now() - i._t < 864e5).length;
      const theme = items[0] ? items[0].theme : null;
      return { key, label: LANE_LABEL[key] || key, ok: String(v).startsWith("ok"), status: v, day, color: theme ? colorOf(theme) : "#5b6b85" };
    });
  }
  const colorOf = (themeId) => (fx.themes[fx.themeIdx.get(themeId)] || {}).color || "#9db4d6";

  /* -------- geometry -------- */
  function layout() {
    const wrap = fx.canvas.parentElement, W = wrap.clientWidth;
    const H = Math.round(Math.max(360, Math.min(560, W * (W < 640 ? 0.95 : 0.56))));
    fx.dpr = Math.min(2, window.devicePixelRatio || 1);
    fx.canvas.width = W * fx.dpr; fx.canvas.height = H * fx.dpr;
    fx.canvas.style.width = `${W}px`; fx.canvas.style.height = `${H}px`;
    const lanesW = W >= 640 ? 190 : 0;
    const cx = lanesW + (W - lanesW) / 2, cy = H / 2 + 6;
    const R = Math.min((W - lanesW) / 2 - (W >= 640 ? 100 : 20), H / 2 - (W >= 640 ? 44 : 26));
    fx.geo = { W, H, lanesW, cx, cy, R };
    place(); draw();
  }

  function sector(themeId) {
    const n = Math.max(1, fx.themes.length), i = fx.themeIdx.get(themeId), gap = 0.06;
    const a0 = -Math.PI / 2 + (i * 2 * Math.PI) / n + gap, a1 = -Math.PI / 2 + ((i + 1) * 2 * Math.PI) / n - gap;
    return [a0, a1];
  }

  function place() {
    if (!fx.geo) return;
    const { cx, cy, R } = fx.geo, win = ((fx.doc && fx.doc.window_days) || 7) * 864e5, now = Date.now();
    fx.points = fx.items.map((it) => {
      const [a0, a1] = sector(it.theme), h1 = hash(it.id), h2 = hash(it.id + "r");
      const a = a0 + 0.04 + h1 * (a1 - a0 - 0.08);
      const age = Math.min(1, Math.max(0, (now - it._t) / win));
      const r = R * Math.min(0.97, Math.max(0.18, 0.22 + 0.74 * (1 - age) + (h2 - 0.5) * 0.08));
      return { it, a, r, x: cx + Math.cos(a) * r, y: cy + Math.sin(a) * r, s: 1.4 + 2.6 * it.severity, recent: now - it._t < 864e5 };
    });
  }

  function laneAnchor(key) {
    const { lanesW, H } = fx.geo; const i = fx.lanes.findIndex((l) => l.key === key);
    if (!lanesW || i < 0) return { x: -10, y: H * (0.2 + 0.6 * Math.random()) };
    return { x: lanesW - 14, y: laneY(i) };
  }
  const laneY = (i) => { const { H } = fx.geo, n = Math.max(1, fx.lanes.length), top = 64, span = H - 110; return top + (n === 1 ? span / 2 : (i * span) / (n - 1)); };

  /* -------- animation -------- */
  function launch(it, delay) {
    if (reduce) { fx.landed.add(it.id); return; }
    fx.landed.delete(it.id);
    fx.flights.push({ id: it.id, start: performance.now() + delay, from: laneAnchor(SOURCE_KEY(it.source)) });
  }
  function replay() {
    const recent = fx.items.filter((i) => Date.now() - i._t < 864e5 * 2).sort((a, b) => a._t - b._t);
    fx.landed = new Set(fx.items.filter((i) => !recent.includes(i)).map((i) => i.id));
    fx.flights = [];
    const step = recent.length ? Math.min(400, REPLAY_MS / recent.length) : 0;
    recent.forEach((it, k) => launch(it, k * step));
    if (reduce) draw();
  }
  function frame() { draw(); requestAnimationFrame(frame); }

  function draw() {
    if (!fx.geo) return;
    const c = fx.ctx, { W, H, cx, cy, R, lanesW } = fx.geo, t = performance.now();
    c.setTransform(fx.dpr, 0, 0, fx.dpr, 0, 0);
    c.clearRect(0, 0, W, H);

    // sphere body
    const g = c.createRadialGradient(cx - R * 0.3, cy - R * 0.35, R * 0.05, cx, cy, R * 1.05);
    g.addColorStop(0, "rgba(64,96,150,0.55)"); g.addColorStop(0.55, "rgba(20,35,64,0.55)"); g.addColorStop(1, "rgba(8,14,28,0.2)");
    c.fillStyle = g; c.beginPath(); c.arc(cx, cy, R * 1.02, 0, Math.PI * 2); c.fill();
    c.strokeStyle = "rgba(157,180,214,0.10)"; c.lineWidth = 1;
    for (let k = 1; k <= 3; k++) { c.beginPath(); c.ellipse(cx, cy, R, R * (0.25 * k), 0, 0, Math.PI * 2); c.stroke(); }
    c.beginPath(); c.ellipse(cx, cy, R * 0.45, R, 0, 0, Math.PI * 2); c.stroke();
    // age rings: rim = now, core = a week ago
    c.setLineDash([2, 5]); c.strokeStyle = "rgba(157,180,214,0.16)";
    [0.96, 0.59, 0.22].forEach((f) => { c.beginPath(); c.arc(cx, cy, R * f, 0, Math.PI * 2); c.stroke(); });
    c.setLineDash([]);

    // sectors on the rim + labels
    c.font = "600 11.5px -apple-system, Segoe UI, Roboto, Arial, sans-serif"; c.textBaseline = "middle";
    fx.themes.forEach((th) => {
      const [a0, a1] = sector(th.id), dim = fx.focus && fx.focus !== th.id;
      c.strokeStyle = th.color; c.globalAlpha = dim ? 0.15 : 0.85; c.lineWidth = 4;
      c.beginPath(); c.arc(cx, cy, R * 1.04, a0, a1); c.stroke();
      c.globalAlpha = 1;
      if (!lanesW) return; // narrow screens: the theme cards below carry the labels
      const am = (a0 + a1) / 2, lr = R * 1.04 + 16, ly = cy + Math.sin(am) * lr;
      const tw = c.measureText(th.label).width, ax = cx + Math.cos(am) * lr;
      const left = Math.cos(am) > 0.25 ? ax : Math.cos(am) < -0.25 ? ax - tw : ax - tw / 2;
      c.fillStyle = dim ? "rgba(223,231,245,0.35)" : "#dfe7f5"; c.textAlign = "left";
      c.fillText(th.label, Math.max(lanesW + 4, Math.min(W - tw - 8, left)), ly + (Math.abs(Math.sin(am)) > 0.9 ? Math.sign(Math.sin(am)) * 4 : 0));
    });

    // landed points
    c.globalCompositeOperation = "lighter";
    for (const p of fx.points) {
      if (!fx.landed.has(p.it.id)) continue;
      const col = colorOf(p.it.theme), dim = fx.focus && fx.focus !== p.it.theme;
      c.globalAlpha = dim ? 0.08 : p.recent ? 0.95 : 0.55;
      c.strokeStyle = col; c.lineWidth = 1;
      const nl = 3 + 12 * p.it.severity;
      c.beginPath(); c.moveTo(p.x, p.y); c.lineTo(p.x + Math.cos(p.a) * nl, p.y + Math.sin(p.a) * nl); c.stroke();
      c.fillStyle = col; c.beginPath(); c.arc(p.x, p.y, p.s, 0, Math.PI * 2); c.fill();
      if (p.recent && !dim && !reduce) {
        const pulse = (Math.sin(t / 600 + p.a * 7) + 1) / 2;
        c.globalAlpha = 0.18 + 0.2 * pulse; c.beginPath(); c.arc(p.x, p.y, p.s + 3 + 3 * pulse, 0, Math.PI * 2); c.fill();
      }
    }
    // flights
    const done = [];
    for (const f of fx.flights) {
      const k = (t - f.start) / FLY_MS; if (k < 0) continue;
      const p = fx.points.find((q) => q.it.id === f.id); if (!p) { done.push(f); continue; }
      if (k >= 1) { fx.landed.add(f.id); done.push(f); continue; }
      const mx = (f.from.x + p.x) / 2, my = Math.min(f.from.y, p.y) - 40;
      const pt = (u) => [(1 - u) ** 2 * f.from.x + 2 * (1 - u) * u * mx + u * u * p.x, (1 - u) ** 2 * f.from.y + 2 * (1 - u) * u * my + u * u * p.y];
      const e = 1 - (1 - k) ** 3, col = colorOf(p.it.theme);
      c.strokeStyle = col; c.lineWidth = 1.5; c.globalAlpha = 0.5; c.beginPath();
      for (let u = Math.max(0, e - 0.25); u <= e; u += 0.025) { const [x, y] = pt(u); u === Math.max(0, e - 0.25) ? c.moveTo(x, y) : c.lineTo(x, y); }
      c.stroke();
      const [hx, hy] = pt(e); c.globalAlpha = 1; c.fillStyle = col; c.beginPath(); c.arc(hx, hy, 2.6, 0, Math.PI * 2); c.fill();
    }
    fx.flights = fx.flights.filter((f) => !done.includes(f));
    c.globalCompositeOperation = "source-over"; c.globalAlpha = 1;

    // core
    const core = c.createRadialGradient(cx, cy, 0, cx, cy, R * 0.2);
    core.addColorStop(0, "rgba(223,231,245,0.35)"); core.addColorStop(1, "rgba(223,231,245,0)");
    c.fillStyle = core; c.beginPath(); c.arc(cx, cy, R * 0.2, 0, Math.PI * 2); c.fill();
    c.fillStyle = "rgba(223,231,245,0.55)"; c.font = "10.5px -apple-system, Segoe UI, Roboto, Arial, sans-serif"; c.textAlign = "center";
    c.fillText("7 days ago", cx, cy + R * 0.22 + 10);
    c.fillText("now", cx, cy - R * 0.96 + 12);

    // source lanes
    if (lanesW) {
      c.textAlign = "left"; c.font = "600 11px -apple-system, Segoe UI, Roboto, Arial, sans-serif";
      c.fillStyle = "rgba(223,231,245,0.6)"; c.fillText("SOURCES", 14, 34);
      fx.lanes.forEach((l, i) => {
        const y = laneY(i);
        c.fillStyle = l.ok ? l.color : "#5b6b85"; c.beginPath(); c.arc(20, y, 4, 0, Math.PI * 2); c.fill();
        c.fillStyle = l.ok ? "#dfe7f5" : "rgba(223,231,245,0.45)"; c.font = "600 12px -apple-system, Segoe UI, Roboto, Arial, sans-serif";
        c.fillText(l.label, 32, y - 6);
        c.fillStyle = "rgba(223,231,245,0.55)"; c.font = "11px -apple-system, Segoe UI, Roboto, Arial, sans-serif";
        c.fillText(l.ok ? `${l.day} in 24h` : "waiting for feed", 32, y + 9);
      });
    }
  }

  /* -------- interaction -------- */
  function nearest(ev) {
    const r = fx.canvas.getBoundingClientRect(), x = ev.clientX - r.left, y = ev.clientY - r.top;
    let best = null, bd = 100;
    for (const p of fx.points) {
      if (!fx.landed.has(p.it.id) || (fx.focus && fx.focus !== p.it.theme)) continue;
      const d = (p.x - x) ** 2 + (p.y - y) ** 2; if (d < bd) { bd = d; best = p; }
    }
    return best;
  }
  function hover(ev) {
    const p = nearest(ev); fx.canvas.style.cursor = p ? "pointer" : "default";
    if (!p) return hideTip();
    const th = fx.themes[fx.themeIdx.get(p.it.theme)];
    showTip(ev, [h("b", { text: th ? th.label : p.it.theme }), h("div", { text: p.it.title }),
      h("div", { class: "orgs", text: `${p.it.source} · ${ago(Date.now() - p.it._t)}` })]);
  }
  function click(ev) {
    const p = nearest(ev); if (!p || !/^https?:\/\//.test(p.it.url)) return;
    const a = h("a", { href: p.it.url, target: "_blank", rel: "noopener noreferrer" }); document.body.append(a); a.click(); a.remove();
  }

  /* -------- HTML panels -------- */
  function renderThemes() {
    const now = Date.now(), days = 7;
    $("flowThemes").replaceChildren(...fx.themes.map((th) => {
      const its = fx.items.filter((i) => i.theme === th.id);
      const day = its.filter((i) => now - i._t < 864e5).length;
      const per = Array.from({ length: days }, (_, k) => its.filter((i) => Math.floor((now - i._t) / 864e5) === days - 1 - k).length);
      const max = Math.max(1, ...per);
      const spark = h("div", { class: "spark", title: "Items per day, last 7 days" });
      per.forEach((n) => { const b = h("span"); b.style.height = `${Math.max(2, (n / max) * 22)}px`; b.style.background = th.color; spark.append(b); });
      const btn = h("button", { type: "button", class: `theme${fx.focus === th.id ? " on" : ""}`, "aria-pressed": String(fx.focus === th.id) },
        h("span", { class: "dot" }), h("span", { class: "tl", text: th.label }),
        h("span", { class: "tn", text: its.length ? `${day} in 24h · ${its.length} this week` : "waiting for feed" }), spark);
      btn.querySelector(".dot").style.background = th.color;
      btn.onclick = () => { fx.focus = fx.focus === th.id ? null : th.id; renderThemes(); if (reduce) draw(); };
      return btn;
    }));
  }

  function renderTicker(fresh) {
    const now = Date.now();
    $("flowTicker").replaceChildren(...fx.items.slice(0, 14).map((it) => {
      const dot = h("span", { class: "dot" }); dot.style.background = colorOf(it.theme);
      const title = /^https?:\/\//.test(it.url) ? h("a", { href: it.url, target: "_blank", rel: "noopener noreferrer", text: it.title }) : h("span", { text: it.title });
      return h("li", { class: fresh && fresh.has(it.id) ? "new" : null }, dot,
        h("div", {}, title, h("div", { class: "meta", text: `${it.source} · ${ago(now - it._t)}` })));
    }));
  }

  function renderSources() {
    const d = fx.doc;
    $("flowUpdated").textContent = d.generated_at ? `Feeds checked ${ago(Date.now() - Date.parse(d.generated_at))} · ${fx.items.length} items this week` : "";
    $("flowSourceList").textContent = Object.entries(d.sources || {}).map(([k, v]) => `${LANE_LABEL[k] || k}: ${v}`).join(" · ");
  }

  init();
})();
