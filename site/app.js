/* INman Cyber Incident Monitor — no dependencies.
   Every value from the data files is untrusted (it comes from external feeds),
   so text is always set with textContent / setAttribute, never innerHTML. */
"use strict";

const TIERS = { 1: "Confirmed", 2: "Claimed (unverified)", 3: "Suspected-cyber outage", 4: "Technical outage" };
const TIER_COLOR = { 1: "#c0392b", 2: "#e67e22", 3: "#d4a017", 4: "#8a8f98" };
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const SVGNS = "http://www.w3.org/2000/svg";

const state = {
  all: [], events: [], context: null, meta: null,
  group: "All", tiers: new Set([1, 2, 3, 4]), orgType: "All", industry: "All", usState: "All", q: "",
  gran: "day", range: null, domain: null, sel: null, showContext: false,
  sort: { key: "date", dir: -1 },
};

/* ---------- small helpers ---------- */
const $ = (id) => document.getElementById(id);
function h(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "text") n.textContent = v; else if (k.startsWith("on")) n.addEventListener(k.slice(2), v); else n.setAttribute(k, v);
  }
  for (const k of kids) if (k != null) n.append(k);
  return n;
}
function s(tag, attrs = {}, ...kids) {
  const n = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null) continue;
    if (k === "text") n.textContent = v; else if (k.startsWith("on")) n.addEventListener(k.slice(2), v); else n.setAttribute(k, v);
  }
  for (const k of kids) if (k != null) n.append(k);
  return n;
}
const dayNum = (iso) => { const [y, m, d] = iso.slice(0, 10).split("-").map(Number); return Date.UTC(y, m - 1, d) / 864e5; };
const isoOf = (n) => new Date(n * 864e5).toISOString().slice(0, 10);
const fmtDay = (n) => { const d = new Date(n * 864e5); return `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}`; };
const weekStart = (n) => n - ((new Date(n * 864e5).getUTCDay() + 6) % 7);
const fmtNum = (v) => v >= 1e9 ? (v / 1e9).toFixed(1) + "B" : v >= 1e6 ? (v / 1e6).toFixed(1) + "M" : v >= 1e4 ? Math.round(v / 1e3) + "K" : v.toLocaleString();
const counted = (r) => (r.records && r.tier !== 2 && !/^claimed/i.test(r.count_basis || "")) ? r.records : 0;
const safeUrl = (u) => /^https?:\/\//i.test(u || "") ? u : null;

/* ---------- data ---------- */
async function getJSON(path, optional) {
  try {
    const r = await fetch(path, { cache: "no-cache" });
    if (!r.ok) throw new Error(r.status);
    return await r.json();
  } catch (e) {
    if (optional) return null;
    throw e;
  }
}

async function init() {
  const [inc, ev, ctx, meta] = await Promise.all([
    getJSON("data/incidents.json"), getJSON("data/events.json", true),
    getJSON("data/context.json", true), getJSON("data/meta.json", true),
  ]);
  state.all = inc.incidents.filter((r) => r && r.date && TIERS[r.tier]).map((r) => ({ ...r, _d: dayNum(r.date) }));
  state.events = (ev && ev.events || []).map((e) => ({ ...e, _d: dayNum(e.date) }));
  state.context = ctx; state.meta = meta;
  const ds = state.all.map((r) => r._d);
  state.domain = [weekStart(Math.min(...ds)), Math.max(...ds)];
  state.range = [...state.domain];
  buildControls();
  renderStatus();
  render();
  new ResizeObserver(() => { renderChart(); renderBrush(); }).observe($("chart"));
}

function filtered() {
  const q = state.q.trim().toLowerCase();
  return state.all.filter((r) =>
    state.tiers.has(r.tier) &&
    (state.group === "All" || r.sector_group === state.group) &&
    (state.orgType === "All" || r.org_type === state.orgType) &&
    (state.industry === "All" || r.industry === state.industry) &&
    (state.usState === "All" || r.state === state.usState) &&
    (!q || [r.org, r.actor, r.summary, r.incident_type, r.industry].join(" ").toLowerCase().includes(q)));
}
const inRange = (r) => r._d >= state.range[0] && r._d <= state.range[1];

/* Buckets cover the whole domain so moving averages and cumulative lines start correctly. */
function buckets(rows, gran) {
  const step = gran === "week" ? 7 : 1;
  const start = gran === "week" ? weekStart(state.domain[0]) : state.domain[0];
  const out = [];
  for (let a = start; a <= state.domain[1]; a += step) out.push({ a, b: a + step - 1, t: { 1: 0, 2: 0, 3: 0, 4: 0 }, total: 0, rec: 0, rows: [], ctx: 0 });
  for (const r of rows) {
    if (gran === "day" && r.date_precision === "Month") continue;
    const i = Math.floor((r._d - start) / step);
    const bk = out[i]; if (!bk) continue;
    bk.t[r.tier]++; bk.total++; bk.rec += counted(r); bk.rows.push(r);
  }
  const win = gran === "week" ? 4 : 7;
  let cum = 0;
  out.forEach((bk, i) => {
    const w = out.slice(Math.max(0, i - win + 1), i + 1);
    bk.avg = w.reduce((s2, x) => s2 + x.total, 0) / w.length;
    cum += bk.rec; bk.cum = cum;
  });
  const byDay = state.context && state.context.by_day;
  if (byDay) for (const [d, c] of Object.entries(byDay)) {
    const i = Math.floor((dayNum(d) - start) / step); if (out[i]) out[i].ctx += c;
  }
  return out;
}

/* ---------- controls ---------- */
function options(sel, values) {
  sel.replaceChildren(h("option", { value: "All", text: "All" }), ...values.map((v) => h("option", { value: v, text: v })));
}
function buildControls() {
  const uniq = (k) => [...new Set(state.all.map((r) => r[k]).filter(Boolean))].sort();
  options($("fOrgType"), uniq("org_type"));
  options($("fIndustry"), uniq("industry"));
  options($("fState"), uniq("state"));
  $("fOrgType").onchange = (e) => { state.orgType = e.target.value; render(); };
  $("fIndustry").onchange = (e) => { state.industry = e.target.value; render(); };
  $("fState").onchange = (e) => { state.usState = e.target.value; render(); };
  let t; $("fSearch").oninput = (e) => { clearTimeout(t); t = setTimeout(() => { state.q = e.target.value; render(); }, 150); };
  document.querySelectorAll("[data-group]").forEach((b) => b.onclick = () => {
    state.group = b.dataset.group;
    document.querySelectorAll("[data-group]").forEach((x) => x.classList.toggle("on", x === b)); render();
  });
  document.querySelectorAll("[data-gran]").forEach((b) => b.onclick = () => {
    state.gran = b.dataset.gran; state.sel = null;
    document.querySelectorAll("[data-gran]").forEach((x) => x.classList.toggle("on", x === b)); render();
  });
  const tt = $("tierToggles");
  for (const k of [1, 2, 3, 4]) {
    const b = h("button", { type: "button", "aria-pressed": "true" }, h("span", { class: `sw t${k}` }), TIERS[k]);
    b.onclick = () => {
      if (state.tiers.has(k) && state.tiers.size > 1) state.tiers.delete(k); else state.tiers.add(k);
      b.classList.toggle("off", !state.tiers.has(k)); b.setAttribute("aria-pressed", String(state.tiers.has(k))); render();
    };
    tt.append(b);
  }
  $("showContext").onchange = (e) => { state.showContext = e.target.checked; renderChart(); renderLegend(); };
  if (!state.context || !state.context.by_day || !Object.keys(state.context.by_day).length) $("showContext").parentElement.classList.add("hidden");
  $("reset").onclick = () => {
    Object.assign(state, { group: "All", orgType: "All", industry: "All", usState: "All", q: "", sel: null, tiers: new Set([1, 2, 3, 4]) });
    state.range = [...state.domain];
    $("fOrgType").value = $("fIndustry").value = $("fState").value = "All"; $("fSearch").value = "";
    document.querySelectorAll("[data-group]").forEach((x) => x.classList.toggle("on", x.dataset.group === "All"));
    tt.querySelectorAll("button").forEach((b) => { b.classList.remove("off"); b.setAttribute("aria-pressed", "true"); });
    render();
  };
  $("bucketChip").onclick = () => { state.sel = null; render(); };
  $("exportCsv").onclick = exportCsv;
}

function renderStatus() {
  const m = state.meta;
  $("status").textContent = m && m.updated_at ? `Data updated ${new Date(m.updated_at).toLocaleString()}` : "Backfill data (feeds not run yet)";
  if (m && m.feeds) $("feedStatus").textContent = "Feed status: " + Object.entries(m.feeds).map(([k, v]) => `${k}: ${v}`).join(" · ");
}

/* ---------- render ---------- */
function render() { renderKpis(); renderLegend(); renderChart(); renderBrush(); renderBreakdowns(); renderTable(); }

function renderKpis() {
  const rows = filtered().filter(inRange);
  const n = (t) => rows.filter((r) => r.tier === t).length;
  const rec = rows.reduce((a, r) => a + counted(r), 0);
  const dis = rows.filter((r) => r.ops_disrupted).length;
  const k = (v, l, cls) => h("div", { class: `kpi ${cls || ""}` }, h("div", { class: "v", text: v }), h("div", { class: "l", text: l }));
  $("kpis").replaceChildren(
    k(rows.length.toLocaleString(), `Incidents, ${fmtDay(state.range[0])} – ${fmtDay(state.range[1])}`),
    k(n(1), "Confirmed attacks/breaches", "t1"), k(n(2), "Unverified claims", "t2"),
    k(n(3) + n(4), "Outages (suspected cyber + technical)", "t34"),
    k(fmtNum(rec), "Records exposed (victim-reported)"),
    k(rows.length ? Math.round((100 * dis) / rows.length) + "%" : "–", "Disrupted operations"));
}

function renderLegend() {
  const item = (cls, label) => h("span", {}, h("span", { class: `sw ${cls}` }), label);
  const win = state.gran === "week" ? "4-week" : "7-day";
  $("legend").replaceChildren(
    item("t1", TIERS[1]), item("t2", TIERS[2] + " (hatched)"), item("t3", TIERS[3]), item("t4", TIERS[4]),
    item("avg", `${win} average`), item("rec", "Cumulative records exposed (log scale)"),
    ...(state.showContext ? [item("ctx", "Global leak-site posts (indexed)")] : []));
  $("chartTitle").textContent = state.gran === "week" ? "Weekly incident volume" : "Daily incident volume";
}

function niceMax(v) { if (v <= 4) return 4; const p = Math.pow(10, Math.floor(Math.log10(v))); for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p; return 10 * p; }

function renderChart() {
  const box = $("chart"); const W = Math.max(320, box.clientWidth); const narrow = W < 560;
  const padL = 34, padR = narrow ? 40 : 52, topY = 18, topH = narrow ? 90 : 120, gap = 26, botH = narrow ? 130 : 170;
  const botY = topY + topH + gap, H = botY + botH + 26;
  const all = buckets(filtered(), state.gran);
  const bks = all.filter((b) => b.b >= state.range[0] && b.a <= state.range[1]);
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Incident volume by tier with moving average" });
  svg.append(s("defs", {}, s("pattern", { id: "hatch", width: 6, height: 6, patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)" },
    s("rect", { width: 6, height: 6, fill: "#f5c79c" }), s("line", { x1: 0, y1: 0, x2: 0, y2: 6, stroke: TIER_COLOR[2], "stroke-width": 3 }))));
  if (!bks.length) { box.replaceChildren(svg); return; }
  const bw = (W - padL - padR) / bks.length, X = (i) => padL + i * bw;

  // bottom pane: stacked bars
  const yMax = niceMax(Math.max(1, ...bks.map((b) => b.total)));
  const Yb = (v) => botY + botH - (v / yMax) * botH;
  const grid = s("g", { stroke: "#e3e6eb" });
  const nT = yMax % 4 === 0 ? 4 : 5;
  for (let i = 0; i <= nT; i++) {
    const v = (yMax / nT) * i, y = Yb(v);
    grid.append(s("line", { x1: padL, x2: W - padR, y1: y, y2: y }));
    svg.append(s("text", { x: padL - 6, y: y + 4, "text-anchor": "end", "font-size": 10.5, fill: "#5d6675", text: Number.isInteger(v) ? v : v.toFixed(1) }));
  }
  svg.prepend(grid);
  const bars = s("g");
  bks.forEach((b, i) => {
    let acc = 0; const w = Math.max(1, bw * (bw > 6 ? 0.78 : 0.95)), x = X(i) + (bw - w) / 2;
    for (const t of [1, 2, 3, 4]) {
      if (!b.t[t]) continue;
      const y0 = Yb(acc + b.t[t]), y1 = Yb(acc);
      bars.append(s("rect", { x, y: y0, width: w, height: Math.max(0.5, y1 - y0), fill: t === 2 ? "url(#hatch)" : TIER_COLOR[t] }));
      acc += b.t[t];
    }
    if (state.sel && b.a === state.sel.a) bars.append(s("rect", { x: X(i), y: botY - 4, width: bw, height: botH + 4, fill: "none", stroke: "#2457c5", "stroke-width": 1.5 }));
  });
  svg.append(bars);
  svg.append(s("text", { x: padL, y: botY - 8, "font-size": 11, fill: "#5d6675", text: `Incidents per ${state.gran}` }));

  // top pane: moving average + cumulative records (+ context)
  const aMax = niceMax(Math.max(1, ...bks.map((b) => b.avg)));
  const Ya = (v) => topY + topH - (v / aMax) * topH;
  const cx = (i) => X(i) + bw / 2;
  svg.append(s("line", { x1: padL, x2: W - padR, y1: topY + topH, y2: topY + topH, stroke: "#e3e6eb" }));
  svg.append(s("text", { x: padL - 6, y: topY + 4, "text-anchor": "end", "font-size": 10.5, fill: "#5d6675", text: aMax }));
  if (state.showContext) {
    const cMax = Math.max(1, ...bks.map((b) => b.ctx));
    const pts = bks.map((b, i) => `${cx(i)},${topY + topH - (b.ctx / cMax) * topH}`);
    svg.append(s("polygon", { points: `${cx(0)},${topY + topH} ${pts.join(" ")} ${cx(bks.length - 1)},${topY + topH}`, fill: "#dfe6f1", stroke: "#b7c3d6" }));
  }
  const lg = (v) => Math.log10(Math.max(1, v));
  const rTop = Math.max(3, Math.ceil(lg(Math.max(...bks.map((b) => b.cum)))));
  const Yr = (v) => topY + topH - (lg(v) / rTop) * topH;
  for (let p = 3; p <= rTop; p += rTop > 6 ? 2 : 1) {
    svg.append(s("text", { x: W - padR + 6, y: Yr(10 ** p) + 4, "font-size": 10.5, fill: "#2457c5", text: fmtNum(10 ** p) }));
  }
  svg.append(s("polyline", { points: bks.map((b, i) => `${cx(i)},${Yr(b.cum)}`).join(" "), fill: "none", stroke: "#2457c5", "stroke-width": 1.5, "stroke-dasharray": "4 3" }));
  svg.append(s("polyline", { points: bks.map((b, i) => `${cx(i)},${Ya(b.avg)}`).join(" "), fill: "none", stroke: "#142340", "stroke-width": 2.2 }));

  // x axis
  const every = Math.max(1, Math.ceil(bks.length / (narrow ? 5 : 10)));
  bks.forEach((b, i) => {
    if (i % every) return;
    svg.append(s("text", { x: cx(i), y: botY + botH + 16, "text-anchor": "middle", "font-size": 10.5, fill: "#5d6675", text: fmtDay(b.a) }));
  });

  // event markers (events in the same bucket share one flag)
  const evGroups = new Map();
  state.events.forEach((e, k) => {
    const i = bks.findIndex((b) => e._d >= b.a && e._d <= b.b); if (i < 0) return;
    if (!evGroups.has(i)) evGroups.set(i, []);
    evGroups.get(i).push({ ...e, n: k + 1 });
  });
  // merge flags that would overlap on narrow screens
  const merged = [];
  for (const [i, list] of [...evGroups.entries()].sort((a, b) => a[0] - b[0])) {
    const last = merged[merged.length - 1];
    if (last && cx(i) - cx(last[0]) < 16) last[1].push(...list); else merged.push([i, [...list]]);
  }
  for (const [i, list] of merged) {
    const x = cx(i), label = list.map((e) => e.n).join(","), fw = 6 + label.length * 5.5;
    const g = s("g", { class: "ev" },
      s("line", { x1: x, x2: x, y1: topY, y2: botY + botH, stroke: "#142340", "stroke-dasharray": "2 3", "stroke-opacity": 0.45 }),
      s("rect", { x: x - fw / 2, y: topY - 12, width: fw, height: 11, rx: 2, fill: "#142340" }),
      s("text", { x, y: topY - 3.5, "text-anchor": "middle", "font-size": 8.5, fill: "#fff", text: label }));
    g.addEventListener("pointerenter", (ev2) => showTip(ev2, list.flatMap((e) => [h("b", { text: `${fmtDay(e._d)} · Event ${e.n}` }), h("div", { text: e.label })])));
    g.addEventListener("pointerleave", hideTip);
    svg.append(g);
  }

  // hover / click targets
  const hit = s("g", { fill: "transparent" });
  bks.forEach((b, i) => {
    const r = s("rect", { x: X(i), y: topY, width: bw, height: botY + botH - topY, cursor: "pointer" });
    r.addEventListener("pointermove", (ev2) => showTip(ev2, bucketTip(b)));
    r.addEventListener("pointerleave", hideTip);
    r.addEventListener("click", () => { state.sel = state.sel && state.sel.a === b.a ? null : { a: b.a, b: b.b }; renderChart(); renderTable(); });
    hit.append(r);
  });
  svg.append(hit);
  box.replaceChildren(svg);
}

function bucketTip(b) {
  const label = b.a === b.b ? fmtDay(b.a) : `Week of ${fmtDay(b.a)}`;
  const rows = [h("b", { text: `${label} · ${b.total} incident${b.total === 1 ? "" : "s"}` })];
  for (const t of [1, 2, 3, 4]) if (b.t[t]) rows.push(h("div", { class: "row" }, h("span", { text: TIERS[t] }), h("span", { text: b.t[t] })));
  rows.push(h("div", { class: "row" }, h("span", { text: "Moving average" }), h("span", { text: b.avg.toFixed(1) })));
  if (b.rows.length) {
    const names = b.rows.slice(0, 6).map((r) => r.org).join(", ") + (b.rows.length > 6 ? ` +${b.rows.length - 6} more` : "");
    rows.push(h("div", { class: "orgs", text: names }));
  }
  return rows;
}
function showTip(ev, kids) {
  const t = $("tip"); t.replaceChildren(...kids); t.classList.remove("hidden");
  const x = Math.min(window.innerWidth - t.offsetWidth - 8, ev.clientX + 14);
  t.style.left = `${Math.max(8, x)}px`; t.style.top = `${Math.max(8, ev.clientY - t.offsetHeight - 10)}px`;
}
function hideTip() { $("tip").classList.add("hidden"); }

/* ---------- range brush ---------- */
function renderBrush() {
  const box = $("brush"); const W = Math.max(320, box.clientWidth), H = 46, padL = 34, padR = W < 560 ? 40 : 52;
  const all = buckets(filtered(), "day");
  const [d0, d1] = state.domain, span = d1 - d0 + 1, bw = (W - padL - padR) / span;
  const X = (d) => padL + (d - d0) * bw, D = (x) => Math.min(d1, Math.max(d0, d0 + Math.floor((x - padL) / bw)));
  const m = Math.max(1, ...all.map((b) => b.total));
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, "aria-hidden": "true" });
  svg.append(s("rect", { x: padL, y: 0, width: W - padL - padR, height: H - 14, fill: "#f4f5f7" }));
  all.forEach((b) => b.total && svg.append(s("rect", { x: X(b.a), y: H - 14 - (b.total / m) * (H - 18), width: Math.max(1, bw - 0.5), height: (b.total / m) * (H - 18), fill: "#9aa6b8" })));
  const win = s("rect", { x: X(state.range[0]), y: 0, width: (state.range[1] - state.range[0] + 1) * bw, height: H - 14, fill: "rgba(36,87,197,.14)", stroke: "#2457c5" });
  svg.append(win);
  [d0, Math.round((d0 + d1) / 2), d1].forEach((d, i) => svg.append(s("text", { x: X(d) + (i === 2 ? bw : 0), y: H - 2, "font-size": 10, fill: "#5d6675", "text-anchor": ["start", "middle", "end"][i], text: fmtDay(d) })));
  box.replaceChildren(svg);

  let mode = null, anchor = 0, start = null;
  const toX = (ev) => (ev.clientX - svg.getBoundingClientRect().left) * (W / svg.getBoundingClientRect().width);
  svg.onpointerdown = (ev) => {
    const x = toX(ev), a = X(state.range[0]), b = X(state.range[1] + 1);
    svg.setPointerCapture(ev.pointerId);
    if (Math.abs(x - a) < 8) mode = "l"; else if (Math.abs(x - b) < 8) mode = "r";
    else if (x > a && x < b) { mode = "move"; anchor = D(x); start = [...state.range]; }
    else { mode = "new"; anchor = D(x); state.range = [anchor, anchor]; }
  };
  svg.onpointermove = (ev) => {
    if (!mode) return;
    const d = D(toX(ev));
    if (mode === "l") state.range = [Math.min(d, state.range[1]), state.range[1]];
    else if (mode === "r") state.range = [state.range[0], Math.max(d, state.range[0])];
    else if (mode === "new") state.range = [Math.min(anchor, d), Math.max(anchor, d)];
    else { const len = start[1] - start[0]; let a2 = start[0] + d - anchor; a2 = Math.max(d0, Math.min(d1 - len, a2)); state.range = [a2, a2 + len]; }
    win.setAttribute("x", X(state.range[0])); win.setAttribute("width", (state.range[1] - state.range[0] + 1) * bw);
    renderChart();
  };
  svg.onpointerup = () => {
    if (!mode) return; mode = null;
    if (state.range[1] - state.range[0] < 2) state.range = [Math.max(d0, state.range[0] - 3), Math.min(d1, state.range[1] + 3)];
    state.sel = null; render();
  };
}

/* ---------- breakdowns ---------- */
function hbars(target, key) {
  const rows = filtered().filter(inRange), groups = new Map();
  for (const r of rows) { const k = r[key] || "Unknown"; const g = groups.get(k) || { 1: 0, 2: 0, 3: 0, 4: 0, n: 0 }; g[r.tier]++; g.n++; groups.set(k, g); }
  const top = [...groups.entries()].sort((a, b) => b[1].n - a[1].n).slice(0, 10), max = top.length ? top[0][1].n : 1;
  $(target).replaceChildren(...(top.length ? top.map(([name, g]) => {
    const track = h("div", { class: "track" });
    for (const t of [1, 2, 3, 4]) if (g[t]) { const seg = h("div", { class: `seg${t}`, title: `${TIERS[t]}: ${g[t]}` }); seg.style.width = `${(100 * g[t]) / max}%`; track.append(seg); }
    return h("div", { class: "hbar" }, h("div", { class: "name", title: name, text: name }), track, h("div", { class: "n", text: g.n }));
  }) : [h("p", { class: "muted", text: "No incidents match." })]));
}
function renderBreakdowns() { hbars("byIndustry", "industry"); hbars("byOrgType", "org_type"); }

/* ---------- table ---------- */
const COLS = [
  ["date", "Date"], ["org", "Organization"], ["tier", "Tier"], ["incident_type", "Type"], ["industry", "Industry"],
  ["state", "State"], ["actor", "Actor"], ["records", "Records"], ["source", "Source"],
];
function tableRows() {
  let rows = filtered().filter(inRange);
  if (state.sel) rows = rows.filter((r) => r._d >= state.sel.a && r._d <= state.sel.b && !(state.gran === "day" && r.date_precision === "Month"));
  const { key, dir } = state.sort;
  return rows.sort((a, b) => {
    const va = key === "records" ? (a.records || 0) : (a[key] ?? ""), vb = key === "records" ? (b.records || 0) : (b[key] ?? "");
    return (va < vb ? -1 : va > vb ? 1 : 0) * dir || (a.date < b.date ? 1 : -1);
  });
}
function renderTable() {
  const rows = tableRows();
  $("tableCount").textContent = `· ${rows.length.toLocaleString()} shown`;
  const chip = $("bucketChip");
  if (state.sel) { chip.textContent = `${state.sel.a === state.sel.b ? fmtDay(state.sel.a) : "Week of " + fmtDay(state.sel.a)} ✕`; chip.classList.remove("hidden"); }
  else chip.classList.add("hidden");
  const thead = $("table").tHead;
  thead.replaceChildren(h("tr", {}, ...COLS.map(([k, label]) => {
    const th = h("th", { class: state.sort.key === k ? `sorted ${state.sort.dir > 0 ? "asc" : ""}` : null, scope: "col", text: label });
    th.onclick = () => { state.sort = { key: k, dir: state.sort.key === k ? -state.sort.dir : (k === "date" || k === "records" ? -1 : 1) }; renderTable(); };
    return th;
  })));
  const body = $("table").tBodies[0];
  body.replaceChildren(...rows.slice(0, 1000).map((r) => {
    const url = safeUrl(r.url), conf = safeUrl(r.confirmed_by);
    return h("tr", {},
      h("td", { class: "date", text: r.date_precision === "Month" ? r.date.slice(0, 7) : r.date }),
      h("td", {}, h("div", { class: "org", text: r.org }), r.summary ? h("div", { class: "sum", text: r.summary }) : null),
      h("td", {}, h("span", { class: `badge b${r.tier}`, text: TIERS[r.tier] })),
      h("td", { text: r.incident_type }), h("td", { text: r.industry }), h("td", { text: r.state }),
      h("td", { text: r.actor }),
      h("td", { class: "num", text: r.records ? r.records.toLocaleString() : "", title: r.count_basis || null }),
      h("td", {}, url ? h("a", { href: url, target: "_blank", rel: "noopener noreferrer", text: r.source }) : r.source,
        conf ? h("div", {}, h("a", { href: conf, target: "_blank", rel: "noopener noreferrer", text: "confirmation" })) : null));
  }));
}

function exportCsv() {
  const fields = ["id", "date", "date_precision", "org", "sector_group", "org_type", "industry", "state", "tier", "tier_label",
    "incident_type", "actor", "records", "count_basis", "ops_disrupted", "data_exposed", "summary", "source", "url", "confirmed_by"];
  const q = (v) => { let t = v == null ? "" : String(v); if (/^[=+\-@]/.test(t)) t = "'" + t; return `"${t.replace(/"/g, '""')}"`; };
  const csv = [fields.join(","), ...tableRows().map((r) => fields.map((f) => q(r[f])).join(","))].join("\r\n");
  const a = h("a", { href: URL.createObjectURL(new Blob([csv], { type: "text/csv" })), download: `incidents_${isoOf(state.range[0])}_${isoOf(state.range[1])}.csv` });
  document.body.append(a); a.click(); a.remove();
}

init().catch((e) => { $("status").textContent = "Could not load data: " + e.message; });
