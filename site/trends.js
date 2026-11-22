/* Trends card: renders site/data/trends.json (built by scripts/trends.py on every scheduled run).
   Reuses h(), s(), $(), showTip() and hideTip() from app.js. All text goes in via textContent. */
"use strict";
(() => {
  const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const day = (iso) => { const [y, m, d] = iso.split("-").map(Number); return `${MON[m - 1]} ${d}`; };
  const POLL_MS = 10 * 60 * 1000;
  let lastStamp = null, lastClaims = null, lastWidth = 0;

  async function load() {
    try {
      const r = await fetch("data/trends.json", { cache: "no-cache" });
      if (!r.ok) return;
      const t = await r.json();
      if (t.generated_at === lastStamp) return;
      lastStamp = t.generated_at;
      render(t);
    } catch (e) { /* optional file: the card stays hidden */ }
  }

  function render(t) {
    $("trendsCard").classList.remove("hidden");
    $("trendsWindow").textContent = `· ${day(t.window.start)} – ${day(t.window.end)}, last ${t.window.days} complete days`;
    const g = new Date(t.generated_at);
    $("trendsUpdated").textContent = `Recomputed ${g.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}`;
    $("trendsFindings").replaceChildren(...(t.findings || []).map((f) => h("li", { text: f.text })));
    $("trendsCaveats").replaceChildren(...(t.caveats || []).map((c) => h("li", { text: c })));
    lastClaims = t.claims;
    renderChart(t.claims);
    renderGroups(t.claims, t.vulns);
  }

  function renderChart(c) {
    const wrap = $("trendsChart"), legend = $("trendsLegend");
    if (!c || !c.weekly || !c.weekly.all.length) { wrap.replaceChildren(); legend.replaceChildren(); return; }
    const all = c.weekly.all, ex = c.weekly.ex_surger, ends = c.weekly.week_ending;
    legend.replaceChildren(h("span", {}, h("i", { class: "sw all" }), "All groups"),
      ...(ex ? [h("span", {}, h("i", { class: "sw ex" }), `Excluding ${c.surger.name}`)] : []));

    // drawn at the container's real width so the axis text stays readable on phones
    const W = Math.max(280, Math.round(wrap.clientWidth || 520)), H = W < 480 ? 190 : 230, L = 34, R = 10, T = 10, B = 26;
    lastWidth = W;
    const max = Math.max(...all, ...(ex || [])), top = Math.ceil(max / 50) * 50 || 50;
    const x = (i) => L + (all.length === 1 ? 0 : i * (W - L - R) / (all.length - 1));
    const y = (v) => T + (H - T - B) * (1 - v / top);
    const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Weekly extortion claims line chart" });
    for (const v of [0, top / 2, top]) {
      svg.append(s("line", { x1: L, x2: W - R, y1: y(v), y2: y(v), class: "grid" }),
        s("text", { x: L - 6, y: y(v) + 3.5, "text-anchor": "end", class: "axis", text: String(v) }));
    }
    const step = Math.max(1, Math.ceil(all.length / (W < 480 ? 4 : 6))), last = ends.length - 1;
    ends.forEach((d, i) => {
      if (i !== last && (i % step || last - i < step * 0.75)) return;   // keep the last label clear of its neighbour
      svg.append(s("text", { x: x(i), y: H - 8, "text-anchor": i === 0 ? "start" : i === ends.length - 1 ? "end" : "middle", class: "axis", text: day(d) }));
    });
    const path = (vals) => vals.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
    if (ex) svg.append(s("path", { d: path(ex), class: "l-ex" }));
    svg.append(s("path", { d: path(all), class: "l-all" }));
    all.forEach((v, i) => {
      svg.append(s("circle", { cx: x(i), cy: y(v), r: 2.6, class: "dot-all" }));
      if (ex) svg.append(s("circle", { cx: x(i), cy: y(ex[i]), r: 2.6, class: "dot-ex" }));
      const half = (W - L - R) / Math.max(1, all.length - 1) / 2;
      const tip = (ev) => showTip(ev, [h("b", { text: `Week ending ${day(ends[i])}` }),
        h("div", { class: "row" }, h("span", { text: "All groups" }), h("span", { text: all[i].toLocaleString() })),
        ...(ex ? [h("div", { class: "row" }, h("span", { text: `Excl. ${c.surger.name}` }), h("span", { text: ex[i].toLocaleString() }))] : [])]);
      svg.append(s("rect", { x: x(i) - half, y: T, width: half * 2, height: H - T - B, class: "hit",
        onmousemove: tip, onmouseleave: hideTip }));
    });
    wrap.replaceChildren(svg);
  }

  function groupList(title, rows, fmt) {
    if (!rows || !rows.length) return null;
    return h("section", { class: "tg" }, h("h3", { text: title }),
      h("ul", {}, ...rows.map((a) => {
        const url = a.attack_url && /^https:\/\/attack\.mitre\.org\//.test(a.attack_url) ? a.attack_url : null;
        const name = url ? h("a", { href: url, target: "_blank", rel: "noopener noreferrer", title: `MITRE ATT&CK ${a.attack_id}`, text: a.name })
          : h("span", { text: a.name });
        return h("li", {}, h("span", {}, name), h("span", { class: "n", text: fmt(a) }));
      })));
  }

  function epssList(v) {
    const e = v && v.epss;
    if (!e || !e.top || !e.top.length) return null;
    return h("section", { class: "tg" }, h("h3", { text: "Most likely exploited (EPSS)" }),
      h("ul", {}, ...e.top.map((t) => {
        const url = /^https:\/\/nvd\.nist\.gov\//.test(t.url || "") ? t.url : null;
        const name = url ? h("a", { href: url, target: "_blank", rel: "noopener noreferrer", title: t.title || t.cve, text: t.cve })
          : h("span", { title: t.title || t.cve, text: t.cve });
        return h("li", {}, h("span", {}, name, t.kev ? h("b", { class: "kevtag", title: "On CISA's Known Exploited Vulnerabilities list", text: "KEV" }) : null),
          h("span", { class: "n", text: `${(t.epss * 100).toFixed(t.epss < 0.1 ? 1 : 0)}%` }));
      })));
  }

  function renderGroups(c, v) {
    const per = c ? c.period_days : 30;
    const arrow = (a) => a.periods.join(" → ");
    const parts = c ? [
      groupList("Steady leaders", c.steady, arrow),
      groupList(c.surger ? "Surging" : "Climbing", c.surger ? [c.surger, ...c.rising] : c.rising, arrow),
      groupList(`New in last ${per} days`, c.new, (a) => String(a.periods[a.periods.length - 1])),
      groupList("Went quiet", c.quiet, (a) => `${a.periods.slice(0, -1).reduce((x, y) => x + y, 0)} → 0`),
    ].filter(Boolean) : [];
    const ep = epssList(v);
    $("trendsEpss").replaceChildren(...(ep ? [ep] : []));
    if (parts.length) parts.push(h("p", { class: "muted small tg-note", text: `Claims per ${per}-day period, oldest first. Linked names open the group's MITRE ATT&CK page.`
      + (ep ? " EPSS is FIRST's estimated chance that a vulnerability is exploited in the next 30 days." : "") }));
    $("trendsGroups").replaceChildren(...parts);
  }

  let resizeTimer = null;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      const w = Math.round($("trendsChart").clientWidth);
      if (lastClaims && w && Math.abs(w - lastWidth) > 8) renderChart(lastClaims);
    }, 150);
  });
  document.addEventListener("DOMContentLoaded", () => { load(); setInterval(load, POLL_MS); });
})();
