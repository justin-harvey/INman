"""Trend summary for the dashboard: site/data/trends.json.

Reads the orb's 90-day history (site/data/flow_history.json) and the curated U.S. incident list
(site/data/incidents.json), and works out the figures behind the Trends card: how fast extortion
claims are growing (with and without any single group that drives most of the growth), how
concentrated they are, which groups are rising, new or quiet, the weekly posting rhythm, the pace
of exploited and new vulnerabilities, and the shape of the U.S. incident list. Every sentence on
the card is built from these numbers, so it stays current on each scheduled run.

Only complete UTC days count: the day of the run is left out because it is still filling.
"""
import argparse
import datetime as dt
import json
import os
import re
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HISTORY = os.path.join(ROOT, "site", "data", "flow_history.json")
INCIDENTS = os.path.join(ROOT, "site", "data", "incidents.json")
META = os.path.join(ROOT, "site", "data", "meta.json")
OUT = os.path.join(ROOT, "site", "data", "trends.json")

PERIODS = 3          # the window is split into this many equal periods (30 days each for 90)
FLAT = 0.15          # changes within +/-15% between halves count as flat
WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def load(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def pct(a, b):
    return None if not a else round((b - a) / a * 100)


def series(daily, days):
    return [int(daily.get(d, 0)) for d in days]


def weekly(vals):
    """Sums of complete 7-day blocks, counted back from the last day."""
    n = len(vals) // 7
    tail = vals[len(vals) - n * 7:]
    return [sum(tail[i * 7:(i + 1) * 7]) for i in range(n)]


def direction(first, second):
    if not first and not second:
        return "none"
    if not first:
        return "rising"
    ch = (second - first) / first
    return "rising" if ch > FLAT else "falling" if ch < -FLAT else "flat"


def display_name(key, info):
    if isinstance(info, dict) and info.get("name"):
        return info["name"]
    # same rule as flow.py: plain lowercase words get a capital; anything stylised (n0n, 3am) stays
    return key[:1].upper() + key[1:] if re.fullmatch(r"[a-z][a-z ]*", key) else key


def claims_section(hist, days):
    daily = hist.get("daily", {}).get("claims", {})
    vals = series(daily, days)
    per = len(days) // PERIODS
    bounds = [(i * per, (i + 1) * per) for i in range(PERIODS)]
    totals = [sum(vals[a:b]) for a, b in bounds]

    actors = []
    meta = hist.get("actors", {})
    for key, d in hist.get("actors_daily", {}).items():
        v = series(d, days)
        p = [sum(v[a:b]) for a, b in bounds]
        actors.append({"name": display_name(key, meta.get(key)), "key": key, "periods": p,
                       "total": sum(p), "daily": v, "attack": meta.get(key) if isinstance(meta.get(key), dict) else None})
    total_named = sum(a["total"] for a in actors)

    # one group driving most of the growth hides the underlying trend: show both
    growth = totals[-1] - totals[0]
    surger = None
    if growth > 0 and actors:
        top = max(actors, key=lambda a: a["periods"][-1] - a["periods"][0])
        rise = top["periods"][-1] - top["periods"][0]
        if rise >= 0.4 * growth and rise >= 50:
            surger = top
    ex_totals = [t - (surger["periods"][i] if surger else 0) for i, t in enumerate(totals)]

    weeks_all = weekly(vals)
    weeks_ex = weekly([v - (surger["daily"][i] if surger else 0) for i, v in enumerate(vals)])
    week_ends = [days[len(days) - (len(weeks_all) - i - 1) * 7 - 1] for i in range(len(weeks_all))]

    by_wd = [[] for _ in range(7)]
    for d, v in zip(days, vals):
        by_wd[dt.date.fromisoformat(d).weekday()].append(v)
    wd_avg = [round(sum(x) / len(x), 1) if x else 0 for x in by_wd]

    ranked = sorted(actors, key=lambda a: -a["total"])
    share = lambda n: round(sum(a["total"] for a in ranked[:n]) / total_named * 100) if total_named else 0
    rising = sorted([a for a in actors if a["periods"][0] > 0 and a["periods"][-1] >= 20 and a["periods"][-1] >= 1.5 * max(a["periods"][0], 1)
                     and a is not surger], key=lambda a: -(a["periods"][-1] - a["periods"][0]))[:4]
    new = sorted([a for a in actors if sum(a["periods"][:-1]) == 0 and a["periods"][-1] >= 10],
                 key=lambda a: -a["periods"][-1])[:6]
    quiet = sorted([a for a in actors if sum(a["periods"][:-1]) >= 20 and a["periods"][-1] == 0],
                   key=lambda a: -sum(a["periods"][:-1]))[:6]
    steady = [a for a in ranked[:5] if a is not surger and a not in rising]

    brief = lambda a: {"name": a["name"], "periods": a["periods"], "total": a["total"],
                       "attack_id": (a["attack"] or {}).get("id"), "attack_url": (a["attack"] or {}).get("url")}
    return {
        "total": sum(vals), "period_days": per, "periods": totals, "change_pct": pct(totals[0], totals[-1]),
        "surger": brief(surger) if surger else None,
        "periods_ex_surger": ex_totals, "change_pct_ex_surger": pct(ex_totals[0], ex_totals[-1]),
        "surger_peaks": sorted(({"date": d, "count": c} for d, c in zip(days, surger["daily"]) if c), key=lambda x: -x["count"])[:2] if surger else [],
        "weekly": {"week_ending": week_ends, "all": weeks_all, "ex_surger": weeks_ex if surger else None},
        "weekday_avg": dict(zip(WEEKDAYS, wd_avg)),
        "top5_share": share(5), "top10_share": share(10), "groups_active": sum(1 for a in actors if a["total"]),
        "steady": [brief(a) for a in steady[:3]], "rising": [brief(a) for a in rising],
        "new": [brief(a) for a in new], "quiet": [brief(a) for a in quiet],
    }


def vuln_section(hist, days):
    out = {}
    for theme in ("kev", "cve"):
        vals = series(hist.get("daily", {}).get(theme, {}), days)
        wk = weekly(vals)
        half = len(wk) // 2
        a, b = sum(wk[:half]), sum(wk[half:2 * half])
        out[theme] = {"total": sum(vals), "per_week": round(sum(wk) / len(wk), 1) if wk else 0,
                      "first_half": a, "second_half": b, "direction": direction(a, b), "weekly": wk}
    ep = hist.get("epss")
    if ep:
        likely = sum(int(ep.get("likely_daily", {}).get(d, 0)) for d in days)
        total = out["cve"]["total"]
        out["epss"] = {"threshold": ep.get("threshold", 0.1), "likely": likely,
                       "share_pct": round(likely / total * 100, 1) if total else 0,
                       "top": [{k: t.get(k) for k in ("cve", "epss", "pct", "url", "kev", "title")} for t in ep.get("top_30d", [])[:6]]}
    return out


def incident_section(incidents):
    rows = [r for r in incidents if r.get("date")]
    if not rows:
        return None
    gov = [r for r in rows if r.get("sector_group") == "Government"]
    corp = [r for r in rows if r.get("sector_group") != "Government"]
    t3 = lambda rs: sum(1 for r in rs if r.get("tier") == 3)
    unnamed = sum(1 for r in rows if not r.get("actor") or str(r["actor"]).strip().lower() in
                  {"not named", "not stated", "none identified", "unknown", "none"})
    counted = sorted((r["records"] for r in rows if isinstance(r.get("records"), (int, float)) and r.get("tier") != 2
                      and not str(r.get("count_basis", "")).lower().startswith("claimed")), reverse=True)
    rec_total = sum(counted)
    return {
        "total": len(rows), "first": min(r["date"] for r in rows)[:10], "last": max(r["date"] for r in rows)[:10],
        "by_tier": {str(k): v for k, v in sorted(Counter(r.get("tier") for r in rows).items())},
        "top_industries": [{"name": k, "count": v} for k, v in Counter(r.get("industry") for r in rows if r.get("industry")).most_common(4)],
        "top_states": [{"name": k, "count": v} for k, v in Counter(r.get("state") for r in rows
                                                                    if r.get("state") and r["state"] != "Unknown").most_common(3)],
        "gov": {"total": len(gov), "suspected_outages": t3(gov)},
        "corp": {"total": len(corp), "suspected_outages": t3(corp)},
        "ops_disrupted_pct": round(sum(1 for r in rows if r.get("ops_disrupted") is True) / len(rows) * 100),
        "actor_unnamed_pct": round(unnamed / len(rows) * 100),
        "official": {"sec": sum(1 for r in rows if r.get("origin") == "sec_edgar"),
                     "hhs": sum(1 for r in rows if r.get("origin") == "hhs_ocr"),
                     "confirmed_existing": sum(1 for r in rows if r.get("origin") not in ("sec_edgar", "hhs_ocr")
                                               and re.search(r"(SEC 8-K|HHS breach report) \(", r.get("confirmed_by") or ""))},
        "records_total": rec_total,
        "records_top3_pct": round(sum(counted[:3]) / rec_total * 100) if rec_total else 0,
    }


def fmt_n(v):
    return f"{v / 1e6:.0f}M" if v >= 1e6 else f"{v:,}"


def names(lst):
    n = [a["name"] for a in lst]
    return n[0] if len(n) == 1 else ", ".join(n[:-1]) + " and " + n[-1] if n else ""


def findings(c, v, inc, per):
    """Plain-language headline sentences, most important first."""
    out = []
    if c and c["total"]:
        arrow = " → ".join(f"{t:,}" for t in c["periods"])
        if c["surger"]:
            s = c["surger"]
            out.append({"key": "growth", "text": f"Extortion claims went {arrow} per {per} days ({c['change_pct']:+d}%). "
                        f"Most of the rise is one group, {s['name']} ({' → '.join(str(p) for p in s['periods'])}); "
                        f"without it, growth is {c['change_pct_ex_surger']:+d}%."})
        elif c["change_pct"] is not None:
            out.append({"key": "growth", "text": f"Extortion claims went {arrow} per {per} days ({c['change_pct']:+d}%)."})
        out.append({"key": "concentration", "text": f"The top 5 groups post {c['top5_share']}% of claims and the top 10 post "
                    f"{c['top10_share']}%, out of {c['groups_active']} active groups."
                    + (f" {names(c['steady'][:2])} are the steady leaders ("
                       + ", ".join(f"{a['name']} {' → '.join(str(p) for p in a['periods'])}" for a in c["steady"][:2]) + ")."
                       if c["steady"] else "")})
        if c["rising"]:
            out.append({"key": "rising", "text": "Climbing: " + "; ".join(
                f"{a['name']} ({a['periods'][0]} → {a['periods'][-1]})" for a in c["rising"]) + "."})
        if c["new"] or c["quiet"]:
            bits = []
            if c["new"]:
                bits.append(f"{len(c['new'])} groups posted only in the last {per} days ({names(c['new'][:3])})")
            if c["quiet"]:
                bits.append(f"{names(c['quiet'][:3])} went quiet")
            text = "; ".join(bits)
            out.append({"key": "churn", "text": text[:1].upper() + text[1:] + "."})
        wd = c["weekday_avg"]
        hi, lo = max(wd, key=wd.get), min(wd, key=wd.get)
        if wd[lo] and wd[hi] >= 1.5 * wd[lo]:
            out.append({"key": "rhythm", "text": f"{hi}s average {wd[hi]:.0f} posts and {lo}s {wd[lo]:.0f}. "
                        "Posting is batched, so compare weeks rather than days."})
    if v:
        word = {"flat": "steady", "rising": "rising", "falling": "slowing", "none": "quiet"}
        out.append({"key": "vulns", "text": f"CISA added about {v['kev']['per_week']:.0f} exploited vulnerabilities a week "
                    f"({word[v['kev']['direction']]}); new high and critical CVEs ran about {v['cve']['per_week']:.0f} a week "
                    f"({word[v['cve']['direction']]})."})
    if v and v.get("epss") and v["epss"]["top"]:
        e = v["epss"]
        top = ", ".join(f"{t['cve']} ({t['epss'] * 100:.0f}%{', on CISA list' if t.get('kev') else ''})" for t in e["top"][:3])
        out.append({"key": "epss", "text": f"At least {e['likely']} new high and critical CVEs ({e['share_pct']:g}%) have a "
                    f"{e['threshold'] * 100:.0f}% or higher chance of being exploited within 30 days, by FIRST's EPSS score. "
                    f"Highest now: {top}."})
    if inc and inc.get("official") and (inc["official"]["sec"] or inc["official"]["hhs"]):
        o = inc["official"]
        bits = [f"{o['sec']} SEC 8-K cybersecurity disclosures" if o["sec"] else "",
                f"{o['hhs']} HHS hacking reports" if o["hhs"] else ""]
        out.append({"key": "official", "text": "Official records add " + " and ".join(b for b in bits if b) + " to the U.S. list"
                    + (f", and confirmed {o['confirmed_existing']} earlier claims or outages." if o["confirmed_existing"] else ".")})
    if inc:
        ind = inc["top_industries"]
        if ind:
            label = lambda i: f"{i['name'][:1].lower() + i['name'][1:]} ({i['count']})"
            out.append({"key": "sectors", "text": f"In the {inc['total']} U.S. incidents, {names([{'name': label(i)} for i in ind[:3]])} lead."})
        g, k = inc["gov"], inc["corp"]
        if g["total"] and k["total"]:
            out.append({"key": "gov", "text": f"Government shows up as outages: {g['suspected_outages']} of {g['total']} government "
                        f"entries are suspected-cyber outages, versus {k['suspected_outages']} of {k['total']} corporate ones."})
        out.append({"key": "impact", "text": f"Operations were disrupted in {inc['ops_disrupted_pct']}% of incidents, and no group "
                    f"is named in {inc['actor_unnamed_pct']}%."
                    + (f" About {fmt_n(inc['records_total'])} records were exposed; the three largest breaches are "
                       f"{inc['records_top3_pct']}% of that." if inc["records_total"] else "")})
    return out


def caveats(hist, meta, days, inc=None):
    out = []
    rl = (meta or {}).get("feeds", {}).get("ransomware.live", "")
    if not str(rl).startswith("ok"):
        out.append("Extortion claims are global: RansomLook does not record the victim's country, so there is no U.S. share "
                   "until ransomware.live is cleared and turned on.")
    # themes whose history starts late are filling in, not growing
    late = []
    for th in hist.get("themes", []):
        d = hist.get("daily", {}).get(th["id"], {})
        first = min((k for k, v in d.items() if v), default=None)
        if first and first > days[len(days) // 3]:
            late.append(th.get("short") or th.get("label") or th["id"])
    if late:
        out.append(f"{names([{'name': x} for x in late])} only reach back a few weeks (status pages and news feeds return recent "
                   "history only), so their recent rise is the record filling in, not a trend.")
    if inc and inc.get("official", {}).get("hhs"):
        out.append("Healthcare has a mandatory public breach register (HHS) and most sectors do not, so its lead partly "
                   "reflects better reporting, not only more attacks. HHS also posts reports up to a few weeks late.")
    out.append("U.S. incident dates are disclosure dates, and confirmed breaches often surface weeks after they happen, "
               "so the latest weeks will grow as disclosures arrive.")
    out.append(f"{len(days)} days describes the current pace, not the next quarter. The history builds up with every run.")
    return out


def build(hist, incidents, meta, today=None):
    today = today or dt.datetime.now(dt.timezone.utc).date()
    span = int(hist.get("history_days", 90))
    end = today - dt.timedelta(days=1)
    days = [(end - dt.timedelta(days=span - 1 - i)).isoformat() for i in range(span)]
    c = claims_section(hist, days)
    v = vuln_section(hist, days)
    inc = incident_section(incidents)
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "window": {"start": days[0], "end": days[-1], "days": span},
        "findings": findings(c, v, inc, c["period_days"]),
        "claims": c, "vulns": v, "incidents": inc,
        "caveats": caveats(hist, meta, days, inc),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--today", help="YYYY-MM-DD (tests)")
    a = ap.parse_args()
    hist = load(HISTORY)
    if not hist:
        print("no flow history yet; trends skipped")
        return
    inc = (load(INCIDENTS, {}) or {}).get("incidents", [])
    out = build(hist, inc, load(META, {}), dt.date.fromisoformat(a.today) if a.today else None)
    with open(OUT, "w") as f:
        json.dump(out, f, indent=1)
    print(f"trends: {len(out['findings'])} findings over {out['window']['start']}..{out['window']['end']}")


if __name__ == "__main__":
    main()
