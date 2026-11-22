"""Build site/data/flow.json: the live inflow behind the orb.

Each source becomes items {id, ts, first_seen, theme, source, title, severity, url}.
Items persist across runs (merged with the previous flow.json) for `window_days`,
so short feeds such as RSS still leave a week of history.

Sources and themes are configured in data/flow_sources.json.
Environment: RL_ENABLED, RL_API_BASE, RL_API_KEY, RL_API_KEY_HEADER (see README),
NVD_API_KEY (optional), GITHUB_TOKEN (optional, for the Upptime adapter),
FIXTURE_DIR (tests: read every source from local files).
"""
import datetime as dt
import email.utils
import hashlib
import json
import os
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG = os.path.join(ROOT, "data", "flow_sources.json")
OUT = os.path.join(ROOT, "site", "data", "flow.json")
INCIDENTS = os.path.join(ROOT, "site", "data", "incidents.json")
UA = "inman-incident-monitor/1.0 (+private team dashboard)"
NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def env(name, default=""):
    return os.environ.get(name, default).strip()


def fixture_name(url):
    return hashlib.sha1(url.encode()).hexdigest()[:12]


def fetch(url, headers=None):
    """Return the response body as text. In tests, read FIXTURE_DIR/<sha1(url)>."""
    if env("FIXTURE_DIR"):
        path = os.path.join(env("FIXTURE_DIR"), fixture_name(url))
        if not os.path.exists(path):  # query strings carry timestamps; fall back to the bare URL
            path = os.path.join(env("FIXTURE_DIR"), fixture_name(url.split("?")[0]))
        if not os.path.exists(path):
            raise FileNotFoundError(f"no fixture for {url}")
        with open(path, encoding="utf-8") as f:
            return f.read()
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def iso(d):
    return d.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value):
    if not value:
        return None
    v = str(value).strip()
    try:
        if len(v) == 10:
            return dt.datetime.fromisoformat(v + "T12:00:00+00:00")
        d = dt.datetime.fromisoformat(v.replace("Z", "+00:00").replace(" ", "T", 1))
        return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        try:
            return email.utils.parsedate_to_datetime(v)
        except (TypeError, ValueError):
            return None


def item(source, theme, key, when, title, severity, url):
    return {"id": hashlib.sha1(f"{source}|{key}".encode()).hexdigest()[:14], "ts": iso(when),
            "first_seen": iso(NOW), "theme": theme, "source": source,
            "title": " ".join(str(title).split())[:180], "severity": round(max(0.0, min(1.0, severity)), 2),
            "url": url if str(url).startswith(("https://", "http://")) else ""}


def enabled(cfg):
    e = cfg.get("enabled", False)
    if isinstance(e, str) and e.startswith("env:"):
        return env(e[4:]).lower() == "true"
    return bool(e)


# ---------------------------------------------------------------- adapters
def a_ransomwatch(cfg, since):
    out = []
    for p in json.loads(fetch(cfg["url"])):
        t = parse_time(p.get("discovered"))
        if not t or t < since:
            continue
        title, group = p.get("post_title", ""), p.get("group_name", "")
        out.append(item("ransomwatch", cfg["theme"], f"{group}|{title}", t, f"{title} · claimed by {group} (global)", 0.55,
                        "https://github.com/joshhighet/ransomwatch"))
    return out


def a_ransomware_live(cfg, since):
    base = env("RL_API_BASE", "https://api.ransomware.live/v2").rstrip("/")
    headers = {env("RL_API_KEY_HEADER", "X-API-KEY"): env("RL_API_KEY")} if env("RL_API_KEY") else {}
    data = json.loads(fetch(f"{base}/countryvictims/US", headers))
    data = data if isinstance(data, list) else data.get("victims", data.get("data", []))
    out = []
    for v in data:
        t = parse_time(v.get("attackdate") or v.get("discovered"))
        if not t or t < since or not v.get("victim"):
            continue
        out.append(item("ransomware.live", cfg["theme"], f"{v.get('group')}|{v['victim']}", t,
                        f"{v['victim']} · claimed by {v.get('group', 'unknown')} (U.S.)", 0.7,
                        v.get("url") or "https://www.ransomware.live/"))
    return out


def a_cisa_kev(cfg, since):
    out = []
    for v in json.loads(fetch(cfg["url"])).get("vulnerabilities", []):
        t = parse_time(v.get("dateAdded"))
        if not t or t < since:
            continue
        known = str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"
        out.append(item("CISA KEV", cfg["theme"], v.get("cveID"), t,
                        f"{v.get('cveID')} · {v.get('vendorProject', '')} {v.get('product', '')}: {v.get('vulnerabilityName', '')}"
                        + (" · used in ransomware" if known else ""),
                        0.95 if known else 0.8, f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}"))
    return out


def a_nvd(cfg, since):
    headers = {"apiKey": env("NVD_API_KEY")} if env("NVD_API_KEY") else {}
    start = max(since, NOW - dt.timedelta(days=7))
    fmt = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
    out = []
    for sev in cfg.get("severities", ["CRITICAL", "HIGH"]):
        q = urllib.parse.urlencode({"pubStartDate": fmt(start), "pubEndDate": fmt(NOW), "cvssV3Severity": sev,
                                    "resultsPerPage": 2000})
        data = json.loads(fetch(f"https://services.nvd.nist.gov/rest/json/cves/2.0?{q}", headers))
        for v in data.get("vulnerabilities", []):
            c = v.get("cve", {})
            score = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
                m = c.get("metrics", {}).get(key)
                if m:
                    score = m[0].get("cvssData", {}).get("baseScore")
                    break
            desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
            t = parse_time(c.get("published"))
            if t:
                out.append(item("NVD", cfg["theme"], c.get("id"), t, f"{c.get('id')} ({score or sev}): {desc}",
                                (score or 7) / 10, f"https://nvd.nist.gov/vuln/detail/{c.get('id')}"))
    return out


IMPACT = {"none": 0.2, "minor": 0.4, "major": 0.7, "critical": 1.0, "maintenance": 0.15}


def a_statuspages(cfg, since):
    out, errors = [], []
    for name, base in cfg.get("pages", {}).items():
        try:
            data = json.loads(fetch(base.rstrip("/") + "/api/v2/incidents.json"))
        except Exception as e:  # one page failing should not drop the rest
            errors.append(f"{name}: {e.__class__.__name__}")
            continue
        for inc in data.get("incidents", []):
            t = parse_time(inc.get("created_at"))
            if not t or t < since:
                continue
            out.append(item(f"{name} status", cfg["theme"], inc.get("id"), t,
                            f"{name}: {inc.get('name', '')} ({inc.get('status', '')})",
                            IMPACT.get(inc.get("impact", "none"), 0.3), inc.get("shortlink") or base))
    if errors and not out:
        raise RuntimeError("; ".join(errors))
    return out


def a_upptime(cfg, since):
    headers = {"Accept": "application/vnd.github+json"}
    if env("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {env('GITHUB_TOKEN')}"
    q = urllib.parse.urlencode({"labels": cfg.get("label", "status"), "state": "all", "per_page": 100,
                                "since": iso(since)})
    out = []
    for issue in json.loads(fetch(f"https://api.github.com/repos/{cfg['repo']}/issues?{q}", headers)):
        t = parse_time(issue.get("created_at"))
        if t and t >= since:
            out.append(item("Upptime", cfg["theme"], issue.get("number"), t, issue.get("title", ""),
                            0.6 if issue.get("state") == "open" else 0.35, issue.get("html_url", "")))
    return out


def a_rss(cfg, since):
    out, errors = [], []
    for name, url in cfg.get("feeds", {}).items():
        try:
            root = ET.fromstring(fetch(url))
        except Exception as e:
            errors.append(f"{name}: {e.__class__.__name__}")
            continue
        atom = "{http://www.w3.org/2005/Atom}"
        entries = root.findall(".//item") or root.findall(f".//{atom}entry")
        for e in entries[:100]:
            title = (e.findtext("title") or e.findtext(f"{atom}title") or "").strip()
            link = e.findtext("link") or ""
            if not link:
                el = e.find(f"{atom}link")
                link = el.get("href", "") if el is not None else ""
            t = parse_time(e.findtext("pubDate") or e.findtext(f"{atom}updated") or e.findtext(f"{atom}published"))
            if title and t and t >= since:
                out.append(item(name, cfg["theme"], link or title, t, title,
                                0.6 if name.startswith("CISA") else 0.45, link.strip()))
    if errors and not out:
        raise RuntimeError("; ".join(errors))
    return out


def a_inman(cfg, since):
    with open(INCIDENTS) as f:
        incidents = json.load(f)["incidents"]
    sev = {1: 0.8, 2: 0.6, 3: 0.5, 4: 0.35}
    out = []
    for r in incidents:
        t = parse_time(r["date"])
        if not t or t < since or r.get("date_precision") == "Month":
            continue
        theme = cfg["theme_by_tier"].get(str(r["tier"]), "incidents")
        out.append(item("INman", theme, r["id"], t, f"{r['org']} · {r.get('incident_type', '')}", sev.get(r["tier"], 0.5),
                        r.get("url", "")))
    return out


ADAPTERS = {"ransomwatch": a_ransomwatch, "ransomware_live": a_ransomware_live, "cisa_kev": a_cisa_kev,
            "nvd": a_nvd, "statuspages": a_statuspages, "upptime": a_upptime, "rss": a_rss, "inman": a_inman}


def main():
    with open(CONFIG) as f:
        conf = json.load(f)
    since = NOW - dt.timedelta(days=int(conf.get("window_days", 7)))
    previous = {}
    if os.path.exists(OUT):
        with open(OUT) as f:
            previous = {i["id"]: i for i in json.load(f).get("items", [])}

    items, status = {}, {}
    for name, cfg in conf["sources"].items():
        if not enabled(cfg):
            status[name] = "off"
            continue
        try:
            got = ADAPTERS[name](cfg, since)
            for it in got:
                if it["id"] in previous:          # keep when we first saw it, so the orb animates only new items
                    it["first_seen"] = previous[it["id"]]["first_seen"]
                items[it["id"]] = it
            status[name] = f"ok ({len(got)})"
        except Exception as e:
            status[name] = f"error: {e.__class__.__name__}: {str(e)[:120]}"

    # carry forward items still in the window that this run did not return (e.g. aged out of an RSS feed)
    failed_or_rolling = {k for k, v in status.items() if not v.startswith("ok")} | {"rss", "statuspages"}
    source_of = {"ransomwatch": "ransomwatch", "ransomware.live": "ransomware_live", "CISA KEV": "cisa_kev", "NVD": "nvd",
                 "Upptime": "upptime", "INman": "inman"}
    for pid, it in previous.items():
        src = source_of.get(it["source"], "statuspages" if it["source"].endswith(" status") else "rss")
        if pid not in items and src in failed_or_rolling and src in status and status[src] != "off" \
                and parse_time(it["ts"]) >= since:
            items[pid] = it

    ordered = sorted(items.values(), key=lambda i: i["ts"], reverse=True)[: int(conf.get("max_items", 2000))]
    doc = {"generated_at": iso(NOW), "window_days": conf.get("window_days", 7), "themes": conf["themes"],
           "sources": status, "items": ordered}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=0, ensure_ascii=False)
        f.write("\n")
    for k, v in status.items():
        print(f"{k}: {v}")
    print(f"flow items: {len(ordered)}")


if __name__ == "__main__":
    sys.exit(main())
