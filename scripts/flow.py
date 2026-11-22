"""Build site/data/flow.json: the live inflow behind the orb.

Each source becomes items {id, ts, first_seen, theme, source, title, severity, url}.
Two outputs:
  site/data/flow.json          every item from the last `window_days` (default 7); polled by the page
  site/data/flow_history.json  `history_days` (default 90): true daily counts per theme, plus the
                               most severe `history_items_per_theme_day` items per theme per day
Items persist across runs, so feeds that only return recent items (RSS, status pages, NVD)
still build up a full history. NVD is backfilled for the whole window on the first run.

Sources and themes are configured in data/flow_sources.json.
Environment: RL_ENABLED, RL_API_BASE, RL_API_KEY, RL_API_KEY_HEADER (see README),
NVD_API_KEY (optional), GITHUB_TOKEN (optional, for the Upptime adapter),
Also: claims seen on several trackers are merged (see corroborate), actors are matched to
MITRE ATT&CK entries from site/data/attack_index.json, and data/watchlist.json sites are checked.
FIXTURE_DIR (tests: read every source from local files).
"""
import datetime as dt
import email.utils
import hashlib
import json
import os
import re
import sys
import urllib.parse
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG = os.path.join(ROOT, "data", "flow_sources.json")
OUT = os.path.join(ROOT, "site", "data", "flow.json")
INCIDENTS = os.path.join(ROOT, "site", "data", "incidents.json")
HISTORY = os.path.join(ROOT, "site", "data", "flow_history.json")
EPSS_CACHE = os.path.join(ROOT, "data", "epss_cache.json")
EPSS_API = "https://api.first.org/data/v1/epss"
EPSS_LIKELY = 0.10      # "likely to be exploited": at least a 10% chance of exploitation activity in the next 30 days
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


def item(source, theme, key, when, title, severity, url, actor="", victim=""):
    it = {"id": hashlib.sha1(f"{source}|{key}".encode()).hexdigest()[:14], "ts": iso(when),
          "first_seen": iso(NOW), "theme": theme, "source": source,
          "title": " ".join(str(title).split())[:180], "severity": round(max(0.0, min(1.0, severity)), 2),
          "url": url if str(url).startswith(("https://", "http://")) else ""}
    if actor and not str(actor).lower().startswith(("not ", "none", "unknown")):
        it["actor"] = str(actor).strip()[:60]
    if victim:
        it["victim"] = str(victim).strip()[:120]
    return it


def norm(s):
    """Lower-case, drop web suffixes and punctuation: used to match names across sources."""
    s = str(s or "").lower()
    s = re.sub(r"https?://|www\.", "", s)
    s = re.sub(r"\.(com|org|net|gov|edu|us|io|co|info|biz)(\.[a-z]{2})?\b", " ", s)
    s = re.sub(r"\b(inc|llc|ltd|corp|corporation|co|company|plc|group|the)\b", " ", s)
    return re.sub(r"[^a-z0-9]+", "", s)


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
                        "https://github.com/joshhighet/ransomwatch", actor=group, victim=title))
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
                        v.get("url") or "https://www.ransomware.live/", actor=v.get("group", ""), victim=v["victim"]))
    return out


BACKFILL = {"nvd": False, "ransomlook": False}   # set by main(): True until history holds older items


def a_ransomlook(cfg, since):
    """RansomLook recent posts (CC BY 4.0, credit RansomLook). Global, like ransomwatch."""
    days = max(1, (NOW - since).days) if BACKFILL["ransomlook"] else 7
    data = json.loads(fetch(f"{cfg.get('url', 'https://www.ransomlook.io/api/posts')}?days={days}"))
    if isinstance(data, dict):
        data = next((v for v in data.values() if isinstance(v, list)), [])
    out = []
    for p in data:
        t = parse_time(p.get("discovered"))
        title, group = p.get("post_title", ""), p.get("group_name", "")
        if not t or t < since or not title:
            continue
        out.append(item("RansomLook", cfg["theme"], f"{group}|{title}", t, f"{title} · claimed by {group} (global)", 0.55,
                        f"https://www.ransomlook.io/group/{urllib.parse.quote(group)}" if group else "https://www.ransomlook.io/",
                        actor=group, victim=title))
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
    """Last 7 days each run; the full history window (paged, rate-limit aware) until backfilled."""
    import time
    headers = {"apiKey": env("NVD_API_KEY")} if env("NVD_API_KEY") else {}
    start = since if BACKFILL["nvd"] else max(since, NOW - dt.timedelta(days=7))
    pause = 0 if env("FIXTURE_DIR") else (0.7 if headers else 6.5)   # NVD: 5 req/30s without a key, 50 with
    fmt = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
    out, calls = [], 0
    for sev in cfg.get("severities", ["CRITICAL", "HIGH"]):
        index = 0
        while True:
            if calls:
                time.sleep(pause)
            q = urllib.parse.urlencode({"pubStartDate": fmt(start), "pubEndDate": fmt(NOW), "cvssV3Severity": sev,
                                        "resultsPerPage": 2000, "startIndex": index})
            data = json.loads(fetch(f"https://services.nvd.nist.gov/rest/json/cves/2.0?{q}", headers))
            calls += 1
            vulns = data.get("vulnerabilities", [])
            for v in vulns:
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
            index += len(vulns)
            if not vulns or index >= int(data.get("totalResults", 0)) or calls >= 20:
                break
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
                        r.get("url", ""), actor=re.sub(r"\s*\(.*?\)", "", r.get("actor", "")).strip("'\" "), victim=r["org"]))
    return out


WATCH_STATE = os.path.join(ROOT, "data", "watch_state.json")
WATCHLIST = os.path.join(ROOT, "data", "watchlist.json")


def check_url(url):
    """Return (up, detail). Connection errors, timeouts and 5xx count as down; 4xx (often bot
    protection) counts as up. In tests the fixture holds the status code or 'timeout'."""
    if env("FIXTURE_DIR"):
        code = fetch(url).strip()
        return (False, "timed out") if code == "timeout" else (int(code) < 500, f"HTTP {code}")
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status < 500, f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return e.code < 500, f"HTTP {e.code}"
    except Exception as e:
        return False, e.__class__.__name__


def a_watchlist(cfg, since):
    """Our own uptime checks: emit an item when a watched site goes down and when it recovers."""
    sites = []
    if os.path.exists(WATCHLIST):
        with open(WATCHLIST) as f:
            sites = json.load(f).get("sites", [])
    if not sites:
        raise LookupError("no sites in data/watchlist.json yet")
    state = {}
    if os.path.exists(WATCH_STATE):
        with open(WATCH_STATE) as f:
            state = json.load(f)
    out = []
    for site in sites:
        name, url = site["name"], site["url"]
        up, detail = check_url(url)
        prev = state.get(url, {"up": True, "since": iso(NOW)})
        if prev["up"] and not up:
            out.append(item("Watchlist", cfg["theme"], f"{url}|down|{iso(NOW)}", NOW, f"{name} is down ({detail})", 0.6, url))
            state[url] = {"up": False, "since": iso(NOW), "detail": detail}
        elif not prev["up"] and up:
            mins = int((NOW - parse_time(prev["since"])).total_seconds() // 60)
            span = f"{mins // 60}h {mins % 60}m" if mins >= 60 else f"{mins}m"
            out.append(item("Watchlist", cfg["theme"], f"{url}|up|{iso(NOW)}", NOW, f"{name} is back up after {span}", 0.25, url))
            state[url] = {"up": True, "since": iso(NOW)}
        else:
            state.setdefault(url, prev)
    with open(WATCH_STATE, "w") as f:
        json.dump(state, f, indent=1, sort_keys=True)
    return out


ATTACK_INDEX = os.path.join(ROOT, "site", "data", "attack_index.json")
ACTOR_ALIASES = os.path.join(ROOT, "data", "actor_aliases.json")


def attack_lookup():
    """Map normalized actor names to MITRE ATT&CK groups/software (built weekly by attack_index.py)."""
    if not os.path.exists(ATTACK_INDEX):
        return lambda actor: None
    with open(ATTACK_INDEX) as f:
        entries = json.load(f).get("entries", [])
    table = {}
    for e in entries:
        for name in [e["name"], *e.get("aliases", [])]:
            table.setdefault(norm(name), e)
    crime = re.compile(r"ransomware|extortion|cyber ?crim|financially motivated|data leak|leak site", re.I)
    aliases = {}
    if os.path.exists(ACTOR_ALIASES):
        with open(ACTOR_ALIASES) as f:
            aliases = {norm(k): norm(v) for k, v in json.load(f).get("aliases", {}).items()}

    def find(actor):
        """Explicit aliases always match. Automatic name matches must describe ransomware, extortion or
        cybercrime, so that a leak-site group called "Aurora" is not linked to an unrelated espionage tool."""
        n = norm(actor)
        candidates = [(aliases[n], True)] if n in aliases else []
        candidates += [(n, False), (re.sub(r"(ransomware|team|group|gang|leaks?|\d+)$", "", n), False)]
        for key, explicit in candidates:
            e = table.get(key) if key else None
            if e and (explicit or crime.search(e.get("summary", ""))):
                return {"id": e["id"], "name": e["name"], "type": e["type"], "url": e["url"]}
        return None
    return find


def corroborate(items):
    """Merge claims about the same victim seen on several trackers (within 4 days) into one item.
    The survivor lists every source in `seen_on` and gains severity. Returns the merged dict."""
    claims = sorted((i for i in items.values() if i["theme"] == "claims" and i.get("victim")), key=lambda i: i["ts"])
    groups = {}
    for it in claims:
        key = norm(it["victim"])
        if not key:
            continue
        bucket = groups.setdefault(key, [])
        for g in bucket:
            if abs((parse_time(g[0]["ts"]) - parse_time(it["ts"])).days) <= 4:
                g.append(it)
                break
        else:
            bucket.append([it])
    for bucket in groups.values():
        for g in bucket:
            sources = sorted({x["source"] for x in g} | {s for x in g for s in x.get("seen_on", [])})
            if len(sources) < 2:
                continue
            keep = g[0]
            keep["seen_on"] = sources
            keep["severity"] = round(min(1.0, max(x["severity"] for x in g) + 0.1 * (len(sources) - 1)), 2)
            if not keep.get("actor"):
                keep["actor"] = next((x["actor"] for x in g if x.get("actor")), "")
            for x in g[1:]:
                items.pop(x["id"], None)
    return items


ADAPTERS = {"ransomwatch": a_ransomwatch, "ransomware_live": a_ransomware_live, "ransomlook": a_ransomlook,
            "watchlist": a_watchlist, "cisa_kev": a_cisa_kev,
            "nvd": a_nvd, "statuspages": a_statuspages, "upptime": a_upptime, "rss": a_rss, "inman": a_inman}


CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")


def epss_enrich(known):
    """Attach FIRST EPSS scores to vulnerability items (NVD and CISA KEV).

    EPSS is the probability that a CVE sees exploitation activity in the next 30 days. Scores change
    daily, so each CVE is looked up at most once per UTC day (data/epss_cache.json); a new CVE that
    EPSS has not scored yet is retried the next day. Likely-to-be-exploited items gain severity, so
    they stand out on the orb and survive the history file's per-day cut. Returns a status line."""
    import time
    try:
        with open(EPSS_CACHE) as f:
            cache = json.load(f).get("scores", {})
    except (OSError, ValueError):
        cache = {}
    today = NOW.date().isoformat()
    vuln = [it for it in known.values() if it["source"] in ("NVD", "CISA KEV")]
    for it in vuln:
        m = CVE_ID.search(it["title"])
        if m:
            it["cve"] = m.group(0)
    wanted = sorted({it["cve"] for it in vuln if it.get("cve") and cache.get(it["cve"], {}).get("d") != today})
    calls, err = 0, None
    for i in range(0, len(wanted), 50):
        if calls >= 60:                       # 3,000 CVEs a run is plenty; the rest wait for the next run
            break
        batch = wanted[i:i + 50]
        if calls and not env("FIXTURE_DIR"):
            time.sleep(0.4)
        try:
            data = json.loads(fetch(f"{EPSS_API}?{urllib.parse.urlencode({'cve': ','.join(batch), 'limit': 100})}"))
        except Exception as e:                # keep yesterday's scores rather than failing the run
            err = f"{e.__class__.__name__}: {str(e)[:80]}"
            break
        calls += 1
        got = {r.get("cve"): r for r in data.get("data", [])}
        for cve in batch:
            r = got.get(cve)
            cache[cve] = {"e": round(float(r["epss"]), 5), "p": round(float(r["percentile"]), 4), "d": today} if r \
                else {"e": None, "p": None, "d": today}
    likely = 0
    for it in vuln:
        sc = cache.get(it.get("cve", ""), {})
        if sc.get("e") is None:
            it.pop("epss", None)
            it.pop("epss_pct", None)
            continue
        it["epss"], it["epss_pct"] = sc["e"], sc["p"]
        if sc["e"] >= EPSS_LIKELY:
            likely += 1
            it["severity"] = round(max(it["severity"], min(1.0, 0.6 + sc["e"])), 2)
    live_cves = {it.get("cve") for it in vuln}
    cache = {k: v for k, v in cache.items() if k in live_cves}     # forget CVEs that left the window
    os.makedirs(os.path.dirname(EPSS_CACHE), exist_ok=True)
    with open(EPSS_CACHE, "w") as f:
        json.dump({"source": "FIRST EPSS (https://www.first.org/epss/)", "scores": dict(sorted(cache.items()))}, f,
                  separators=(",", ":"))
    scored = sum(1 for it in vuln if "epss" in it)
    note = f"{scored} of {len(vuln)} scored, {likely} likely to be exploited ({calls} lookups)"
    return (f"error: {err}; using saved scores, " + note) if err else f"ok ({note})"


def day_of(it):
    return it["ts"][:10]


def main():
    with open(CONFIG) as f:
        conf = json.load(f)
    live_days = int(conf.get("window_days", 7))
    hist_days = int(conf.get("history_days", 90))
    per_day = int(conf.get("history_items_per_theme_day", 12))
    live_since = NOW - dt.timedelta(days=live_days)
    hist_since = NOW - dt.timedelta(days=hist_days)

    def load(path):
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
        return {}

    prev_live = {i["id"]: i for i in load(OUT).get("items", [])}
    prev_hist = load(HISTORY)
    prev_items = {i["id"]: i for i in prev_hist.get("items", [])}
    prev_items.update(prev_live)
    for key, src in (("nvd", "NVD"), ("ransomlook", "RansomLook")):
        BACKFILL[key] = not any(i["source"] == src and parse_time(i["ts"]) < NOW - dt.timedelta(days=8)
                                for i in prev_items.values())

    fetched, status = {}, {}
    for name, cfg in conf["sources"].items():
        if not enabled(cfg):
            status[name] = "off"
            continue
        try:
            got = ADAPTERS[name](cfg, hist_since)
            for it in got:
                if it["id"] in prev_items:      # keep when we first saw it, so the orb animates only new items
                    it["first_seen"] = prev_items[it["id"]]["first_seen"]
                fetched[it["id"]] = it
            status[name] = f"ok ({len(got)})"
        except LookupError as e:          # nothing configured yet (e.g. an empty watchlist)
            status[name] = f"idle: {e}"
        except Exception as e:
            status[name] = f"error: {e.__class__.__name__}: {str(e)[:120]}"

    # everything known this run: fresh items + earlier ones still inside the history window
    # (RSS, status pages and NVD only return recent items, so older ones are carried forward)
    known = dict(fetched)
    for pid, it in prev_items.items():
        if pid not in known and parse_time(it["ts"]) >= hist_since:
            known[pid] = it

    # actors: one display name per spelling ("qilin", "Qilin" -> "Qilin"), then their MITRE ATT&CK match
    find = attack_lookup()
    canon = {}
    for it in sorted(known.values(), key=lambda i: i["ts"]):
        a = it.get("actor")
        if a:
            k = norm(a)
            if k not in canon or (canon[k].islower() and not a.islower()):
                canon[k] = a
    for k, name in canon.items():       # prefer ATT&CK's spelling; otherwise capitalise all-lowercase names
        m = find(name)
        canon[k] = m["name"] if m else (name[:1].upper() + name[1:] if re.fullmatch(r"[a-z][a-z ]*", name) else name)
    for it in list(known.values()) + list(fetched.values()):
        if it.get("actor"):
            it["actor"] = canon.get(norm(it["actor"]), it["actor"])
    corroborate(known)
    enrichment = {"epss": epss_enrich(known) if env("EPSS_ENABLED", "true").lower() != "false" else "off"}
    for pid in list(fetched):
        if pid not in known:
            fetched.pop(pid)

    actor_meta = {}
    for it in known.values():
        a = it.get("actor")
        if a and a not in actor_meta:
            actor_meta[a] = find(a)

    # live file: every item from the last `window_days`
    live = sorted((i for i in known.values() if parse_time(i["ts"]) >= live_since), key=lambda i: i["ts"], reverse=True)
    live = live[: int(conf.get("max_items", 2000))]

    # history file: true daily counts per theme + the most severe items per theme per day
    counts = {}
    for it in list(fetched.values()) + [i for i in prev_live.values() if i["id"] in known]:
        if parse_time(it["ts"]) >= hist_since:
            counts.setdefault(it["theme"], {}).setdefault(day_of(it), set()).add(it["id"])
    actor_counts = {}
    for it in list(fetched.values()) + [i for i in prev_live.values() if i["id"] in known]:
        if it.get("actor") and parse_time(it["ts"]) >= hist_since:
            actor_counts.setdefault(it["actor"], {}).setdefault(day_of(it), set()).add(it["id"])
    daily = {}
    first_day = hist_since.date().isoformat()
    for th in conf["themes"]:
        old = prev_hist.get("daily", {}).get(th["id"], {})
        new = {d: len(ids) for d, ids in counts.get(th["id"], {}).items()}
        merged = {d: max(old.get(d, 0), new.get(d, 0)) for d in set(old) | set(new) if d >= first_day}
        daily[th["id"]] = dict(sorted(merged.items()))
    prev_actors = {}
    for a, days in prev_hist.get("actors_daily", {}).items():
        merged_prev = prev_actors.setdefault(canon.get(norm(a), a), {})
        for d, n in days.items():
            merged_prev[d] = max(merged_prev.get(d, 0), n)
    actors_daily = {}
    for actor in set(actor_counts) | set(prev_actors):
        old = prev_actors.get(actor, {})
        new = {d: len(ids) for d, ids in actor_counts.get(actor, {}).items()}
        merged = {d: max(old.get(d, 0), new.get(d, 0)) for d in set(old) | set(new) if d >= first_day}
        if merged:
            actors_daily[actor] = dict(sorted(merged.items()))
            if actor not in actor_meta:
                actor_meta[actor] = find(actor)
    buckets = {}
    for it in known.values():
        buckets.setdefault((it["theme"], day_of(it)), []).append(it)
    hist_items = []
    for group in buckets.values():
        group.sort(key=lambda i: (i["severity"], i["ts"]), reverse=True)
        hist_items.extend(group[:per_day])
    hist_items.sort(key=lambda i: i["ts"], reverse=True)

    # EPSS: new high/critical CVEs per publication day that are likely to be exploited, and the top few
    epss_daily = {}
    for it in known.values():
        if it["source"] == "NVD" and (it.get("epss") or 0) >= EPSS_LIKELY and parse_time(it["ts"]) >= hist_since:
            epss_daily[day_of(it)] = epss_daily.get(day_of(it), 0) + 1
    recent = NOW - dt.timedelta(days=30)
    top = sorted((it for it in known.values() if it.get("epss") is not None and parse_time(it["ts"]) >= recent),
                 key=lambda i: (-i["epss"], i["ts"]))
    kev_cves = {it.get("cve") for it in known.values() if it["source"] == "CISA KEV"}
    seen_cve, epss_top = set(), []
    for it in top:
        if it["cve"] in seen_cve:
            continue
        seen_cve.add(it["cve"])
        epss_top.append({"cve": it["cve"], "epss": it["epss"], "pct": it["epss_pct"], "title": it["title"],
                         "url": it["url"], "kev": it["cve"] in kev_cves})
        if len(epss_top) >= 8:
            break

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    actors = {a: m for a, m in sorted(actor_meta.items())}
    write(OUT, {"generated_at": iso(NOW), "window_days": live_days, "history_days": hist_days,
                "themes": conf["themes"], "sources": status, "enrichment": enrichment, "actors": actors, "items": live})
    write(HISTORY, {"generated_at": iso(NOW), "history_days": hist_days, "items_per_theme_day": per_day,
                    "themes": conf["themes"], "daily": daily, "actors_daily": actors_daily, "actors": actors,
                    "epss": {"threshold": EPSS_LIKELY, "likely_daily": dict(sorted(epss_daily.items())), "top_30d": epss_top},
                    "items": hist_items})
    for k, v in {**status, **enrichment}.items():
        print(f"{k}: {v}")
    print(f"live items: {len(live)} · history items: {len(hist_items)}")


def write(path, doc):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, separators=(",", ":"), ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    sys.exit(main())
