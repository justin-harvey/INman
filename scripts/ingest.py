"""Pull live feeds into site/data/*.json. Run by the scheduled GitHub Action.

What it does, in order:
  1. Loads the current incidents (site/data/incidents.json).
  2. ransomware.live adapter (OFF unless RL_ENABLED=true): U.S. leak-site claims
     become Tier 2 incidents. Turn it on only after your use is cleared under
     ransomware.live's terms (commercial use needs written approval).
  3. ransomwatch adapter (public domain): counts global leak-site posts per day
     into site/data/context.json. Its posts carry no country, so they are used
     only as a market-volume backdrop, never as U.S. incidents.
  4. Official disclosures (scripts/official.py): SEC 8-K cybersecurity filings
     and HHS breach-portal hacking reports become Tier 1 incidents, or confirm
     and promote an existing entry for the same organization.
  5. Applies analyst overrides from data/overrides.json (e.g. promote a claim
     to Tier 1 with the confirming source).
  6. Validates, sorts and writes files only when something changed.

A feed that fails is logged in site/data/meta.json; the run still succeeds so
one outage upstream never blanks the dashboard.

Environment:
  RL_ENABLED        "true" to pull ransomware.live (default off)
  RL_API_BASE       default https://api.ransomware.live/v2
  RL_API_KEY        optional token (sent in the header named by RL_API_KEY_HEADER)
  RL_API_KEY_HEADER default X-API-KEY
  RL_COUNTRY        default US
  LOOKBACK_DAYS     default 30 (claims older than this are ignored)
  RANSOMWATCH_URL   default the public posts.json
  SEC_ENABLED, HHS_ENABLED          "false" turns either official feed off (default on)
  SEC_LOOKBACK_DAYS, HHS_LOOKBACK_DAYS  default 60
  HHS_EVERY_HOURS   default 6 (the portal is read four times a day; every manual run reads it too)
  SEC_USER_AGENT    "<organization> <contact email>", as SEC asks of automated clients
  FIXTURE_DIR       read feeds from local files instead of the network (tests)
"""
import datetime as dt
import hashlib
import json
import os
import sys
import urllib.request
from collections import Counter

sys.path.insert(0, os.path.dirname(__file__))
from schema import FIELDS, TIERS, norm_org, validate  # noqa: E402
import official  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA = os.path.join(ROOT, "site", "data")
INCIDENTS = os.path.join(DATA, "incidents.json")
CONTEXT = os.path.join(DATA, "context.json")
META = os.path.join(DATA, "meta.json")
OVERRIDES = os.path.join(ROOT, "data", "overrides.json")

UA = "cyber-incident-monitor/1.0 (+private team dashboard)"
TODAY = dt.datetime.now(dt.timezone.utc).date()


def env(name, default=""):
    return os.environ.get(name, default).strip()


def fetch_json(url, headers=None, fixture=None):
    fixture_dir = env("FIXTURE_DIR")
    if fixture_dir and fixture:
        with open(os.path.join(fixture_dir, fixture)) as f:
            return json.load(f)
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8"))


def to_date(value):
    """Accept '2026-11-20', '2026-11-20 14:03:11', '2026-11-20T14:03:11Z'."""
    if not value:
        return None
    try:
        return dt.date.fromisoformat(str(value).strip()[:10])
    except ValueError:
        return None


def blank(**kw):
    rec = {f: "" for f in FIELDS}
    rec.update(records=None, ops_disrupted=False, data_exposed="Unknown", confirmed_by="")
    rec.update(kw)
    return rec


# ---------------------------------------------------------------- adapters
def ransomware_live(existing_keys):
    if env("RL_ENABLED").lower() != "true":
        return [], "skipped (RL_ENABLED is not true; see README licensing note)"
    base = env("RL_API_BASE", "https://api.ransomware.live/v2").rstrip("/")
    country = env("RL_COUNTRY", "US")
    headers = {}
    if env("RL_API_KEY"):
        headers[env("RL_API_KEY_HEADER", "X-API-KEY")] = env("RL_API_KEY")
    payload = fetch_json(f"{base}/countryvictims/{country}", headers, fixture="ransomware_live.json")
    items = payload if isinstance(payload, list) else payload.get("victims", payload.get("data", []))
    lookback = TODAY - dt.timedelta(days=int(env("LOOKBACK_DAYS", "30")))
    new = []
    for v in items:
        org = (v.get("victim") or v.get("post_title") or "").strip()
        group = (v.get("group") or v.get("group_name") or "").strip()
        d = to_date(v.get("attackdate")) or to_date(v.get("discovered"))
        if not org or not d or d < lookback or d > TODAY:
            continue
        key = norm_org(org)
        if not key or key in existing_keys:
            continue
        existing_keys.add(key)
        rid = "RL-" + hashlib.sha1(f"{key}|{group.lower()}".encode()).hexdigest()[:10]
        new.append(blank(
            id=rid, date=d.isoformat(), date_precision="Day", org=org,
            sector_group="Unclassified", org_type="Unclassified",
            industry=(v.get("activity") or v.get("sector") or "Unclassified"),
            state="Unknown", tier=2, tier_label=TIERS[2], incident_type="Leak-site claim",
            actor=group or "Not stated", summary="Listed on a ransomware leak site; not confirmed by the organization.",
            source="Ransomware.live", url=v.get("url") or v.get("post_url") or "https://www.ransomware.live/",
            origin="ransomware.live", first_seen=TODAY.isoformat(),
        ))
    return new, f"ok ({len(items)} records read, {len(new)} new)"


def ransomwatch_context():
    """Global leak-site posts per day. RansomLook first (CC BY 4.0, current); ransomwatch as fallback."""
    try:
        posts = fetch_json("https://www.ransomlook.io/api/posts?days=120", fixture="ransomlook_posts.json")
        if isinstance(posts, dict):
            posts = next((v for v in posts.values() if isinstance(v, list)), [])
        source, source_url = "RansomLook (CC BY 4.0)", "https://www.ransomlook.io/"
    except Exception:
        url = env("RANSOMWATCH_URL", "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json")
        posts = fetch_json(url, fixture="ransomwatch_posts.json")
        source, source_url = "ransomwatch (public domain)", "https://github.com/joshhighet/ransomwatch"
    since = TODAY - dt.timedelta(days=120)
    days = Counter()
    for p in posts:
        d = to_date(p.get("discovered"))
        if d and since <= d <= TODAY:
            days[d.isoformat()] += 1
    latest = max(days) if days else None
    ctx = {"label": "Global leak-site posts per day (all countries)",
           "source": source, "source_url": source_url,
           "latest_post_date": latest, "by_day": dict(sorted(days.items()))}
    stale = latest is None or (TODAY - dt.date.fromisoformat(latest)).days > 7
    return ctx, ("ok" if not stale else f"stale (latest post {latest})") + f", {sum(days.values())} posts in window"


# ---------------------------------------------------------------- overrides
def apply_overrides(incidents):
    if not os.path.exists(OVERRIDES):
        return 0
    with open(OVERRIDES) as f:
        overrides = json.load(f).get("overrides", {})
    n = 0
    for rec in incidents:
        o = overrides.get(rec["id"])
        if not o:
            continue
        for k, v in o.items():
            if k == "tier":
                rec["tier"], rec["tier_label"] = int(v), TIERS[int(v)]
            elif k in FIELDS:
                rec[k] = v
        n += 1
    return n


# ---------------------------------------------------------------- main
def load(path, default):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return default


def write_if_changed(path, obj):
    text = json.dumps(obj, indent=1, ensure_ascii=False) + "\n"
    old = None
    if os.path.exists(path):
        with open(path) as f:
            old = f.read()
    if old != text:
        with open(path, "w") as f:
            f.write(text)
        return True
    return False


def main():
    os.makedirs(DATA, exist_ok=True)
    doc = load(INCIDENTS, {"schema_version": 1, "incidents": []})
    incidents = doc["incidents"]
    keys = {norm_org(r["org"]) for r in incidents}
    status = {}

    try:
        new, status["ransomware.live"] = ransomware_live(keys)
        incidents.extend(new)
    except Exception as e:  # keep the dashboard up if a feed breaks
        status["ransomware.live"] = f"error: {e.__class__.__name__}: {e}"

    official.run(incidents, blank, TODAY, status, load(META, {}).get("feeds"))

    try:
        ctx, status["ransomwatch"] = ransomwatch_context()
        write_if_changed(CONTEXT, ctx)
    except Exception as e:
        status["ransomwatch"] = f"error: {e.__class__.__name__}: {e}"

    status["overrides"] = f"{apply_overrides(incidents)} applied"

    bad = [(r.get("id"), p) for r in incidents for p in validate(r)]
    if bad:
        for rid, p in bad:
            print(f"invalid {rid}: {p}", file=sys.stderr)
        sys.exit(1)

    incidents.sort(key=lambda r: (r["date"], r["org"]), reverse=True)
    changed = write_if_changed(INCIDENTS, {"schema_version": 1, "incidents": incidents})

    meta = load(META, {})
    tiers = Counter(r["tier"] for r in incidents)
    meta_new = {"updated_at": meta.get("updated_at"), "feeds": status, "total": len(incidents),
                "by_tier": {str(k): tiers.get(k, 0) for k in TIERS}}
    if changed or meta.get("feeds") != status or meta.get("total") != len(incidents):
        meta_new["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    write_if_changed(META, meta_new)
    for k, v in status.items():
        print(f"{k}: {v}")
    print(f"incidents: {len(incidents)} ({'changed' if changed else 'unchanged'})")


if __name__ == "__main__":
    main()
