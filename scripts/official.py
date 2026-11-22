"""Official U.S. disclosure feeds: confirmed incidents straight from regulators' public records.

  SEC EDGAR  Form 8-K filings that disclose a cybersecurity incident: Item 1.05 (material, required
             within four business days of the materiality decision) and voluntary Item 8.01 filings.
             Found with EDGAR full-text search; 8.01 hits are kept only when the filing itself reads
             like an incident notice (it says the company identified or became aware of unauthorized
             activity), so passing mentions do not count.
  HHS OCR    The breach portal's list of breaches of health information affecting 500 or more people.
             Only "Hacking/IT Incident" reports are used; theft of laptops, misdirected mail and the
             like are not cyber incidents. Counts of 500 or 501 are the placeholders entities file
             while they investigate, so they are kept out of record totals.

Both are U.S. government public records. SEC asks automated clients to identify themselves: set the
repository variable SEC_USER_AGENT to "<your organization> <contact email>".

Each record either becomes a new Tier 1 incident or, when the same organization is already listed
within 120 days, confirms that entry instead: a Tier 2 claim or Tier 3 suspected outage is promoted
to Tier 1 and the record notes which filing confirmed it.
"""
import datetime as dt
import hashlib
import html
import http.cookiejar
import json
import os
import re
import time
import urllib.parse
import urllib.request

from schema import TIERS, norm_org

SEC_SEARCH = "https://efts.sec.gov/LATEST/search-index"
HHS_PAGES = ["https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf",
             "https://ocrportal.hhs.gov/ocr/breach/breach_report_hip.jsf"]
HHS_PUBLIC = HHS_PAGES[0]
MERGE_WINDOW_DAYS = 120
US_STATES = set("AL AK AZ AR CA CO CT DE DC FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND "
                "OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY PR GU VI AS MP".split())
INCIDENT_NOTICE = re.compile(
    r"(became aware|identified|detected|discovered|determined that)[^.]{0,240}"
    r"(unauthori[sz]ed|cybersecurity incident|ransomware|threat actor|malicious|suspicious activity)", re.I)


def env(name, default=""):
    return os.environ.get(name, default).strip()


def fixture(name):
    d = env("FIXTURE_DIR")
    if not d:
        return None
    path = os.path.join(d, name)
    if not os.path.exists(path):
        raise FileNotFoundError(f"no fixture {name}")
    with open(path, encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------- SEC EDGAR
def sec_agent():
    ua = env("SEC_USER_AGENT")
    if ua:
        return ua
    repo = env("GITHUB_REPOSITORY", "incident-monitor")
    return f"{repo.replace('/', '-')} incident-monitor (https://github.com/{repo})"


def sec_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": sec_agent(), "Accept-Encoding": "identity"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        if e.code == 403:
            raise RuntimeError("SEC refused the request (403): set the repository variable SEC_USER_AGENT "
                               "to '<your organization> <contact email>'") from e
        raise


SIC_INDUSTRY = [((100, 999), "Other"), ((1000, 1499), "Energy/utilities"), ((1500, 1799), "Construction"),
                ((2000, 2799), "Manufacturing/auto"), ((2830, 2836), "Pharma/biotech"), ((2800, 3999), "Manufacturing/auto"),
                ((4000, 4799), "Transportation"), ((4800, 4899), "Telecom"), ((4900, 4999), "Energy/utilities"),
                ((5000, 5199), "Retail"), ((5200, 5999), "Retail"), ((6000, 6799), "Finance/insurance"),
                ((7000, 7099), "Hospitality"), ((7370, 7379), "Tech/SaaS"), ((7300, 7399), "Professional services"),
                ((8000, 8099), "Healthcare"), ((8200, 8299), "Education"), ((8700, 8799), "Professional services")]


def sic_industry(sics):
    for s in sics or []:
        try:
            n = int(str(s)[:4])
        except ValueError:
            continue
        for (a, b), name in SIC_INDUSTRY:
            if a <= n <= b:
                return name
    return "Unclassified"


KEEP_UPPER = {"LLC", "LP", "LLP", "PLC", "USA", "US", "PC", "PA", "PLLC", "MD", "DDS", "DMD", "OD", "DO", "PT", "ENT",
              "II", "III", "IV", "NA", "N.A.", "HMO", "PPO", "UCLA", "UC", "AI", "IT"}


def tidy(name):
    """All-caps names (common in both registers) read better in title case; abbreviations stay upper."""
    name = re.sub(r"\s+", " ", str(name or "")).strip(" ,")
    if name.isupper():
        name = " ".join(w if w.strip(",.") in KEEP_UPPER else w.capitalize() for w in name.split())
    return name


def clean_company(display):
    return tidy(re.sub(r"\s*\((?:CIK [^)]*|[A-Z0-9.,\- ]{1,30})\)", "", display or ""))


def sec_state(src):
    for st in src.get("biz_states") or []:
        if st in US_STATES:
            return st
    for loc in src.get("biz_locations") or []:
        m = re.search(r",\s*([A-Z]{2})$", loc or "")
        if m and m.group(1) in US_STATES:
            return m.group(1)
    return "Unknown"


def sec_hits(since, until):
    """Every 8-K/8-K/A document whose text mentions a cybersecurity incident, grouped by filing."""
    raw = fixture("sec_efts.json")
    pages = [json.loads(raw)] if raw is not None else []
    if raw is None:
        offset = 0
        while offset < 500:
            q = urllib.parse.urlencode({"q": '"cybersecurity incident"', "forms": "8-K,8-K/A", "dateRange": "custom",
                                        "startdt": since.isoformat(), "enddt": until.isoformat(), "from": offset})
            page = json.loads(sec_get(f"{SEC_SEARCH}?{q}"))
            pages.append(page)
            n = len(page.get("hits", {}).get("hits", []))
            total = page.get("hits", {}).get("total", {}).get("value", 0)
            offset += n
            if not n or offset >= total:
                break
            time.sleep(0.2)                     # SEC fair access: well under 10 requests a second
    filings = {}
    for page in pages:
        for h in page.get("hits", {}).get("hits", []):
            src = h.get("_source", {})
            adsh = src.get("adsh")
            if not adsh:
                continue
            f = filings.setdefault(adsh, {"src": src, "docs": []})
            f["docs"].append((h.get("_id", "").split(":", 1)[-1], src.get("file_type", "")))
    return filings


def sec_filings(since, until, known_ids=()):
    out, checked = [], 0
    for adsh, f in sec_hits(since, until).items():
        src = f["src"]
        items = [str(i) for i in src.get("items") or []]
        material = "1.05" in items
        if not material and "8.01" not in items:
            continue                                  # earnings releases etc. that only mention the phrase
        main = next((d for d, t in f["docs"] if str(t).upper().startswith("8-K")), f["docs"][0][0])
        cik = int((src.get("ciks") or ["0"])[0])
        url = f"https://www.sec.gov/Archives/edgar/data/{cik}/{adsh.replace('-', '')}/{main}"
        if not material and f"SEC-{adsh}" not in known_ids:   # voluntary filing: read it to make sure it is an incident notice
            text = fixture(f"sec_doc_{adsh}.htm") if env("FIXTURE_DIR") else None
            if text is None:
                if checked:
                    time.sleep(0.2)
                text = sec_get(url)
                checked += 1
            plain = html.unescape(re.sub(r"<[^>]+>", " ", text))
            if not INCIDENT_NOTICE.search(plain):
                continue
        out.append({"adsh": adsh, "company": clean_company((src.get("display_names") or [""])[0]),
                    "date": src.get("file_date", "")[:10], "form": src.get("form", "8-K"), "material": material,
                    "state": sec_state(src), "industry": sic_industry(src.get("sics")), "url": url})
    return out


# ---------------------------------------------------------------- HHS OCR breach portal
class Portal:
    """Minimal JSF/PrimeFaces client: keeps the session cookie and the view state between requests."""

    def __init__(self):
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.headers = {"User-Agent": "Mozilla/5.0 (compatible; incident-monitor/1.0)"}

    def get(self, url):
        with self.opener.open(urllib.request.Request(url, headers=self.headers), timeout=60) as r:
            return r.read().decode("utf-8", "replace")

    def post(self, url, fields):
        data = urllib.parse.urlencode(fields).encode()
        hdr = {**self.headers, "Faces-Request": "partial/ajax", "X-Requested-With": "XMLHttpRequest",
               "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
        with self.opener.open(urllib.request.Request(url, data=data, headers=hdr), timeout=60) as r:
            return r.read().decode("utf-8", "replace")


def cells(row_html):
    return [re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", c))).strip()
            for c in re.findall(r"<td\b[^>]*>(.*?)</td>", row_html, re.S | re.I)]


ENTITY_TYPES = {"healthcare provider", "health plan", "business associate", "healthcare clearing house",
                "health care clearinghouse", "healthcare clearinghouse"}
BREACH_TYPES = re.compile(r"hacking|unauthorized|theft|loss|improper disposal|^other$", re.I)


def parse_row(c):
    """Pick fields by what they look like, so a reordered or extra column does not break parsing."""
    rec = {}
    for v in c:
        if not v:
            continue
        if "date" not in rec and re.fullmatch(r"\d{2}/\d{2}/\d{4}", v):
            m, d, y = v.split("/")
            rec["date"] = f"{y}-{m}-{d}"
        elif "state" not in rec and v in US_STATES:
            rec["state"] = v
        elif "affected" not in rec and re.fullmatch(r"[\d,]+", v):
            rec["affected"] = int(v.replace(",", ""))
        elif "etype" not in rec and v.lower() in ENTITY_TYPES:
            rec["etype"] = v
        elif "btype" not in rec and BREACH_TYPES.search(v) and len(v) < 120:
            rec["btype"] = v
        elif "name" not in rec and len(v) > 1 and not v.lower().startswith(("view", "expand")):
            rec["name"] = v
        elif "btype" in rec and "location" not in rec:
            rec["location"] = v
    return rec if {"name", "date", "btype"} <= set(rec) else None


def rows_from(markup):
    return [r for r in (parse_row(cells(tr)) for tr in re.findall(r"<tr\b[^>]*data-ri=[^>]*>(.*?)</tr>", markup, re.S | re.I)) if r]


def hhs_rows():
    """All rows of the portal's current-investigations table (about two years of reports)."""
    if env("FIXTURE_DIR"):
        first = fixture("hhs_page.html")
        rows, n = rows_from(first), 1
        while True:
            try:
                rows += rows_from(fixture(f"hhs_page_{n}.xml"))
            except FileNotFoundError:
                break
            n += 1
        return rows, "fixture"
    portal, last_err = Portal(), None
    for url in HHS_PAGES:
        try:
            page = portal.get(url)
        except Exception as e:  # try the next known address
            last_err = e
            continue
        rows = rows_from(page)
        vs = re.search(r'name="(?:javax|jakarta)\.faces\.ViewState"[^>]*value="([^"]+)"', page) or \
            re.search(r'value="([^"]+)"[^>]*name="(?:javax|jakarta)\.faces\.ViewState"', page)
        table = re.search(r'<div id="([^"]+)" class="ui-datatable', page)
        form = re.search(r'<form id="([^"]+)"', page)
        if not (vs and table and form):
            return rows, f"first page only ({len(rows)} rows; table controls not found)"
        tid, fid, vs_name = table.group(1), form.group(1), ("jakarta" if "jakarta.faces.ViewState" in page else "javax")
        per_page, first = 100, 0
        for _ in range(12):                       # 12 x 100 rows is well past the ~700 open investigations
            resp = portal.post(url, {
                f"{vs_name}.faces.partial.ajax": "true", f"{vs_name}.faces.source": tid,
                f"{vs_name}.faces.partial.execute": tid, f"{vs_name}.faces.partial.render": tid,
                tid: tid, f"{tid}_pagination": "true", f"{tid}_first": str(first), f"{tid}_rows": str(per_page),
                f"{tid}_skipChildren": "true", f"{tid}_encodeFeature": "true",
                fid: fid, f"{vs_name}.faces.ViewState": vs.group(1)})
            got = rows_from(resp)
            if not got:
                break
            rows += got
            first += per_page
            if len(got) < per_page:
                break
            time.sleep(0.5)
        return rows, f"{len(rows)} rows read"
    raise RuntimeError(f"HHS breach portal unreachable: {last_err}")


def hhs_breaches(since):
    rows, note = hhs_rows()
    seen, out = set(), []
    for r in rows:
        if "hacking" not in r["btype"].lower():
            continue
        key = (norm_org(r["name"]), r["date"])
        if key in seen or r["date"] < since.isoformat():
            continue
        seen.add(key)
        out.append(r)
    return out, note


# ---------------------------------------------------------------- merge into incidents
def merge(incidents, rec, label):
    """Add `rec`, or confirm an existing entry for the same organization within the merge window.
    Returns 'new', 'promoted', 'confirmed' or 'known'."""
    if any(r["id"] == rec["id"] for r in incidents):
        return "known"
    key, d = norm_org(rec["org"]), dt.date.fromisoformat(rec["date"])
    for r in incidents:
        if norm_org(r["org"]) != key:
            continue
        try:
            gap = abs((dt.date.fromisoformat(r["date"]) - d).days)
        except ValueError:
            continue
        if gap > MERGE_WINDOW_DAYS:
            continue
        if label in (r.get("confirmed_by") or ""):
            return "known"
        r["confirmed_by"] = "; ".join(x for x in [r.get("confirmed_by"), f"{label} ({rec['date']}): {rec['url']}"] if x)
        if r["tier"] in (2, 3):
            r["tier"], r["tier_label"] = 1, TIERS[1]
            return "promoted"
        return "confirmed"
    incidents.append(rec)
    return "new"


def sec_records(blank, today, lookback_days, known_ids=()):
    since = today - dt.timedelta(days=lookback_days)
    recs = []
    for f in sec_filings(since, today, known_ids):
        what = "Item 1.05 (material cybersecurity incident)" if f["material"] else "Item 8.01 (voluntary disclosure)"
        recs.append(blank(
            id=f"SEC-{f['adsh']}", date=f["date"], date_precision="Day", org=f["company"],
            sector_group="Corporate & private", org_type="Private company", industry=f["industry"], state=f["state"],
            tier=1, tier_label=TIERS[1], incident_type="Intrusion (unspecified)", actor="Not named",
            count_basis="", summary=f"Disclosed a cybersecurity incident to the SEC on Form {f['form']}, {what}.",
            source="SEC EDGAR", url=f["url"], origin="sec_edgar", first_seen=today.isoformat(),
            confirmed_by=f"SEC Form {f['form']}"))
    return recs


def hhs_records(blank, today, lookback_days, known_ids=()):
    since = today - dt.timedelta(days=lookback_days)
    rows, note = hhs_breaches(since)
    recs = []
    for r in rows:
        n = r.get("affected")
        placeholder = n in (500, 501)
        recs.append(blank(
            id="HHS-" + hashlib.sha1(f"{norm_org(r['name'])}|{r['date']}".encode()).hexdigest()[:10],
            date=r["date"], date_precision="Day", org=tidy(r["name"]),
            sector_group="Corporate & private", org_type="Private company", industry="Healthcare",
            state=r.get("state", "Unknown"), tier=1, tier_label=TIERS[1], incident_type="Data breach/theft",
            actor="Not named", records=None if placeholder or n is None else n,
            count_basis="HHS placeholder (500/501): true count pending" if placeholder else "Reported to HHS",
            data_exposed="Yes",
            summary=f"Reported to HHS as a hacking/IT incident affecting {'at least 500' if placeholder else f'{n:,}' if n else 'an unknown number of'} people"
                    + (f" ({r['etype'].lower()})" if r.get("etype") else "")
                    + (f"; breached information was in {r['location'].lower()}" if r.get("location") else "") + ".",
            source="HHS OCR breach portal", url=HHS_PUBLIC, origin="hhs_ocr", first_seen=today.isoformat(),
            confirmed_by="HHS OCR breach report"))
    return recs, note


def due(every_hours, now=None):
    """The HHS portal is read a few times a day, not every 30 minutes: on the first scheduled run of
    every `every_hours`-th UTC hour, and always on a manual run."""
    if env("FIXTURE_DIR") or env("GITHUB_EVENT_NAME") == "workflow_dispatch" or every_hours <= 1:
        return True
    now = now or dt.datetime.now(dt.timezone.utc)
    return now.hour % every_hours == 0 and now.minute < 30


def run(incidents, blank, today, status, prev_status=None):
    """Pull both feeds into `incidents` in place; record a status line for each."""
    known_ids = {r["id"] for r in incidents}
    for name, enabled_var, build, label, lookback, every in (
            ("sec_edgar", "SEC_ENABLED", sec_records, "SEC 8-K", int(env("SEC_LOOKBACK_DAYS", "60")), 1),
            ("hhs_ocr", "HHS_ENABLED", hhs_records, "HHS breach report", int(env("HHS_LOOKBACK_DAYS", "60")),
             int(env("HHS_EVERY_HOURS", "6")))):
        if env(enabled_var, "true").lower() == "false":
            status[name] = f"off ({enabled_var} is false)"
            continue
        if not due(every):
            status[name] = (prev_status or {}).get(name) or f"scheduled (read every {every} hours)"
            continue
        try:
            got = build(blank, today, lookback, known_ids)
            recs, note = got if isinstance(got, tuple) else (got, "")
            tally = {}
            for rec in recs:
                res = merge(incidents, rec, label)
                tally[res] = tally.get(res, 0) + 1
            parts = [f"{len(recs)} in the last {lookback} days"] + [f"{v} {k}" for k, v in sorted(tally.items()) if k != "known"]
            status[name] = "ok (" + ", ".join(parts) + (f"; {note}" if note and note != "fixture" else "") + ")"
        except Exception as e:  # one feed failing never blanks the dashboard
            status[name] = f"error: {e.__class__.__name__}: {str(e)[:160]}"
