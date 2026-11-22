# INman · Cyber Incident Monitor

A private team dashboard for cyberattacks, breaches, extortion claims and major outages affecting U.S. government bodies and companies. It is a static site (no server, no dependencies) that reads `site/data/incidents.json`. A scheduled GitHub Action refreshes the data, and Netlify redeploys on every push.

![tiers](site/favicon.svg)

## What's on the dashboard

- **Volume chart.** Daily or weekly bars stacked by tier, a moving-average line, cumulative records exposed (log scale) and numbered flags for anchor events. Drag across the strip below to zoom. Click a bar to list that period's incidents.
- **Filters.** Government vs. corporate, tier, org type, industry, state and free-text search.
- **Breakdowns.** Incidents by industry and by org type, split by tier.
- **Table.** Sortable, linked to sources, with CSV export of whatever is filtered.

## Tiers

| Tier | Meaning |
| --- | --- |
| 1 Confirmed | The organization, a regulator or credible reporting confirmed malicious activity |
| 2 Claimed | Listed by an extortion group or hacker with no confirmation (drawn hatched) |
| 3 Suspected-cyber outage | Systems taken offline for a security reason, no attack confirmed |
| 4 Technical outage | Major outage attributed to a non-malicious cause |

A claim moves from Tier 2 to Tier 1 only when a confirming source is recorded (see *Analyst workflow*).

## Repository layout

```
site/                 the dashboard (Netlify publishes this folder)
  index.html, app.js, styles.css
  data/incidents.json all incidents (backfill + feeds)
  data/events.json    anchor events shown as flags
  data/context.json   global leak-site posts per day (written by ingest)
  data/meta.json      last update time + feed status (written by ingest)
  data/flow.json      last week of live items for the orb (written by flow.py)
  data/flow_history.json  90 days: daily counts + top items per theme per day
  data/trends.json    trend summary for the Trends card (written by trends.py)
  flow.js             the orb
  trends.js           the Trends card
scripts/
  ingest.py           pulls feeds, dedupes, applies overrides
  flow.py             builds the orb's live flow from data/flow_sources.json
  trends.py           recomputes the Trends card from the history and incidents
  xlsx_to_json.py     converts the analyst workbook into incidents.json
  check_data.py       Netlify build gate: refuses malformed data
  schema.py           shared field list, tiers, validation
data/overrides.json   analyst corrections and tier promotions
data/flow_sources.json  orb themes and sources
tests/                offline tests (run in CI before every ingest)
.github/workflows/ingest.yml   runs every 30 minutes
netlify.toml          publish settings + security headers
```

## Deploy on Netlify

1. In Netlify, choose **Add new site → Import an existing project → GitHub**, and pick this repo.
2. Leave the build settings as `netlify.toml` defines them (publish `site`, build command `python3 scripts/check_data.py`).
3. **Restrict access before sharing the URL.** Use Netlify's site protection (password or team login; what's available depends on your Netlify plan), or put the site behind your company's SSO proxy. The site also sends `noindex` headers, but that's not access control.

## Turn on the feeds

The workflow runs every 30 minutes (GitHub can delay scheduled runs at busy times) and on demand from the **Actions** tab. It needs **Settings → Actions → General → Workflow permissions → Read and write** so it can commit data updates.

| Feed | Default | What it does |
| --- | --- | --- |
| Global leak-site posts (context line) | On | Counts global leak-site posts per day from RansomLook (CC BY 4.0), falling back to ransomwatch. These posts carry no country, so they never become U.S. incidents. meta.json flags the line as `stale` if the newest post is over 7 days old. |
| ransomware.live | **Off** | Adds U.S. leak-site claims as Tier 2. |

**Licensing gate for ransomware.live.** Its terms allow free non-commercial use with attribution. Commercial use needs written approval from its owner, and the terms also bar republishing raw data and dashboards that copy its look. Get approval (or confirm your use is non-commercial) before enabling it. Then set, under **Settings → Secrets and variables → Actions**:

- Variable `RL_ENABLED` = `true`
- Optional variable `RL_API_BASE` (default `https://api.ransomware.live/v2`). If they issue you a token for their newer API, set the base URL they give you here.
- Optional secret `RL_API_KEY` and variable `RL_API_KEY_HEADER` (default `X-API-KEY`). Confirm the header name in their API docs.

The adapter calls `/countryvictims/US` and keeps claims from the last 30 days (`LOOKBACK_DAYS`). It skips any organization already in the data, after normalizing names.

## Live threat flow (the orb)

The top of the dashboard is an orb of everything the feeds brought in. Each sector is one theme. The rim is "now" and the core is the start of the chosen range: **48 hours, 1 week, 30 days, 60 days or 90 days**. Pick a range and the orb replays it on a clock: items stream in from their source lane, land at the rim and sink toward the core as time passes. Drag the slider to any moment, pause, or jump back to live. Click a theme card to focus it, hover a point for details, click it to open the source. In live mode the page re-checks `data/flow.json` every 5 minutes and animates anything new.

`scripts/flow.py` runs on the same 30-minute schedule and writes two files:

- `site/data/flow.json`: every item from the last 7 days (48-hour and 1-week views, live polling).
- `site/data/flow_history.json`: 90 days of exact daily counts per theme, plus the 12 most severe items per theme per day (30/60/90-day views; loaded only when picked). Change `history_days` and `history_items_per_theme_day` in `data/flow_sources.json`.

History builds up from the first scheduled run for feeds that only publish recent items (RSS, status pages). RansomLook, CISA KEV and the curated incidents fill the full 90 days at once, and NVD is backfilled for the whole window on the first run (slowly, to respect its rate limit; add `NVD_API_KEY` to speed it up). Sources and themes live in `data/flow_sources.json`; turn any source off with `"enabled": false`.

| Theme | Sources (default) | Terms |
| --- | --- | --- |
| Extortion claims | RansomLook (global, on); ransomwatch (off: its feed stopped updating; re-enable if it resumes); ransomware.live (U.S., off until licensing is cleared) | RansomLook: CC BY 4.0, credit shown on the dashboard. ransomwatch: Unlicense. ransomware.live: terms above |
| Exploited vulnerabilities | CISA Known Exploited Vulnerabilities feed | U.S. government public data |
| New high/critical CVEs | NVD CVE API 2.0 (optional secret `NVD_API_KEY` raises the rate limit) | Public API. Show NVD's notice: "This product uses the NVD API but is not endorsed or certified by the NVD." |
| Outages & service health | Public Statuspage pages (GitHub, Cloudflare, Atlassian, Twilio, Zoom); the built-in **site watchlist** (`data/watchlist.json`, empty until you add sites); optionally your own Upptime repo (off) | Public status pages |
| Advisories & news | CISA advisories, BleepingComputer and The Record RSS (headlines and links only) | Headlines only |
| Confirmed U.S. incidents | This repo's curated incidents (claims and outages go to their own sectors) | — |

**Corroborated claims.** When the same victim appears on more than one tracker within 4 days, the claims merge into one point with a white ring, a "seen on" list and a higher severity. Ransomware groups do post false claims, so a second tracker is a useful (not conclusive) signal.

**Trends.** Below the orb, the Trends card summarizes the last 90 complete days: how fast extortion claims are growing (shown with and without any single group that drives most of the growth, since one bulk poster can hide the underlying pace), how concentrated they are, which groups are steady, climbing, new or quiet, the weekly posting rhythm, the pace of exploited and new vulnerabilities, and the shape of the curated U.S. incidents. `scripts/trends.py` rebuilds every sentence and figure from the data on each scheduled run, so nothing on the card is hand-written. Its "What this can't tell you yet" list names the limits: claims are global until ransomware.live is on, feeds with short history are filling in rather than rising, and disclosure lag makes the latest weeks look low.

**Most active groups.** Claims and curated incidents that name a group are counted for the chosen range. Groups that match a MITRE ATT&CK® group or software entry link to its profile. `scripts/attack_index.py` rebuilds `site/data/attack_index.json` from MITRE's public STIX data once a week; automatic matches are accepted only when the ATT&CK entry describes ransomware, extortion or cybercrime, so a leak-site group that shares a name with an unrelated espionage tool is not linked. When a tracker spells a group differently from ATT&CK (for example `alphv` for BlackCat), add the pair to `data/actor_aliases.json`; listed pairs always match. MITRE ATT&CK content © The MITRE Corporation, used under the [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).

**Vulnerability velocity.** New high/critical CVEs and additions to CISA's exploited list, per day (per 4 hours for 48 hours), for the chosen range.

**Site watchlist.** Add `{"name": "...", "url": "https://..."}` entries to `data/watchlist.json`. Each run checks them; a timeout, connection error or HTTP 5xx counts as down (4xx counts as up, since bot protection often answers 403). Going down and coming back each appear in the outages sector, and the state is kept in `data/watch_state.json`.

Items persist even after they drop out of a short feed such as RSS. A source that fails is shown as such on the dashboard and does not erase the others.

## Analyst workflow

- **Promote or correct a feed incident.** Add its id to `data/overrides.json`, for example `{"RL-0123456789": {"tier": 1, "confirmed_by": "https://…", "state": "SC"}}`. Open a pull request so a second analyst reviews it. The next ingest run applies it.
- **Add researched incidents.** Edit the Excel workbook, save it in Excel, then run
  `python3 scripts/xlsx_to_json.py path/to/workbook.xlsx --merge`
  and commit `site/data/incidents.json`. `--merge` keeps feed-sourced rows.
- **Add an event flag.** Append to `site/data/events.json`.

## Run locally

```bash
python3 -m unittest discover -s tests -v   # offline tests
python3 scripts/ingest.py                  # pull feeds (needs internet)
cd site && python3 -m http.server 8000     # open http://localhost:8000
```

## Guardrails

- Organization-level data only. Never store or display individuals' data or leaked files.
- No self-run scraping of leak sites; use the trackers' published feeds and respect their rate limits.
- Keep the repo private and the site access-controlled. A public list of fresh extortion victims can amplify the extortion.
- Personnel data (such as reported deaths of agency staff) is out of scope for this dashboard.

## Data notes

The backfill holds 187 incidents disclosed Sep 21 – Nov 22, 2026, compiled from news and breach trackers; each row links its source. It is a sample of publicly reported incidents, not a complete count. Dates are disclosure dates; rows with only a month are excluded from the daily chart and included in the weekly one.
