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
scripts/
  ingest.py           pulls feeds, dedupes, applies overrides
  xlsx_to_json.py     converts the analyst workbook into incidents.json
  check_data.py       Netlify build gate: refuses malformed data
  schema.py           shared field list, tiers, validation
data/overrides.json   analyst corrections and tier promotions
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
| ransomwatch | On | Counts global leak-site posts per day for the context line. Public domain. Its posts carry no country, so they never become U.S. incidents. Check that its `posts.json` is still being updated; meta.json flags it as `stale` if the newest post is over 7 days old. |
| ransomware.live | **Off** | Adds U.S. leak-site claims as Tier 2. |

**Licensing gate for ransomware.live.** Its terms allow free non-commercial use with attribution. Commercial use needs written approval from its owner, and the terms also bar republishing raw data and dashboards that copy its look. Get approval (or confirm your use is non-commercial) before enabling it. Then set, under **Settings → Secrets and variables → Actions**:

- Variable `RL_ENABLED` = `true`
- Optional variable `RL_API_BASE` (default `https://api.ransomware.live/v2`). If they issue you a token for their newer API, set the base URL they give you here.
- Optional secret `RL_API_KEY` and variable `RL_API_KEY_HEADER` (default `X-API-KEY`). Confirm the header name in their API docs.

The adapter calls `/countryvictims/US` and keeps claims from the last 30 days (`LOOKBACK_DAYS`). It skips any organization already in the data, after normalizing names.

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
