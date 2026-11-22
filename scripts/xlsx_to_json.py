"""Convert the analyst workbook (Incidents sheet) into site/data/incidents.json.

Usage:
    python scripts/xlsx_to_json.py path/to/workbook.xlsx [--out site/data/incidents.json] [--merge]

The workbook must have been saved by Excel (or recalculated) so formula columns
hold values. With --merge, feed-sourced rows already in the JSON are kept and
workbook rows replace rows with the same id.
"""
import argparse
import datetime as dt
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from schema import FIELDS, TIERS, sector_group, tier_from_label, validate  # noqa: E402

HEADER_MAP = {
    "ID": "id", "Date": "date", "Date Precision": "date_precision", "Organization": "org",
    "Org Type": "org_type", "Industry": "industry", "State": "state", "Event Tier": "tier",
    "Incident Type": "incident_type", "Threat Actor": "actor", "Records Affected": "records",
    "Count Basis": "count_basis", "Ops Disrupted": "ops_disrupted", "Data Exposed": "data_exposed",
    "Summary": "summary", "Earlier Intrusion Window": "earlier_window", "Source": "source",
    "Source URL": "url",
}


def read_workbook(path):
    from openpyxl import load_workbook
    ws = load_workbook(path, data_only=True)["Incidents"]
    rows = ws.iter_rows(values_only=True)
    header = [str(h).strip() if h else "" for h in next(rows)]
    idx = {HEADER_MAP[h]: i for i, h in enumerate(header) if h in HEADER_MAP}
    out = []
    for row in rows:
        if not row or row[idx["id"]] in (None, ""):
            continue
        rec = {k: row[i] for k, i in idx.items()}
        d = rec["date"]
        rec["date"] = d.date().isoformat() if isinstance(d, dt.datetime) else str(d)[:10]
        rec["tier"] = tier_from_label(rec["tier"])
        rec["tier_label"] = TIERS[rec["tier"]]
        rec["sector_group"] = sector_group(rec.get("org_type"))
        rec["records"] = int(rec["records"]) if isinstance(rec.get("records"), (int, float)) else None
        rec["ops_disrupted"] = str(rec.get("ops_disrupted", "")).strip().lower() == "yes"
        rec["data_exposed"] = str(rec.get("data_exposed") or "Unknown")
        for k in ("state", "actor", "count_basis", "summary", "earlier_window", "url", "industry",
                  "incident_type", "date_precision"):
            rec[k] = "" if rec.get(k) is None else str(rec[k])
        rec.setdefault("origin", "backfill")
        rec["origin"] = "backfill"
        rec["first_seen"] = rec["date"]
        rec["confirmed_by"] = ""
        out.append({f: rec.get(f) for f in FIELDS})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("workbook")
    ap.add_argument("--out", default="site/data/incidents.json")
    ap.add_argument("--merge", action="store_true")
    a = ap.parse_args()

    recs = read_workbook(a.workbook)
    bad = [(r["id"], p) for r in recs for p in validate(r)]
    if bad:
        for rid, p in bad:
            print(f"{rid}: {p}", file=sys.stderr)
        sys.exit(1)

    if a.merge and os.path.exists(a.out):
        with open(a.out) as f:
            existing = {r["id"]: r for r in json.load(f)["incidents"]}
        existing.update({r["id"]: r for r in recs})
        recs = list(existing.values())

    recs.sort(key=lambda r: (r["date"], r["org"]), reverse=True)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w") as f:
        json.dump({"schema_version": 1, "incidents": recs}, f, indent=1, ensure_ascii=False)
    print(f"Wrote {len(recs)} incidents to {a.out}")


if __name__ == "__main__":
    main()
