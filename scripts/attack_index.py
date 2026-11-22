"""Build site/data/attack_index.json: MITRE ATT&CK groups and software (names, aliases, IDs, links)
from MITRE's public STIX bundle. Used to link threat actors on the dashboard to ATT&CK.

Runs from the scheduled workflow but only rebuilds when the index is older than --max-age-days
(default 7), since the bundle is large and changes a few times a year.

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. ATT&CK content is used under the
ATT&CK Terms of Use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/
"""
import argparse
import re
import datetime as dt
import json
import os
import sys
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "site", "data", "attack_index.json")
BUNDLE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
VERSION = 2
NOTICE = ("MITRE ATT&CK® content © The MITRE Corporation. Used under the ATT&CK Terms of Use, which grant a "
          "non-exclusive, royalty-free license and require MITRE's copyright designation and license to be "
          "reproduced: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/")


def build(bundle):
    entries = []
    for o in bundle.get("objects", []):
        if o.get("type") not in ("intrusion-set", "malware", "tool") or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ref = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ref or not ref.get("external_id"):
            continue
        aliases = sorted({*o.get("aliases", []), *o.get("x_mitre_aliases", [])} - {o["name"]})
        desc = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", (o.get("description") or "").split("(Citation")[0]).strip()
        first = desc.split(". ")[0].strip().rstrip(".")
        entries.append({"id": ref["external_id"], "name": o["name"], "aliases": aliases,
                        "type": "group" if o["type"] == "intrusion-set" else "software",
                        "url": ref.get("url") or f"https://attack.mitre.org/{'groups' if o['type'] == 'intrusion-set' else 'software'}/{ref['external_id']}/",
                        "summary": (first + ".")[:240] if first else ""})
    entries.sort(key=lambda e: e["id"])
    return entries


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-age-days", type=float, default=7)
    ap.add_argument("--bundle", help="local STIX bundle instead of downloading (tests)")
    a = ap.parse_args()
    if os.path.exists(OUT) and not a.bundle:
        with open(OUT) as f:
            built = json.load(f).get("built_at")
        with open(OUT) as f:
            version = json.load(f).get("version")
        if built and version == VERSION and (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(built)).days < a.max_age_days:
            print(f"attack_index.json is fresh (built {built}); skipping")
            return
    if a.bundle:
        with open(a.bundle) as f:
            bundle = json.load(f)
    else:
        req = urllib.request.Request(BUNDLE, headers={"User-Agent": "inman-incident-monitor/1.0"})
        with urllib.request.urlopen(req, timeout=120) as r:
            bundle = json.loads(r.read().decode("utf-8"))
    entries = build(bundle)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"version": VERSION, "built_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "source": BUNDLE,
                   "notice": NOTICE, "entries": entries}, f, separators=(",", ":"), ensure_ascii=False)
        f.write("\n")
    print(f"attack_index.json: {len(entries)} groups and software")


if __name__ == "__main__":
    sys.exit(main())
