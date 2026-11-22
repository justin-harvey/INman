"""Netlify build step: refuse to deploy if incidents.json is malformed."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from schema import validate  # noqa: E402

path = os.path.join(os.path.dirname(__file__), "..", "site", "data", "incidents.json")
with open(path) as f:
    incidents = json.load(f)["incidents"]
bad = [(r.get("id"), p) for r in incidents for p in validate(r)]
ids = [r["id"] for r in incidents]
dupes = {i for i in ids if ids.count(i) > 1}
for rid, p in bad:
    print(f"invalid {rid}: {p}")
if dupes:
    print(f"duplicate ids: {sorted(dupes)}")
if bad or dupes:
    sys.exit(1)
print(f"OK: {len(incidents)} incidents")
