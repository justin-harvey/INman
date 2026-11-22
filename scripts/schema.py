"""Shared schema for incident records.

Every record in site/data/incidents.json follows FIELDS. Tier numbers never change
meaning, so feeds, overrides and the dashboard can all rely on them.
"""
import re

TIERS = {
    1: "Confirmed attack/breach",
    2: "Claimed (unverified)",
    3: "Outage/disruption, suspected cyber",
    4: "Outage, technical (non-malicious)",
}

GOVERNMENT_TYPES = {
    "Federal government",
    "State government",
    "Local government",
    "Public school/university",
}

FIELDS = [
    "id", "date", "date_precision", "org", "sector_group", "org_type", "industry", "state",
    "tier", "tier_label", "incident_type", "actor", "records", "count_basis",
    "ops_disrupted", "data_exposed", "summary", "earlier_window", "source", "url",
    "origin", "first_seen", "confirmed_by",
]

REQUIRED = ["id", "date", "org", "tier", "source"]

_SUFFIXES = re.compile(r"\b(inc|llc|ltd|corp|corporation|co|company|plc|pc|p c|group|holdings)\b")


def tier_from_label(label):
    """Map '1 - Confirmed attack/breach' or 'Confirmed attack/breach' to 1..4."""
    label = str(label or "").strip()
    m = re.match(r"^([1-4])\b", label)
    if m:
        return int(m.group(1))
    for k, v in TIERS.items():
        if v.lower() == label.lower():
            return k
    raise ValueError(f"Unknown tier label: {label!r}")


def sector_group(org_type):
    if org_type in GOVERNMENT_TYPES:
        return "Government"
    if not org_type or org_type == "Unclassified":
        return "Unclassified"
    return "Corporate & private"


def norm_org(name):
    """Normalize an organization name for de-duplication."""
    s = str(name or "").lower()
    s = re.sub(r"\(.*?\)", " ", s)          # drop parentheticals
    s = re.sub(r"https?://|www\.", " ", s)
    s = re.sub(r"\.(com|org|net|gov|edu|us|io)\b", " ", s)
    s = re.sub(r"[^a-z0-9 ]+", " ", s)
    s = _SUFFIXES.sub(" ", s)
    s = re.sub(r"^the ", "", s.strip())
    return re.sub(r"\s+", " ", s).strip()


def validate(rec):
    """Return a list of problems with one record (empty = valid)."""
    problems = [f"missing {f}" for f in REQUIRED if rec.get(f) in (None, "")]
    if rec.get("tier") not in TIERS:
        problems.append(f"bad tier {rec.get('tier')!r}")
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", str(rec.get("date", ""))):
        problems.append(f"bad date {rec.get('date')!r}")
    if rec.get("records") is not None and not isinstance(rec["records"], int):
        problems.append("records must be an integer or null")
    return problems
