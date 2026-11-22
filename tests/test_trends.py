"""Offline tests for scripts/trends.py on synthetic history."""
import datetime as dt
import importlib.util
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("trends_under_test", os.path.join(ROOT, "scripts", "trends.py"))
trends = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trends)

TODAY = dt.date(2026, 11, 22)
DAYS = [(TODAY - dt.timedelta(days=90 - i)).isoformat() for i in range(90)]   # 90 complete days before today


def history():
    steady = {d: 3 for d in DAYS}
    surge = {d: (0 if i < 60 else 10) for i, d in enumerate(DAYS)}               # appears in the last 30 days only
    quiet = {d: 2 for d in DAYS[:40]}
    claims = {d: steady[d] + surge[d] + quiet.get(d, 0) for d in DAYS}
    claims[TODAY.isoformat()] = 999                                                # today is incomplete: ignored
    return {"history_days": 90,
            "themes": [{"id": "claims", "short": "Extortion claims"}, {"id": "kev", "short": "Exploited vulns"},
                       {"id": "outages", "short": "Outages"}],
            "daily": {"claims": claims, "kev": {d: 1 for d in DAYS},
                      "outages": {d: 5 for d in DAYS[-10:]}},
            "actors_daily": {"qilin": steady, "bulkposter": surge, "oldgang": quiet},
            "actors": {"qilin": {"id": "S1242", "name": "Qilin", "url": "https://attack.mitre.org/software/S1242"}}}


INCIDENTS = [
    {"date": "2026-11-01", "sector_group": "Government", "tier": 3, "industry": "Government administration", "actor": "Not named", "ops_disrupted": True},
    {"date": "2026-11-02", "sector_group": "Corporate & private", "tier": 1, "industry": "Healthcare", "actor": "Qilin",
     "records": 1000, "count_basis": "Victim-reported", "ops_disrupted": False},
    {"date": "2026-11-03", "sector_group": "Corporate & private", "tier": 2, "industry": "Healthcare", "actor": "n0n",
     "records": 99999, "count_basis": "Claimed by actor", "ops_disrupted": False},
]


class TrendTests(unittest.TestCase):
    def setUp(self):
        self.t = trends.build(history(), INCIDENTS, {"feeds": {"ransomware.live": "skipped"}}, TODAY)

    def test_window_excludes_today(self):
        self.assertEqual(self.t["window"]["end"], (TODAY - dt.timedelta(days=1)).isoformat())
        self.assertEqual(self.t["claims"]["total"], 3 * 90 + 10 * 30 + 2 * 40)

    def test_surger_separated(self):
        c = self.t["claims"]
        self.assertEqual(c["surger"]["name"], "Bulkposter")
        self.assertEqual(c["periods"][-1] - c["periods_ex_surger"][-1], 300)
        self.assertIn("without it", self.t["findings"][0]["text"])

    def test_groups(self):
        c = self.t["claims"]
        self.assertEqual([a["name"] for a in c["quiet"]], ["Oldgang"])
        self.assertEqual(c["steady"][0]["name"], "Qilin")          # ATT&CK name wins
        self.assertEqual(c["steady"][0]["attack_id"], "S1242")

    def test_incidents_and_caveats(self):
        inc = self.t["incidents"]
        self.assertEqual(inc["records_total"], 1000)               # claimed counts are left out
        self.assertEqual(inc["gov"]["suspected_outages"], 1)
        self.assertEqual(inc["actor_unnamed_pct"], 33)
        text = " ".join(self.t["caveats"])
        self.assertIn("global", text)
        self.assertIn("Outages", text)                              # short-history feed flagged
        self.assertNotIn("Exploited vulns", text)


if __name__ == "__main__":
    unittest.main()
