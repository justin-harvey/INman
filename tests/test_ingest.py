"""Offline tests: feeds are read from tests/fixtures, data is written to a temp copy."""
import datetime as dt
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import schema  # noqa: E402


class SchemaTests(unittest.TestCase):
    def test_tier_labels(self):
        self.assertEqual(schema.tier_from_label("1 - Confirmed attack/breach"), 1)
        self.assertEqual(schema.tier_from_label("Claimed (unverified)"), 2)
        with self.assertRaises(ValueError):
            schema.tier_from_label("Severe")

    def test_norm_org(self):
        self.assertEqual(schema.norm_org("The Container Store, Inc."), schema.norm_org("Container Store"))
        self.assertEqual(schema.norm_org("Boeing"), schema.norm_org("boeing.com"))

    def test_backfill_is_valid(self):
        with open(os.path.join(ROOT, "site", "data", "incidents.json")) as f:
            recs = json.load(f)["incidents"]
        self.assertGreater(len(recs), 0)
        for r in recs:
            self.assertEqual(schema.validate(r), [], r["id"])
        self.assertEqual(len({r["id"] for r in recs}), len(recs))


class IngestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        for d in ("site/data", "data", "scripts"):
            os.makedirs(os.path.join(self.tmp, d), exist_ok=True)
        shutil.copy(os.path.join(ROOT, "site", "data", "incidents.json"), os.path.join(self.tmp, "site", "data"))
        for f in ("ingest.py", "schema.py"):
            shutil.copy(os.path.join(ROOT, "scripts", f), os.path.join(self.tmp, "scripts"))
        self._write_fixtures(os.path.join(self.tmp, "fixtures"))
        os.environ["FIXTURE_DIR"] = os.path.join(self.tmp, "fixtures")
        sys.path.insert(0, os.path.join(self.tmp, "scripts"))
        spec = importlib.util.spec_from_file_location("ingest_under_test", os.path.join(self.tmp, "scripts", "ingest.py"))
        self.ingest = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.ingest)
        self.before = len(self._load())

    @staticmethod
    def _write_fixtures(path):
        """Feed samples dated relative to today, so the tests never go stale."""
        os.makedirs(path)
        today = dt.datetime.now(dt.timezone.utc).date()
        d = lambda n: (today - dt.timedelta(days=n)).isoformat()
        claims = [
            {"victim": "Example Water District", "group": "qilin", "attackdate": d(2) + " 10:00:00",
             "country": "US", "activity": "Public Sector", "url": "https://www.ransomware.live/"},
            {"victim": "Boeing", "group": "unknown", "attackdate": d(3), "country": "US"},  # in backfill
            {"victim": "Old Claim LLC", "group": "akira", "attackdate": d(90), "country": "US"},  # too old
            {"victim": "", "group": "akira", "attackdate": d(1), "country": "US"},  # no name
            {"victim": "Example Water District Inc.", "group": "qilin", "discovered": d(2)},  # same org
        ]
        posts = [{"post_title": f"victim{i}", "group_name": "g", "discovered": d(i % 5) + " 01:00:00.000000"}
                 for i in range(20)] + [{"post_title": "old", "group_name": "g", "discovered": "2020-01-01 00:00:00"}]
        with open(os.path.join(path, "ransomware_live.json"), "w") as f:
            json.dump(claims, f)
        with open(os.path.join(path, "ransomwatch_posts.json"), "w") as f:
            json.dump(posts, f)

    def tearDown(self):
        sys.path.remove(os.path.join(self.tmp, "scripts"))
        for k in ("FIXTURE_DIR", "RL_ENABLED"):
            os.environ.pop(k, None)
        shutil.rmtree(self.tmp)

    def _load(self, name="incidents.json"):
        with open(os.path.join(self.tmp, "site", "data", name)) as f:
            data = json.load(f)
        return data["incidents"] if name == "incidents.json" else data

    def test_claims_feed_off_by_default(self):
        self.ingest.main()
        self.assertEqual(len(self._load()), self.before)
        self.assertIn("skipped", self._load("meta.json")["feeds"]["ransomware.live"])

    def test_claims_feed_adds_new_us_claims_once(self):
        os.environ["RL_ENABLED"] = "true"
        self.ingest.main()
        recs = self._load()
        new = [r for r in recs if r["origin"] == "ransomware.live"]
        self.assertEqual([r["org"] for r in new], ["Example Water District"])  # dedupe, lookback, blanks
        self.assertEqual(new[0]["tier"], 2)
        self.ingest.main()  # second run adds nothing
        self.assertEqual(len(self._load()), self.before + 1)

    def test_context_counts(self):
        self.ingest.main()
        ctx = self._load("context.json")
        self.assertEqual(sum(ctx["by_day"].values()), 20)

    def test_override_promotes_claim(self):
        os.environ["RL_ENABLED"] = "true"
        self.ingest.main()
        rid = next(r["id"] for r in self._load() if r["origin"] == "ransomware.live")
        with open(os.path.join(self.tmp, "data", "overrides.json"), "w") as f:
            json.dump({"overrides": {rid: {"tier": 1, "confirmed_by": "https://example.gov"}}}, f)
        self.ingest.main()
        rec = next(r for r in self._load() if r["id"] == rid)
        self.assertEqual((rec["tier"], rec["tier_label"]), (1, schema.TIERS[1]))


if __name__ == "__main__":
    unittest.main()
