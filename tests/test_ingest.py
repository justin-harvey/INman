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
        for f in ("ingest.py", "schema.py", "official.py"):
            shutil.copy(os.path.join(ROOT, "scripts", f), os.path.join(self.tmp, "scripts"))
        self._write_fixtures(os.path.join(self.tmp, "fixtures"))
        os.environ["FIXTURE_DIR"] = os.path.join(self.tmp, "fixtures")
        os.environ["SEC_ENABLED"] = os.environ["HHS_ENABLED"] = "false"   # turned on by the tests that need them
        sys.modules.pop("official", None)
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
        # SEC EDGAR full-text search: one hit per document, several documents per filing
        with open(os.path.join(ROOT, "site", "data", "incidents.json")) as f:
            claim = next(r for r in json.load(f)["incidents"] if r["tier"] == 2)
        src = lambda adsh, name, items, ftype, **kw: {"_id": f"{adsh}:{ftype.lower().replace('.', '_')}.htm", "_source": {
            "adsh": adsh, "ciks": ["0000123456"], "display_names": [name], "form": "8-K", "root_forms": ["8-K"],
            "file_type": ftype, "file_date": d(5), "items": items, **kw}}
        efts = {"hits": {"total": {"value": 6}, "hits": [
            src("0000123456-26-000001", "ACME WIDGETS CORP  (ACMW)  (CIK 0000123456)", ["1.05", "9.01"], "8-K",
                biz_locations=["Dayton, OH"], sics=["3714"]),
            src("0000123456-26-000001", "ACME WIDGETS CORP  (ACMW)  (CIK 0000123456)", ["1.05", "9.01"], "EX-99.1"),
            src("0000123456-26-000002", "Northwind Health, Inc.  (NWH)  (CIK 0000222222)", ["8.01"], "8-K", sics=["8062"]),
            src("0000123456-26-000003", "Settled Co  (STL)  (CIK 0000333333)", ["8.01"], "8-K"),
            src("0000123456-26-000004", "Earnings Inc  (ERN)  (CIK 0000444444)", ["2.02", "9.01"], "8-K"),
            src("0000123456-26-000005", f"{claim['org']}  (CLM)  (CIK 0000555555)", ["1.05"], "8-K"),
        ]}}
        with open(os.path.join(path, "sec_efts.json"), "w") as f:
            json.dump(efts, f)
        with open(os.path.join(path, "sec_doc_0000123456-26-000002.htm"), "w") as f:
            f.write("<p>On October 30, the Company <b>identified</b> unauthorized access to certain systems.</p>")
        with open(os.path.join(path, "sec_doc_0000123456-26-000003.htm"), "w") as f:
            f.write("<p>The Company agreed to settle litigation arising from a 2023 cybersecurity incident.</p>")
        # HHS breach portal: a PrimeFaces table, then one AJAX page
        us = lambda n: (today - dt.timedelta(days=n)).strftime("%m/%d/%Y")
        row = lambda i, name, st, et, n, day, bt, loc: (
            f'<tr data-ri="{i}" class="ui-widget-content"><td role="gridcell"><div class="ui-row-toggler"></div></td>'
            f'<td role="gridcell">{name}</td><td role="gridcell">{st}</td><td role="gridcell">{et}</td>'
            f'<td role="gridcell">{n}</td><td role="gridcell">{us(day)}</td><td role="gridcell">{bt}</td>'
            f'<td role="gridcell">{loc}</td></tr>')
        page = ('<form id="ocrForm"><div id="ocrForm:reportResultTable" class="ui-datatable"><table><tbody>'
                + row(0, "Lakeside Family Clinic &amp; Labs", "MI", "Healthcare Provider", "12,345", 4, "Hacking/IT Incident", "Network Server")
                + row(1, "Prairie Dental Group", "KS", "Healthcare Provider", "501", 6, "Hacking/IT Incident", "Email")
                + row(2, "Stolen Laptop Medical", "TX", "Healthcare Provider", "2,000", 3, "Theft", "Laptop")
                + row(3, "Ancient Breach Hospital", "OH", "Healthcare Provider", "9,999", 200, "Hacking/IT Incident", "Network Server")
                + '</tbody></table></div><input type="hidden" name="javax.faces.ViewState" value="abc" /></form>')
        with open(os.path.join(path, "hhs_page.html"), "w") as f:
            f.write(page)
        with open(os.path.join(path, "hhs_page_1.xml"), "w") as f:
            f.write('<partial-response><changes><update id="ocrForm:reportResultTable"><![CDATA['
                    + row(100, "Coastal Health Plan", "FL", "Health Plan", "88,000", 9, "Hacking/IT Incident", "Network Server")
                    + ']]></update></changes></partial-response>')
        with open(os.path.join(path, "ransomware_live.json"), "w") as f:
            json.dump(claims, f)
        with open(os.path.join(path, "ransomwatch_posts.json"), "w") as f:
            json.dump(posts, f)

    def tearDown(self):
        sys.path.remove(os.path.join(self.tmp, "scripts"))
        sys.modules.pop("official", None)
        for k in ("FIXTURE_DIR", "RL_ENABLED", "SEC_ENABLED", "HHS_ENABLED"):
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

    def test_context_prefers_ransomlook(self):
        today = dt.datetime.now(dt.timezone.utc).date()
        with open(os.path.join(os.environ["FIXTURE_DIR"], "ransomlook_posts.json"), "w") as f:
            json.dump([{"post_title": "x", "group_name": "g", "discovered": today.isoformat() + " 01:00:00"}] * 3, f)
        self.ingest.main()
        ctx = self._load("context.json")
        self.assertEqual(sum(ctx["by_day"].values()), 3)
        self.assertTrue(ctx["source"].startswith("RansomLook"))

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


    def test_sec_filings(self):
        os.environ["SEC_ENABLED"] = "true"
        claim_before = {r["id"]: r for r in self._load() if r["tier"] == 2}
        self.ingest.main()
        recs = self._load()
        sec = {r["org"]: r for r in recs if r["origin"] == "sec_edgar"}
        self.assertEqual(sorted(sec), ["Acme Widgets Corp", "Northwind Health, Inc."])   # 8.01 settlement + 2.02 skipped
        acme = sec["Acme Widgets Corp"]
        self.assertEqual((acme["tier"], acme["state"], acme["industry"]), (1, "OH", "Manufacturing/auto"))
        self.assertTrue(acme["url"].endswith("/123456/000012345626000001/8-k.htm"))
        self.assertIn("Item 1.05", acme["summary"])
        self.assertEqual(sec["Northwind Health, Inc."]["industry"], "Healthcare")
        promoted = [r for r in recs if r["id"] in claim_before and r["tier"] == 1]
        self.assertEqual(len(promoted), 1)                      # the matching claim is confirmed, not duplicated
        self.assertIn("SEC 8-K", promoted[0]["confirmed_by"])
        self.assertIn("1 promoted", self._load("meta.json")["feeds"]["sec_edgar"])
        self.ingest.main()                                      # idempotent
        self.assertEqual(len(self._load()), self.before + 2)

    def test_hhs_breaches(self):
        os.environ["HHS_ENABLED"] = "true"
        self.ingest.main()
        hhs = {r["org"]: r for r in self._load() if r["origin"] == "hhs_ocr"}
        self.assertEqual(sorted(hhs), ["Coastal Health Plan", "Lakeside Family Clinic & Labs", "Prairie Dental Group"])
        self.assertEqual(hhs["Lakeside Family Clinic & Labs"]["records"], 12345)
        self.assertIsNone(hhs["Prairie Dental Group"]["records"])          # 501 is a placeholder
        self.assertIn("placeholder", hhs["Prairie Dental Group"]["count_basis"])
        self.assertEqual(hhs["Coastal Health Plan"]["state"], "FL")        # from the second page
        for r in hhs.values():
            self.assertEqual(schema.validate(r), [])
        self.ingest.main()
        self.assertEqual(len(self._load()), self.before + 3)
        self.assertTrue(self._load("meta.json")["feeds"]["hhs_ocr"].startswith("ok"))


if __name__ == "__main__":
    unittest.main()
