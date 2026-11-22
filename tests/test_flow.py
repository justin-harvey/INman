"""Offline tests for scripts/flow.py. Every source is served from generated fixtures."""
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


def load_flow(tmp):
    spec = importlib.util.spec_from_file_location("flow_under_test", os.path.join(tmp, "scripts", "flow.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        for d in ("scripts", "data", "site/data", "fx"):
            os.makedirs(os.path.join(self.tmp, d), exist_ok=True)
        shutil.copy(os.path.join(ROOT, "scripts", "flow.py"), os.path.join(self.tmp, "scripts"))
        shutil.copy(os.path.join(ROOT, "data", "flow_sources.json"), os.path.join(self.tmp, "data"))
        shutil.copy(os.path.join(ROOT, "site", "data", "incidents.json"), os.path.join(self.tmp, "site", "data"))
        os.environ["FIXTURE_DIR"] = os.path.join(self.tmp, "fx")
        self.flow = load_flow(self.tmp)
        self.conf = json.load(open(os.path.join(self.tmp, "data", "flow_sources.json")))
        self._fixtures()

    def tearDown(self):
        for k in ("FIXTURE_DIR", "RL_ENABLED"):
            os.environ.pop(k, None)
        shutil.rmtree(self.tmp)

    def put(self, url, body):
        with open(os.path.join(self.tmp, "fx", self.flow.fixture_name(url)), "w") as f:
            f.write(body if isinstance(body, str) else json.dumps(body))

    def _fixtures(self):
        now = dt.datetime.now(dt.timezone.utc)
        ago = lambda h: (now - dt.timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")
        day = lambda n: (now - dt.timedelta(days=n)).date().isoformat()
        src = self.conf["sources"]
        self.put(src["ransomwatch"]["url"], [
            {"post_title": "acme.example", "group_name": "qilin", "discovered": ago(3).replace("T", " ").rstrip("Z")},
            {"post_title": "old.example", "group_name": "akira", "discovered": "2020-01-01 00:00:00"}])
        self.put(src["cisa_kev"]["url"], {"vulnerabilities": [
            {"cveID": "CVE-2026-0001", "vendorProject": "Acme", "product": "Gateway", "vulnerabilityName": "Auth bypass",
             "dateAdded": day(1), "knownRansomwareCampaignUse": "Known"},
            {"cveID": "CVE-2019-0001", "vendorProject": "Old", "product": "Thing", "vulnerabilityName": "x", "dateAdded": "2019-01-01"}]})
        self.put("https://services.nvd.nist.gov/rest/json/cves/2.0", {"vulnerabilities": [
            {"cve": {"id": "CVE-2026-1111", "published": ago(5).rstrip("Z") + ".000",
                     "descriptions": [{"lang": "en", "value": "Remote code execution in Example."}],
                     "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}}]})
        for name, base in src["statuspages"]["pages"].items():
            incs = [{"id": f"{name}-1", "name": "Elevated errors", "status": "resolved", "impact": "major",
                     "created_at": ago(10), "shortlink": base}] if name == "GitHub" else []
            self.put(base + "/api/v2/incidents.json", {"incidents": incs})
        rss = f"""<?xml version="1.0"?><rss><channel>
          <item><title>CISA adds two KEVs</title><link>https://www.cisa.gov/a</link><pubDate>{now.strftime('%a, %d %b %Y %H:%M:%S +0000')}</pubDate></item>
        </channel></rss>"""
        atom = f"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
          <entry><title>Hospital hit by ransomware</title><link href="https://therecord.media/x"/><updated>{ago(2)}</updated></entry></feed>"""
        feeds = src["rss"]["feeds"]
        self.put(feeds["CISA advisories"], rss)
        self.put(feeds["BleepingComputer"], "not xml at all")   # a broken feed must not sink the others
        self.put(feeds["The Record"], atom)

    def run_flow(self):
        self.flow.main()
        with open(os.path.join(self.tmp, "site", "data", "flow.json")) as f:
            return json.load(f)

    def test_all_sources(self):
        doc = self.run_flow()
        by_source = {}
        for it in doc["items"]:
            by_source.setdefault(it["source"], []).append(it)
        self.assertEqual(len(by_source["ransomwatch"]), 1)
        self.assertEqual(by_source["CISA KEV"][0]["severity"], 0.95)
        self.assertEqual(by_source["NVD"][0]["severity"], 0.98)
        self.assertEqual(len(by_source["NVD"]), 1)  # served for CRITICAL and HIGH, deduped by id
        self.assertEqual(by_source["GitHub status"][0]["theme"], "outages")
        self.assertIn("The Record", by_source)
        self.assertIn("CISA advisories", by_source)
        self.assertTrue(doc["sources"]["ransomware_live"] == "off")
        self.assertTrue(doc["sources"]["rss"].startswith("ok"))
        themes = {t["id"] for t in doc["themes"]}
        self.assertTrue(all(it["theme"] in themes for it in doc["items"]))

    def test_first_seen_is_kept_between_runs(self):
        first = {i["id"]: i["first_seen"] for i in self.run_flow()["items"]}
        self.flow.NOW = self.flow.NOW + dt.timedelta(minutes=30)
        second = {i["id"]: i["first_seen"] for i in self.run_flow()["items"]}
        shared = set(first) & set(second)
        self.assertTrue(shared)
        self.assertTrue(all(first[k] == second[k] for k in shared))


if __name__ == "__main__":
    unittest.main()
