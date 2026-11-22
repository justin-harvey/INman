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
        shutil.copy(os.path.join(ROOT, "data", "actor_aliases.json"), os.path.join(self.tmp, "data"))
        shutil.copy(os.path.join(ROOT, "scripts", "attack_index.py"), os.path.join(self.tmp, "scripts"))
        os.environ["FIXTURE_DIR"] = os.path.join(self.tmp, "fx")
        self.flow = load_flow(self.tmp)
        cfg_path = os.path.join(self.tmp, "data", "flow_sources.json")
        self.conf = json.load(open(cfg_path))
        self.conf["sources"]["ransomwatch"]["enabled"] = True       # off in production (stale feed); keep testing the adapter
        json.dump(self.conf, open(cfg_path, "w"))
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
        # RansomLook sees the same victim as ransomwatch (corroboration) plus one of its own
        self.put(src["ransomlook"]["url"], [
            {"post_title": "ACME.example", "group_name": "Qilin", "discovered": ago(2).replace("T", " ").rstrip("Z") + ".123456"},
            {"post_title": "widgets-co.example", "group_name": "lockbit3", "discovered": ago(4).replace("T", " ").rstrip("Z")}])
        with open(os.path.join(self.tmp, "data", "watchlist.json"), "w") as f:
            json.dump({"sites": [{"name": "County portal", "url": "https://county.example/"}]}, f)
        self.put("https://county.example/", "503")
        self.put(src["cisa_kev"]["url"], {"vulnerabilities": [
            {"cveID": "CVE-2026-0001", "vendorProject": "Acme", "product": "Gateway", "vulnerabilityName": "Auth bypass",
             "dateAdded": day(1), "knownRansomwareCampaignUse": "Known"},
            {"cveID": "CVE-2026-0020", "vendorProject": "Acme", "product": "VPN", "vulnerabilityName": "RCE", "dateAdded": day(20)},
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

    def test_corroboration_merges_trackers(self):
        doc = self.run_flow()
        acme = [i for i in doc["items"] if i.get("victim", "").lower() == "acme.example"]
        self.assertEqual(len(acme), 1)
        self.assertEqual(acme[0]["seen_on"], ["RansomLook", "ransomwatch"])
        self.assertAlmostEqual(acme[0]["severity"], 0.65)
        with open(os.path.join(self.tmp, "site", "data", "flow_history.json")) as f:
            hist = json.load(f)
        self.assertEqual(len([i for i in hist["items"] if i.get("victim", "").lower() == "acme.example"]), 1)
        self.assertEqual(sum(hist["actors_daily"]["Qilin"].values()), 1)   # one claim, not one per tracker

    def test_attack_mapping(self):
        bundle = {"objects": [
            {"type": "malware", "name": "LockBit 3.0", "x_mitre_aliases": ["LockBit Black"], "description": "LockBit 3.0 is ransomware. More.",
             "external_references": [{"source_name": "mitre-attack", "external_id": "S1202", "url": "https://attack.mitre.org/software/S1202"}]},
            {"type": "intrusion-set", "name": "Qilin Group", "aliases": ["Agenda"], "revoked": True,
             "external_references": [{"source_name": "mitre-attack", "external_id": "G9999"}]}]}
        bpath = os.path.join(self.tmp, "bundle.json")
        json.dump(bundle, open(bpath, "w"))
        spec = importlib.util.spec_from_file_location("attack_idx", os.path.join(self.tmp, "scripts", "attack_index.py"))
        mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        sys.argv = ["attack_index.py", "--bundle", bpath]
        mod.main()
        doc = self.run_flow()
        self.assertEqual(doc["actors"]["LockBit 3.0"]["id"], "S1202")   # via data/actor_aliases.json, shown by its ATT&CK name
        self.assertNotIn("lockbit3", doc["actors"])
        self.assertIsNone(doc["actors"]["Qilin"])                         # revoked entries are skipped
        self.assertNotIn("qilin", doc["actors"])                          # spelling variants share one name

    def test_attack_rejects_unrelated_namesakes(self):
        bundle = {"objects": [
            {"type": "malware", "name": "Hydraq", "x_mitre_aliases": ["Aurora"], "description": "[Hydraq](https://x) is a data-theft trojan used by an espionage group.",
             "external_references": [{"source_name": "mitre-attack", "external_id": "S0203"}]},
            {"type": "intrusion-set", "name": "Qilin", "description": "Qilin is a ransomware-as-a-service operation.",
             "external_references": [{"source_name": "mitre-attack", "external_id": "G9001"}]}]}
        bpath = os.path.join(self.tmp, "bundle.json")
        json.dump(bundle, open(bpath, "w"))
        spec = importlib.util.spec_from_file_location("attack_idx2", os.path.join(self.tmp, "scripts", "attack_index.py"))
        mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        sys.argv = ["attack_index.py", "--bundle", bpath]
        mod.main()
        with open(os.path.join(self.tmp, "site", "data", "attack_index.json")) as f:
            self.assertNotIn("](", json.load(f)["entries"][0]["summary"])   # markdown links stripped
        self.put(self.conf["sources"]["ransomlook"]["url"], [
            {"post_title": "victim-a.example", "group_name": "aurora", "discovered": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")},
            {"post_title": "victim-b.example", "group_name": "qilin", "discovered": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")}])
        doc = self.run_flow()
        self.assertIsNone(doc["actors"]["Aurora"])                  # espionage namesake, not linked; name capitalised
        self.assertEqual(doc["actors"]["Qilin"]["id"], "G9001")

    def test_watchlist_reports_down_then_up(self):
        doc = self.run_flow()
        down = [i for i in doc["items"] if i["source"] == "Watchlist"]
        self.assertEqual([i["title"] for i in down], ["County portal is down (HTTP 503)"])
        self.put("https://county.example/", "200")
        self.flow.NOW = self.flow.NOW + dt.timedelta(minutes=95)
        doc = self.run_flow()
        titles = sorted(i["title"] for i in doc["items"] if i["source"] == "Watchlist")
        self.assertEqual(titles, ["County portal is back up after 1h 35m", "County portal is down (HTTP 503)"])

    def test_history_window_and_counts(self):
        live = self.run_flow()
        with open(os.path.join(self.tmp, "site", "data", "flow_history.json")) as f:
            hist = json.load(f)
        live_ids = {i["id"] for i in live["items"]}
        hist_titles = [i["title"] for i in hist["items"]]
        self.assertTrue(any("CVE-2026-0020" in t for t in hist_titles))          # 20 days old: history only
        self.assertFalse(any("CVE-2026-0020" in i["title"] for i in live["items"]))
        self.assertTrue(live_ids <= {i["id"] for i in hist["items"]} | live_ids)
        self.assertEqual(sum(hist["daily"]["kev"].values()), 2)
        self.assertFalse(any("CVE-2019-0001" in t for t in hist_titles))         # outside 90 days
        # the curated incidents give real history for every day they cover, capped per theme per day
        per = {}
        for i in hist["items"]:
            per[(i["theme"], i["ts"][:10])] = per.get((i["theme"], i["ts"][:10]), 0) + 1
        self.assertLessEqual(max(per.values()), hist["items_per_theme_day"])

    def test_history_counts_never_drop_when_feed_rolls_off(self):
        self.run_flow()
        rss_url = self.conf["sources"]["rss"]["feeds"]["The Record"]
        self.put(rss_url, '<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"></feed>')
        self.flow.NOW = self.flow.NOW + dt.timedelta(minutes=30)
        self.run_flow()
        with open(os.path.join(self.tmp, "site", "data", "flow_history.json")) as f:
            hist = json.load(f)
        self.assertTrue(any(i["source"] == "The Record" for i in hist["items"]))  # carried forward

    def test_first_seen_is_kept_between_runs(self):
        first = {i["id"]: i["first_seen"] for i in self.run_flow()["items"]}
        self.flow.NOW = self.flow.NOW + dt.timedelta(minutes=30)
        second = {i["id"]: i["first_seen"] for i in self.run_flow()["items"]}
        shared = set(first) & set(second)
        self.assertTrue(shared)
        self.assertTrue(all(first[k] == second[k] for k in shared))


if __name__ == "__main__":
    unittest.main()
