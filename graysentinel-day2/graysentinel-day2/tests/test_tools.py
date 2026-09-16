import json, os, subprocess, sys, unittest
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(BASE, "src"); DATA = os.path.join(BASE, "data")
sys.path.insert(0, SRC)
import macro_analyzer as MA
import killchain_reconstructor as CKR

BAS = os.path.join(DATA, "invoice_Q3.docm.extracted.bas")
EDR = os.path.join(DATA, "edr_telemetry.csv")

class TestMacroAnalyzer(unittest.TestCase):
    def setUp(self): self.r = MA.analyze(BAS)
    def test_verdict_malicious(self): self.assertEqual(self.r["verdict"], "MALICIOUS")
    def test_has_critical(self): self.assertGreaterEqual(self.r["counts"]["CRITICAL"], 1)
    def test_detects_autoopen(self):
        self.assertTrue(any(f["rule_id"] == "MSA-01" for f in self.r["findings"]))
    def test_detects_download_cradle(self):
        self.assertTrue(any(f["rule_id"] == "MSA-04" for f in self.r["findings"]))
    def test_detects_launchdaemon(self):
        self.assertTrue(any(f["rule_id"] == "MSA-07" for f in self.r["findings"]))
    def test_detects_powershell_enc(self):
        self.assertTrue(any(f["rule_id"] == "MSA-02" for f in self.r["findings"]))
    def test_findings_sorted_by_severity(self):
        ranks = [MA.SEV_RANK[f["severity"]] for f in self.r["findings"]]
        self.assertEqual(ranks, sorted(ranks))
    def test_every_finding_has_attck(self):
        for f in self.r["findings"]:
            self.assertRegex(f["attck"], r"^T\d{4}")
    def test_clean_file_verdict(self):
        p = os.path.join(DATA, "_clean.bas"); open(p, "w").write("Sub Hi()\n MsgBox 1\nEnd Sub\n")
        try: self.assertEqual(MA.analyze(p)["verdict"], "CLEAN")
        finally: os.remove(p)
    def test_markdown_renders(self):
        self.assertIn("Verdict", MA.to_markdown(self.r))
    def test_exit_code_2_on_critical(self):
        rc = subprocess.call([sys.executable, os.path.join(SRC, "macro_analyzer.py"), BAS,
                              "--json", "/tmp/f.json"]); self.assertEqual(rc, 2)

class TestReconstructor(unittest.TestCase):
    def setUp(self):
        MA.main([BAS, "--json", "/tmp/macro.json"])
        self.r = CKR.build(EDR, "/tmp/macro.json")
    def test_priority_p1(self): self.assertEqual(self.r["priority"], "P1")
    def test_timeline_ordered(self):
        ts = [t["ts"] for t in self.r["timeline"]]; self.assertEqual(ts, sorted(ts))
    def test_c2_ips_found(self):
        joined = " ".join(self.r["iocs"]["c2_ips"])
        self.assertIn("203.0.113.9", joined); self.assertIn("198.51.100.44", joined)
    def test_persistence_ioc(self):
        self.assertTrue(any(".plist" in p for p in self.r["iocs"]["persistence"]))
    def test_file_hash_ioc(self):
        self.assertTrue(all(len(h) == 64 for h in self.r["iocs"]["file_hashes"]))
    def test_miner_stage_present(self):
        self.assertTrue(any(t["stage"] == "Miner launch" for t in self.r["timeline"]))
    def test_attck_matrix_nonempty(self): self.assertGreaterEqual(len(self.r["attck"]), 6)
    def test_html_has_badge(self): self.assertIn("badge", CKR.to_html(self.r))
    def test_md_has_containment(self): self.assertIn("Containment", CKR.to_md(self.r))
    def test_priority_without_macro(self):
        r2 = CKR.build(EDR, None); self.assertIn(r2["priority"], ("P1", "P2", "P3"))

if __name__ == "__main__":
    unittest.main(verbosity=2)
