#!/usr/bin/env python3
"""Unit tests for ci_cloud_token_hunter.py — python3 -m unittest test_ci_cloud_token_hunter -v"""
import csv, io, os, tempfile, unittest
from contextlib import redirect_stdout

import make_cloud_lab_data as lab
import ci_cloud_token_hunter as h

HERE = os.path.dirname(os.path.abspath(__file__))


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.ctp = os.path.join(cls.tmp, "ct.csv")
        cls.ghp = os.path.join(cls.tmp, "gh.csv")
        with open(cls.ctp, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=lab.CT_FIELDS); w.writeheader(); w.writerows(lab.build_ct())
        with open(cls.ghp, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=lab.GH_FIELDS); w.writeheader(); w.writerows(lab.build_gh())
        cls.ct = h.load(cls.ctp, ["ts", "eventName", "sourceIP"])
        cls.gh = h.load(cls.ghp, ["ts", "action"])
        cls.r = h.analyze(cls.ct, cls.gh)
        cls.kinds = {f["kind"] for f in cls.r["findings"]}


class TestCloud(Base):
    def test_01_classification_is_supply_chain(self):
        self.assertIn("Supply-chain", self.r["classification"])

    def test_02_long_key_abuse_flagged_once(self):
        n = sum(1 for f in self.r["findings"] if "long-lived key" in f["kind"])
        self.assertEqual(n, 1)

    def test_03_privilege_escalation_detected(self):
        self.assertIn("IAM privilege escalation", self.kinds)
        acts = {f["action"] for f in self.r["findings"] if f["kind"] == "IAM privilege escalation"}
        self.assertEqual(acts, {"CreateAccessKey", "AttachUserPolicy"})

    def test_04_secret_retrieval_detected(self):
        self.assertIn("secret retrieval", self.kinds)

    def test_05_unusual_bucket_access(self):
        self.assertIn("unusual object-storage access", self.kinds)
        self.assertIn("arn:aws:s3:::example-prod-pii", self.r["iocs"]["buckets"])

    def test_06_public_bucket_exfil(self):
        self.assertIn("storage made public", self.kinds)
        self.assertIn("arn:aws:s3:::example-prod-pii", self.r["iocs"]["public_buckets"])

    def test_07_blocked_backdoor_is_review_not_ioc(self):
        f = next(f for f in self.r["findings"] if "backdoor" in f["kind"])
        self.assertEqual(f["verdict"], "REVIEW")

    def test_08_ioc_summary_has_key_and_ip(self):
        self.assertIn("AKIAEXAMPLE7RUNNER01", self.r["iocs"]["access_keys"])
        self.assertIn("203.0.113.77", self.r["iocs"]["source_ips"])
        self.assertTrue(self.r["iocs"]["new_keys"])


class TestGitHub(Base):
    def test_09_workflow_tamper_detected(self):
        self.assertTrue(any("workflow modified" in f["kind"] for f in self.r["gh_findings"]))

    def test_10_stale_identity_detected(self):
        self.assertTrue(any("stale developer identity" in f["kind"] for f in self.r["gh_findings"]))

    def test_11_ci_secret_exposed(self):
        self.assertTrue(any("secret exposed" in f["kind"] for f in self.r["gh_findings"]))


class TestBaselineAndRobustness(Base):
    def test_12_baseline_oidc_not_flagged(self):
        # 30 days of AssumeRoleWithWebIdentity from GitHub ranges must produce no cloud findings
        base_only = [e for e in self.ct if e["principalType"] != "IAMUser"]
        self.assertEqual(h.analyze(base_only, [])["findings"], [])

    def test_13_ci_source_classification(self):
        self.assertTrue(h.ci_source("140.82.112.10"))
        self.assertFalse(h.ci_source("203.0.113.77"))
        self.assertFalse(h.ci_source("bad-ip"))

    def test_14_malformed_rows_skipped(self):
        p = os.path.join(self.tmp, "junk.csv")
        with open(p, "w") as f:
            f.write(",".join(lab.CT_FIELDS) + "\nbad-ts,s3,GetObject" + "," * 9 + "\n")
        self.assertEqual(h.load(p, ["ts", "eventName", "sourceIP"]), [])

    def test_15_cli_exit_codes(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(h.main([self.ctp, self.ghp]), 1)
            self.assertEqual(h.main([os.path.join(self.tmp, "nope.csv")]), 2)

    def test_16_kill_chain_covers_full_path(self):
        joined = " ".join(self.r["kill_chain_stages"])
        for s in ("runner compromise", "privilege escalation", "collection", "exfiltration"):
            self.assertIn(s, joined)


if __name__ == "__main__":
    unittest.main(verbosity=2)
