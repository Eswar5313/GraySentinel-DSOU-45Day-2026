#!/usr/bin/env python3
"""Unit tests for pipeline_chain_analyzer.py — python3 -m unittest test_pipeline_chain_analyzer -v"""
import csv, io, json, os, tempfile, unittest
from contextlib import redirect_stdout

import make_pipeline_lab_data as lab
import pipeline_chain_analyzer as h

HERE = os.path.dirname(os.path.abspath(__file__))


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.csvp = os.path.join(cls.tmp, "a.csv")
        with open(cls.csvp, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=lab.FIELDS); w.writeheader(); w.writerows(lab.build())
        cls.events = h.load(cls.csvp, ["ts", "source", "action"])
        cls.ctx = json.loads(json.dumps(lab.CONTEXT))
        cls.r = h.analyze(cls.events, cls.ctx)
        cls.kinds = {f["kind"] for f in cls.r["findings"]}


class TestChain(Base):
    def test_01_full_chain_observed(self):
        self.assertTrue(self.r["full_chain_observed"])

    def test_02_all_five_stages(self):
        self.assertEqual(self.r["kill_chain_stages"],
                         ["developer identity", "CI/CD abuse", "malicious image / registry",
                          "kubernetes", "cloud access"])

    def test_03_stale_identity(self):
        self.assertIn("stale/terminated identity active", self.kinds)

    def test_04_offhours_run(self):
        self.assertIn("off-hours pipeline run", self.kinds)

    def test_05_unexpected_digest(self):
        self.assertIn("unexpected image digest", self.kinds)

    def test_06_unsigned_image(self):
        self.assertIn("unsigned / no provenance", self.kinds)

    def test_07_deploy_non_trusted_digest(self):
        self.assertIn("deploy of non-trusted digest", self.kinds)

    def test_08_excessive_rbac(self):
        self.assertIn("excessive RBAC used", self.kinds)

    def test_09_kube_system_workload(self):
        self.assertIn("workload created in kube-system", self.kinds)

    def test_10_cloud_access(self):
        self.assertIn("workload identity reached cloud", self.kinds)

    def test_11_image_delete_is_review(self):
        f = next(f for f in self.r["findings"] if "image deleted" in f["kind"])
        self.assertEqual(f["verdict"], "REVIEW")

    def test_12_dfir_sources(self):
        self.assertEqual(self.r["dfir_sources"], ["cloud", "gitlab", "k8s", "registry"])


class TestBaselineAndRobustness(Base):
    def test_13_baseline_only_is_clean(self):
        base = [e for e in self.events if e["digest"] in ("", lab.TRUSTED_DIGEST)
                and e["actor"] not in ("ex.developer", "system:serviceaccount:payments:deployer",
                                       "irsa:payments-deployer")
                and e["action"] != "image.delete" and e["_t"].hour < 16 and e["_t"].weekday() < 5]
        r = h.analyze(base, self.ctx)
        self.assertEqual(r["findings"], [])
        self.assertFalse(r["full_chain_observed"])

    def test_14_in_window_logic(self):
        from datetime import datetime
        w = self.ctx["release_window_utc"]
        self.assertTrue(h.in_window(datetime(2026, 10, 6, 8, 0), w))     # Tue 08:00
        self.assertFalse(h.in_window(datetime(2026, 10, 6, 21, 0), w))   # Tue 21:00
        self.assertFalse(h.in_window(datetime(2026, 10, 10, 8, 0), w))   # Sat

    def test_15_malformed_rows_skipped(self):
        p = os.path.join(self.tmp, "junk.csv")
        with open(p, "w") as f:
            f.write(",".join(lab.FIELDS) + "\nbad-ts,k8s,pod.create" + "," * 10 + "\n")
        self.assertEqual(h.load(p, ["ts", "source", "action"]), [])

    def test_16_cli_exit_codes(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(h.main([self.csvp, os.path.join(HERE, "pipeline_context_SYNTHETIC.json")]), 1)
            self.assertEqual(h.main([os.path.join(self.tmp, "nope.csv")]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
