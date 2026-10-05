#!/usr/bin/env python3
"""Unit tests for rdp_chain_hunter.py — run: python3 -m unittest test_rdp_chain_hunter -v"""
import csv, io, json, os, tempfile, unittest
from contextlib import redirect_stdout

import make_rdp_lab_data as lab
import rdp_chain_hunter as h

HERE = os.path.dirname(os.path.abspath(__file__))


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.csv = os.path.join(cls.tmp, "ev.csv")
        with open(cls.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=lab.FIELDS)
            w.writeheader()
            w.writerows(lab.build())
        cls.events = h.load_events(cls.csv)
        cls.ctx = json.loads(json.dumps(lab.CONTEXT))
        cls.cases = h.investigate(cls.events, cls.ctx)
        cls.bad = next(c for c in cls.cases if c["triage"]["user"] == "ananya.rao")
        cls.good = [c for c in cls.cases if c["triage"]["user"] == "it.helpdesk"]


class TestTriage(Base):
    def test_01_attack_session_found(self):
        t = self.bad["triage"]
        self.assertEqual((t["source_ip"], t["source_host"], t["dest_host"]),
                         ("203.0.113.45", "DESKTOP-9KX2TQ", "HR-WS-017"))

    def test_02_failed_attempts_counted(self):
        self.assertEqual(self.bad["triage"]["failed_attempts"], 23)

    def test_03_success_timestamp_and_type(self):
        self.assertEqual(self.bad["triage"]["success_ts"], "2026-10-04T21:53:02Z")
        self.assertEqual(self.bad["triage"]["logon_type"], 10)

    def test_04_baseline_says_user_never_rdps(self):
        self.assertFalse(self.bad["triage"]["normally_uses_rdp"])
        self.assertEqual(self.bad["triage"]["rdp_baseline_30d"], 0)

    def test_05_privileges_and_powershell(self):
        self.assertIn("SeDebugPrivilege", self.bad["triage"]["privileges"])
        self.assertIn("-Enc", self.bad["triage"]["powershell_cmdline"])

    def test_06_same_ip_other_endpoints(self):
        o = self.bad["triage"]["same_ip_other_hosts"]
        self.assertEqual(o["HR-WS-021"], {"fail": 6, "success": 0})
        self.assertEqual(o["FIN-WS-004"]["fail"], 4)

    def test_07_internet_exposure_found(self):
        self.assertEqual(self.bad["triage"]["internet_exposure"][0]["rule"], "NAT-LEGACY-HR-3389")


class TestHypotheses(Base):
    def test_08_h1_compromised(self):
        self.assertEqual(self.bad["hypotheses"]["H1"]["verdict"], "COMPROMISED")

    def test_09_h2_rejected_for_attack(self):
        self.assertEqual(self.bad["hypotheses"]["H2"]["verdict"], "REJECTED")

    def test_10_h3_confirmed(self):
        self.assertEqual(self.bad["hypotheses"]["H3"]["verdict"], "CONFIRMED")

    def test_11_helpdesk_is_legitimate_admin(self):
        self.assertTrue(self.good)
        for c in self.good:
            self.assertEqual(c["hypotheses"]["H2"]["verdict"], "SUPPORTED")
            self.assertFalse(c["detection"]["fired"])
            self.assertEqual(c["detection"]["severity"], "INFO")


class TestDetectionAndLateral(Base):
    def test_12_detection_fires_critical(self):
        self.assertTrue(self.bad["detection"]["fired"])
        self.assertEqual(self.bad["detection"]["severity"], "CRITICAL")

    def test_13_lateral_smb_dc_and_files(self):
        lat = self.bad["lateral"]
        self.assertEqual(lat["smb"], ["10.20.30.15"])
        self.assertEqual(lat["dc_contact"], ["10.20.0.10"])
        self.assertEqual(lat["onward_logons"], ["FS-HR-01"])
        self.assertEqual(len(lat["sensitive_files"]), 3)

    def test_14_rfc5737_treated_as_external(self):
        self.assertFalse(h.is_internal("198.51.100.23"))
        self.assertFalse(h.is_internal("203.0.113.45"))
        self.assertTrue(h.is_internal("10.20.30.15"))
        self.assertFalse(h.is_internal("not-an-ip"))

    def test_15_timeline_is_ordered(self):
        tl = [x[0] for x in self.bad["timeline"]]
        self.assertEqual(tl, sorted(tl))
        self.assertIn("4624/10", [x[1] for x in self.bad["timeline"]])

    def test_16_powershell_outside_window_does_not_fire(self):
        cases = h.investigate(self.events, self.ctx, window_min=1)
        bad = next(c for c in cases if c["triage"]["user"] == "ananya.rao")
        self.assertFalse(bad["detection"]["fired"])


class TestRobustness(Base):
    def test_17_garbage_rows_skipped(self):
        p = os.path.join(self.tmp, "junk.csv")
        with open(p, "w") as f:
            f.write(",".join(lab.FIELDS) + "\nnot-a-time,X,Security,abc" + "," * 12 + "\n")
        self.assertEqual(h.load_events(p), [])

    def test_18_cli_exit_codes(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(h.main([self.csv, os.path.join(HERE, "auth_context_SYNTHETIC.json")]), 1)
            self.assertEqual(h.main([os.path.join(self.tmp, "missing.csv")]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
