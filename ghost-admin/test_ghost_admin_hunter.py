#!/usr/bin/env python3
"""Unit tests for ghost_admin_hunter.py — python3 -m unittest test_ghost_admin_hunter -v"""
import csv, io, json, os, tempfile, unittest
from contextlib import redirect_stdout

import make_ghostadmin_lab_data as lab
import ghost_admin_hunter as h

HERE = os.path.dirname(os.path.abspath(__file__))


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.csv = os.path.join(cls.tmp, "ev.csv")
        with open(cls.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=lab.FIELDS); w.writeheader(); w.writerows(lab.build())
        cls.events = h.load_events(cls.csv)
        cls.ctx = json.loads(json.dumps(lab.CONTEXT))
        cls.cases = h.investigate(cls.events, cls.ctx)
        cls.c = next(c for c in cls.cases if c["identity"]["user"] == "s.menon")


class TestIdentity(Base):
    def test_01_one_case_the_attacker(self):
        self.assertEqual(len(self.cases), 1)
        self.assertEqual(self.c["identity"]["user"], "s.menon")

    def test_02_target_is_dc(self):
        self.assertEqual(self.c["identity"]["dc"], "DC-02")
        self.assertEqual(self.c["identity"]["source_host"], "WKS-FIN-204")

    def test_03_logon_type_and_ntlm(self):
        self.assertEqual(self.c["identity"]["logon_type"], 3)
        self.assertEqual(self.c["identity"]["auth_pkg"], "NTLM")

    def test_04_user_not_normally_privileged(self):
        self.assertFalse(self.c["identity"]["normally_privileged"])
        self.assertEqual(self.c["identity"]["tier0_baseline_30d"], 0)

    def test_05_failed_attempts_counted(self):
        self.assertEqual(self.c["identity"]["failed_attempts"], 12)

    def test_06_priv_group_adds(self):
        self.assertIn("Domain Admins", self.c["identity"]["privileged_group_adds"])
        self.assertIn("Administrators", self.c["identity"]["privileged_group_adds"])

    def test_07_no_change_ticket(self):
        self.assertIsNone(self.c["identity"]["change_ticket"])


class TestHypotheses(Base):
    def test_08_h1_compromised(self):
        self.assertEqual(self.c["hypotheses"]["H1"]["verdict"], "COMPROMISED")

    def test_09_h2_privilege_escalation_confirmed(self):
        self.assertEqual(self.c["hypotheses"]["H2"]["verdict"], "CONFIRMED")

    def test_10_h3_lateral_confirmed(self):
        self.assertEqual(self.c["hypotheses"]["H3"]["verdict"], "CONFIRMED")


class TestDetectionPersistenceLateral(Base):
    def test_11_detection_critical(self):
        self.assertTrue(self.c["detection"]["fired"])
        self.assertEqual(self.c["detection"]["severity"], "CRITICAL")

    def test_12_dcsync_detected(self):
        self.assertTrue(self.c["persistence"]["dcsync"])

    def test_13_new_service_persistence(self):
        self.assertTrue(any("WinSysMon2" in s for s in self.c["persistence"]["new_services"]))

    def test_14_onward_logons(self):
        self.assertEqual(self.c["lateral"]["onward_logons"], ["DC-01", "FS-CORP-01"])

    def test_15_legit_admin_not_flagged(self):
        # da.patel RDPs DC-02 from the approved PAW with a change ticket in the baseline
        self.assertFalse(any(c["identity"]["user"] == "da.patel" for c in self.cases))

    def test_16_timeline_ordered_and_has_escalation(self):
        tl = [x[0] for x in self.c["timeline"]]
        self.assertEqual(tl, sorted(tl))
        self.assertIn("4728", [x[1] for x in self.c["timeline"]])


class TestRobustness(Base):
    def test_17_garbage_rows_skipped(self):
        p = os.path.join(self.tmp, "junk.csv")
        with open(p, "w") as f:
            f.write(",".join(lab.FIELDS) + "\nbad-ts,DC-02,Security,notanint" + "," * 12 + "\n")
        self.assertEqual(h.load_events(p), [])

    def test_18_cli_exit_codes(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(h.main([self.csv, os.path.join(HERE, "ghostadmin_context_SYNTHETIC.json")]), 1)
            self.assertEqual(h.main([os.path.join(self.tmp, "nope.csv")]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
