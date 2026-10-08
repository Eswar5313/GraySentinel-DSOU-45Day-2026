#!/usr/bin/env python3
"""Unit tests for session_trust_analyzer.py — python3 -m unittest test_session_trust_analyzer -v"""
import csv, io, json, os, tempfile, unittest
from contextlib import redirect_stdout, redirect_stderr

import make_session_lab_data as lab
import session_trust_analyzer as h

HERE = os.path.dirname(os.path.abspath(__file__))
DAY = "2026-10-08"


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.csvp = os.path.join(cls.tmp, "t.csv")
        with open(cls.csvp, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=lab.FIELDS); w.writeheader(); w.writerows(lab.build())
        cls.events = h.load(cls.csvp)
        cls.ctx = json.loads(json.dumps(lab.CONTEXT))
        cls.r = h.analyze(cls.events, cls.ctx, DAY)
        cls.kinds = {f["kind"] for f in cls.r["findings"]}
        cls.sess = {s["session"]: s for s in cls.r["sessions"]}

    def without(self, pred):
        return h.analyze([e for e in self.events if not pred(e)], self.ctx, DAY)


class TestSessionTrust(Base):
    def test_01_owner_session_is_trusted(self):
        self.assertEqual(self.sess["S-1001"]["trust"], "TRUSTED")
        self.assertEqual(self.sess["S-1001"]["dimensions_failed"], [])

    def test_02_ghost_session_is_not_the_owner(self):
        self.assertEqual(self.sess["S-1002"]["trust"], "NOT THE OWNER")

    def test_03_all_five_dimensions_fail(self):
        self.assertEqual(self.r["dimensions_failed"], ["Behaviour", "Device", "Location", "Resource", "Time"])

    def test_04_unregistered_device_and_inherited_mfa(self):
        self.assertIn("session on an unregistered device", self.kinds)
        self.assertIn("new session without a fresh MFA challenge", self.kinds)

    def test_05_two_environments_at_once(self):
        self.assertIn("identity active in two environments at once", self.kinds)

    def test_06_unseen_app_and_endpoint_mismatch(self):
        self.assertIn("previously unseen application", self.kinds)
        self.assertIn("cloud says yes, endpoint says no", self.kinds)

    def test_07_first_seen_internal_resource_and_mass_access(self):
        self.assertIn("first-seen internal resource", self.kinds)
        f = next(f for f in self.r["findings"] if f["kind"] == "mass file access")
        self.assertIn("412 files", f["evidence"])

    def test_08_permission_grant_and_after_hours(self):
        self.assertIn("application permission granted from the suspect session", self.kinds)
        self.assertIn("session active outside working hours", self.kinds)


class TestPivotAndDecision(Base):
    def test_09_pivot_is_the_token_in_two_geographies(self):
        p = self.r["pivot_event"]
        self.assertEqual(p["kind"], "one session token in two geographies")
        self.assertEqual(p["ts"], "2026-10-08T05:09:00Z")          # 10:39 IST
        self.assertFalse(p["owner_explainable"])

    def test_10_everything_before_the_pivot_is_owner_explainable(self):
        before = [f for f in self.r["findings"] if f["ts"] < self.r["pivot_event"]["ts"]]
        self.assertTrue(before and all(f["owner_explainable"] for f in before))

    def test_11_decision_is_contain(self):
        self.assertEqual(self.r["decision"], "CONTAIN")

    def test_12_without_geo_proof_decision_is_investigate(self):
        r = self.without(lambda e: e["country"] == "NL")
        self.assertIsNone(r["pivot_event"]); self.assertEqual(r["decision"], "INVESTIGATE")
        self.assertEqual({s["session"]: s["trust"] for s in r["sessions"]}["S-1002"], "UNVERIFIED")

    def test_13_owner_only_day_is_monitor(self):
        r = self.without(lambda e: e["device"] == lab.GHOST_DEV)
        self.assertEqual(r["decision"], "MONITOR"); self.assertEqual(r["findings"], [])

    def test_14_baseline_day_is_clean(self):
        r = h.analyze(self.events, self.ctx, "2026-10-01")
        self.assertEqual((r["decision"], r["findings"]), ("MONITOR", []))


class TestTimelineAndAnswers(Base):
    def test_15_timeline_has_all_required_fields(self):
        need = {"ts", "identity", "device", "source", "destination", "action", "risk", "evidence", "confidence"}
        self.assertTrue(all(need <= set(t) for t in self.r["timeline"]))
        self.assertEqual(self.r["timeline"][0]["ist"], "10:02")

    def test_16_timeline_risk_peaks_at_pivot(self):
        crit = [t["ist"] for t in self.r["timeline"] if t["risk"] == "CRITICAL"]
        self.assertEqual(crit, ["10:39"])

    def test_17_success_criteria_answered(self):
        a = self.r["answers"]
        self.assertEqual(list(a), ["WHO", "WHERE", "WHEN", "WHAT", "HOW", "IMPACT"])
        self.assertIn("412 files", a["IMPACT"]); self.assertIn("FS-FIN-02", a["WHAT"])

    def test_18_exposure_and_edr_clean(self):
        self.assertEqual(self.r["exposure"]["files"], 412)
        self.assertEqual(self.r["exposure"]["app_grants"], ["MailSync Helper"])
        self.assertEqual(self.r["edr_verdict"], "clean")


class TestRobustness(Base):
    def test_19_malformed_rows_skipped(self):
        p = os.path.join(self.tmp, "junk.csv")
        with open(p, "w") as f:
            f.write(",".join(lab.FIELDS) + "\nbad-ts,idp,signin\n2026-10-08T04:00:00Z,,\n")
        self.assertEqual(h.load(p), [])

    def test_20_cli_exit_codes(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(h.main([self.csvp, os.path.join(HERE, "session_context_SYNTHETIC.json")]), 1)
            self.assertEqual(h.main([self.csvp, os.path.join(HERE, "session_context_SYNTHETIC.json"), "--day", "2026-10-01"]), 0)
            self.assertEqual(h.main([os.path.join(self.tmp, "nope.csv")]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
