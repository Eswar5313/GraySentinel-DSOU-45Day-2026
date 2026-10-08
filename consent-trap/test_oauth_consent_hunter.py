#!/usr/bin/env python3
"""Unit tests for oauth_consent_hunter.py — python3 -m unittest test_oauth_consent_hunter -v"""
import csv, io, json, os, tempfile, unittest
from contextlib import redirect_stdout, redirect_stderr

import make_consent_lab_data as lab
import oauth_consent_hunter as h

HERE = os.path.dirname(os.path.abspath(__file__))


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.csvp = os.path.join(cls.tmp, "a.csv")
        with open(cls.csvp, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=lab.FIELDS); w.writeheader(); w.writerows(lab.build())
        cls.events = h.load(cls.csvp)
        cls.ctx = json.loads(json.dumps(lab.CONTEXT))
        cls.r = h.hunt(cls.events, cls.ctx)
        cls.bad = [x for x in cls.r["hunt_table"] if x["application"] == lab.BAD_APP]

    def at(self, hhmmss, user=None):
        return next(x for x in self.bad if x["ist"].endswith(hhmmss) and (user is None or x["user"] == user))


class TestHuntTable(Base):
    def test_01_first_consent_is_suspicious_not_high(self):
        self.assertEqual(self.at("08:42:11")["risk"], "SUSPICIOUS")

    def test_02_first_api_call_is_suspicious(self):
        x = self.at("08:49:32")
        self.assertEqual(x["risk"], "SUSPICIOUS"); self.assertIn("7 min after consent", x["why"])

    def test_03_mailbox_from_germany_is_high(self):
        x = self.at("09:03:18")
        self.assertEqual(x["risk"], "HIGH PRIORITY"); self.assertIn("DE", x["why"])

    def test_04_out_of_baseline_file_access_is_high(self):
        self.assertEqual(self.at("09:07:42")["risk"], "HIGH PRIORITY")
        self.assertIn("outside the user's 30-day baseline", self.at("09:07:42")["why"])

    def test_05_second_user_consent_is_high(self):
        x = self.at("09:21:11")
        self.assertEqual(x["risk"], "HIGH PRIORITY"); self.assertIn("second user", x["why"])

    def test_06_multi_user_api_is_high(self):
        for u in ("finance.user", "hr.user"):
            self.assertEqual(self.at("09:31:52", u)["risk"], "HIGH PRIORITY")

    def test_07_approved_and_low_risk_apps_are_normal(self):
        other = {x["application"]: x["risk"] for x in self.r["hunt_table"] if x["application"] != lab.BAD_APP}
        self.assertEqual(set(other.values()), {"NORMAL"})
        self.assertEqual(set(other), {lab.OK_APP, lab.NEW_OK_APP, lab.SSO_APP})


class TestProfileAndDetection(Base):
    def test_08_risk_profile_flags(self):
        a = self.r["applications"][lab.BAD_ID]
        self.assertFalse(a["publisher_verified"]); self.assertEqual(a["risk_attributes"], 7)
        self.assertEqual(self.r["applications"][lab.NEW_OK_ID]["risk_attributes"], 0)

    def test_09_detection_fires_for_both_users(self):
        d = {x["user"]: x for x in self.r["detections"]}
        self.assertEqual(sorted(d), ["finance.user", "hr.user"])
        self.assertTrue(all(x["fired"] for x in d.values()))

    def test_10_time_deltas(self):
        d = next(x for x in self.r["detections"] if x["user"] == "finance.user")
        self.assertAlmostEqual(d["consent_to_first_api_min"], 7.3, places=1)
        self.assertAlmostEqual(d["consent_to_first_data_min"], 21.1, places=1)

    def test_11_exposure_counts(self):
        d = next(x for x in self.r["detections"] if x["user"] == "finance.user")
        self.assertEqual((d["mail_items"], d["files"]), (340, 23))
        self.assertEqual(d["new_sites"], ["Board-Packs", "Finance-Treasury"])

    def test_12_iocs(self):
        i = self.r["iocs"][0]
        self.assertEqual(i["application_id"], lab.BAD_ID)
        self.assertEqual(i["source_ips"], [lab.BAD_IP])
        self.assertEqual(i["redirect_uri_domains"], [lab.BAD_DOMAIN])
        self.assertEqual(len(i["related_domains_osint"]), 2)

    def test_13_delivery_clicks_linked_by_client_id(self):
        self.assertEqual([d["user"] for d in self.r["delivery"]], ["finance.user", "hr.user"])

    def test_14_assessment_high_but_no_attribution(self):
        self.assertIn("IDENTITY-BASED INTRUSION", self.r["assessment"])
        self.assertEqual(self.r["confidence"], "HIGH"); self.assertTrue(self.r["attribution"].startswith("none"))


class TestConfidenceLadderAndRobustness(Base):
    def test_15_single_user_is_medium(self):
        ev = [e for e in self.events if e["user"] != "hr.user"]
        r = h.hunt(ev, self.ctx)
        self.assertEqual(r["confidence"], "MEDIUM"); self.assertEqual(r["affected_users"], ["finance.user"])

    def test_16_consent_without_activity_is_low_and_not_fired(self):
        ev = [e for e in self.events if not (e["app_id"] == lab.BAD_ID and not h.is_consent(e)) and e["user"] != "hr.user"]
        r = h.hunt(ev, self.ctx)
        self.assertEqual(r["confidence"], "LOW"); self.assertFalse(any(d["fired"] for d in r["detections"]))

    def test_17_admin_approved_app_never_fires_even_if_listed_scopes_grow(self):
        ctx = json.loads(json.dumps(self.ctx)); ctx["approved_apps"][lab.BAD_ID] = lab.BAD_APP
        r = h.hunt(self.events, ctx)
        self.assertEqual(r["detections"], []); self.assertEqual(r["assessment"], "NO RISKY CONSENT OBSERVED")

    def test_18_baseline_only_is_clean(self):
        ev = [e for e in self.events if e["app_id"] != lab.BAD_ID and e["source"] != "proxy"]
        r = h.hunt(ev, self.ctx)
        self.assertEqual(r["iocs"], []); self.assertEqual({x["risk"] for x in r["hunt_table"]}, {"NORMAL"})

    def test_19_malformed_rows_skipped(self):
        p = os.path.join(self.tmp, "junk.csv")
        with open(p, "w") as f:
            f.write(",".join(lab.FIELDS) + "\nbad-ts,entra_audit,Consent to application\n2026-10-08T03:00:00Z,,\n")
        self.assertEqual(h.load(p), [])

    def test_20_cli_exit_codes(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(h.main([self.csvp, os.path.join(HERE, "consent_context_SYNTHETIC.json")]), 1)
            self.assertEqual(h.main([os.path.join(self.tmp, "nope.csv")]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
