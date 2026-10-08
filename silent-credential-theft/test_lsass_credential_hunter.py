#!/usr/bin/env python3
"""Unit tests for lsass_credential_hunter.py — python3 -m unittest test_lsass_credential_hunter -v"""
import csv, io, json, os, tempfile, unittest
from contextlib import redirect_stdout, redirect_stderr

import make_lsass_lab_data as lab
import lsass_credential_hunter as h

HERE = os.path.dirname(os.path.abspath(__file__))


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.csvp = os.path.join(cls.tmp, "e.csv")
        with open(cls.csvp, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=lab.FIELDS); w.writeheader(); w.writerows(lab.build())
        cls.events = h.load_events(cls.csvp)
        cls.ctx = json.loads(json.dumps(lab.CONTEXT))
        cls.r = h.investigate(cls.events, cls.ctx)
        cls.c = cls.r["cases"][0]


class TestTriageAndDetection(Base):
    def test_01_exactly_one_case(self):
        self.assertEqual(len(self.r["cases"]), 1)
        self.assertEqual(self.c["triage"]["host"], "FIN-WS-117")

    def test_02_process_and_parent_identified(self):
        self.assertTrue(self.c["triage"]["process"].endswith("dbgsvc.exe"))
        self.assertTrue(self.c["triage"]["parent"].endswith("WINWORD.EXE"))

    def test_03_signature_hash_mask(self):
        t = self.c["triage"]
        self.assertEqual((t["signed"], t["granted_access"]), ("false", "0x1010"))
        self.assertEqual(t["hash_seen_on"], ["FIN-WS-117"])

    def test_04_defender_and_edr_not_flagged(self):
        s = self.r["lsass_access_summary"]
        self.assertEqual(s["suspicious"], 1)
        self.assertEqual(s["expected_images"], ["edr-agent.exe", "msmpeng.exe"])

    def test_05_lsass_existing_alone_never_alerts(self):
        e = {"event_id": 1, "target": "", "process": r"C:\Windows\System32\lsass.exe"}
        self.assertIsNone(h.classify_lsass_access(e, self.ctx))

    def test_06_approved_path_but_unsigned_is_not_expected(self):
        e = {"event_id": 10, "target": lab.LSASS, "process": lab.DEFENDER, "signed": "false",
             "granted_access": "0x1010", "hash": "x", "ts": "2026-10-08T04:00:00Z", "host": "H", "user": "u"}
        self.assertNotEqual(h.classify_lsass_access(e, self.ctx)["verdict"], "EXPECTED")

    def test_07_query_only_mask_by_unknown_signed_tool_is_review(self):
        e = {"event_id": 10, "target": lab.LSASS, "process": r"C:\Program Files\Tool\diag.exe", "signed": "true",
             "granted_access": "0x1000", "hash": "x", "ts": "2026-10-08T04:00:00Z", "host": "H", "user": "u"}
        self.assertEqual(h.classify_lsass_access(e, self.ctx)["verdict"], "REVIEW")


class TestHypotheses(Base):
    def test_08_h1_supported(self):
        self.assertEqual(self.c["hypotheses"]["H1"]["verdict"], "SUPPORTED")

    def test_09_h2_rejected_no_ticket_non_paw(self):
        self.assertEqual(self.c["hypotheses"]["H2"]["verdict"], "REJECTED")

    def test_10_h3_supported_with_explicit_creds(self):
        v = self.c["hypotheses"]["H3"]
        self.assertEqual(v["verdict"], "SUPPORTED")
        self.assertTrue(any("4648" in x for x in v["evidence"]))

    def test_11_privileged_account_involved(self):
        self.assertEqual(self.c["triage"]["privileged_accounts"], ["adm.kiran"])
        self.assertEqual(self.c["triage"]["failed_logons"], 6)

    def test_12_legit_admin_from_paw_is_legitimate(self):
        ctrl = {(a["host"], a["verdict"]) for a in self.r["admin_controls"]}
        self.assertIn(("FILE-SRV-03", "LEGITIMATE"), ctrl)
        self.assertTrue(all(a["src"] == "PAW-ADMIN-01" for a in self.r["admin_controls"]))


class TestLateralAndCorrelation(Base):
    def test_13_new_destinations(self):
        d = self.c["destinations"]
        self.assertEqual(sorted(d), ["FILE-SRV-03", "FIN-WS-121"])
        self.assertTrue(all(v["prior_30d"] == 0 for v in d.values()))

    def test_14_sensitive_share_and_kerberos(self):
        self.assertEqual(len(self.c["sensitive_files"]), 14)
        self.assertEqual(len(self.c["kerberos_unusual"]), 4)

    def test_15_full_correlation_is_critical(self):
        self.assertEqual(self.c["correlation"]["score"], "4/4")
        self.assertEqual(self.c["detection"]["severity"], "CRITICAL")
        self.assertLessEqual(self.c["correlation"]["gaps"]["A_to_B_min"], 10)

    def test_16_lsass_alone_is_only_medium(self):
        only = [e for e in self.events if not (e["_t"].strftime("%Y-%m-%d") == "2026-10-08"
                                               and e["event_id"] in (4624, 4625, 4648, 4672, 4769, 5145)
                                               and e["host"] != "FIN-WS-117")]
        only = [e for e in only if e["event_id"] != 4648]
        c = h.investigate(only, self.ctx)["cases"][0]
        self.assertEqual(c["correlation"]["score"], "1/4")
        self.assertEqual(c["detection"]["severity"], "MEDIUM")
        self.assertEqual(c["hypotheses"]["H3"]["verdict"], "NOT SUPPORTED")

    def test_17_scope_order_source_dc_server_workstation(self):
        s = self.c["investigate_next"]
        self.assertTrue(s[0].startswith("FIN-WS-117") and s[1].startswith("DC-01"))
        self.assertLess(next(i for i, x in enumerate(s) if x.startswith("FILE-SRV-03")),
                        next(i for i, x in enumerate(s) if x.startswith("FIN-WS-121")))


class TestBaselineAndRobustness(Base):
    def test_18_baseline_only_is_clean(self):
        base = [e for e in self.events if e["_t"].strftime("%Y-%m-%d") < "2026-10-08"]
        r = h.investigate(base, self.ctx)
        self.assertEqual(r["cases"], [])

    def test_19_malformed_rows_skipped(self):
        p = os.path.join(self.tmp, "junk.csv")
        with open(p, "w") as f:
            f.write(",".join(lab.FIELDS) + "\nnot-a-date,H,Security,4624\n2026-10-08T04:00:00Z,H,Security,abc\n")
        self.assertEqual(h.load_events(p), [])

    def test_20_cli_exit_codes(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(h.main([self.csvp, os.path.join(HERE, "lsass_context_SYNTHETIC.json")]), 1)
            self.assertEqual(h.main([os.path.join(self.tmp, "nope.csv")]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
