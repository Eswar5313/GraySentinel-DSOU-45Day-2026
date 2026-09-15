"""
Tests for auth_investigator.py — run from project-01/:  python3 -m unittest -v tests.test_auth_investigator
Covers expected cases (each detection fires on its trigger) and edge cases
(typos are NOT brute force, empty/garbage input does not crash, thresholds are honoured).
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import auth_investigator as ai  # noqa: E402

H = "soc-lab-01"


def line(ts, proc, msg, pid=1):
    return f"{ts} {H} {proc}[{pid}]: {msg}"


def run(lines, **kw):
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
        f.write("\n".join(lines) + "\n")
        path = f.name
    try:
        ev = ai.parse_log(path)
        return ev, ai.detect(ev, **kw)
    finally:
        os.unlink(path)


class ParseTests(unittest.TestCase):
    def test_parses_failed_and_accepted(self):
        ev, _ = run([line("Sep 14 10:00:01", "sshd", "Failed password for root from 203.0.113.9 port 1 ssh2"),
                     line("Sep 14 10:00:02", "sshd", "Accepted publickey for ops from 192.0.2.5 port 2 ssh2: RSA SHA256:x")])
        self.assertEqual([e["type"] for e in ev], ["ssh_fail", "ssh_ok"])
        self.assertEqual(ev[0]["ip"], "203.0.113.9")
        self.assertEqual(ev[1]["method"], "publickey")

    def test_invalid_user_flag(self):
        ev, _ = run([line("Sep 14 10:00:01", "sshd", "Failed password for invalid user admin from 203.0.113.9 port 1 ssh2")])
        self.assertTrue(ev[0]["invalid"])
        self.assertEqual(ev[0]["user"], "admin")

    def test_garbage_lines_are_skipped_not_fatal(self):
        ev, f = run(["this is not a syslog line", "", "Sep 99 99:99:99 host sshd[1]: nonsense"])
        self.assertEqual(ev, [])
        self.assertEqual(f, [])

    def test_empty_file(self):
        ev, f = run([])
        self.assertEqual((ev, f), ([], []))


class DetectionTests(unittest.TestCase):
    def test_brute_force_fires_at_threshold(self):
        lines = [line(f"Sep 14 01:00:{i:02d}", "sshd", "Failed password for root from 203.0.113.9 port 1 ssh2") for i in range(10)]
        _, f = run(lines, bf_threshold=10)
        self.assertTrue(any("brute force" in x["title"] for x in f))
        _, f2 = run(lines, bf_threshold=11)
        self.assertFalse(any("brute force" in x["title"] for x in f2), "threshold must be honoured")

    def test_two_typos_are_not_an_incident(self):
        lines = [line("Sep 14 10:00:01", "sshd", "Failed password for priya from 192.0.2.14 port 1 ssh2"),
                 line("Sep 14 10:00:09", "sshd", "Failed password for priya from 192.0.2.14 port 2 ssh2"),
                 line("Sep 14 10:00:18", "sshd", "Accepted password for priya from 192.0.2.14 port 3 ssh2")]
        _, f = run(lines)
        self.assertEqual(f, [], "a real user mistyping twice must not raise a finding")

    def test_success_after_burst_is_critical(self):
        lines = [line(f"Sep 14 01:00:{i:02d}", "sshd", "Failed password for root from 203.0.113.9 port 1 ssh2") for i in range(5)]
        lines.append(line("Sep 14 01:00:30", "sshd", "Accepted password for root from 203.0.113.9 port 9 ssh2"))
        _, f = run(lines, bf_threshold=50)
        crit = [x for x in f if x["severity"] == "CRITICAL"]
        self.assertEqual(len(crit), 1)
        self.assertIn("Successful login after failure", crit[0]["title"])
        self.assertEqual(crit[0]["mitre_attack"], "T1078 Valid Accounts")

    def test_success_outside_window_not_linked(self):
        lines = [line(f"Sep 14 01:00:{i:02d}", "sshd", "Failed password for root from 203.0.113.9 port 1 ssh2") for i in range(5)]
        lines.append(line("Sep 14 03:00:00", "sshd", "Accepted password for root from 203.0.113.9 port 9 ssh2"))
        _, f = run(lines, bf_threshold=50, window_min=10)
        self.assertFalse(any(x["severity"] == "CRITICAL" for x in f))

    def test_password_spray(self):
        users = ["u%d" % i for i in range(8)]
        lines = [line(f"Sep 14 02:00:{i:02d}", "sshd", f"Failed password for invalid user {u} from 198.51.100.7 port 1 ssh2") for i, u in enumerate(users)]
        _, f = run(lines, spray_users=8)
        titles = [x["title"] for x in f]
        self.assertTrue(any("spraying" in t for t in titles))
        self.assertFalse(any("brute force" in t for t in titles), "spray and brute force are mutually exclusive per IP")

    def test_off_hours_root_login(self):
        _, f = run([line("Sep 14 23:30:00", "sshd", "Accepted password for root from 192.0.2.5 port 1 ssh2")], business_hours=(8, 20))
        self.assertTrue(any("outside business hours" in x["title"] for x in f))
        _, f2 = run([line("Sep 14 11:30:00", "sshd", "Accepted password for root from 192.0.2.5 port 1 ssh2")], business_hours=(8, 20))
        self.assertEqual(f2, [])

    def test_sudo_failures_and_su(self):
        lines = [line("Sep 14 11:00:15", "sudo", "    arjun : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/arjun ; USER=root ; COMMAND=/bin/cat /etc/shadow"),
                 line("Sep 14 11:30:00", "su", "(to root) arjun on pts/1")]
        _, f = run(lines)
        titles = [x["title"] for x in f]
        self.assertTrue(any("failed sudo" in t for t in titles))
        self.assertTrue(any("su to root" in t for t in titles))

    def test_account_manipulation(self):
        lines = [line("Sep 14 00:10:00", "useradd", "new user: name=svc_backup, UID=1007, GID=1007, home=/home/svc_backup, shell=/bin/bash"),
                 line("Sep 14 00:10:20", "usermod", "add 'svc_backup' to group 'sudo'")]
        _, f = run(lines)
        sev = {x["title"]: x["severity"] for x in f}
        self.assertEqual(sev["New local account created"], "HIGH")
        self.assertEqual(sev["Account added to privileged group"], "CRITICAL")

    def test_findings_sorted_by_severity(self):
        ev = ai.parse_log(os.path.join(os.path.dirname(__file__), "..", "data", "auth.log"))
        f = ai.detect(ev)
        order = [ai.SEV_ORDER[x["severity"]] for x in f]
        self.assertEqual(order, sorted(order))
        self.assertEqual(len(f), 10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
