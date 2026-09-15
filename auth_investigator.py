#!/usr/bin/env python3
"""
auth_investigator.py — Authentication Log Investigation Tool
GraySentinel Cyber Defence Lab · Day 1 · Project 01 · Eswar Mahalingam (Blue Team)

Parses a Linux auth.log (sshd / sudo / su / useradd / usermod), reconstructs
authentication activity and raises findings for:

  F1  SSH brute force            many failures from one source IP
  F2  Password spraying          one source IP, few attempts each, MANY users
  F3  Success after failures     failures then an Accepted login from same IP  (CRITICAL)
  F4  Off-hours root login       root/admin login outside business window
  F5  Invalid-user probing       logins to accounts that do not exist
  F6  Privilege escalation       failed sudo bursts, su-to-root attempts
  F7  Account manipulation       useradd / usermod to sudo group
  F8  Payload staging            sudo curl/wget to a remote host or /tmp/*.sh

Standard library only. Python 3.8+.

Usage:
  python3 auth_investigator.py --log ../data/auth.log --out ../evidence/findings.json --md ../evidence/findings.md
  python3 auth_investigator.py --log ../data/auth.log --bf-threshold 10 --spray-users 8 --business-hours 08-20
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

YEAR = datetime.now().year  # syslog has no year; assume current year

# ---------- regexes -----------------------------------------------------------
RE_LINE = re.compile(r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<proc>[\w\-/]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$")
RE_FAIL = re.compile(r"Failed password for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)")
RE_OK = re.compile(r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)")
RE_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")
RE_SUDO_FAIL = re.compile(r"\s*(?P<user>\S+) : (?P<n>\d+) incorrect password attempts.*COMMAND=(?P<cmd>.*)")
RE_SUDO_OK = re.compile(r"\s*(?P<user>\S+) : TTY=.*USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)")
RE_SU = re.compile(r"\(to (?P<target>\S+)\) (?P<user>\S+) on")
RE_USERADD = re.compile(r"new user: name=(?P<user>\S+),")
RE_USERMOD = re.compile(r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'")

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def parse_ts(s: str) -> datetime:
    return datetime.strptime(f"{YEAR} {s}", "%Y %b %d %H:%M:%S")


# ---------- parsing -----------------------------------------------------------
def parse_log(path: str) -> list[dict]:
    """Return a list of normalised auth events. Unparseable lines are counted, not crashed on."""
    events, skipped = [], 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, raw in enumerate(fh, 1):
            raw = raw.rstrip("\n")
            if not raw.strip():
                continue
            m = RE_LINE.match(raw)
            if not m:
                skipped += 1
                continue
            try:
                ts = parse_ts(m["ts"])
            except ValueError:
                skipped += 1
                continue
            ev = {"line": n, "ts": ts, "host": m["host"], "proc": m["proc"], "msg": m["msg"], "type": "other"}
            msg = m["msg"]
            if m["proc"] == "sshd":
                if (x := RE_FAIL.search(msg)):
                    ev.update(type="ssh_fail", user=x["user"], ip=x["ip"], port=int(x["port"]), invalid=bool(x["invalid"]))
                elif (x := RE_OK.search(msg)):
                    ev.update(type="ssh_ok", user=x["user"], ip=x["ip"], port=int(x["port"]), method=x["method"])
                elif (x := RE_INVALID.search(msg)):
                    ev.update(type="ssh_invalid_user", user=x["user"], ip=x["ip"])
            elif m["proc"] == "sudo":
                if (x := RE_SUDO_FAIL.search(msg)):
                    ev.update(type="sudo_fail", user=x["user"], attempts=int(x["n"]), cmd=x["cmd"].strip())
                elif (x := RE_SUDO_OK.search(msg)):
                    ev.update(type="sudo_ok", user=x["user"], target=x["target"], cmd=x["cmd"].strip())
            elif m["proc"] == "su":
                if (x := RE_SU.search(msg)):
                    ev.update(type="su_attempt", user=x["user"], target=x["target"])
            elif m["proc"] == "useradd":
                if (x := RE_USERADD.search(msg)):
                    ev.update(type="useradd", user=x["user"])
            elif m["proc"] == "usermod":
                if (x := RE_USERMOD.search(msg)):
                    ev.update(type="usermod", user=x["user"], group=x["group"])
            events.append(ev)
    if skipped:
        print(f"[warn] {skipped} line(s) did not match the syslog auth format and were skipped", file=sys.stderr)
    return events


# ---------- detections --------------------------------------------------------
def make_finding(fid, sev, title, ip, users, first, last, count, evidence_lines, technique, detail):
    return {
        "id": fid, "severity": sev, "title": title, "source_ip": ip,
        "users": sorted(set(users)), "first_seen": first.isoformat(sep=" "), "last_seen": last.isoformat(sep=" "),
        "event_count": count, "evidence_lines": sorted(set(evidence_lines))[:25],
        "mitre_attack": technique, "detail": detail,
    }


def detect(events: list[dict], bf_threshold=10, spray_users=8, business_hours=(8, 20), window_min=10) -> list[dict]:
    findings = []
    fails_by_ip = defaultdict(list)
    ok_by_ip = defaultdict(list)
    invalid_by_ip = defaultdict(set)
    for e in events:
        if e["type"] == "ssh_fail":
            fails_by_ip[e["ip"]].append(e)
        elif e["type"] == "ssh_ok":
            ok_by_ip[e["ip"]].append(e)
        elif e["type"] == "ssh_invalid_user":
            invalid_by_ip[e["ip"]].add(e["user"])

    n = 1
    # F1 brute force + F2 spraying (mutually exclusive per IP; spraying wins if user spread is wide)
    for ip, fl in fails_by_ip.items():
        users = [e["user"] for e in fl]
        uc = Counter(users)
        distinct = len(uc)
        if distinct >= spray_users and max(uc.values()) <= 3:
            findings.append(make_finding(
                f"F{n:02d}", "HIGH", "Password spraying (one source, many accounts)", ip, users,
                fl[0]["ts"], fl[-1]["ts"], len(fl), [e["line"] for e in fl], "T1110.003 Password Spraying",
                f"{len(fl)} failures across {distinct} distinct usernames, max {max(uc.values())} attempt(s) per user — "
                "the signature of spraying a single password against a user list to stay under lockout thresholds."))
            n += 1
        elif len(fl) >= bf_threshold:
            top_user, top_n = uc.most_common(1)[0]
            span = (fl[-1]["ts"] - fl[0]["ts"]).total_seconds() or 1
            findings.append(make_finding(
                f"F{n:02d}", "HIGH", "SSH brute force (many failures from one source)", ip, users,
                fl[0]["ts"], fl[-1]["ts"], len(fl), [e["line"] for e in fl], "T1110.001 Password Guessing",
                f"{len(fl)} failed passwords in {span/60:.1f} min ({len(fl)/span*60:.1f}/min); "
                f"primary target '{top_user}' ({top_n} attempts)."))
            n += 1

    # F3 success after failures — the one that matters most
    for ip, oks in ok_by_ip.items():
        fl = fails_by_ip.get(ip, [])
        if len(fl) < 3:
            continue  # a couple of typos by a real user is not an incident
        for ok in oks:
            prior = [f for f in fl if 0 <= (ok["ts"] - f["ts"]).total_seconds() <= window_min * 60]
            if len(prior) >= 3:
                findings.append(make_finding(
                    f"F{n:02d}", "CRITICAL", "Successful login after failure burst (likely compromised credential)", ip,
                    [ok["user"]] + [f["user"] for f in prior], prior[0]["ts"], ok["ts"], len(prior) + 1,
                    [f["line"] for f in prior] + [ok["line"]], "T1078 Valid Accounts",
                    f"'{ok['user']}' accepted via {ok['method']} from {ip} after {len(prior)} failures in the preceding "
                    f"{window_min} min. Treat the account and host as compromised until proven otherwise."))
                n += 1

    # F4 off-hours privileged login
    lo, hi = business_hours
    for ip, oks in ok_by_ip.items():
        for ok in oks:
            if ok["user"] in ("root", "admin", "administrator") and not (lo <= ok["ts"].hour < hi):
                findings.append(make_finding(
                    f"F{n:02d}", "MEDIUM", "Privileged account login outside business hours", ip, [ok["user"]],
                    ok["ts"], ok["ts"], 1, [ok["line"]], "T1078 Valid Accounts",
                    f"'{ok['user']}' logged in at {ok['ts'].strftime('%H:%M')} (allowed window {lo:02d}:00–{hi:02d}:00)."))
                n += 1

    # F5 invalid-user probing
    for ip, users in invalid_by_ip.items():
        if len(users) >= 3:
            evs = [e for e in events if e["type"] == "ssh_invalid_user" and e["ip"] == ip]
            findings.append(make_finding(
                f"F{n:02d}", "MEDIUM", "Username enumeration / invalid-user probing", ip, list(users),
                evs[0]["ts"], evs[-1]["ts"], len(evs), [e["line"] for e in evs], "T1087 Account Discovery",
                f"{len(users)} non-existent usernames tried: {', '.join(sorted(users)[:8])}{'…' if len(users) > 8 else ''}."))
            n += 1

    # F6 privilege escalation attempts
    sudo_fail = [e for e in events if e["type"] == "sudo_fail"]
    by_user = defaultdict(list)
    for e in sudo_fail:
        by_user[e["user"]].append(e)
    for u, evs in by_user.items():
        total = sum(e["attempts"] for e in evs)
        if total >= 3:
            findings.append(make_finding(
                f"F{n:02d}", "HIGH", "Repeated failed sudo (local privilege-escalation probing)", "local", [u],
                evs[0]["ts"], evs[-1]["ts"], len(evs), [e["line"] for e in evs], "T1548.003 Sudo and Sudo Caching",
                f"'{u}' failed sudo {total} times; last command attempted: {evs[-1]['cmd']}"))
            n += 1
    for e in events:
        if e["type"] == "su_attempt" and e["target"] == "root":
            findings.append(make_finding(
                f"F{n:02d}", "MEDIUM", "su to root attempted", "local", [e["user"]], e["ts"], e["ts"], 1, [e["line"]],
                "T1548 Abuse Elevation Control Mechanism", f"'{e['user']}' attempted 'su root' on {e['msg'].split(' on ')[-1]}."))
            n += 1

    # F8 suspicious privileged command (remote payload fetch / staging in /tmp)
    for e in events:
        if e["type"] == "sudo_ok" and re.search(r"\b(curl|wget)\b.*(https?://|/tmp/)|/tmp/\S+\.sh|chmod \+x /tmp", e["cmd"]):
            findings.append(make_finding(
                f"F{n:02d}", "HIGH", "Privileged command fetched/staged a remote payload", "local", [e["user"]], e["ts"], e["ts"], 1,
                [e["line"]], "T1105 Ingress Tool Transfer", f"'{e['user']}' ran as {e['target']}: {e['cmd']}"))
            n += 1

    # F7 account manipulation
    for e in events:
        if e["type"] == "useradd":
            findings.append(make_finding(
                f"F{n:02d}", "HIGH", "New local account created", "local", [e["user"]], e["ts"], e["ts"], 1, [e["line"]],
                "T1136.001 Create Account: Local", f"Account '{e['user']}' created — verify against change tickets."))
            n += 1
        elif e["type"] == "usermod" and e["group"] in ("sudo", "wheel", "admin", "root"):
            findings.append(make_finding(
                f"F{n:02d}", "CRITICAL", "Account added to privileged group", "local", [e["user"]], e["ts"], e["ts"], 1,
                [e["line"]], "T1098 Account Manipulation", f"'{e['user']}' added to '{e['group']}' — backdoor admin pattern."))
            n += 1

    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["first_seen"]))
    return findings


# ---------- reporting ---------------------------------------------------------
def summarise(events: list[dict]) -> dict:
    c = Counter(e["type"] for e in events)
    ips = Counter(e["ip"] for e in events if e.get("ip"))
    users_ok = Counter(e["user"] for e in events if e["type"] == "ssh_ok")
    return {
        "total_events": len(events),
        "time_range": [events[0]["ts"].isoformat(sep=" "), events[-1]["ts"].isoformat(sep=" ")] if events else [],
        "by_type": dict(c), "top_source_ips": ips.most_common(5), "successful_logins_by_user": users_ok.most_common(10),
    }


def to_markdown(summary: dict, findings: list[dict], logpath: str) -> str:
    out = ["# Authentication Log Investigation — Findings", "",
           f"**Source log:** `{logpath}`  ",
           f"**Events parsed:** {summary['total_events']}  ",
           f"**Time range:** {summary['time_range'][0]} → {summary['time_range'][1]}  " if summary["time_range"] else "",
           f"**Findings:** {len(findings)} "
           f"({', '.join(f'{s}: {sum(1 for f in findings if f['severity']==s)}' for s in SEV_ORDER if any(f['severity']==s for f in findings))})",
           "", "## Event mix", "", "| Type | Count |", "|---|---|"]
    out += [f"| {k} | {v} |" for k, v in sorted(summary["by_type"].items(), key=lambda kv: -kv[1])]
    out += ["", "## Top source IPs", "", "| IP | Events |", "|---|---|"]
    out += [f"| {ip} | {n} |" for ip, n in summary["top_source_ips"]]
    out += ["", "## Findings", "", "| ID | Severity | Title | Source | Users | Events | First seen | Last seen | ATT&CK |", "|---|---|---|---|---|---|---|---|---|"]
    for f in findings:
        out.append(f"| {f['id']} | **{f['severity']}** | {f['title']} | `{f['source_ip']}` | {', '.join(f['users'][:4])}{'…' if len(f['users'])>4 else ''} | {f['event_count']} | {f['first_seen'][11:]} | {f['last_seen'][11:]} | {f['mitre_attack']} |")
    out.append("")
    for f in findings:
        out += [f"### {f['id']} · {f['severity']} · {f['title']}", "", f"{f['detail']}", "",
                f"- Source: `{f['source_ip']}` · Users: {', '.join(f['users'])}",
                f"- Evidence lines in log: {', '.join(map(str, f['evidence_lines'][:15]))}{'…' if len(f['evidence_lines'])>15 else ''}", ""]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Authentication Log Investigation Tool (GraySentinel Day 1 · Project 01)")
    ap.add_argument("--log", required=True, help="path to auth.log")
    ap.add_argument("--out", help="write findings JSON here")
    ap.add_argument("--md", help="write Markdown findings report here")
    ap.add_argument("--bf-threshold", type=int, default=10, help="failures from one IP to call brute force (default 10)")
    ap.add_argument("--spray-users", type=int, default=8, help="distinct users from one IP to call spraying (default 8)")
    ap.add_argument("--business-hours", default="08-20", help="HH-HH window for privileged logins (default 08-20)")
    ap.add_argument("--window", type=int, default=10, help="minutes before a success to look back for failures (default 10)")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)

    lo, hi = (int(x) for x in a.business_hours.split("-"))
    events = parse_log(a.log)
    findings = detect(events, a.bf_threshold, a.spray_users, (lo, hi), a.window)
    summary = summarise(events)
    result = {"tool": "auth_investigator", "version": "1.0", "generated": datetime.now().isoformat(sep=" ", timespec="seconds"),
              "log": a.log, "summary": summary, "findings": findings}

    if a.out:
        with open(a.out, "w") as fh:
            json.dump(result, fh, indent=2, default=str)
    if a.md:
        with open(a.md, "w") as fh:
            fh.write(to_markdown(summary, findings, a.log))
    if not a.quiet:
        print(f"Parsed {summary['total_events']} events from {a.log}")
        print(f"Event mix: {summary['by_type']}")
        print(f"\n{len(findings)} finding(s):")
        for f in findings:
            print(f"  [{f['severity']:<8}] {f['id']}  {f['title']:<62} src={f['source_ip']:<15} n={f['event_count']}")
        if a.out:
            print(f"\nJSON  -> {a.out}")
        if a.md:
            print(f"MD    -> {a.md}")
    return 2 if any(f["severity"] == "CRITICAL" for f in findings) else (1 if findings else 0)


if __name__ == "__main__":
    sys.exit(main())
