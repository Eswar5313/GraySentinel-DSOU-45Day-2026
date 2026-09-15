#!/usr/bin/env python3
"""
incident_summary.py — SOC Incident Summary Generator
GraySentinel Cyber Defence Lab · Day 1 · Project 02 · Eswar Mahalingam (Blue Team)

Takes the findings produced by an investigation tool (Project 01's findings.json,
or any alert CSV with the same columns) and turns them into an analyst-ready
SOC incident summary:

  * Incident ID, overall severity + priority (P1–P4), confidence
  * Executive summary (3 lines, plain English — for the manager)
  * Attack narrative (correlated across findings, in time order)
  * Timeline table (first seen → last seen per finding)
  * Indicators of Compromise (IPs, accounts, commands) with a recommended action each
  * MITRE ATT&CK mapping
  * Containment / Eradication / Recovery checklist (NIST SP 800-61 stages)
  * Escalation decision (who to notify, within how long)

Outputs Markdown (default), JSON, and a self-contained HTML ticket.
Standard library only. Python 3.8+.

Usage:
  python3 incident_summary.py --findings ../data/findings.json --md ../evidence/incident_summary.md --html ../evidence/incident_summary.html --json ../evidence/incident_summary.json
  python3 incident_summary.py --csv ../data/alerts_sample.csv --md out.md
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import sys
import zlib
from collections import Counter
from datetime import datetime

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_SCORE = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 1}
PRIORITY = {"CRITICAL": ("P1", "15 min", "SOC Lead + IR Manager + system owner; page on-call"),
            "HIGH": ("P2", "1 hour", "SOC Lead + system owner"),
            "MEDIUM": ("P3", "4 hours", "Shift analyst queue; owner informed at shift hand-over"),
            "LOW": ("P4", "next business day", "Log and monitor"),
            "INFO": ("P4", "none", "Log only")}

# What to do per finding type — keyed by a keyword in the title
PLAYBOOK = [
    ("Successful login after failure", "Isolate host from network; disable/reset the account; kill active sessions (`who`, `pkill -KILL -u <user>`); preserve /var/log and shell history; hunt for follow-on activity from the same source IP."),
    ("Account added to privileged group", "Remove the account from the group immediately (`gpasswd -d <user> sudo`); check /etc/sudoers.d for drop-ins; audit all commands run by the account."),
    ("New local account created", "Confirm against change management; if unapproved, lock (`usermod -L`) and expire the account; check for SSH keys planted in its home directory."),
    ("remote payload", "Hash and quarantine the dropped file (`sha256sum /tmp/x.sh`); check crontab/systemd for persistence; block the payload host; do NOT execute the file."),
    ("brute force", "Block source IP at perimeter firewall/fail2ban; enforce key-only SSH (`PasswordAuthentication no`); rate-limit port 22; check whether the IP appears in other logs."),
    ("spraying", "Block source IP; force password reset for any account that later succeeded; enable account lockout / MFA; review password policy for the sprayed user list."),
    ("failed sudo", "Interview the user's manager; check whether the account is shared; review sudoers grants for least privilege; enable sudo I/O logging."),
    ("su to root", "Verify with the user; if unexplained, treat as credential misuse; restrict `su` to the wheel group in /etc/pam.d/su."),
    ("outside business hours", "Confirm with the account owner; if unconfirmed, treat as part of the compromise chain; add a time-based alert rule for privileged logins."),
    ("enumeration", "Block source IP; ensure sshd returns identical responses for valid/invalid users (default in modern OpenSSH); add IP to watchlist."),
]


def load_findings_json(path: str) -> tuple[dict, list[dict]]:
    with open(path) as fh:
        data = json.load(fh)
    return data.get("summary", {}), data.get("findings", [])


def load_findings_csv(path: str) -> tuple[dict, list[dict]]:
    """Generic alert CSV: id,severity,title,source_ip,users,first_seen,last_seen,event_count,mitre_attack,detail"""
    findings = []
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            row["users"] = [u.strip() for u in row.get("users", "").split(";") if u.strip()]
            row["event_count"] = int(row.get("event_count") or 0)
            row["evidence_lines"] = []
            findings.append(row)
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["first_seen"]))
    return {"total_events": sum(f["event_count"] for f in findings)}, findings


# ---------- analysis ----------------------------------------------------------
def playbook_for(title: str) -> str:
    for key, action in PLAYBOOK:
        if key.lower() in title.lower():
            return action
    return "Triage manually; document decision."


def overall_severity(findings: list[dict]) -> str:
    return min((f["severity"] for f in findings), key=lambda s: SEV_ORDER.get(s, 9)) if findings else "INFO"


def risk_score(findings: list[dict]) -> int:
    """0–100. Highest finding sets the floor, breadth pushes it up."""
    if not findings:
        return 0
    top = max(SEV_SCORE.get(f["severity"], 1) for f in findings) * 6
    breadth = min(40, sum(SEV_SCORE.get(f["severity"], 1) for f in findings))
    return min(100, top + breadth)


def confidence(findings: list[dict]) -> str:
    """Correlated evidence => high confidence. Single medium alert => low."""
    n = len(findings)
    crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
    if crit and n >= 3:
        return "HIGH — multiple independent findings corroborate a single attack chain"
    if n >= 3 or crit:
        return "MEDIUM — findings are consistent but not yet corroborated by host forensics"
    return "LOW — single alert; could be misconfiguration or benign activity"


def correlate(findings: list[dict]) -> list[str]:
    """Build a plain-English attack narrative by grouping findings per source and ordering in time."""
    by_src = {}
    for f in sorted(findings, key=lambda x: x["first_seen"]):
        by_src.setdefault(f["source_ip"], []).append(f)
    story = []
    for src, fs in by_src.items():
        who = "the attacker at " + src if src != "local" else "an actor already on the host"
        steps = "; then ".join(f"{f['first_seen'][11:16]} — {f['title'].lower()} ({', '.join(f['users'][:3])})" for f in fs)
        story.append(f"From {src}: {who} — {steps}.")
    # explicit chain if brute force + success + account manipulation exist
    titles = " ".join(f["title"].lower() for f in findings)
    if "brute force" in titles and "successful login after failure" in titles:
        chain = "Chain: credential guessing → successful root login → "
        chain += "new account + sudo grant (persistence)" if "privileged group" in titles else "post-login activity"
        story.insert(0, chain + ". This is a confirmed intrusion, not a scan.")
    return story


def iocs(findings: list[dict]) -> list[dict]:
    out, seen = [], set()
    for f in findings:
        ip = f["source_ip"]
        if ip != "local" and ip not in seen:
            seen.add(ip)
            out.append({"type": "IPv4", "value": ip, "context": f["title"], "action": "Block at perimeter; add to threat-intel watchlist; search other logs"})
        for u in f["users"]:
            key = "user:" + u
            if key not in seen and f["severity"] in ("CRITICAL", "HIGH"):
                seen.add(key)
                act = "Disable + reset credential; review sessions" if f["severity"] == "CRITICAL" else "Force password reset; monitor"
                out.append({"type": "Account", "value": u, "context": f["title"], "action": act})
        d = f.get("detail", "")
        if "COMMAND=" in d or "curl" in d or "/tmp/" in d:
            cmd = d.split("last command attempted: ")[-1] if "last command attempted" in d else d.split(" ran as ")[-1].split(": ", 1)[-1]
            key = "cmd:" + cmd[:60]
            if key not in seen:
                seen.add(key)
                out.append({"type": "Command", "value": cmd[:120], "context": f["title"], "action": "Check for dropped files; hash and sandbox any payload"})
    return out


def build(summary: dict, findings: list[dict], analyst: str, source: str) -> dict:
    sev = overall_severity(findings)
    pri, sla, notify = PRIORITY[sev]
    now = datetime.now()
    first = min((f["first_seen"] for f in findings), default="")
    last = max((f["last_seen"] for f in findings), default="")
    mitre = sorted({f.get("mitre_attack", "") for f in findings if f.get("mitre_attack")})
    exec_lines = [
        f"{len(findings)} security findings were raised on the monitored host between {first[11:16] or '?'} and {last[11:16] or '?'} on {first[:10] or 'the review date'}.",
        f"Overall severity is {sev} (priority {pri}); risk score {risk_score(findings)}/100; confidence: {confidence(findings).split(' — ')[0]}.",
        f"The highest-impact finding is: {findings[0]['title']} ({findings[0]['source_ip']})." if findings else "No findings.",
    ]
    return {
        "incident_id": f"GS-INC-{now:%Y%m%d}-{zlib.crc32(source.encode()) % 1000:03d}",
        "generated": now.isoformat(sep=" ", timespec="seconds"),
        "analyst": analyst, "source": source,
        "severity": sev, "priority": pri, "sla_response": sla, "notify": notify,
        "risk_score": risk_score(findings), "confidence": confidence(findings),
        "window": {"first_seen": first, "last_seen": last},
        "events_analysed": summary.get("total_events"),
        "counts": dict(Counter(f["severity"] for f in findings)),
        "executive_summary": exec_lines,
        "attack_narrative": correlate(findings),
        "timeline": [{"time": f["first_seen"], "end": f["last_seen"], "id": f["id"], "severity": f["severity"],
                      "title": f["title"], "source": f["source_ip"], "users": f["users"], "events": f["event_count"]}
                     for f in sorted(findings, key=lambda x: x["first_seen"])],
        "iocs": iocs(findings),
        "mitre_attack": mitre,
        "actions": [{"finding": f["id"], "severity": f["severity"], "title": f["title"], "action": playbook_for(f["title"])} for f in findings],
        "nist_stages": {
            "Containment": ["Block attacker IPs at firewall", "Isolate affected host from production VLAN", "Disable compromised + rogue accounts", "Kill active attacker sessions"],
            "Eradication": ["Remove rogue account and sudo grant", "Delete dropped files (/tmp/x.sh) after hashing", "Rotate root and all local passwords; enforce SSH keys", "Patch and re-baseline sshd/sudo configuration"],
            "Recovery": ["Restore host from known-good image if root was compromised", "Re-enable monitoring; add detection rules for the observed pattern", "Monitor for 14 days for re-entry from the same IOCs"],
            "Lessons learned": ["Why was password auth for root enabled?", "Why did 37 failures not trigger fail2ban?", "Add off-hours privileged-login alert"],
        },
        "findings": findings,
    }


# ---------- renderers ---------------------------------------------------------
def to_markdown(inc: dict) -> str:
    L = [f"# SOC Incident Summary — {inc['incident_id']}", "",
         f"| Field | Value |", "|---|---|",
         f"| **Severity / Priority** | **{inc['severity']} / {inc['priority']}** |",
         f"| Risk score | {inc['risk_score']} / 100 |",
         f"| Confidence | {inc['confidence']} |",
         f"| Response SLA | {inc['sla_response']} |",
         f"| Notify | {inc['notify']} |",
         f"| Activity window | {inc['window']['first_seen']} → {inc['window']['last_seen']} |",
         f"| Events analysed | {inc['events_analysed']} |",
         f"| Findings | {', '.join(f'{k}: {v}' for k, v in inc['counts'].items())} |",
         f"| Analyst | {inc['analyst']} |",
         f"| Generated | {inc['generated']} |",
         f"| Source | `{inc['source']}` |", "",
         "## 1. Executive summary", ""] + [f"- {l}" for l in inc["executive_summary"]] + [
         "", "## 2. Attack narrative", ""] + [f"{i+1}. {l}" for i, l in enumerate(inc["attack_narrative"])] + [
         "", "## 3. Timeline", "", "| Time | End | ID | Severity | Finding | Source | Accounts | Events |", "|---|---|---|---|---|---|---|---|"]
    for t in inc["timeline"]:
        L.append(f"| {t['time'][11:]} | {t['end'][11:]} | {t['id']} | {t['severity']} | {t['title']} | `{t['source']}` | {', '.join(t['users'][:3])}{'…' if len(t['users'])>3 else ''} | {t['events']} |")
    L += ["", "## 4. Indicators of Compromise", "", "| Type | Value | Seen in | Recommended action |", "|---|---|---|---|"]
    L += [f"| {i['type']} | `{i['value']}` | {i['context']} | {i['action']} |" for i in inc["iocs"]]
    L += ["", "## 5. MITRE ATT&CK", ""] + [f"- {m}" for m in inc["mitre_attack"]]
    L += ["", "## 6. Recommended actions per finding", "", "| ID | Sev | Finding | Action |", "|---|---|---|---|"]
    L += [f"| {a['finding']} | {a['severity']} | {a['title']} | {a['action']} |" for a in inc["actions"]]
    L += ["", "## 7. Response checklist (NIST SP 800-61)", ""]
    for stage, items in inc["nist_stages"].items():
        L.append(f"**{stage}**")
        L += [f"- [ ] {i}" for i in items]
        L.append("")
    L += ["## 8. Escalation decision", "",
          f"Priority **{inc['priority']}** → notify **{inc['notify']}** within **{inc['sla_response']}**. "
          "Open a ticket, attach this summary and the raw log, and hand over with the checklist above.", ""]
    return "\n".join(L)


def to_html(inc: dict) -> str:
    e = html.escape
    col = {"CRITICAL": "#b91c1c", "HIGH": "#c2410c", "MEDIUM": "#a16207", "LOW": "#15803d", "INFO": "#334155"}
    rows = "".join(f"<tr><td>{e(t['time'][11:])}</td><td>{e(t['id'])}</td><td><span class='sev' style='background:{col[t['severity']]}'>{t['severity']}</span></td><td>{e(t['title'])}</td><td><code>{e(t['source'])}</code></td><td>{e(', '.join(t['users'][:3]))}</td><td>{t['events']}</td></tr>" for t in inc["timeline"])
    ioc = "".join(f"<tr><td>{e(i['type'])}</td><td><code>{e(i['value'])}</code></td><td>{e(i['context'])}</td><td>{e(i['action'])}</td></tr>" for i in inc["iocs"])
    acts = "".join(f"<tr><td>{e(a['finding'])}</td><td><span class='sev' style='background:{col[a['severity']]}'>{a['severity']}</span></td><td>{e(a['title'])}</td><td>{e(a['action'])}</td></tr>" for a in inc["actions"])
    nist = "".join(f"<h4>{e(k)}</h4><ul>" + "".join(f"<li><input type='checkbox'> {e(i)}</li>" for i in v) + "</ul>" for k, v in inc["nist_stages"].items())
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>{e(inc['incident_id'])}</title>
<style>body{{font:14px/1.5 system-ui,Segoe UI,Arial;margin:0;background:#0b1220;color:#e5e7eb}}main{{max-width:1000px;margin:0 auto;padding:24px}}
h1{{margin:0 0 4px;font-size:24px}}h2{{border-bottom:1px solid #334155;padding-bottom:4px;margin-top:28px;font-size:18px}}h4{{margin:12px 0 4px}}
.hdr{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:16px 0}}.card{{background:#111a2e;border:1px solid #1f2a44;border-radius:8px;padding:10px}}
.card b{{display:block;font-size:11px;text-transform:uppercase;color:#94a3b8}}.card span{{font-size:20px;font-weight:700}}
table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{border:1px solid #1f2a44;padding:6px 8px;text-align:left;vertical-align:top}}th{{background:#111a2e}}
.sev{{color:#fff;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700}}code{{background:#1e293b;padding:1px 5px;border-radius:3px}}ul{{margin:4px 0}}
.top{{background:{col[inc['severity']]};color:#fff;padding:14px 18px;border-radius:8px}}</style></head><body><main>
<div class="top"><h1>SOC Incident Summary · {e(inc['incident_id'])}</h1>Severity <b>{inc['severity']}</b> · Priority <b>{inc['priority']}</b> · respond within <b>{e(inc['sla_response'])}</b> · notify: {e(inc['notify'])}</div>
<div class="hdr"><div class="card"><b>Risk score</b><span>{inc['risk_score']}/100</span></div><div class="card"><b>Findings</b><span>{len(inc['findings'])}</span></div><div class="card"><b>Events analysed</b><span>{inc['events_analysed']}</span></div><div class="card"><b>Confidence</b><span style="font-size:14px">{e(inc['confidence'].split(' — ')[0])}</span></div></div>
<p><b>Window:</b> {e(inc['window']['first_seen'])} → {e(inc['window']['last_seen'])} &nbsp;·&nbsp; <b>Analyst:</b> {e(inc['analyst'])} &nbsp;·&nbsp; <b>Generated:</b> {e(inc['generated'])} &nbsp;·&nbsp; <b>Source:</b> <code>{e(inc['source'])}</code></p>
<h2>1. Executive summary</h2><ul>{''.join(f'<li>{e(l)}</li>' for l in inc['executive_summary'])}</ul>
<h2>2. Attack narrative</h2><ol>{''.join(f'<li>{e(l)}</li>' for l in inc['attack_narrative'])}</ol>
<h2>3. Timeline</h2><table><tr><th>Time</th><th>ID</th><th>Sev</th><th>Finding</th><th>Source</th><th>Accounts</th><th>Events</th></tr>{rows}</table>
<h2>4. Indicators of Compromise</h2><table><tr><th>Type</th><th>Value</th><th>Seen in</th><th>Action</th></tr>{ioc}</table>
<h2>5. MITRE ATT&amp;CK</h2><ul>{''.join(f'<li>{e(m)}</li>' for m in inc['mitre_attack'])}</ul>
<h2>6. Recommended actions</h2><table><tr><th>ID</th><th>Sev</th><th>Finding</th><th>Action</th></tr>{acts}</table>
<h2>7. Response checklist (NIST SP 800-61)</h2>{nist}
<h2>8. Escalation</h2><p>Priority <b>{inc['priority']}</b> → notify <b>{e(inc['notify'])}</b> within <b>{e(inc['sla_response'])}</b>.</p>
</main></body></html>"""


def main(argv=None):
    ap = argparse.ArgumentParser(description="SOC Incident Summary Generator (GraySentinel Day 1 · Project 02)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--findings", help="findings.json from auth_investigator (Project 01)")
    src.add_argument("--csv", help="generic alert CSV (id,severity,title,source_ip,users,first_seen,last_seen,event_count,mitre_attack,detail)")
    ap.add_argument("--analyst", default="Eswar Mahalingam (Blue Team, GS-STU-DSOU-2026-039A)")
    ap.add_argument("--md"); ap.add_argument("--html"); ap.add_argument("--json")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)

    summary, findings = load_findings_json(a.findings) if a.findings else load_findings_csv(a.csv)
    inc = build(summary, findings, a.analyst, a.findings or a.csv)

    if a.md:
        open(a.md, "w").write(to_markdown(inc))
    if a.html:
        open(a.html, "w").write(to_html(inc))
    if a.json:
        json.dump(inc, open(a.json, "w"), indent=2, default=str)
    if not a.quiet:
        print(f"Incident {inc['incident_id']}  severity={inc['severity']} priority={inc['priority']} risk={inc['risk_score']}/100")
        print(f"Findings: {inc['counts']}   IOCs: {len(inc['iocs'])}   ATT&CK: {len(inc['mitre_attack'])} techniques")
        print("Executive summary:")
        for l in inc["executive_summary"]:
            print("  - " + l)
        print("Narrative:")
        for l in inc["attack_narrative"]:
            print("  * " + l)
        for k, p in (("MD", a.md), ("HTML", a.html), ("JSON", a.json)):
            if p:
                print(f"{k:<5}-> {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
