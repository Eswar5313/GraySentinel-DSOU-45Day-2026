#!/usr/bin/env python3
"""
GraySentinel DSOU — Day 2, Tool B
Cryptominer Kill-Chain Reconstructor (CKR)

Consumes Tool A's macro findings JSON + synthetic EDR telemetry CSV and
reconstructs the phishing -> macro -> download -> miner -> persistence chain.
Emits a P1-P4 incident brief with timeline, IOC table, ATT&CK matrix, and a
macOS containment / persistence-removal checklist. Markdown + HTML + JSON.

stdlib-only · Python 3.8+ · synthetic lab data.

Usage:
    python3 killchain_reconstructor.py --edr edr.csv [--macro findings.json] \
        --md incident.md --html incident.html --json incident.json
"""
import argparse
import csv
import html
import json
import sys
from datetime import datetime, timezone

TOOL = "GraySentinel Cryptominer Kill-Chain Reconstructor"
VERSION = "1.0.0"

# Lockheed-Martin-style stages mapped to what we look for in telemetry
STAGE_ORDER = ["Delivery", "Execution", "Download (C2 stage-1)", "Miner launch",
               "Persistence", "Beaconing / Impact"]

ATTCK_MATRIX = [
    ("Initial Access", "T1566.001", "Spearphishing attachment (macro-enabled doc)"),
    ("Execution",      "T1204.002", "User opens document; AutoOpen fires macro"),
    ("Execution",      "T1059.002", "osascript 'do shell script' pivot"),
    ("Command & Control","T1105",   "curl pulls stage-1 binary from 198.51.100.44"),
    ("Execution",      "T1059.004", "sh chmod +x and runs /tmp/.u miner"),
    ("Impact",         "T1496",     "XMRig-style resource hijack (98% CPU)"),
    ("Persistence",    "T1543.001", "LaunchDaemon com.apple.softwareupdated.helper"),
    ("Command & Control","T1071.001","HTTPS beacon to 203.0.113.9:8443/gate"),
]


def load_edr(path):
    rows = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            rows.append({k: (v or "").strip() for k, v in row.items()})
    return rows


def classify_stage(row):
    p = row.get("process", "").lower()
    c = row.get("cmdline", "").lower()
    et = row.get("event_type", "").upper()
    if "word" in p and row.get("parent", "").lower() == "launchd":
        return "Delivery"
    if "osascript" in p:
        return "Execution"
    if "curl" in p or ("http" in c and et == "FILE_WRITE"):
        return "Download (C2 stage-1)"
    if p in (".u", "/tmp/.u") or "--pool" in c:
        return "Miner launch"
    if "launchctl" in p or "launchdaemons" in c:
        return "Persistence"
    if et in ("NETWORK", "CPU"):
        return "Beaconing / Impact"
    return "Execution"


def extract_iocs(rows):
    ips, files, procs, persist = set(), set(), set(), set()
    for r in rows:
        if r.get("remote_ip"):
            port = f":{r['remote_port']}" if r.get("remote_port") else ""
            ips.add(r["remote_ip"] + port)
        if r.get("sha256") and len(r["sha256"]) == 64:
            files.add(r["sha256"])
        if "/tmp/.u" in r.get("cmdline", "") or r.get("process") == ".u":
            procs.add("/tmp/.u")
        if ".plist" in r.get("cmdline", "").lower():
            for tok in r["cmdline"].split():
                if tok.lower().endswith(".plist"):
                    persist.add(tok)
    return {"c2_ips": sorted(ips), "file_hashes": sorted(files),
            "dropped": sorted(procs), "persistence": sorted(persist)}


def score_priority(macro, iocs):
    crit = (macro or {}).get("counts", {}).get("CRITICAL", 0)
    has_persist = bool(iocs["persistence"])
    has_c2 = bool(iocs["c2_ips"])
    if crit and has_persist and has_c2:
        return "P1", "Active compromise: RCE + running miner + reboot persistence + live C2."
    if crit and (has_persist or has_c2):
        return "P2", "Confirmed execution with either persistence or C2 established."
    if has_c2 or crit:
        return "P3", "Suspicious execution / outbound contact; contain and verify."
    return "P4", "Low-signal; monitor."


def build(edr_path, macro_path):
    rows = load_edr(edr_path)
    macro = None
    if macro_path:
        with open(macro_path) as fh:
            macro = json.load(fh)
    timeline = []
    for r in rows:
        timeline.append({
            "ts": r.get("timestamp", ""), "stage": classify_stage(r),
            "process": r.get("process", ""), "parent": r.get("parent", ""),
            "detail": (r.get("cmdline") or r.get("event_type") or "")[:120],
            "remote": (r.get("remote_ip", "") + (":" + r["remote_port"] if r.get("remote_port") else "")),
        })
    timeline.sort(key=lambda x: x["ts"])
    iocs = extract_iocs(rows)
    prio, rationale = score_priority(macro, iocs)
    host = rows[0]["host"] if rows else "unknown"
    return {
        "tool": TOOL, "version": VERSION,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": host, "priority": prio, "rationale": rationale,
        "macro_verdict": (macro or {}).get("verdict", "n/a"),
        "timeline": timeline, "iocs": iocs, "attck": ATTCK_MATRIX,
    }


CONTAIN = [
    "Isolate mac-victim-07 from the network (disable Wi-Fi + pull cable).",
    "Kill the miner:  sudo launchctl bootout system/com.apple.softwareupdated.helper",
    "Remove persistence:  sudo rm /Library/LaunchDaemons/com.apple.softwareupdated.helper.plist",
    "Delete dropped binary:  sudo rm -f /tmp/.u",
    "Block C2 at the firewall/proxy: 198.51.100.44 (stage-1), 203.0.113.9:8443 (C2).",
    "Hunt the sender: pull the phishing email + attachment; search mail flow for the same doc hash.",
    "Sweep fleet for the plist name + /tmp/.u across all macOS endpoints (same IOC set).",
    "Rotate credentials used on the host; reimage before returning to service.",
    "Preserve /var/log + EDR export as evidence before wipe.",
]


def to_md(r):
    o = [f"# Incident Brief — {r['priority']} · {r['host']}",
         f"*{r['tool']} v{r['version']} · {r['generated_utc']}*\n",
         f"**Priority {r['priority']}** — {r['rationale']}  ",
         f"**Macro verdict (Tool A):** {r['macro_verdict']}\n",
         "## Attack timeline",
         "| Time (UTC) | Stage | Process | Parent | Remote | Detail |",
         "|---|---|---|---|---|---|"]
    for t in r["timeline"]:
        o.append(f"| {t['ts']} | {t['stage']} | {t['process']} | {t['parent']} | {t['remote']} | {t['detail']} |")
    o += ["\n## Indicators of Compromise (IOCs)",
          "| Type | Value |", "|---|---|"]
    for ip in r["iocs"]["c2_ips"]:
        o.append(f"| C2 / network | `{ip}` |")
    for h in r["iocs"]["file_hashes"]:
        o.append(f"| SHA-256 | `{h}` |")
    for d in r["iocs"]["dropped"]:
        o.append(f"| Dropped file | `{d}` |")
    for p in r["iocs"]["persistence"]:
        o.append(f"| Persistence | `{p}` |")
    o += ["\n## ATT&CK coverage", "| Tactic | Technique | Note |", "|---|---|---|"]
    for tac, tid, note in r["attck"]:
        o.append(f"| {tac} | {tid} | {note} |")
    o += ["\n## Containment & eradication checklist"]
    for i, step in enumerate(CONTAIN, 1):
        o.append(f"{i}. {step}")
    return "\n".join(o) + "\n"


def to_html(r):
    md_rows = "".join(
        f"<tr><td>{html.escape(t['ts'])}</td><td>{html.escape(t['stage'])}</td>"
        f"<td>{html.escape(t['process'])}</td><td>{html.escape(t['remote'])}</td>"
        f"<td>{html.escape(t['detail'])}</td></tr>" for t in r["timeline"])
    steps = "".join(f"<li>{html.escape(s)}</li>" for s in CONTAIN)
    return f"""<!doctype html><meta charset=utf-8>
<title>Incident Brief {html.escape(r['priority'])}</title>
<style>body{{font-family:system-ui,Segoe UI,Arial;background:#0B1E3F;color:#F4F1E8;margin:0;padding:28px}}
h1{{color:#E8B04B;margin:0 0 4px}} .sub{{color:#9fb3d1;font-size:13px}}
.badge{{display:inline-block;background:#E8B04B;color:#0B1E3F;font-weight:700;padding:3px 10px;border-radius:6px}}
table{{border-collapse:collapse;width:100%;margin:14px 0;font-size:13px}}
td,th{{border:1px solid #24406e;padding:6px 8px;text-align:left}} th{{background:#16305c;color:#E8B04B}}
li{{margin:4px 0}}</style>
<h1>Incident Brief — <span class=badge>{html.escape(r['priority'])}</span> {html.escape(r['host'])}</h1>
<div class=sub>{html.escape(r['tool'])} v{r['version']} · {html.escape(r['generated_utc'])} · macro verdict {html.escape(r['macro_verdict'])}</div>
<p>{html.escape(r['rationale'])}</p>
<h2 style="color:#E8B04B">Timeline</h2>
<table><tr><th>Time</th><th>Stage</th><th>Process</th><th>Remote</th><th>Detail</th></tr>{md_rows}</table>
<h2 style="color:#E8B04B">Containment</h2><ol>{steps}</ol>"""


def main(argv=None):
    ap = argparse.ArgumentParser(description="Reconstruct cryptominer kill-chain (defensive).")
    ap.add_argument("--edr", required=True)
    ap.add_argument("--macro", help="Tool A findings.json")
    ap.add_argument("--md")
    ap.add_argument("--html")
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    r = build(a.edr, a.macro)
    if a.md:
        open(a.md, "w").write(to_md(r))
    if a.html:
        open(a.html, "w").write(to_html(r))
    if a.json:
        json.dump(r, open(a.json, "w"), indent=2)
    if not any([a.md, a.html, a.json]):
        print(to_md(r))
    else:
        print(f"[{r['priority']}] {r['host']} · {len(r['timeline'])} events · "
              f"{len(r['iocs']['c2_ips'])} C2 IPs · verdict {r['macro_verdict']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
