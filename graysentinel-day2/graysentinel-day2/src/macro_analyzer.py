#!/usr/bin/env python3
"""
GraySentinel DSOU — Day 2, Tool A
Macro Static Analyzer (MSA)

Statically triages EXTRACTED VBA source (olevba-style .bas dump) and raises
ranked, ATT&CK-mapped findings. Defensive-only: it reads source text and
pattern-matches known malicious constructs. It never executes anything.

stdlib-only · Python 3.8+ · synthetic lab data.
Exit code 2 if any CRITICAL finding is raised (CI-gate friendly).

Usage:
    python3 macro_analyzer.py <extracted.bas> [--json out.json] [--md out.md]
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone

TOOL = "GraySentinel Macro Static Analyzer"
VERSION = "1.0.0"

# rule = (id, severity, attck, title, compiled_regex, why)
RULES = [
    ("MSA-01", "HIGH", "T1137.001", "Auto-execution trigger (AutoOpen/Document_Open)",
     re.compile(r"\b(AutoOpen|Document_Open|AutoExec|Workbook_Open|Auto_Open)\b", re.I),
     "Macro runs the moment the document opens — no user click needed."),
    ("MSA-02", "CRITICAL", "T1059.001", "PowerShell encoded-command execution",
     re.compile(r"powershell.{0,40}(-enc|-encodedcommand|-e\b|-w\s+hidden)", re.I),
     "Hidden/encoded PowerShell is a classic in-memory execution cradle."),
    ("MSA-03", "HIGH", "T1059.002", "AppleScript / osascript shell-out (macOS)",
     re.compile(r"osascript.{0,60}do\s+shell\s+script", re.I),
     "VBA pivoting to osascript to run macOS shell commands."),
    ("MSA-04", "CRITICAL", "T1105", "Remote download cradle",
     re.compile(r"(curl|wget|urldownloadtofile|xmlhttp|winhttp|msxml2).{0,80}https?://", re.I),
     "Fetches a second-stage payload from a remote host."),
    ("MSA-05", "HIGH", "T1059.005", "Living-off-VBA runner (Shell/WScript.Shell)",
     re.compile(r"(WScript\.Shell|CreateObject\(\s*[\"']?wscript|\bShell\s+[\"'])", re.I),
     "Spawns arbitrary processes from inside the macro."),
    ("MSA-06", "MEDIUM", "T1140", "Base64 / obfuscated blob",
     re.compile(r"[\"'][A-Za-z0-9+/]{40,}={0,2}[\"']"),
     "Long base64 literal — commonly a packed command or payload."),
    ("MSA-07", "CRITICAL", "T1543.001", "macOS LaunchDaemon/Agent persistence",
     re.compile(r"/Library/Launch(Daemons|Agents)/.+\.plist", re.I),
     "Writes a plist to survive reboot — persistence."),
    ("MSA-08", "MEDIUM", "T1036.005", "Apple-service masquerade name",
     re.compile(r"com\.apple\.[a-z.]*\b", re.I),
     "Names itself after a legit Apple service to blend in."),
    ("MSA-09", "MEDIUM", "T1071.001", "Hard-coded C2 / beacon endpoint",
     re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}(:\d+)?/\w+", re.I),
     "Raw IP URL with a path — beacon/gate to an operator server."),
    ("MSA-10", "LOW", "T1564.003", "Hidden-window execution flag",
     re.compile(r"\bvbHide\b|,\s*0\s*,\s*(False|True)\s*\)", re.I),
     "Runs children with no visible window to avoid the user noticing."),
]

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def analyze(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    findings = []
    for rid, sev, attck, title, rx, why in RULES:
        for i, line in enumerate(lines, 1):
            if rx.search(line):
                findings.append({
                    "rule_id": rid, "severity": sev, "attck": attck,
                    "title": title, "line": i, "evidence": line.strip()[:140],
                    "why": why,
                })
    findings.sort(key=lambda f: (SEV_RANK[f["severity"]], f["line"]))
    counts = {s: 0 for s in SEV_RANK}
    for f in findings:
        counts[f["severity"]] += 1
    return {
        "tool": TOOL, "version": VERSION,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_file": path, "lines_scanned": len(lines),
        "counts": counts, "total_findings": len(findings),
        "verdict": "MALICIOUS" if counts["CRITICAL"] else ("SUSPICIOUS" if findings else "CLEAN"),
        "findings": findings,
    }


def to_markdown(r):
    out = []
    out.append(f"# {r['tool']} — Findings\n")
    out.append(f"- **Source:** `{r['source_file']}`  ")
    out.append(f"- **Scanned:** {r['generated_utc']} · {r['lines_scanned']} lines  ")
    out.append(f"- **Verdict:** **{r['verdict']}**  ")
    c = r["counts"]
    out.append(f"- **Severity mix:** 🔴 {c['CRITICAL']} · 🟠 {c['HIGH']} · 🟡 {c['MEDIUM']} · 🔵 {c['LOW']}\n")
    out.append("| # | Sev | Rule | ATT&CK | Line | Finding | Evidence |")
    out.append("|---|-----|------|--------|------|---------|----------|")
    for n, f in enumerate(r["findings"], 1):
        out.append(f"| {n} | {f['severity']} | {f['rule_id']} | {f['attck']} | {f['line']} | {f['title']} | `{f['evidence']}` |")
    out.append("\n## Why each fired\n")
    for f in r["findings"]:
        out.append(f"- **{f['rule_id']} ({f['attck']})** — {f['why']}")
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Static VBA macro triage (defensive).")
    ap.add_argument("source", help="extracted .bas / VBA text dump")
    ap.add_argument("--json", help="write findings JSON here")
    ap.add_argument("--md", help="write findings Markdown here")
    a = ap.parse_args(argv)
    r = analyze(a.source)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(r, fh, indent=2)
    if a.md:
        with open(a.md, "w") as fh:
            fh.write(to_markdown(r))
    if not a.json and not a.md:
        print(json.dumps(r, indent=2))
    else:
        print(f"[{r['verdict']}] {r['total_findings']} findings "
              f"(CRIT {r['counts']['CRITICAL']}/HIGH {r['counts']['HIGH']}) -> {a.source}")
    return 2 if r["counts"]["CRITICAL"] else 0


if __name__ == "__main__":
    sys.exit(main())
