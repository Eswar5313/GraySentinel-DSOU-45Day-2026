#!/usr/bin/env python3
"""
GraySentinel DSOU - Day 1 | Blue-Team Threat Hunter
Workflow-Orchestration RCE (Orkes Conductor CVE-2026-58138)

PURPOSE (defensive only): parse mock API-gateway and process-creation logs to
hunt for evidence of exploitation of the pre-auth GraalVM evaluator RCE.
It DETECTS attacks; it does NOT perform any.

Detection logic:
  1) API layer  - workflow definitions submitted with evaluator task types
                  (INLINE/LAMBDA/DO_WHILE/SWITCH) carrying OS-command patterns.
  2) Host layer - the Conductor JVM (java) spawning a shell / network binary,
                  the behavioural chokepoint of the exploit.
  3) Correlate  - external submitter + subsequent process spawn = high confidence.

Usage:
  python3 day1_conductor_rce_hunt.py \
      --access evidence/mock_conductor_access.log \
      --procs  evidence/mock_process_creation.log
"""
import argparse
import re
import sys
from pathlib import Path

EVAL_TYPES = ("INLINE", "LAMBDA", "DO_WHILE", "SWITCH")
CMD_PATTERNS = ("Runtime", "ProcessBuilder", "exec(", "/bin/sh", "curl", "wget",
                "bash", "subprocess", "getRuntime")
SUSPICIOUS_CHILDREN = ("/sh", "/bash", "/curl", "/wget", "/python", "/python3",
                       "/nc", "/ncat", "/perl")
PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "127.")


def is_external(ip: str) -> bool:
    return not any(ip.startswith(p) for p in PRIVATE_PREFIXES)


def parse_pipe(path: Path):
    rows = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rows.append([c.strip() for c in line.split("|")])
    return rows


def hunt_api(rows):
    findings = []
    for r in rows:
        if len(r) < 7:
            continue
        ts, ip, method, path, status, ua, body = r[:7]
        if any(t in body for t in EVAL_TYPES) and any(p in body for p in CMD_PATTERNS):
            findings.append({
                "ts": ts, "ip": ip, "path": path, "status": status, "ua": ua,
                "external": is_external(ip),
                "why": "workflow definition with evaluator task + OS-command pattern",
            })
    return findings


def hunt_procs(rows):
    findings = []
    for r in rows:
        if len(r) < 7:
            continue
        ts, host, pimg, pcmd, img, cmd, user = r[:7]
        if "java" in pimg and any(img.endswith(c) for c in SUSPICIOUS_CHILDREN):
            sev = "CRITICAL"
            note = "Conductor JVM spawned shell/network binary"
            if "169.254.169.254" in cmd:
                note += " -> cloud metadata/credential theft attempt"
            findings.append({"ts": ts, "host": host, "child": img,
                             "cmd": cmd, "user": user, "sev": sev, "why": note})
    return findings


def main():
    ap = argparse.ArgumentParser(description="Day 1 - Conductor RCE defensive hunter")
    base = Path(__file__).resolve().parent.parent
    ap.add_argument("--access", default=str(base / "evidence/mock_conductor_access.log"))
    ap.add_argument("--procs", default=str(base / "evidence/mock_process_creation.log"))
    args = ap.parse_args()

    access_p, procs_p = Path(args.access), Path(args.procs)
    if not access_p.exists() or not procs_p.exists():
        print("[!] input log(s) not found", file=sys.stderr)
        sys.exit(2)

    api = hunt_api(parse_pipe(access_p))
    procs = hunt_procs(parse_pipe(procs_p))

    print("=" * 68)
    print(" GraySentinel DSOU | Day 1 - Conductor RCE Hunt (CVE-2026-58138)")
    print("=" * 68)

    print(f"\n[MISSION] API-layer exploitation attempts: {len(api)} found")
    for f in api:
        tag = "EXTERNAL" if f["external"] else "internal"
        print(f"  [!] {f['ts']} src={f['ip']} ({tag}) {f['path']} status={f['status']}")
        print(f"      UA={f['ua']} :: {f['why']}")

    print(f"\n[MISSION] Host-layer suspicious process spawns: {len(procs)} found")
    for f in procs:
        print(f"  [{f['sev']}] {f['ts']} {f['host']} child={f['child']} user={f['user']}")
        print(f"      cmd: {f['cmd']}")
        print(f"      -> {f['why']}")

    ext_ips = {f["ip"] for f in api if f["external"]}
    correlated = bool(ext_ips) and bool(procs)
    print("\n[CORRELATION]")
    if correlated:
        print("  [CONFIRMED] External evaluator payload submission + subsequent JVM")
        print(f"             process spawn. Attacker IP(s): {', '.join(sorted(ext_ips))}")
        print("  VERDICT: Pre-patch exploitation likely. Answer to 'close incident?' = NOT YET.")
        meta = any("169.254.169.254" in f["cmd"] for f in procs)
        note = "cloud role FIRST - metadata endpoint access observed" if meta else "cloud role first"
        print("  NEXT: isolate pod, preserve, rotate ALL engine-reachable credentials")
        print(f"        ({note}).")
    else:
        print("  No end-to-end exploitation chain confirmed in provided logs.")

    print("\nMITRE ATT&CK: T1190, T1059, T1552.005")
    print("Done.")


if __name__ == "__main__":
    main()
