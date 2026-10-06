#!/usr/bin/env python3
"""
pipeline_chain_analyzer.py — GraySentinel SSOU war-room "Broken Pipeline".

BLUE-TEAM analyzer (detection only — no exploit code). Reads a unified CI/CD + registry +
Kubernetes + cloud AUDIT CSV and reconstructs the theoretical supply-chain chain as
evidence-backed detections mapped to the kill chain:

  developer identity -> CI/CD abuse -> malicious image -> registry -> kubernetes -> cloud access

It only reads audit logs. Python 3.8+, standard library only.

usage: python3 pipeline_chain_analyzer.py pipeline_audit_SYNTHETIC.csv pipeline_context_SYNTHETIC.json [--json out.json]
"""
import argparse, csv, json, sys
from datetime import datetime


def ts(s): return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")


def load(path, required):
    out = []
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            if all(k in r for k in required):
                try:
                    r["_t"] = ts(r["ts"])
                except ValueError:
                    continue
                out.append(r)
    out.sort(key=lambda r: r["_t"]); return out


def in_window(dt, w):
    if w.get("weekdays_only") and dt.weekday() >= 5:
        return False
    return w["start_hour"] <= dt.hour < w["end_hour"]


def analyze(events, ctx):
    trusted = ctx.get("trusted", {})
    window = ctx.get("release_window_utc", {})
    ids = ctx.get("identities", {})
    rbac = ctx.get("rbac", {})
    findings = []

    def add(stage, kind, verdict, e, why):
        findings.append({"stage": stage, "kind": kind, "verdict": verdict, "ts": e["ts"],
                         "actor": e.get("actor"), "source": e["source"], "why": why})

    for e in events:
        src, act = e["source"], e["action"]
        # H1 — stale / terminated identity active
        if e.get("actor") in ids and ids[e["actor"]].get("still_in_automation") and act in ("auth.success", "pipeline.run"):
            add("developer identity", "stale/terminated identity active", "IoC", e,
                f"{e['actor']} ({ids[e['actor']].get('status')}) still runs pipelines")
        # CI run outside the release window
        if act == "pipeline.run" and not in_window(e["_t"], window):
            add("CI/CD abuse", "off-hours pipeline run", "IoC", e, "run outside release window")
        # H2 — image push with new/untrusted digest or unsigned
        if src == "registry" and act == "image.push":
            if e.get("digest") and e["digest"] != trusted.get("digest"):
                add("malicious image / registry", "unexpected image digest", "IoC", e,
                    f"digest {e['digest']} != trusted {trusted.get('digest')}")
            if "NO cosign" in (e.get("detail") or "") or "NO provenance" in (e.get("detail") or ""):
                add("malicious image / registry", "unsigned / no provenance", "IoC", e, e["detail"])
        # deployment pulling a non-trusted digest
        if src == "k8s" and act == "deployment.update" and e.get("digest") and e["digest"] != trusted.get("digest"):
            add("kubernetes", "deploy of non-trusted digest", "IoC", e,
                "deployment pulled a digest that differs from the signed baseline")
        # H3 — excessive RBAC / service-account abuse
        if src == "k8s" and act in ("serviceaccount.token.use", "rbac.read", "pod.create"):
            key = f"{e.get('namespace')}:{e.get('serviceaccount')}"
            excessive = "EXCESSIVE" in (rbac.get(key, {}).get("actual", "")).upper() or "cluster-admin" in (e.get("detail") or "")
            if excessive:
                add("kubernetes", "excessive RBAC used", "IoC", e,
                    f"{key}: {e.get('verb')} {e.get('object')} — {e.get('detail')}")
            if e.get("namespace") == "kube-system" and act == "pod.create":
                add("kubernetes", "workload created in kube-system", "IoC", e, e.get("detail"))
        # cloud access from workload identity
        if src == "cloud" and act in ("sts.AssumeRole", "secretsmanager.GetSecretValue"):
            add("cloud access", "workload identity reached cloud", "IoC", e,
                f"{act} {e.get('object')} from {e.get('sourceIP')} — {e.get('detail')}")
        # anti-forensics
        if src == "registry" and act == "image.delete":
            add("defense evasion", "image deleted (audit trail remains)", "REVIEW", e,
                "image removed, but digest persists in k8s + audit logs")

    stages = []
    for s in ("developer identity", "CI/CD abuse", "malicious image / registry", "kubernetes", "cloud access"):
        if any(f["stage"] == s for f in findings):
            stages.append(s)
    full_chain = len(stages) >= 4
    return {"findings": findings, "kill_chain_stages": stages, "full_chain_observed": full_chain,
            "dfir_sources": sorted({f["source"] for f in findings})}


def render(r):
    out = ["=" * 78, "GraySentinel SSOU · Broken Pipeline — CI/CD → K8s supply-chain (blue-team view)",
           "=" * 78, f"Full chain observed: {r['full_chain_observed']}",
           "Kill-chain stages: " + " -> ".join(r["kill_chain_stages"]),
           "DFIR sources with evidence: " + ", ".join(r["dfir_sources"]), "", "FINDINGS:"]
    for f in r["findings"]:
        out.append(f"  [{f['verdict']:<6}] {f['stage']:<26} {f['ts']}  {f['kind']:<34} — {f['why']}")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="GraySentinel SSOU Broken Pipeline blue-team analyzer")
    ap.add_argument("audit"); ap.add_argument("context", nargs="?"); ap.add_argument("--json")
    a = ap.parse_args(argv)
    try:
        events = load(a.audit, ["ts", "source", "action"])
        ctx = json.load(open(a.context)) if a.context else {}
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr); return 2
    r = analyze(events, ctx)
    print(render(r))
    if a.json:
        with open(a.json, "w") as f:
            json.dump(r, f, indent=2, default=str)
    return 1 if r["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
