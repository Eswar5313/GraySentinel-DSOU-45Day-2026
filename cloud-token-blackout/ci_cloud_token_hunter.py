#!/usr/bin/env python3
"""
ci_cloud_token_hunter.py — GraySentinel RIU intel war-room "Cloud Token Blackout".

Defensive / intel tool. Reads a CloudTrail-style CSV (+ optional GitHub Actions audit CSV)
and surfaces CI/CD cloud-credential abuse as evidence-backed IoCs mapped to the kill chain:

  runner compromise -> credential access -> cloud auth -> privilege escalation -> collection -> exfil

It only reads logs. Flags are evidence-backed; each is labelled IoC vs REVIEW so analysts can
separate valid indicators from benign baseline. Python 3.8+, standard library only.

usage: python3 ci_cloud_token_hunter.py cloudtrail_SYNTHETIC.csv [gh_audit_SYNTHETIC.csv] [--json out.json]
"""
import argparse, csv, ipaddress, json, sys
from datetime import datetime

PRIVESC = {"CreateAccessKey", "AttachUserPolicy", "PutUserPolicy", "AttachRolePolicy",
           "CreatePolicyVersion", "CreateUser", "CreateLoginProfile", "UpdateAssumeRolePolicy"}
SECRETS = {"GetSecretValue", "GetParameter", "GetParameters", "Decrypt", "BatchGetSecretValue"}
COLLECTION = {"GetObject", "ListBuckets", "ListObjects", "GetBucketPolicy", "CopyObject"}
EXFIL_PUBLIC = {"PutBucketPolicy", "PutBucketAcl", "PutObjectAcl", "DeletePublicAccessBlock"}
INTERNAL_UA = ("actions", "aws-cli/deploy")
INTERNAL_NETS = [ipaddress.ip_network("140.82.112.0/20"), ipaddress.ip_network("10.0.0.0/8")]


def ts(s): return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")


def ci_source(ip):
    try:
        return any(ipaddress.ip_address(ip) in n for n in INTERNAL_NETS)
    except ValueError:
        return False


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


def analyze(ct, gh):
    # baseline: which (principal, key) pairs + source IPs are normal
    key_ips = {}
    for e in ct:
        key_ips.setdefault(e.get("accessKeyId", ""), set()).add(e["sourceIP"])

    findings, iocs = [], {"principals": set(), "access_keys": set(), "source_ips": set(),
                          "buckets": set(), "new_keys": set(), "public_buckets": set()}

    def add(kind, verdict, stage, e, why):
        findings.append({"kind": kind, "verdict": verdict, "stage": stage, "ts": e["ts"],
                         "principal": e.get("principal"), "action": e.get("eventName") or e.get("action"),
                         "sourceIP": e["sourceIP"], "why": why})

    long_key_abuse = False
    for e in ct:
        name, ua, ip = e["eventName"], e.get("userAgent", ""), e["sourceIP"]
        key = e.get("accessKeyId", "")
        external = not ci_source(ip)
        # Long-lived IAM user key used from a brand-new external IP with a generic SDK UA
        if (e["principalType"] == "IAMUser" and key and external
                and not any(t in ua for t in INTERNAL_UA)):
            if name == "GetCallerIdentity" or (len(key_ips.get(key, set())) >= 1 and "140.82" not in ip):
                if not long_key_abuse:
                    add("long-lived key used off a runner", "IoC", "credential access / cloud auth", e,
                        f"IAM user key {key} from {ip} (hosting ASN), non-CI user-agent, no MFA")
                    long_key_abuse = True
                iocs["access_keys"].add(key); iocs["source_ips"].add(ip); iocs["principals"].add(e["principal"])
        if name in PRIVESC and e["result"] == "Success":
            add("IAM privilege escalation", "IoC", "privilege escalation", e, f"{name} on {e.get('resource')}")
            if name == "CreateAccessKey":
                iocs["new_keys"].add((e.get("detail") or "new access key"))
        if name in SECRETS and e["result"] == "Success" and external:
            add("secret retrieval", "IoC", "credential access", e, f"{name} {e.get('resource')}")
        if name in COLLECTION and external and "never accessed" in (e.get("detail") or ""):
            add("unusual object-storage access", "IoC", "collection", e, f"{name} {e.get('resource')}")
            if e.get("resource", "").startswith("arn:aws:s3"):
                iocs["buckets"].add(e["resource"])
        if name in EXFIL_PUBLIC and e["result"] == "Success":
            add("storage made public", "IoC", "exfiltration / persistence", e,
                f"{name} {e.get('resource')} — {e.get('detail')}")
            iocs["public_buckets"].add(e.get("resource"))
        if name == "CreateUser" and e["result"] == "AccessDenied":
            add("backdoor-user attempt (blocked)", "REVIEW", "persistence", e, "CreateUser AccessDenied")

    gh_findings = []
    for e in (gh or []):
        a = e["action"]
        if a == "workflow.edited" and ("curl" in (e.get("detail") or "") or "env" in (e.get("detail") or "")):
            gh_findings.append({"kind": "CI workflow modified to leak env", "verdict": "IoC",
                                "stage": "runner compromise", "ts": e["ts"], "actor": e["actor"],
                                "sourceIP": e["sourceIP"], "why": e.get("detail")})
            iocs["source_ips"].add(e["sourceIP"])
        if "contractor" in e.get("detail", "") or e["actor"].startswith("ex."):
            gh_findings.append({"kind": "stale developer identity active", "verdict": "IoC",
                                "stage": "initial access", "ts": e["ts"], "actor": e["actor"],
                                "sourceIP": e["sourceIP"], "why": "terminated identity still referenced in automation"})
        if a == "secret.retrieved":
            gh_findings.append({"kind": "CI secret exposed to step", "verdict": "IoC",
                                "stage": "credential access", "ts": e["ts"], "actor": e["actor"],
                                "sourceIP": e["sourceIP"], "why": e.get("detail")})

    stages_hit = sorted({f["stage"] for f in findings + gh_findings})
    classification = ("Supply-chain abuse + cloud takeover" if any("public" in f["kind"] for f in findings)
                      and gh_findings else "CI/CD credential theft")
    return {"findings": findings, "gh_findings": gh_findings,
            "iocs": {k: sorted(v) for k, v in iocs.items()},
            "kill_chain_stages": stages_hit, "classification": classification}


def render(r):
    out = ["=" * 78, "GraySentinel RIU · Cloud Token Blackout — CI/CD credential-abuse intel", "=" * 78,
           f"Classification: {r['classification']}",
           "Kill-chain stages observed: " + " -> ".join(r["kill_chain_stages"]), "", "CLOUD FINDINGS:"]
    for f in r["findings"]:
        out.append(f"  [{f['verdict']:<6}] {f['stage']:<28} {f['ts']}  {f['action']:<22} {f['sourceIP']}  — {f['why']}")
    out.append("\nCI/CD (GitHub) FINDINGS:")
    for f in r["gh_findings"]:
        out.append(f"  [{f['verdict']:<6}] {f['stage']:<20} {f['ts']}  {f['actor']:<14} {f['sourceIP']}  — {f['why']}")
    out.append("\nIoC SUMMARY:")
    for k, v in r["iocs"].items():
        if v:
            out.append(f"  {k:<14} {', '.join(v)}")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="GraySentinel RIU Cloud Token Blackout analyzer")
    ap.add_argument("cloudtrail"); ap.add_argument("gh_audit", nargs="?"); ap.add_argument("--json")
    a = ap.parse_args(argv)
    try:
        ct = load(a.cloudtrail, ["ts", "eventName", "sourceIP"])
        gh = load(a.gh_audit, ["ts", "action"]) if a.gh_audit else []
    except OSError as e:
        print(f"error: {e}", file=sys.stderr); return 2
    r = analyze(ct, gh)
    print(render(r))
    if a.json:
        with open(a.json, "w") as f:
            json.dump(r, f, indent=2, default=str)
    return 1 if r["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
