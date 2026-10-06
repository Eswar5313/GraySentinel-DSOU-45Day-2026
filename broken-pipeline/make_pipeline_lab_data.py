#!/usr/bin/env python3
"""
make_pipeline_lab_data.py — SYNTHETIC evidence for GraySentinel SSOU war-room
"Broken Pipeline" (CI/CD → registry → Kubernetes supply-chain).

LAB ONLY. Declared-synthetic: hosts *.corp.internal, RFC-5737 / RFC-1918 IPs, example digests.
NO exploit code, NO payloads, NO real credentials. Rows model GitLab/registry/Kubernetes/cloud
AUDIT fields only — this is blue-team telemetry used to detect the theoretical chain.

Outputs:
  pipeline_audit_SYNTHETIC.csv   unified audit events (source, action, actor, object, detail)
  pipeline_context_SYNTHETIC.json baseline: release windows, trusted digests, RBAC, identities
"""
import csv, json, os
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
UTC = timezone.utc
FIELDS = ["ts", "source", "action", "actor", "sourceIP", "object", "image", "digest",
          "namespace", "serviceaccount", "verb", "result", "detail"]

STALE_DEV = "ex.developer"           # terminated, still referenced in automation
RUNNER_IP = "10.30.6.21"             # normal self-hosted runner
ODD_IP = "10.30.44.90"               # unusual internal host
TRUSTED_DIGEST = "sha256:aaaa1111trusted"
BAD_DIGEST = "sha256:beef9999untrusted"
IMAGE = "registry.corp.internal/payments/api"


def iso(dt): return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def e(rows, dt, source, action, **kw):
    r = {k: "" for k in FIELDS}
    r.update(ts=iso(dt), source=source, action=action)
    r.update({k: str(v) for k, v in kw.items()}); rows.append(r)


def build():
    rows = []
    base = datetime(2026, 9, 6, 5, 0, tzinfo=UTC)   # ~10:30 IST business hours
    # 30-day baseline: normal releases in-window, trusted digest, correct runner
    for d in range(30):
        t = base + timedelta(days=d)
        if t.weekday() < 5:
            e(rows, t, "gitlab", "pipeline.run", actor="dev.anita", sourceIP=RUNNER_IP,
              object="payments/api", result="success", detail="MR approved; release window")
            e(rows, t + timedelta(minutes=8), "registry", "image.push", actor="ci-runner",
              sourceIP=RUNNER_IP, image=IMAGE, digest=TRUSTED_DIGEST, result="success",
              detail="signed by cosign; provenance attested")
            e(rows, t + timedelta(minutes=12), "k8s", "deployment.update", actor="ci-deployer",
              namespace="payments", serviceaccount="deployer", image=IMAGE, digest=TRUSTED_DIGEST,
              verb="patch", result="allowed", detail="in-window deploy")
    # --- Theoretical attack chain (06 Oct 2026, off-hours ~02:50 IST = 21:20Z prev day) ---
    t = datetime(2026, 10, 5, 21, 20, tzinfo=UTC)
    e(rows, t, "gitlab", "auth.success", actor=STALE_DEV, sourceIP=ODD_IP, result="success",
      detail="terminated developer account still active in automation (Mission: stale identity)")
    e(rows, t + timedelta(minutes=2), "gitlab", "pipeline.run", actor=STALE_DEV, sourceIP=ODD_IP,
      object="payments/api", result="success", detail="off-hours run outside release window")
    # malicious-but-trusted-looking image push: same tag, NEW digest, unsigned
    e(rows, t + timedelta(minutes=6), "registry", "image.push", actor="ci-runner", sourceIP=ODD_IP,
      image=IMAGE, digest=BAD_DIGEST, result="success",
      detail="tag :latest reused; NO cosign signature; NO provenance attestation")
    # deployment pulls the new digest
    e(rows, t + timedelta(minutes=10), "k8s", "deployment.update", actor="ci-deployer",
      namespace="payments", serviceaccount="deployer", image=IMAGE, digest=BAD_DIGEST,
      verb="patch", result="allowed", detail="off-hours deploy; digest changed from trusted baseline")
    # over-privileged service account token used against the API server
    e(rows, t + timedelta(minutes=12), "k8s", "serviceaccount.token.use", actor="system:serviceaccount:payments:deployer",
      namespace="payments", serviceaccount="deployer", verb="create", object="secrets",
      result="allowed", detail="SA has cluster-admin via rolebinding (excessive RBAC)")
    e(rows, t + timedelta(minutes=13), "k8s", "rbac.read", actor="system:serviceaccount:payments:deployer",
      namespace="payments", serviceaccount="deployer", verb="list", object="secrets/*",
      result="allowed", detail="enumerated secrets cluster-wide")
    e(rows, t + timedelta(minutes=14), "k8s", "pod.create", actor="system:serviceaccount:payments:deployer",
      namespace="kube-system", serviceaccount="deployer", verb="create", object="pod/host-mount",
      result="allowed", detail="pod requests hostPath mount + SA token (persistence vector)")
    # cloud access from the workload identity
    e(rows, t + timedelta(minutes=18), "cloud", "sts.AssumeRole", actor="irsa:payments-deployer",
      sourceIP="203.0.113.90", result="success", object="role/payments-deploy",
      detail="workload identity used from pod to reach cloud; first-seen external egress")
    e(rows, t + timedelta(minutes=20), "cloud", "secretsmanager.GetSecretValue",
      actor="irsa:payments-deployer", sourceIP="203.0.113.90", object="prod/payments/db",
      result="success", detail="cloud secret read")
    # runtime telemetry: image deleted to hide, but audit log remains
    e(rows, t + timedelta(minutes=30), "registry", "image.delete", actor=STALE_DEV, sourceIP=ODD_IP,
      image=IMAGE, digest=BAD_DIGEST, result="success", detail="attacker deletes image; digest stays in k8s + audit")
    e(rows, t + timedelta(minutes=31), "edr", "scan", result="clean", detail="container AV: 0 detections (trusted pipeline)")
    rows.sort(key=lambda r: r["ts"]); return rows


CONTEXT = {
    "_note": "SYNTHETIC context for Broken Pipeline lab (*.corp.internal, RFC-5737/1918). LAB ONLY.",
    "release_window_utc": {"start_hour": 4, "end_hour": 16, "weekdays_only": True},
    "trusted": {"image": IMAGE, "digest": TRUSTED_DIGEST, "runner_ip": RUNNER_IP,
                "signing": "cosign required", "provenance": "SLSA attestation required"},
    "identities": {STALE_DEV: {"status": "terminated 2026-09-20", "still_in_automation": True},
                   "dev.anita": {"status": "active", "team": "payments"}},
    "rbac": {"payments:deployer": {"intended": "patch deployments in 'payments' ns",
                                   "actual": "cluster-admin via ClusterRoleBinding (EXCESSIVE)"}},
    "retention": "Kubernetes audit logs retained 7 days",
}


def main():
    with open(os.path.join(HERE, "pipeline_audit_SYNTHETIC.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS); w.writeheader(); w.writerows(build())
    with open(os.path.join(HERE, "pipeline_context_SYNTHETIC.json"), "w") as f:
        json.dump(CONTEXT, f, indent=2)
    print("wrote pipeline_audit_SYNTHETIC.csv + pipeline_context_SYNTHETIC.json")


if __name__ == "__main__":
    main()
