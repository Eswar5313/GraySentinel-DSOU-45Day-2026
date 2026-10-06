🟡 Intel War Room submission — Cloud Token Blackout (CI/CD cloud-credential abuse) · Eswar (Cand. 13)

🎯 CTI Lead's question — app or the identity that builds/deploys it? THE IDENTITY. A long-lived AWS key on a self-hosted runner was used from a hosting IP → AdministratorAccess → read PII + DB-backup buckets → pulled prod/db/master → made a bucket public. Valid creds, no app exploit.

📄 1) Exposure card: OIDC (short-lived, repo-scoped, minutes) vs long-lived AKIA keys (never expire, full policy, work anywhere = one leak is standing access). Runners are prime targets: they hold deploy-grade perms, run arbitrary code, sit between source + prod. 7-day CloudTrail = blast radius may be unrecoverable.

🧠 2) TTP map: T1078.004 (cloud valid accounts) → T1552.001 (creds in files) → T1555.006 (cloud secrets) → T1098.001 (new access key + AttachUserPolicy) → T1530 (S3 data) → T1537 (public-ACL exfil). Resembles: initial access (stale identity) → credential theft → cloud persistence → data theft → supply-chain abuse.

🛡️ 3) OSINT methodology (OSINT only): GitHub key/`.env`/workflow search, Google dorks (`filetype:yml aws-access-key`, exposed .tfstate), public S3/Blob + `*:*` IAM checks, Linux runner forensics (bash_history, env, ~/.aws, auth.log). VALID IoC only when it ties to YOUR account ID/ARN/domain — AWS sample keys + honeytokens = false positives.

🔐 4) IoCs: IAM user runner-deploy (should be OIDC role only), source 203.0.113.77 (hosting), key AKIAEXAMPLE7RUNNER01, attacker-made key AKIAEXAMPLEN3WKEY99, AttachUserPolicy→AdministratorAccess, GetObject on example-prod-pii + example-db-backups, public bucket example-prod-pii, deploy.yml tampered by ex.contractor (terminated). Sigma correlation pack (4 rules) fires CRITICAL on ≥2 hits/principal in 10 min.
Diamond: Adversary = access broker ("developer infrastructure") · Capability = stolen token+privesc+collection+public-ACL · Infra = 203.0.113.77 / cdn-sync.example.net / victim's runner · Victim = GitHub-CI→AWS with long-lived creds + 7-day logs.
Senior Q — rebuild the runner, still HIGH because: stolen creds (incl. attacker-made key) still auth from anywhere, active STS sessions live until expiry, IAM persistence (admin attach, public bucket) survives, and the data/secret is already out. HIGH until every key revoked, IAM diffed to baseline, DB secret rotated, bucket closed.

🚨 5) CISO brief — 24h: revoke both keys, review non-CI cloud auth, hunt runners, preserve logs (7-day!), close public bucket. 7d: rotate long-lived secrets + DB master, strip admin off runners, enable CloudTrail data events/GuardDuty, remove stale identities. 30d: move to short-lived OIDC workload identity, least privilege, centralize logs ≥90d, CI/CD hunt playbooks, signed artifacts.

🧠 Senior — B >> A: one key + one bucket (A) is bounded data exposure. A CI/CD identity that deploys code, creates resources, reads secrets and changes prod (B) is the factory keys — bigger data value, persistence (mint new creds, IAM backdoors, re-enter via trusted pipeline), full privilege, and highest attacker ROI (resale/supply-chain). Identity is the new perimeter.

📦 Pack (16/16 tests, report PDF, Sigma, analyzer, synthetic evidence):
https://github.com/Eswar5313/GraySentinel-DSOU-45Day-2026/tree/main/cloud-token-blackout
📊 Dashboard: https://eswar5313.github.io/GraySentinel-DSOU-45Day-2026/#cloudtoken
