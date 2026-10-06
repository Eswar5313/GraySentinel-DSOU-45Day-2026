🔴 Red-Team War Room submission — Broken Pipeline (CI/CD → registry → K8s) · Eswar (Cand. 13)
«LAB ONLY. No production testing, no exploit code, no payloads, no destructive actions, no real credentials.»

🎯 Thesis: the dangerous move isn't popping one container — it's compromising the CI/CD TRUST CHAIN so malicious content ships inside a trusted pipeline. Reproduced at the audit-log level only, with a blue-team analyzer (16/16 tests).

🗺️ 1) Attack surface: ex.developer (terminated, still in automation) → GitLab off-hours run → registry push of same tag :latest / NEW unsigned digest → payments deployment patched to bad digest → deploy SA = cluster-admin (lists secrets, kube-system pod w/ hostPath) → pod workload identity (IRSA) → AssumeRole → GetSecretValue (prod DB).

🧠 2) Attack paths
H1 compromised dev identity → T1078/T1098: stale actor runs pipeline off-hours. Detect: terminated identity active, out-of-window run, new host. Blue: disable, revoke PAT/keys, rotate CI tokens.
H2 supply-chain → T1195.002/T1610: unsigned push + digest change vs signed baseline + deploy pulls non-baseline digest. Blue: admission signature enforcement, freeze tag, diff image.
H3 K8s privesc → cluster-admin deploy SA, secrets list cluster-wide, kube-system pod + hostPath. Legit deploys patch one ns in-window; this isn't.

🛡️ 3) Evasion "trusted image, untrusted content": same name/tag, pushed by real ci-runner, deployed by normal ci-deployer → AV/EDR miss it (no malware, identity/config abuse). Provenance matters: only digest + signer prove what runs. After container delete, the DIGEST persists in Deployment spec, ReplicaSet, kubelet cache + audit. Blue chain: UNEXPECTED DIGEST → OFF-HOURS PUSH → DEPLOY → NEW SA ACTIVITY → CLOUD API — 6 Sigma-style K8s-audit/registry/cloud rules + 30-min correlation + Falco runtime (unexpected egress, shell-in-container, SA-token read).

🔐 4) Identity & RBAC: excessive CI perms (cluster-admin deploy SA) = one pipeline compromise owns cluster+secrets+cloud; stale identities; require cosign + SLSA; audit cluster-admin/secrets/exec/escalate/bind bindings; scope workload identity least-privilege.
Senior Q — deleting the malicious container is NOT enough: identity (stale dev + SA token) still works, registry still serves the bad digest (pod respawns), RBAC unchanged (re-escalate), cloud tokens live until revoked, persistence (kube-system pod, modified workflow, new bindings) remains. Rotate identities/tokens, fix RBAC, revoke cloud creds, enforce signed digests at admission, hunt persistence.

🚨 5) Closure: foothold (stale identity) → CI abuse → supply-chain (unsigned digest) → K8s privesc → cloud secret. DFIR: GitLab + runner + registry + K8s audit + cloud audit + Falco. Remediation: disable stale identity, namespace-scope SA, require signed digests, rotate SA tokens + cloud creds, extend 7-day audit retention. Business impact: customer data + prod availability + software supply chain + regulatory (fintech PCI/DPDP).

🧠 Senior — B >> A: one container detected in minutes (A) is contained, low dwell. Owning the CI/CD trust chain (B) influences every future deployment: better OPSEC (hides in trusted pipeline activity), persistence (re-ships each release, downstream backdoors), blast radius (every artifact + cluster + cloud + customers), highest ROI (durable, reusable). Trust the pipeline, verify the artifact, hunt the identity.

📦 Pack (16/16 tests, report PDF, detection rules, analyzer, synthetic audit data):
https://github.com/Eswar5313/GraySentinel-DSOU-45Day-2026/tree/main/broken-pipeline
📊 Dashboard: https://eswar5313.github.io/GraySentinel-DSOU-45Day-2026/#brokenpipeline
