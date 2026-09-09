# How to push this repo to GitHub

This session can't create repos on your account, so here's the one-time setup.
Everything below runs from inside this folder.

## 1. Create an empty repo on GitHub
Go to https://github.com/new → name it **GraySentinel-DSOU-Day1-ZeroDay-2026**
→ Public → do NOT add a README/licence (this repo already has one) → Create.

## 2. Push (git history is already initialised in this zip)
```bash
git remote add origin https://github.com/<your-username>/GraySentinel-DSOU-Day1-ZeroDay-2026.git
git branch -M main
git push -u origin main
```
If git isn't initialised (you extracted without .git), run first:
```bash
git init && git add . && git commit -m "GraySentinel DSOU Day 1 — Zero-Day Discovery: detection rule + report"
```

## 3. Add it to LinkedIn / CV
- LinkedIn → Licenses & certifications → GraySentinel DSOU · Day 1 Zero-Day Discovery
  · Credential ID **GS-STU-DSOU-2026-039A** · Issued Sep 2026 · Expires Mar 2027
  · link the repo under "Credential URL" or as Featured.
- Keep it under **Certifications & Training** (it's a trainee/Officer-Candidate lab,
  not a full-time role) — Zidio Data Scientist stays your headline.

## Repo layout
```
detection/detection-rule.sigma   the deliverable Sigma rule
report/report.md                 CISO report (source)
report/GraySentinel_ZeroDay_Report_Eswar.pdf   styled navy/gold report
mission-log/day1-phases.md       what ran in each phase
certificate/...039A.png          your Day 1 certificate
README.md
```

## Note on scope
Defensive artifacts only — Sigma rule + report. No exploit code is included, by
design. The CVE identifier is lab scaffolding; verify against the real advisory
before any production use.
