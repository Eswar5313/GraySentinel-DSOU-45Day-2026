# How to Push to GitHub

## Step 1 — Create the repo on GitHub
1. Go to https://github.com/new
2. Repository name: `GraySentinel-DSOU-Day2-MacOSMiner-2026`
3. Description: `GraySentinel DSOU Day 2 — macOS Miner Attack Chain | Blue Team Lab | Eswar Mahalingam`
4. Set to **Public**
5. Do NOT initialise with README (we already have one)
6. Click **Create repository**

## Step 2 — Extract the zip and push

```bash
# Extract the zip you downloaded
unzip GraySentinel-DSOU-Day2-MacOSMiner-2026.zip
cd GraySentinel-DSOU-Day2-MacOSMiner-2026

# Initialise git and push
git init
git add .
git commit -m "feat: GraySentinel DSOU Day 2 — macOS Miner Attack Chain complete

- 6 phases completed (oletools, CVE-2026-65400, AdaptixC2, XMRig, Tookie-OSINT, Remediation)
- 170 risks identified and mapped
- 6-tripwire Sigma detection rule (ATT&CK T1566/T1203/T1071/T1098/T1543/T1496)
- Wazuh SIEM rules (IDs 100200-100206)
- 2-page navy/gold PDF incident report
- All artifacts defensive only — GS-STU-DSOU-2026-039A"

git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/GraySentinel-DSOU-Day2-MacOSMiner-2026.git
git push -u origin main
```

## Step 3 — Share on LinkedIn

Post the GitHub repo link on LinkedIn with:
- Tag: GraySentinel, Blue Team, Cybersecurity, SOC, DSOU
- Operator ID: GS-STU-DSOU-2026-039A
- Mention: CVE-2026-65400, XMRig, AdaptixC2, macOS forensics
