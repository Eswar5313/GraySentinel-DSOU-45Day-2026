# Push this addition to the existing repo

The folder `graysentinel-day1/` is an **addition** to `Eswar5313/GraySentinel-DSOU-Day1-ZeroDay-2026` (which already holds the Day 1 Zero-Day lab). No existing files are touched.

## Option A — GitHub web upload (≤100 files; this folder is ~35 files)
1. Open https://github.com/Eswar5313/GraySentinel-DSOU-Day1-ZeroDay-2026 → **Add file → Upload files**.
2. Drag the whole `graysentinel-day1` folder in (keep the folder, do not drag its contents loose).
3. Commit message: `Add Day 1 individual projects: auth log investigator + SOC incident summary generator` → **Commit changes**.

## Option B — git
```bash
git clone https://github.com/Eswar5313/GraySentinel-DSOU-Day1-ZeroDay-2026.git && cd GraySentinel-DSOU-Day1-ZeroDay-2026
unzip ~/Downloads/graysentinel-day1.zip -d .        # creates ./graysentinel-day1
git add graysentinel-day1 && git commit -m "Add Day 1 individual projects (P01 auth investigator, P02 incident summary)" && git push
```

## Enable the live checker (GitHub Pages)
Settings → Pages → Source: *Deploy from a branch* → Branch `main`, folder `/ (root)` → Save.
Live URL after ~1 min: https://Eswar5313.github.io/GraySentinel-DSOU-Day1-ZeroDay-2026/graysentinel-day1/docs/
(If the repo already publishes from `/docs`, move `graysentinel-day1/docs/index.html` to `docs/day1-projects/index.html` and use that URL.)

## Send in the group
```
Name: Eswar Mahalingam
Project 01: https://github.com/Eswar5313/GraySentinel-DSOU-Day1-ZeroDay-2026/blob/main/graysentinel-day1/project-01/README.md
Project 02: https://github.com/Eswar5313/GraySentinel-DSOU-Day1-ZeroDay-2026/blob/main/graysentinel-day1/project-02/README.md
Evidence: Repository contains code + report + evidence
Status: Submitted for Review
```
