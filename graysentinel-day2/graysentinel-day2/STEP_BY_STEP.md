# STEP_BY_STEP — Day 2 runbook (copy-paste, with expected output)

> Needs only Python 3.8+. No installs. Run from the `graysentinel-day2/` folder.

## 0. Sanity check
```bash
python3 --version        # 3.8 or higher
ls src data tests        # should list the .py, .bas/.csv, and test file
```

## 1. Static macro triage (Tool A)
```bash
python3 src/macro_analyzer.py data/invoice_Q3.docm.extracted.bas --json findings.json --md findings.md
```
**Expected:**
```
[MALICIOUS] 16 findings (CRIT 3/HIGH 7) -> data/invoice_Q3.docm.extracted.bas
```
Exit code is **2** on purpose (CRITICAL gate). Check it:
```bash
echo $?                  # -> 2
```

## 2. Reconstruct the kill chain (Tool B)
```bash
python3 src/killchain_reconstructor.py --edr data/edr_telemetry.csv --macro findings.json \
    --md incident_brief.md --html incident_brief.html --json incident_brief.json
```
**Expected:**
```
[P1] mac-victim-07 · 12 events · 2 C2 IPs · verdict MALICIOUS
```

## 3. Run the tests
```bash
python3 -m unittest discover -s tests -v
```
**Expected tail:**
```
Ran 21 tests in 0.05s
OK
```

## 4. Look at the outputs
```bash
cat findings.md            # rule table + ATT&CK + why-each-fired
cat incident_brief.md      # timeline, IOCs, ATT&CK matrix, containment
open incident_brief.html   # (macOS) styled navy/gold brief; Linux: xdg-open
```

## 5. Push to GitHub (same repo as Day 1)
```bash
# unzip graysentinel-day2.zip into your local clone, then:
git add graysentinel-day2
git commit -m "Day 2 — macOS cryptominer kill-chain (2 tools, 21 tests, P1 brief)"
git push
```
Enable Pages once (Settings → Pages → main / root) → live checker at
`https://eswar5313.github.io/GraySentinel-DSOU-45Day-2026/graysentinel-day2/docs/`
