# STEP-BY-STEP RUNBOOK — reproduce and verify both projects in 5 minutes

Copy-paste each block. The **expected output** under each block is what a reviewer must see. Every expected output here is copied from `evidence/terminal_output.txt` — not typed by hand.

## Step 0 — Requirements
```bash
python3 --version        # 3.8 or newer. Nothing to pip-install.
git clone https://github.com/Eswar5313/GraySentinel-DSOU-Day1-ZeroDay-2026.git
cd GraySentinel-DSOU-Day1-ZeroDay-2026/graysentinel-day1
```

## PROJECT 01 — Authentication Log Investigation Tool

### Step 1 — (Re)generate the synthetic lab log
```bash
cd project-01
python3 data/make_lab_data.py
```
Expected: `wrote auth.log with 135 lines` — the generator is seeded, so the file is byte-identical every run (`sha256sum data/auth.log` should match the reviewer's).

### Step 2 — Look at the raw data (know what you are investigating)
```bash
head -5 data/auth.log
grep -c "Failed password" data/auth.log      # 55
grep -c "Accepted" data/auth.log             # 26
grep "useradd\|usermod" data/auth.log        # the persistence lines at 00:08–00:09
```

### Step 3 — Run the investigation
```bash
python3 src/auth_investigator.py --log data/auth.log --out evidence/findings.json --md evidence/findings.md
echo "exit=$?"
```
Expected: `Parsed 135 events`, `10 finding(s)`, first two lines `[CRITICAL] F03 Successful login after failure burst…` and `[CRITICAL] F10 Account added to privileged group`, and `exit=2` (2 = CRITICAL present).

### Step 4 — Open the outputs
```bash
cat evidence/findings.md | head -40         # human report with tables
python3 -c "import json;d=json.load(open('evidence/findings.json'));print(d['summary']['top_source_ips']);print([f['id']+':'+f['severity'] for f in d['findings']])"
```
Expected top IPs: `203.0.113.45 (61)`, `198.51.100.77 (32)` (brute-force and spray sources).

### Step 5 — Run the tests (13 must pass)
```bash
python3 -m unittest -v tests.test_auth_investigator
```
Expected last lines: `Ran 13 tests … OK`.

### Step 6 — Edge cases a reviewer should try
```bash
# tuning: raise thresholds -> brute force/spray suppressed, CRITICAL still fires
python3 src/auth_investigator.py --log data/auth.log --bf-threshold 50 --spray-users 20 --quiet; echo "exit=$?"     # exit=2
# garbage input -> warned and skipped, no crash
printf "garbage line\n\n" > /tmp/bad.log && python3 src/auth_investigator.py --log /tmp/bad.log; echo "exit=$?"    # exit=0
# change the business window -> F04 disappears
python3 src/auth_investigator.py --log data/auth.log --business-hours 00-24 | grep -c "outside business"            # 0
```

### Step 7 — Compare with the committed evidence
```bash
diff <(python3 src/auth_investigator.py --log data/auth.log --quiet; python3 -m unittest tests.test_auth_investigator 2>&1 | tail -1) <(echo OK)
sed -n 1,30p evidence/terminal_output.txt
```

## PROJECT 02 — SOC Incident Summary Generator

### Step 8 — Feed Project 01's findings in
```bash
cd ../project-02
cp ../project-01/evidence/findings.json data/findings.json      # already committed; copy refreshes it
python3 src/incident_summary.py --findings data/findings.json --md evidence/incident_summary.md --html evidence/incident_summary.html --json evidence/incident_summary.json
```
Expected: `Incident GS-INC-<date>-701  severity=CRITICAL priority=P1 risk=100/100`, `IOCs: 23   ATT&CK: 9 techniques`, and the narrative line starting `Chain: credential guessing → successful root login → new account + sudo grant (persistence).`

### Step 9 — Read the ticket three ways
```bash
head -30 evidence/incident_summary.md                # Markdown ticket
xdg-open evidence/incident_summary.html 2>/dev/null || open evidence/incident_summary.html || echo "open the HTML in a browser"
python3 -c "import json;d=json.load(open('evidence/incident_summary.json'));print(d['priority'],d['sla_response'],'|',d['notify']);print(d['nist_stages']['Containment'])"
```

### Step 10 — Prove it works on a different input (generic CSV)
```bash
python3 src/incident_summary.py --csv data/alerts_sample.csv --md evidence/incident_summary_from_csv.md
```
Expected: `severity=HIGH priority=P2`, 3 findings, no "Chain:" line (no success-after-failure in that data).

### Step 11 — Run the tests (12 must pass)
```bash
python3 -m unittest -v tests.test_incident_summary
```
Expected: `Ran 12 tests … OK`.

### Step 12 — Regenerate screenshots from real output (optional)
```bash
cd .. && python3 docs/render_screens.py     # needs Pillow: pip install pillow
```

## What the reviewer should be able to say afterwards
1. The CRITICAL findings are the *success after failures* and the *sudo-group grant* — not the brute force volume.
2. Legitimate typos (`priya`) produced zero alerts.
3. Project 02's P1 / 15-minute SLA follows deterministically from the worst finding; the IOC table lists exactly two external IPs to block.
4. Every number in both reports traces back to a line number in `data/auth.log` or a rule in the source.
