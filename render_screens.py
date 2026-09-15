"""Renders captured terminal output into PNG 'screenshots' (real output, drawn with PIL). Re-run after regenerating evidence."""
from PIL import Image, ImageDraw, ImageFont
import textwrap, sys, os
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
def render(src, dst, title, start=None, end=None):
    lines = open(src).read().splitlines()[start:end]
    lines = [l for chunk in lines for l in (textwrap.wrap(chunk, 118) or [""])]
    f = ImageFont.truetype(FONT, 15); ft = ImageFont.truetype(FONT, 14)
    W, lh = 1100, 21; H = 56 + lh*len(lines) + 24
    im = Image.new("RGB", (W, H), (12, 18, 32)); d = ImageDraw.Draw(im)
    d.rectangle([0,0,W,40], fill=(30,41,59))
    for i,c in enumerate([(255,95,86),(255,189,46),(39,201,63)]): d.ellipse([14+i*22,13,28+i*22,27], fill=c)
    d.text((90,11), title, font=ft, fill=(203,213,225))
    y = 52
    for l in lines:
        col = (250,204,21) if l.startswith("$") else (248,113,113) if "CRITICAL" in l or "FAIL" in l or "Traceback" in l else (74,222,128) if l.startswith("test_") or "OK" in l or "ok" == l.strip() else (226,232,240)
        d.text((16,y), l, font=f, fill=col); y += lh
    im.save(dst); print("wrote", dst, im.size)
p1="project-01/evidence/terminal_output.txt"; p2="project-02/evidence/terminal_output.txt"
render(p1,"project-01/screenshots/01_generate_lab_data_and_run.png","eswar@soc-lab-01: ~/graysentinel-day1/project-01 — run",0,26)
render(p1,"project-01/screenshots/02_unit_tests_13_pass.png","eswar@soc-lab-01: project-01 — python3 -m unittest -v",26,48)
render(p1,"project-01/screenshots/03_edge_cases_thresholds_and_garbage_input.png","eswar@soc-lab-01: project-01 — edge cases",48,None)
render(p2,"project-02/screenshots/01_generate_incident_summary.png","eswar@soc-lab-01: ~/graysentinel-day1/project-02 — run",0,30)
render(p2,"project-02/screenshots/02_unit_tests_12_pass.png","eswar@soc-lab-01: project-02 — python3 -m unittest -v",30,52)
render(p2,"project-02/screenshots/03_markdown_summary_head.png","eswar@soc-lab-01: project-02 — head evidence/incident_summary.md",52,None)
