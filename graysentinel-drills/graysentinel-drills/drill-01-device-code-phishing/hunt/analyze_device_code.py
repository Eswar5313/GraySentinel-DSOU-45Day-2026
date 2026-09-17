#!/usr/bin/env python3
"""Drill 01 analyzer — Entra ID Sign-in Logs CSV -> 'Timestamp | User | App | Legit? + Why' table.
Usage: python3 analyze_device_code.py export.csv [--home-countries IN,AE] [--allow-apps "Azure CLI,Microsoft Azure PowerShell"]
Stdlib only. Reads the portal CSV export (interactive or non-interactive)."""
import csv, argparse, collections

DC_MARKERS = ("device code", "devicecode")
DEFAULT_ALLOW_APPS = ["Azure CLI", "Microsoft Azure PowerShell", "Microsoft Azure CLI", "Microsoft Teams Rooms", "Microsoft Intune",
                      "Visual Studio", "Microsoft Intune Company Portal"]
VPN_HINTS = ("vpn", "proxy", "hosting", "datacenter", "data center", "cloud", "digitalocean", "ovh", "m247",
             "hetzner", "vultr", "linode", "tor", "nord", "surfshark", "residential")

def col(row, *names):
    for n in names:
        for k in row:
            if k.strip().lower() == n.lower():
                return (row[k] or "").strip()
    return ""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv"); ap.add_argument("--home-countries", default="IN")
    ap.add_argument("--allow-apps", default=",".join(DEFAULT_ALLOW_APPS))
    a = ap.parse_args()
    home = {c.strip().upper() for c in a.home_countries.split(",")}
    allow = {x.strip().lower() for x in a.allow_apps.split(",")}
    rows = list(csv.DictReader(open(a.csv, encoding="utf-8-sig")))
    seen_c, seen_app = collections.defaultdict(collections.Counter), collections.defaultdict(collections.Counter)
    for r in rows:
        u = col(r, "User", "Username", "User principal name")
        seen_c[u][col(r, "Location", "Country")] += 1
        seen_app[u][col(r, "Application", "App display name")] += 1
    out = []
    for r in rows:
        proto = " ".join([col(r, "Authentication Protocol", "Authentication protocol"),
                          col(r, "Authentication Details", "Authentication details")]).lower()
        if not any(m in proto for m in DC_MARKERS):
            continue
        u = col(r, "User", "Username", "User principal name"); app = col(r, "Application", "App display name")
        loc = col(r, "Location", "Country"); ip = col(r, "IP address", "IP")
        asn = col(r, "Autonomous system number", "ISP", "ASN"); status = col(r, "Status")
        ca = col(r, "Conditional Access", "Conditional access status")
        country = loc.split(",")[-1].strip().upper()[:2] if loc else ""
        why, score = [], 0
        if status and "success" not in status.lower():
            why.append("token NOT issued (failed) — attempt only")
        if country and country not in home: why.append(f"location {loc} outside home countries"); score += 3
        elif loc and sum(seen_c[u].values()) > 3 and seen_c[u][loc] <= 1: why.append(f"first sign-in from {loc}"); score += 2
        elif loc and sum(seen_c[u].values()) <= 3: why.append(f"home location {loc} (thin baseline in export — widen date range)")
        if app.lower() not in allow: why.append(f"app '{app}' is not a device-code-native client"); score += 2
        else: why.append(f"'{app}' normally uses device code")
        if any(h in asn.lower() for h in VPN_HINTS): why.append(f"ISP/ASN looks like VPN/hosting ({asn})"); score += 2
        if ca and "not applied" in ca.lower(): why.append("no Conditional Access policy applied"); score += 1
        if sum(seen_app[u].values()) > 3 and seen_app[u][app] <= 1: why.append("first use of this app by user"); score += 1
        verdict = "No" if score >= 3 else "Yes"
        out.append((col(r, "Date (UTC)", "Date", "Created at", "Timestamp"), u, app, ip, verdict, score, "; ".join(why)))
    if not out:
        print("No device-code-flow sign-ins found in export (check filter/columns)."); return
    print("Timestamp | User | App | IP | Was it legit? | Why")
    for t, u, app, ip, v, s, w in sorted(out, key=lambda x: -x[5]):
        print(f"{t} | {u} | {app} | {ip} | {v} | {w}")
    print(f"\n{len(out)} device-code sign-ins, {sum(1 for o in out if o[4]=='No')} flagged. "
          "Next for 'No': revoke sessions + reset, check mailbox rules/OAuth consents, block device code flow via Conditional Access.")

if __name__ == "__main__":
    main()
