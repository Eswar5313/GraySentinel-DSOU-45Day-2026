#!/usr/bin/env python3
"""
ghost_admin_hunter.py — GraySentinel DSOU war-room "Ghost Admin".

Defensive hunt tool. Reads a unified Windows event export (Security + PowerShell +
Sysmon, one CSV) + identity context (JSON) and reconstructs privileged-identity
abuse on a domain controller:

  Mission 01  identity attack-surface facts     Mission 03  "Privileged Identity Anomaly" detection
  Mission 02  H1/H2/H3 verdicts                 Mission 04  persistence hunt
  (timeline + lateral movement)                 Mission 05  closure inputs

It only reads logs. Python 3.8+, standard library only.

usage: python3 ghost_admin_hunter.py ghostadmin_events_SYNTHETIC.csv ghostadmin_context_SYNTHETIC.json
                                     [--window 15] [--json out.json]
"""
import argparse, csv, ipaddress, json, sys
from datetime import datetime, timedelta

PRIV_GROUPS = ("domain admins", "enterprise admins", "administrators", "backup operators",
               "account operators", "schema admins")
SUSPICIOUS_PS = ("-enc", "-encodedcommand", "-w hidden", "-nop", "-noni", "iex", "downloadstring")
DCSYNC = "ds-replication-get-changes"
INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")


def is_internal(ip):
    try:
        return any(ipaddress.ip_address(ip) in n for n in INTERNAL_NETS)
    except ValueError:
        return False


def load_events(path):
    out = []
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            try:
                r["_t"] = ts(r["ts"]); r["event_id"] = int(r["event_id"])
            except (KeyError, ValueError):
                continue
            out.append(r)
    out.sort(key=lambda r: r["_t"])
    return out


def load_context(path):
    if not path:
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def baseline_tier0_logons(events, user, before, dcs):
    lo = before - timedelta(days=30)
    return sum(1 for e in events if e["event_id"] == 4624 and e["host"] in dcs
               and e["user"] == user and lo <= e["_t"] < before)


def investigate(events, ctx, window_min=15):
    assets = ctx.get("assets", {})
    users = ctx.get("users", {})
    dcs = {h for h, a in assets.items() if "Domain Controller" in a.get("role", "")}
    tickets = {t["host"] + "|" + t["user"]: t["id"] for t in ctx.get("change_tickets", [])}
    cases = []
    # a "case" = a privileged-group add OR a Tier-0 logon from an unusual source
    group_adds = [e for e in events if e["event_id"] in (4728, 4732)]
    seen = set()
    triggers = []
    for e in events:
        if e["event_id"] in (4728, 4732):
            triggers.append(e)
        elif e["event_id"] == 4624 and e["host"] in dcs and e["logon_type"] in ("3", "10"):
            prof = users.get(e["user"], {})
            if e["src_ip"] not in prof.get("approved_sources", []) and not prof.get("normally_admin", False):
                triggers.append(e)
    for trig in triggers:
        user = trig.get("member") or trig["user"]
        key = user
        if key in seen:
            continue
        seen.add(key)
        prof = users.get(user, {})
        # first unusual DC logon for this user
        logon = next((e for e in events if e["event_id"] == 4624 and e["host"] in dcs
                      and e["user"] == user), None)
        host = logon["host"] if logon else trig["host"]
        src = logon["src_ip"] if logon else ""
        src_host = logon["src_host"] if logon else ""
        t0 = (logon or trig)["_t"]
        t_end = t0 + timedelta(minutes=window_min)
        fails = [e for e in events if e["event_id"] == 4625 and e["host"] in dcs
                 and e["src_ip"] == src and t0 - timedelta(minutes=30) <= e["_t"] <= t0]
        privs = [p for e in events if e["event_id"] == 4672 and e["user"] == user
                 and t0 <= e["_t"] <= t_end for p in e["detail"].split(";") if p]
        adds = [e for e in events if e["event_id"] in (4728, 4732) and (e.get("member") == user)
                and any(g in (e.get("group", "").lower()) for g in PRIV_GROUPS)]
        procs = [e for e in events if e["event_id"] in (4688, 1) and e["host"] in dcs
                 and e["user"] == user and t0 <= e["_t"] <= t_end]
        ps = [e for e in procs if "powershell" in e["process"].lower()]
        ps_flags = sorted({k for e in ps for k in SUSPICIOUS_PS if k in e["cmdline"].lower()})
        ldap = [e for e in events if e["event_id"] == 4662 and e["user"] == user and t0 <= e["_t"] <= t_end]
        dcsync = [e for e in ldap if DCSYNC in e["detail"].lower()]
        svcs = [e for e in events if e["event_id"] == 7045 and e["host"] in dcs and t0 <= e["_t"] <= t_end]
        onward = [e for e in events if e["event_id"] == 4624 and e["user"] == user
                  and e["host"] != host and t0 <= e["_t"] <= t_end
                  and (e["src_host"] == host or e["src_ip"] == assets.get(host, {}).get("ip"))]
        files = [e for e in events if e["event_id"] in (5140, 5145) and e["user"] == user and t0 <= e["_t"] <= t_end]
        krb = [e for e in events if e["event_id"] in (4768, 4769) and e["user"] == user and t0 <= e["_t"] <= t_end]
        prior = baseline_tier0_logons(events, user, t0, dcs)
        ticket = tickets.get(host + "|" + user, "")

        # ---- verdicts ----
        h1 = []
        if fails: h1.append(f"{len(fails)} failed logons from same source before success")
        if src and not any(src == users.get(u, {}).get("x") for u in users) and src != assets.get("PAW-ADMIN-01", {}).get("ip"):
            if src not in prof.get("approved_sources", []): h1.append(f"source {src} ({src_host}) not an approved admin host")
        if prior == 0: h1.append("no Tier-0 logon by this user in 30-day baseline")
        if logon and "NTLM" in logon.get("detail", ""): h1.append("NTLM to a DC (no Kerberos PAC) — credential-relay/theft pattern")
        if not prof.get("normally_admin", True): h1.append("account is not normally privileged")
        h1v = "COMPROMISED" if len(h1) >= 3 else ("INCONCLUSIVE" if h1 else "LEGITIMATE")

        h2 = []
        if adds: h2.append("added to " + ", ".join(sorted({e.get("group") for e in adds})))
        if privs: h2.append("special privileges: " + ", ".join(sorted(set(privs))[:4]))
        if ps_flags or ldap: h2.append("admin activity right after the privilege change")
        h2v = "CONFIRMED" if adds and len(h2) >= 2 else ("POSSIBLE" if adds else "NOT OBSERVED")

        h3 = []
        if onward: h3.append("onward logons: " + ", ".join(sorted({e["host"] for e in onward})))
        if files: h3.append(f"{len(files)} remote share/file access events")
        if dcsync: h3.append("directory replication read (DCSync-style)")
        if any(e["event_id"] == 4768 and "RC4" in e["detail"] for e in krb): h3.append("Kerberos TGT with RC4 downgrade")
        h3v = "CONFIRMED" if len(h3) >= 2 else ("POSSIBLE" if h3 else "NOT OBSERVED")

        legit = (src in prof.get("approved_sources", []) and prof.get("normally_admin")) or bool(ticket)
        unusual = not legit
        fired = unusual and (bool(adds) or bool(ps_flags) or bool(onward))
        severity = "CRITICAL" if fired and (dcsync or h3v == "CONFIRMED") else ("HIGH" if fired else
                   ("MEDIUM" if unusual else "INFO"))

        tl = []
        if fails:
            tl.append((fails[0]["_t"], str(fails[0]["event_id"]), f"first of {len(fails)} failed logons from {src}"))
        if logon: tl.append((logon["_t"], "4624/" + logon["logon_type"], f"logon {user} on {host} from {src} ({logon.get('detail','')})"))
        for e in sorted(adds, key=lambda e: e["_t"]):
            tl.append((e["_t"], str(e["event_id"]), f"{user} added to {e.get('group')}"))
        for e in events:
            if e["event_id"] == 4672 and e["user"] == user and t0 <= e["_t"] <= t_end:
                tl.append((e["_t"], "4672", "privileges: " + e["detail"]))
        for e in ps: tl.append((e["_t"], str(e["event_id"]), f"{e['parent']} → powershell: {e['cmdline'][:60]}"))
        for e in events:
            if e["event_id"] == 4104 and e["user"] == user and t0 <= e["_t"] <= t_end:
                tl.append((e["_t"], "4104", "script block: " + e["cmdline"][:70]))
        if ldap: tl.append((ldap[0]["_t"], "4662", f"{len(ldap)} directory-access events" + (" incl. replication read" if dcsync else "")))
        for e in svcs: tl.append((e["_t"], "7045", "new service: " + e["detail"]))
        for e in onward: tl.append((e["_t"], "4624/" + e["logon_type"], f"onward logon {user} on {e['host']} from {e['src_ip']}"))
        for e in files: tl.append((e["_t"], str(e["event_id"]), f"{e['host']}: {e['detail']}"))
        for e in krb: tl.append((e["_t"], str(e["event_id"]), e["detail"]))
        tl.sort(key=lambda x: x[0])

        cases.append({
            "identity": {"user": user, "normally_privileged": prof.get("normally_admin", False),
                         "tier": prof.get("tier"), "source_ip": src, "source_host": src_host,
                         "dc": host, "logon_type": int(logon["logon_type"]) if logon else None,
                         "auth_pkg": "NTLM" if logon and "NTLM" in logon.get("detail", "") else "Kerberos",
                         "failed_attempts": len(fails), "tier0_baseline_30d": prior,
                         "pwd_last_set": prof.get("pwd_last_set"), "mfa": prof.get("mfa"),
                         "privileged_group_adds": sorted({e.get("group") for e in adds}),
                         "change_ticket": ticket or None},
            "hypotheses": {"H1": {"verdict": h1v, "evidence": h1},
                           "H2": {"verdict": h2v, "evidence": h2 or ["no privileged-group change"]},
                           "H3": {"verdict": h3v, "evidence": h3 or ["no lateral movement observed"]}},
            "detection": {"name": "Privileged Identity Anomaly", "fired": fired, "severity": severity},
            "persistence": {"new_services": [e["detail"] for e in svcs], "dcsync": bool(dcsync),
                            "priv_group_adds": [f"{e.get('member')}→{e.get('group')}" for e in adds]},
            "lateral": {"onward_logons": sorted({e["host"] for e in onward}),
                        "share_access": [e["detail"] for e in files],
                        "kerberos": [e["detail"] for e in krb]},
            "timeline": [(t.strftime("%Y-%m-%d %H:%M:%SZ"), k, d) for t, k, d in tl],
        })
    return cases


def render(cases):
    out = ["=" * 78, f"GraySentinel DSOU · Ghost Admin hunt · {len(cases)} identity case(s)", "=" * 78]
    for c in sorted(cases, key=lambda c: c["detection"]["severity"] != "CRITICAL"):
        i, d = c["identity"], c["detection"]
        out.append(f"\n[{d['severity']:<8}] {i['user']} on {i['dc']} from {i['source_ip']} "
                   f"({i['source_host']})  detection_fired={d['fired']}")
        out.append("  -- Mission 01 identity --")
        for k in ("normally_privileged", "tier", "logon_type", "auth_pkg", "failed_attempts",
                  "tier0_baseline_30d", "privileged_group_adds", "mfa", "change_ticket"):
            out.append(f"   {k:<22} {i[k]}")
        out.append("  -- Mission 02 hypotheses --")
        for h, v in c["hypotheses"].items():
            out.append(f"   {h} {v['verdict']:<12} " + " | ".join(v["evidence"]))
        out.append("  -- Mission 04 persistence --")
        pr = c["persistence"]
        out.append(f"   priv-group adds: {pr['priv_group_adds']}  DCSync: {pr['dcsync']}  new services: {pr['new_services']}")
        out.append("  -- lateral movement --")
        la = c["lateral"]
        out.append(f"   onward: {la['onward_logons']}  shares: {len(la['share_access'])}  kerberos: {la['kerberos']}")
        out.append("  -- Mission (timeline) --")
        for when, k, desc in c["timeline"]:
            out.append(f"   {when}  {k:<9} {desc}")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="GraySentinel DSOU Ghost Admin hunter")
    ap.add_argument("events"); ap.add_argument("context", nargs="?")
    ap.add_argument("--window", type=int, default=15); ap.add_argument("--json")
    a = ap.parse_args(argv)
    try:
        events = load_events(a.events); ctx = load_context(a.context)
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr); return 2
    cases = investigate(events, ctx, a.window)
    print(render(cases))
    if a.json:
        with open(a.json, "w") as f:
            json.dump(cases, f, indent=2, default=str)
    return 1 if any(c["detection"]["fired"] for c in cases) else 0


if __name__ == "__main__":
    sys.exit(main())
