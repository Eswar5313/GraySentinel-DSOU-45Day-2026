#!/usr/bin/env python3
"""
rdp_chain_hunter.py — GraySentinel DSOU war-room: "The Silent RDP Login"

Defensive hunt tool. Reads a unified event export (Windows Security + Sysmon +
PowerShell + Defender, one CSV) plus identity/VPN/firewall context (JSON) and
answers the war-room questions for every successful RDP logon (4624 Type 10):

  Mission 01  triage fields          Mission 03  ordered attack timeline
  Mission 02  H1/H2/H3 verdicts      Mission 04  "Suspicious RDP-to-PowerShell Chain" detection
  Mission 05  lateral-movement hunt  (same user / same source IP / internal hosts)

It only reads logs. Python 3.8+, standard library only.

usage: python3 rdp_chain_hunter.py rdp_events_SYNTHETIC.csv auth_context_SYNTHETIC.json
                                   [--window 15] [--fail-lookback 30] [--json out.json]
"""
import argparse, csv, ipaddress, json, sys
from datetime import datetime, timedelta

SUSPICIOUS_PS = ("-enc", "-encodedcommand", "-w hidden", "-windowstyle hidden", "-nop",
                 "invoke-webrequest", "iex", "downloadstring", "-noni")
DISCOVERY = ("whoami", "nltest", "net group", "net user", "domain admins", "get-aduser",
             "get-adcomputer", "net view", "arp -a")
HIGH_PRIVS = ("SeDebugPrivilege", "SeBackupPrivilege", "SeTakeOwnershipPrivilege",
              "SeImpersonatePrivilege", "SeTcbPrivilege")
SENSITIVE_PATH = ("payroll", "salary", "bank", "hr$")


def ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")


INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def is_internal(ip):
    """RFC-1918 only. (Python's is_private also flags RFC-5737 lab ranges, which here
    stand in for *internet* addresses, so we check the corporate ranges explicitly.)"""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in INTERNAL_NETS)


def load_events(path):
    out = []
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            try:
                r["_t"] = ts(r["ts"])
                r["event_id"] = int(r["event_id"])
            except (KeyError, ValueError):
                continue                       # skip malformed rows, never crash
            out.append(r)
    out.sort(key=lambda r: r["_t"])
    return out


def load_context(path):
    if not path:
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def baseline_rdp(events, user, before):
    """Count prior Type-10 logons for this user in the 30 days before the session."""
    lo = before - timedelta(days=30)
    return sum(1 for e in events if e["event_id"] == 4624 and e["logon_type"] == "10"
               and e["user"] == user and lo <= e["_t"] < before)


def investigate(events, ctx, window_min=15, fail_lookback_min=30):
    users = ctx.get("users", {})
    tickets = {t["host"] + "|" + t["user"]: t["id"] for t in ctx.get("change_tickets", [])}
    cases = []
    for s in (e for e in events if e["event_id"] == 4624 and e["logon_type"] == "10"):
        user, host, src, t0 = s["user"], s["host"], s["src_ip"], s["_t"]
        t_end = t0 + timedelta(minutes=window_min)
        prof = users.get(user, {})
        fails = [e for e in events if e["event_id"] == 4625 and e["host"] == host
                 and e["src_ip"] == src and t0 - timedelta(minutes=fail_lookback_min) <= e["_t"] <= t0]
        sess = [e for e in events if e["host"] == host and t0 <= e["_t"] <= t_end
                and (e["logon_id"] == s["logon_id"] or (e["user"] == user and e["channel"] in ("Sysmon", "PowerShell")))]
        privs = [p for e in sess if e["event_id"] == 4672 for p in e["detail"].split(";") if p in HIGH_PRIVS]
        procs = [e for e in sess if e["event_id"] in (4688, 1)]
        ps = [e for e in procs if "powershell" in e["process"].lower()]
        ps_flags = sorted({k for e in ps for k in SUSPICIOUS_PS if k in e["cmdline"].lower()})
        blocks = [e for e in sess if e["event_id"] == 4104]
        disco = sorted({e["cmdline"] for e in procs if any(k in e["cmdline"].lower() for k in DISCOVERY)})
        net = [e for e in sess if e["event_id"] == 3]
        net_int = [e for e in net if is_internal(e["dst_ip"])]
        net_ext = [e for e in net if e["dst_ip"] and not is_internal(e["dst_ip"])]
        victim_ip = victim_ip_of(host, events)
        onward = [e for e in events if e["event_id"] == 4624 and e["logon_type"] in ("3", "10")
                  and e["user"] == user and e["host"] != host and t0 <= e["_t"] <= t_end
                  and (e["src_host"] == host or e["src_ip"] == victim_ip)]
        files = [e for e in events if e["event_id"] in (5140, 5145) and e["user"] == user
                 and t0 <= e["_t"] <= t_end]
        sens = [e for e in files if e["event_id"] == 5145 and any(k in e["detail"].lower() for k in SENSITIVE_PATH)]
        other_hosts = {}
        for e in events:
            if e["src_ip"] == src and e["host"] != host and e["event_id"] in (4624, 4625):
                h = other_hosts.setdefault(e["host"], {"fail": 0, "success": 0})
                h["fail" if e["event_id"] == 4625 else "success"] += 1
        prior = baseline_rdp(events, user, t0)
        approved = src in prof.get("approved_sources", [])
        ticket = tickets.get(host + "|" + user) or (s["detail"] if s["detail"].startswith("CHG-") else "")
        idp = [i for i in ctx.get("idp_signins", []) if i["user"] == user and i["ip"] == src]
        vpn_at_login = [v for v in ctx.get("vpn_sessions", []) if v["user"] == user
                        and ts(v["start"]) <= t0 and (not v["end"] or t0 <= ts(v["end"]))]
        exposure = [f for f in ctx.get("firewall", []) if victim_ip and f["to"].split(":")[0] == victim_ip]
        unusual_src = (not is_internal(src)) or (not approved and prior == 0)

        # ---------- verdicts ----------
        h1_ev = []
        if fails: h1_ev.append(f"{len(fails)} failed RDP attempts from same source before success")
        if not is_internal(src): h1_ev.append(f"external source {src} ({s['src_host']})")
        if prior == 0: h1_ev.append("no Type-10 logon by this user in 30-day baseline")
        if not prof.get("rdp_allowed", True): h1_ev.append("account not authorised for RDP")
        if idp: h1_ev.append(f"same IP already had the correct password in IdP ({len(idp)} MFA-denied sign-ins)")
        if not vpn_at_login and ctx.get("vpn_sessions") is not None: h1_ev.append("user had no VPN session at login time")
        h1 = "COMPROMISED" if len(h1_ev) >= 3 else ("INCONCLUSIVE" if h1_ev else "LEGITIMATE")
        h2_ev = [x for x, ok in (("approved admin source", approved), ("change ticket " + ticket, bool(ticket)),
                                 ("user is RDP-authorised", prof.get("rdp_allowed", False)),
                                 ("behaviour matches baseline", prior > 0)) if ok]
        h2 = "SUPPORTED" if len(h2_ev) >= 3 else "REJECTED"
        h3_ev = []
        if ps_flags: h3_ev.append("obfuscated/hidden PowerShell: " + ", ".join(ps_flags))
        if disco: h3_ev.append(f"{len(disco)} discovery commands")
        if net_int: h3_ev.append("internal connections: " + ", ".join(f"{e['dst_ip']}:{e['dst_port']}" for e in net_int))
        if onward: h3_ev.append("onward auth: " + ", ".join(f"{e['host']} (Type {e['logon_type']})" for e in onward))
        if sens: h3_ev.append(f"{len(sens)} sensitive file accesses")
        if net_ext: h3_ev.append("external egress: " + ", ".join(f"{e['dst_ip']}:{e['dst_port']}" for e in net_ext))
        h3 = "CONFIRMED" if len(h3_ev) >= 3 else ("POSSIBLE" if h3_ev else "NOT OBSERVED")

        # ---------- Mission 04 detection ----------
        ps_in_window = any(e["_t"] - t0 <= timedelta(minutes=window_min) for e in ps)
        fired = bool(ps_in_window and unusual_src)
        stages = sum(bool(x) for x in (fails, True, privs, procs, ps, net, files or onward, onward))
        severity = "CRITICAL" if fired and h3 == "CONFIRMED" else ("HIGH" if fired else
                   ("MEDIUM" if unusual_src else "INFO"))

        tl = [(f["_t"], "4625", f"failed RDP {f['user']} from {f['src_ip']}") for f in fails[:1]]
        if len(fails) > 1:
            tl.append((fails[-1]["_t"], "4625", f"…{len(fails)} failures total (last)"))
        tl.append((t0, "4624/10", f"RDP success {user} from {src} ({s['src_host']})"))
        tl += [(e["_t"], str(e["event_id"]), f"{e['parent']} → {e['process']}: {e['cmdline'][:70]}")
               for e in procs]
        tl += [(e["_t"], "4672", "privileges: " + ";".join(privs)) for e in sess if e["event_id"] == 4672]
        tl += [(e["_t"], "4104", "script block: " + e["cmdline"][:70] + "…") for e in blocks]
        tl += [(e["_t"], "Sysmon3", f"{e['process']} → {e['dst_ip']}:{e['dst_port']} {e['detail']}") for e in net]
        tl += [(e["_t"], "4624/" + e["logon_type"], f"{user} onward logon on {e['host']} from {e['src_ip']}") for e in onward]
        tl += [(e["_t"], str(e["event_id"]), f"{e['host']}: {e['detail']}") for e in files]
        tl.sort(key=lambda x: x[0])

        cases.append({
            "triage": {
                "user": user, "source_ip": src, "source_host": s["src_host"], "dest_host": host,
                "failed_attempts": len(fails), "success_ts": s["ts"], "logon_type": 10,
                "mfa_on_rdp": False, "idp_mfa": prof.get("mfa", "unknown"),
                "normally_uses_rdp": prior > 0, "rdp_baseline_30d": prior,
                "first_process": procs[0]["process"] if procs else None,
                "powershell_cmdline": ps[0]["cmdline"] if ps else None,
                "privileges": privs, "pwd_last_set": prof.get("pwd_last_set"),
                "idp_hits_same_ip": len(idp), "same_ip_other_hosts": other_hosts,
                "internet_exposure": exposure,
            },
            "hypotheses": {"H1": {"verdict": h1, "evidence": h1_ev},
                           "H2": {"verdict": h2, "evidence": h2_ev or ["none of the admin indicators present"]},
                           "H3": {"verdict": h3, "evidence": h3_ev}},
            "detection": {"name": "Suspicious RDP-to-PowerShell Chain", "fired": fired,
                          "severity": severity, "chain_stages": stages},
            "lateral": {"smb": [e["dst_ip"] for e in net_int if e["dst_port"] == "445"],
                        "dc_contact": [e["dst_ip"] for e in net_int if e["dst_port"] in ("389", "88", "636")],
                        "onward_logons": [e["host"] for e in onward],
                        "sensitive_files": [e["detail"] for e in sens],
                        "same_ip_other_hosts": other_hosts},
            "timeline": [(t.strftime("%Y-%m-%d %H:%M:%SZ"), k, d) for t, k, d in tl],
        })
    return cases


def victim_ip_of(host, events):
    for e in events:
        if e["src_host"] == host and e["host"] != host and is_internal(e["src_ip"]):
            return e["src_ip"]
    return None


def render(cases):
    out = ["=" * 78, "GraySentinel DSOU · RDP chain hunt · " + f"{len(cases)} RDP session(s) reviewed", "=" * 78]
    for c in sorted(cases, key=lambda c: c["detection"]["severity"] != "CRITICAL"):
        t, d = c["triage"], c["detection"]
        out.append(f"\n[{d['severity']:<8}] {t['user']} → {t['dest_host']} from {t['source_ip']} "
                   f"({t['source_host']}) at {t['success_ts']}  detection_fired={d['fired']}")
        if d["severity"] == "INFO":
            out.append("  H2 legitimate admin access: " + "; ".join(c["hypotheses"]["H2"]["evidence"]))
            continue
        out.append("  -- Mission 01 triage --")
        for k in ("failed_attempts", "normally_uses_rdp", "rdp_baseline_30d", "mfa_on_rdp", "privileges",
                  "first_process", "powershell_cmdline", "pwd_last_set", "idp_hits_same_ip", "same_ip_other_hosts"):
            out.append(f"   {k:<20} {t[k]}")
        for e in t["internet_exposure"]:
            out.append(f"   exposure            {e['rule']} {e['public']} → {e['to']} ({e['note']})")
        out.append("  -- Mission 02 hypotheses --")
        for h, v in c["hypotheses"].items():
            out.append(f"   {h} {v['verdict']:<13} " + " | ".join(v["evidence"]))
        out.append("  -- Mission 03 timeline --")
        for when, k, desc in c["timeline"]:
            out.append(f"   {when}  {k:<8} {desc}")
        lat = c["lateral"]
        out.append("  -- Mission 05 lateral movement --")
        out.append(f"   SMB→ {lat['smb']}  DC→ {lat['dc_contact']}  onward logons→ {lat['onward_logons']}")
        out.append(f"   sensitive files: {len(lat['sensitive_files'])}  same IP elsewhere: {lat['same_ip_other_hosts']}")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("events")
    ap.add_argument("context", nargs="?")
    ap.add_argument("--window", type=int, default=15, help="minutes after RDP logon to correlate (default 15)")
    ap.add_argument("--fail-lookback", type=int, default=30, help="minutes of 4625 lookback (default 30)")
    ap.add_argument("--json", help="write full results to this JSON file")
    a = ap.parse_args(argv)
    try:
        events = load_events(a.events)
        ctx = load_context(a.context)
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    cases = investigate(events, ctx, a.window, a.fail_lookback)
    print(render(cases))
    if a.json:
        with open(a.json, "w") as f:
            json.dump(cases, f, indent=2, default=str)
    return 1 if any(c["detection"]["fired"] for c in cases) else 0


if __name__ == "__main__":
    sys.exit(main())
