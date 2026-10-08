#!/usr/bin/env python3
"""
lsass_credential_hunter.py — GraySentinel DSOU war-room "Silent Credential Theft".

Defensive hunt tool. Reads a unified Windows export (Security + Sysmon + EDR, one CSV) and an
asset/identity context (JSON) and answers the war-room missions for a workstation that shows
LSASS access followed by unusual authentication:

  Mission 01  triage facts (who / host / process / parent / hash / access mask)
  Mission 02  H1 credential access · H2 legitimate admin · H3 credential abuse — verdict + evidence
  Mission 03  authentication timeline
  Mission 04  "Suspicious LSASS Process Access" reference detection (context, not the mere name)
  Mission 05  account + lateral-movement scope (which systems to investigate next)
  Mission 07  correlation score A+B+C+D

It only reads logs. Python 3.8+, standard library only.

usage: python3 lsass_credential_hunter.py lsass_events_SYNTHETIC.csv lsass_context_SYNTHETIC.json
                                          [--window 30] [--json out.json]
"""
import argparse, csv, json, sys
from datetime import datetime, timedelta

USER_WRITABLE = ("\\users\\", "\\temp\\", "\\appdata\\", "\\programdata\\", "\\downloads\\", "\\public\\")
UNUSUAL_PARENTS = ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "chrome.exe", "msedge.exe",
                   "acrord32.exe", "wscript.exe", "mshta.exe")
VM_READ = 0x0010          # PROCESS_VM_READ — needed to read LSASS memory
BENIGN_MASKS = (0x1000, 0x0400, 0x1400)   # query-limited / query-information only


def ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")


def load_events(path):
    out = []
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            try:
                r["_t"] = ts(r["ts"]); r["event_id"] = int(r["event_id"])
            except (KeyError, ValueError, TypeError):
                continue
            out.append(r)
    out.sort(key=lambda r: r["_t"])
    return out


def load_context(path):
    if not path:
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def base(path):
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def classify_lsass_access(e, ctx):
    """Mission 04 logic: judge WHO touched LSASS and HOW, never the fact that lsass.exe exists."""
    if e["event_id"] != 10 or base(e.get("target", "")) != "lsass.exe":
        return None
    approved = {p.lower() for p in ctx.get("approved_lsass_readers", [])}
    img = e.get("process", "")
    reasons = []
    try:
        mask = int(e.get("granted_access") or "0", 16)
    except ValueError:
        mask = 0
    is_approved = img.lower() in approved and e.get("signed") == "true"
    if not is_approved:
        reasons.append("source image not on the approved LSASS-reader list")
    if e.get("signed") != "true":
        reasons.append("binary is unsigned")
    if any(p in img.lower() for p in USER_WRITABLE) and not is_approved:
        reasons.append("runs from a user-writable path")
    if mask & VM_READ and not is_approved:
        reasons.append(f"GrantedAccess {e.get('granted_access')} includes PROCESS_VM_READ")
    verdict = "EXPECTED" if is_approved else ("SUSPICIOUS" if len(reasons) >= 2 else "REVIEW")
    return {"verdict": verdict, "reasons": reasons, "image": img, "mask": e.get("granted_access"),
            "signed": e.get("signed"), "hash": e.get("hash"), "ts": e["ts"], "host": e["host"], "user": e["user"]}


def has_ticket(ctx, host, user, when, src_ip):
    for t in ctx.get("change_tickets", []):
        if t["host"] == host and t["user"] == user and t["date"] == when.strftime("%Y-%m-%d") \
                and t.get("source", src_ip) == src_ip:
            return t["id"]
    return None


def assess_admin_logons(events, ctx, exclude_src=()):
    """H2 control: privileged network logons that did NOT originate from a flagged host."""
    users, out = ctx.get("users", {}), []
    for e in events:
        if e["event_id"] == 4624 and e["logon_type"] in ("3", "10") and users.get(e["user"], {}).get("privileged") \
                and e["src_host"] not in exclude_src:
            ticket = has_ticket(ctx, e["host"], e["user"], e["_t"], e["src_ip"])
            ok_src = e["src_ip"] in users[e["user"]].get("approved_sources", [])
            out.append({"ts": e["ts"], "user": e["user"], "host": e["host"], "src": e["src_host"],
                        "ticket": ticket, "approved_source": ok_src,
                        "verdict": "LEGITIMATE" if ok_src and (ticket or "INC-" in e.get("detail", "")) else
                                   ("LIKELY LEGITIMATE" if ok_src else "REVIEW")})
    return out


def investigate(events, ctx, window_min=30):
    assets, users = ctx.get("assets", {}), ctx.get("users", {})
    sensitive = {s.lower() for s in ctx.get("sensitive_shares", [])}
    accesses = [a for a in (classify_lsass_access(e, ctx) for e in events) if a]
    cases, flagged_hosts = [], set()
    for a in accesses:
        if a["verdict"] == "EXPECTED" or a["host"] in flagged_hosts:
            continue
        host, t0 = a["host"], ts(a["ts"])
        flagged_hosts.add(host)
        host_ip = assets.get(host, {}).get("ip", "")
        t_end = t0 + timedelta(minutes=window_min)
        inwin = [e for e in events if t0 <= e["_t"] <= t_end]
        from_host = lambda e: e.get("src_host") == host or (host_ip and e.get("src_ip") == host_ip)

        # -- Mission 01: the process behind the access --
        proc = next((e for e in events if e["event_id"] in (1, 4688) and e["host"] == host
                     and e["process"].lower() == a["image"].lower()
                     and t0 - timedelta(minutes=10) <= e["_t"] <= t0), None)
        parent = proc["parent"] if proc else ""
        unusual_parent = base(parent) in UNUSUAL_PARENTS
        session = next((e for e in reversed(events) if e["event_id"] == 4624 and e["host"] == host
                        and e["logon_type"] in ("2", "10", "11") and e["_t"] <= t0), None)
        same_hash_hosts = sorted({e["host"] for e in events if a["hash"] and e.get("hash") == a["hash"]})
        edr = [e for e in inwin if e["channel"] == "EDR" and e["host"] == host]

        # -- authentication that followed --
        fails = [e for e in inwin if e["event_id"] == 4625 and from_host(e)]
        explicit = [e for e in inwin if e["event_id"] == 4648 and e["host"] == host]
        logons = [e for e in inwin if e["event_id"] == 4624 and e["logon_type"] == "3"
                  and from_host(e) and e["host"] != host]
        accounts = sorted({a["user"]} | {e["user"] for e in logons} |
                          {e["target"].split("@")[0] for e in explicit if e.get("target")})
        accounts = [u for u in accounts if not u.upper().startswith("NT AUTHORITY")]
        priv_accounts = [u for u in accounts if users.get(u, {}).get("privileged")]
        special = [e for e in inwin if e["event_id"] == 4672 and e["user"] in accounts and e["host"] != host]
        krb = [e for e in inwin if e["event_id"] == 4769 and from_host(e)]
        base_spn = {e["service"] for e in events if e["event_id"] == 4769 and e["_t"] < t0 and from_host(e)}
        krb_unusual = [e for e in krb if "RC4" in e["detail"] or e["service"] not in base_spn]
        shares = [e for e in inwin if e["event_id"] in (5140, 5145) and e["user"] in accounts
                  and (not host_ip or e["src_ip"] == host_ip)]
        sens = [e for e in shares if e.get("share", "").lower() in sensitive]
        dests = {}
        for e in logons:
            prior = sum(1 for x in events if x["event_id"] == 4624 and x["user"] == e["user"]
                        and x["host"] == e["host"] and from_host(x) and x["_t"] < t0)
            dests.setdefault(e["host"], {"role": assets.get(e["host"], {}).get("role", "unknown"),
                                         "accounts": set(), "prior_30d": 0, "auth": set()})
            dests[e["host"]]["accounts"].add(e["user"]); dests[e["host"]]["prior_30d"] += prior
            dests[e["host"]]["auth"].add(e["auth_pkg"])
        new_dests = [h for h, d in dests.items() if d["prior_30d"] == 0]
        other_ws = [h for h, d in dests.items() if d["role"] == "Workstation"]
        tickets = [t for t in (has_ticket(ctx, e["host"], e["user"], e["_t"], e["src_ip"]) for e in logons) if t]

        # -- Mission 02 verdicts --
        h1 = list(a["reasons"])
        if unusual_parent: h1.append(f"unusual parent {base(parent)}")
        if edr: h1.append("EDR credential-access alert on the same process")
        if same_hash_hosts == [host]: h1.append("hash first-seen, present on this host only")
        h1v = "SUPPORTED" if len(h1) >= 3 else ("POSSIBLE" if h1 else "NOT SUPPORTED")

        h2 = []
        if tickets: h2.append("change ticket " + ", ".join(tickets))
        if priv_accounts and all(host_ip in users.get(u, {}).get("approved_sources", []) for u in priv_accounts):
            h2.append("privileged account used from an approved admin source")
        h2_against = []
        if not tickets: h2_against.append("no change/incident ticket for the destinations")
        if priv_accounts and not h2: h2_against.append(f"{host} is not an approved admin source for " + ", ".join(priv_accounts))
        if unusual_parent: h2_against.append("admin tools are not spawned by an Office application")
        h2v = "SUPPORTED" if h2 and not h2_against else ("REJECTED" if h2_against and not h2 else "INCONCLUSIVE")

        h3 = []
        if explicit and priv_accounts:
            h3.append("explicit credentials (4648) for privileged " + ", ".join(priv_accounts))
        if new_dests: h3.append("new destinations (0 prior logons): " + ", ".join(sorted(new_dests)))
        if sens: h3.append(f"{len(sens)} reads on sensitive share {sens[0]['share']}")
        if other_ws: h3.append("same account on another workstation: " + ", ".join(sorted(other_ws)))
        if krb_unusual: h3.append(f"{len(krb_unusual)} unusual service tickets (RC4 / first-seen SPN)")
        if len(fails) >= 3: h3.append(f"{len(fails)} failed network logons from {host} first")
        h3v = "SUPPORTED" if len(h3) >= 2 else ("POSSIBLE" if h3 else "NOT SUPPORTED")

        # -- Mission 07 correlation --
        first_srv = min((e["_t"] for e in logons if dests[e["host"]]["role"] != "Workstation"), default=None)
        first_ws = min((e["_t"] for e in logons if dests[e["host"]]["role"] == "Workstation"), default=None)
        corr = {
            "A_lsass_access": True,
            "B_type3_to_server": bool(first_srv),
            "C_other_workstation": bool(first_ws),
            "D_sensitive_share": bool(sens),
        }
        score = sum(corr.values())
        severity = {4: "CRITICAL", 3: "HIGH", 2: "HIGH"}.get(score, "MEDIUM")
        gaps = {"A_to_B_min": round((first_srv - t0).total_seconds() / 60, 1) if first_srv else None,
                "A_to_C_min": round((first_ws - t0).total_seconds() / 60, 1) if first_ws else None}

        # -- Mission 05 scope --
        dcs = sorted({e["host"] for e in krb})
        scope = [f"{host} (source — isolate, preserve memory + Sysmon/EDR)"]
        scope += [f"{d} (Domain Controller — 4768/4769/4776 for " + ", ".join(accounts) + ")" for d in dcs]
        scope += [f"{h} ({d['role']} — logons by " + ", ".join(sorted(d['accounts'])) + ")"
                  for h, d in sorted(dests.items(), key=lambda kv: kv[1]["role"] == "Workstation")]
        spn_hosts = sorted({e["service"].split("/")[1].split(":")[0] for e in krb_unusual} - set(dests) - {host})
        scope += [f"{h} (service ticket requested — check for a later logon)" for h in spn_hosts]

        # -- Mission 03 timeline --
        tl = []
        if session: tl.append((session["_t"], "4624/" + session["logon_type"], f"{session['user']} logs on to {host}"))
        if proc: tl.append((proc["_t"], str(proc["event_id"]), f"{base(parent)} → {base(a['image'])} (signed={proc['signed']})"))
        tl.append((t0, "Sysmon10", f"{base(a['image'])} accesses lsass.exe GrantedAccess={a['mask']}"))
        for e in edr: tl.append((e["_t"], "EDR", e["detail"]))
        if fails: tl.append((fails[0]["_t"], "4625", f"first of {len(fails)} failed network logons from {host} "
                             f"({', '.join(sorted({e['user'] for e in fails}))})"))
        for e in explicit: tl.append((e["_t"], "4648", f"{e['user']} uses explicit credentials for {e['target']}"))
        for e in logons: tl.append((e["_t"], "4624/3", f"{e['user']} → {e['host']} ({e['auth_pkg']})"))
        for e in special: tl.append((e["_t"], "4672", f"{e['user']} on {e['host']}: {e['detail']}"))
        if krb: tl.append((krb[0]["_t"], "4769", f"{len(krb)} service tickets: " + ", ".join(e["service"] for e in krb)))
        if shares: tl.append((shares[0]["_t"], "5145", f"{len(shares)} file reads on {shares[0]['share']} by {shares[0]['user']}"))
        tl.sort(key=lambda x: x[0])

        cases.append({
            "triage": {"host": host, "ip": host_ip, "session_user": session["user"] if session else a["user"],
                       "process": a["image"], "parent": parent, "cmdline": proc["cmdline"] if proc else "",
                       "signed": a["signed"], "hash": a["hash"], "granted_access": a["mask"],
                       "lsass_access_ts": a["ts"], "hash_seen_on": same_hash_hosts,
                       "accounts_involved": accounts, "privileged_accounts": priv_accounts,
                       "failed_logons": len(fails), "successful_type3": len(logons),
                       "explicit_credential_events": len(explicit), "edr_alerts": len(edr)},
            "hypotheses": {"H1": {"verdict": h1v, "evidence": h1},
                           "H2": {"verdict": h2v, "evidence": h2 or h2_against},
                           "H3": {"verdict": h3v, "evidence": h3 or ["no onward authentication observed"]}},
            "detection": {"name": "Suspicious LSASS Process Access", "fired": True,
                          "severity": severity, "reasons": a["reasons"]},
            "correlation": {"signals": corr, "score": f"{score}/4", "gaps": gaps},
            "destinations": {h: {"role": d["role"], "accounts": sorted(d["accounts"]),
                                 "prior_30d": d["prior_30d"], "auth": sorted(d["auth"])} for h, d in dests.items()},
            "kerberos_unusual": [e["service"] for e in krb_unusual],
            "sensitive_files": [e["detail"] for e in sens],
            "investigate_next": scope,
            "timeline": [(t.strftime("%Y-%m-%d %H:%M:%SZ"), k, d) for t, k, d in tl],
        })
    expected = [a for a in accesses if a["verdict"] == "EXPECTED"]
    return {"cases": cases,
            "lsass_access_summary": {"total": len(accesses), "expected": len(expected),
                                     "suspicious": len(accesses) - len(expected),
                                     "expected_images": sorted({base(a["image"]) for a in expected})},
            "admin_controls": assess_admin_logons(events, ctx, exclude_src=flagged_hosts)}


def render(r):
    s = r["lsass_access_summary"]
    out = ["=" * 78, f"GraySentinel DSOU · Silent Credential Theft hunt · {len(r['cases'])} case(s)", "=" * 78,
           f"LSASS access events: {s['total']} total · {s['expected']} expected ({', '.join(s['expected_images'])}) "
           f"· {s['suspicious']} suspicious"]
    for c in r["cases"]:
        t, d = c["triage"], c["detection"]
        out.append(f"\n[{d['severity']:<8}] {t['host']} ({t['ip']}) session={t['session_user']}  correlation={c['correlation']['score']}")
        out.append("  -- Mission 01 triage --")
        for k in ("process", "parent", "cmdline", "signed", "hash", "granted_access", "lsass_access_ts",
                  "hash_seen_on", "accounts_involved", "privileged_accounts", "failed_logons",
                  "successful_type3", "explicit_credential_events", "edr_alerts"):
            out.append(f"   {k:<27} {t[k]}")
        out.append("  -- Mission 02 hypotheses --")
        for h, v in c["hypotheses"].items():
            out.append(f"   {h} {v['verdict']:<13} " + " | ".join(v["evidence"]))
        out.append("  -- Mission 03 timeline --")
        for when, k, desc in c["timeline"]:
            out.append(f"   {when}  {k:<9} {desc}")
        out.append("  -- Mission 05 scope: investigate next --")
        for i, x in enumerate(c["investigate_next"], 1):
            out.append(f"   {i}. {x}")
        out.append("  -- Mission 07 correlation --")
        out.append("   " + "  ".join(f"{k}={'YES' if v else 'no'}" for k, v in c["correlation"]["signals"].items()))
        out.append(f"   gaps: A→B {c['correlation']['gaps']['A_to_B_min']} min · A→C {c['correlation']['gaps']['A_to_C_min']} min")
    out.append("\n  -- H2 control: privileged logons NOT from a flagged host --")
    for a in r["admin_controls"]:
        out.append(f"   {a['ts']}  {a['user']} → {a['host']} from {a['src']}  ticket={a['ticket']}  {a['verdict']}")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="GraySentinel DSOU Silent Credential Theft hunter")
    ap.add_argument("events"); ap.add_argument("context", nargs="?")
    ap.add_argument("--window", type=int, default=30); ap.add_argument("--json")
    a = ap.parse_args(argv)
    try:
        events = load_events(a.events); ctx = load_context(a.context)
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr); return 2
    r = investigate(events, ctx, a.window)
    print(render(r))
    if a.json:
        with open(a.json, "w") as f:
            json.dump(r, f, indent=2, default=str)
    return 1 if r["cases"] else 0


if __name__ == "__main__":
    sys.exit(main())
