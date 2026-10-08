#!/usr/bin/env python3
"""
session_trust_analyzer.py — GraySentinel SSOU war-room "Ghost Session".

BLUE-TEAM analyzer for the lab's adversary simulation (detection only — no offensive code).
Reads unified IdP + cloud + remote-access + file-server + proxy + EDR telemetry and asks the
question behind the whole operation: *is this legitimate session being used by its owner?*

It scores every session on five dimensions —  Device + Location + Time + Behaviour + Resource —
rebuilds the identity attack timeline (Mission 06), finds the pivot event that turns an
"unusual login" into a potential identity compromise, answers WHO / WHERE / WHEN / WHAT / HOW /
IMPACT (Mission 08 success criteria) and recommends Monitor / Investigate / Contain (Mission 11).

It only reads logs. Python 3.8+, standard library only.

usage: python3 session_trust_analyzer.py session_telemetry_SYNTHETIC.csv session_context_SYNTHETIC.json
                                         [--day 2026-10-08] [--json out.json]
"""
import argparse, csv, json, sys
from datetime import datetime, timedelta

IST = timedelta(hours=5, minutes=30)
RISK_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")


def load(path):
    out = []
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            try:
                r["_t"] = ts(r["ts"]); r["_n"] = int(r.get("count") or 0)
            except (KeyError, ValueError, TypeError):
                continue
            if not r.get("source") or not r.get("action"):
                continue
            out.append(r)
    out.sort(key=lambda r: r["_t"])
    return out


def ist_hour(dt):
    return (dt + IST).hour


def analyze(events, ctx, day=None):
    users = ctx.get("users", {})
    managed = ctx.get("managed_devices", {})
    sensitive = set(ctx.get("sensitive_resources", []))
    if day is None:
        day = max(e["_t"] + IST for e in events).strftime("%Y-%m-%d") if events else ""
    today = [e for e in events if (e["_t"] + IST).strftime("%Y-%m-%d") == day]
    timeline, findings = [], []
    sessions, token_geo = {}, {}

    def flag(e, dim, kind, risk, conf, evidence, owner_explainable=True):
        findings.append({"ts": e["ts"], "dimension": dim, "kind": kind, "risk": risk, "confidence": conf,
                         "evidence": evidence, "owner_explainable": owner_explainable,
                         "session": e.get("session_id") or sess_of(e)})

    def sess_of(e):
        """file-server / proxy rows have no session id — attribute them by device."""
        for sid, s in sessions.items():
            if e["device"] in s["devices"]:
                return sid
        return ""

    for e in today:
        prof = users.get(e["user"], {})
        before = len(findings)
        sid = e.get("session_id")
        if sid:
            s = sessions.setdefault(sid, {"session": sid, "first": e["ts"], "devices": set(), "ips": set(),
                                          "countries": set(), "apps": set(), "mfa": e.get("mfa") or "", "last": e["ts"]})
            s["devices"].add(e["device"]); s["ips"].add(e["src_ip"]); s["last"] = e["ts"]
            if e["country"]: s["countries"].add(e["country"])
            if e["app"]: s["apps"].add(e["app"])
        # ---- DEVICE ----
        if e["source"] == "idp" and e["action"] in ("signin", "session_created") and e["device"] not in managed:
            flag(e, "Device", "session on an unregistered device", "MEDIUM", "Medium",
                 f"{e['device']} is not a managed/compliant device ({e['detail'].split(';')[0]})")
        if e["source"] == "idp" and e["action"] == "session_created" and e.get("mfa") == "inherited":
            flag(e, "Device", "new session without a fresh MFA challenge", "MEDIUM", "Medium",
                 "MFA status 'satisfied' was inherited from existing session context, not re-proved")
        # ---- LOCATION ----
        if e.get("token_id") and e["country"]:
            seen = token_geo.setdefault(e["token_id"], {})
            other = [(c, t) for c, t in seen.items() if c != e["country"]]
            if other and e["country"] not in seen:
                c0, t0 = other[-1]
                gap = round((e["_t"] - t0).total_seconds() / 60)
                flag(e, "Location", "one session token in two geographies", "CRITICAL", "High",
                     f"token {e['token_id']} used from {c0} and then {e['country']} ({e['src_ip']}) {gap} min apart — "
                     "a session does not travel; the owner's laptop session is still active", owner_explainable=False)
            seen[e["country"]] = e["_t"]
        if e["country"] and prof.get("countries") and e["country"] not in prof["countries"] \
                and e["action"] not in ("token_use",):
            flag(e, "Location", "activity from a country outside the identity baseline", "HIGH", "Medium",
                 f"{e['country']} ({e['src_ip']}); baseline {'/'.join(prof['countries'])}")
        # concurrent environments: a second live session for the identity from a different device
        if e["source"] == "idp" and e["action"] == "session_created":
            live = [s for k, s in sessions.items() if k != sid and not (s["devices"] & {e["device"]})]
            if live:
                flag(e, "Location", "identity active in two environments at once", "MEDIUM", "Medium",
                     f"{sid} on {e['device']} via {e['src_ip']} while {live[0]['session']} is live on "
                     f"{', '.join(sorted(live[0]['devices']))}")
        # ---- TIME ----
        wh = prof.get("work_hours_ist")
        if wh and e["source"] in ("idp", "cloud", "fileserver") and not (wh[0] <= ist_hour(e["_t"]) < wh[1]):
            flag(e, "Time", "session active outside working hours", "MEDIUM", "Medium",
                 f"{(e['_t'] + IST).strftime('%H:%M')} IST; normal hours {wh[0]:02d}:00–{wh[1]:02d}:00 — {e['detail'].split(';')[-1].strip()}")
        # ---- BEHAVIOUR ----
        if e["source"] == "cloud" and e["action"] == "app_access" and e["app"] not in prof.get("apps", []):
            flag(e, "Behaviour", "previously unseen application", "MEDIUM", "Medium",
                 f"'{e['app']}' never used by this identity in the 30-day baseline")
            # endpoint/cloud mismatch: did the owner's managed device actually make this request?
            dev_ips = {d["ip"] for d in managed.values()}
            match = any(p["source"] == "proxy" and p["src_ip"] in dev_ips and p["app"] == e["app"]
                        and abs((p["_t"] - e["_t"]).total_seconds()) <= 120 for p in today)
            if not match:
                flag(e, "Behaviour", "cloud says yes, endpoint says no", "HIGH", "High",
                     f"no proxy/DNS record from the owner's managed device for '{e['app']}' at this time")
        if e["source"] == "cloud" and e["action"] == "app_permission_grant":
            flag(e, "Behaviour", "application permission granted from the suspect session", "HIGH", "High",
                 f"'{e['app']}': {e['detail'].split(';')[0]} — a persistence opportunity that outlives the session")
        if e["source"] == "fileserver" and e["action"] == "file_access" and e["_n"] > 5 * prof.get("max_daily_files", 10 ** 9):
            flag(e, "Behaviour", "mass file access", "HIGH", "High",
                 f"{e['_n']} files on {e['resource']}; daily baseline ≤ {prof.get('max_daily_files')}")
        # ---- RESOURCE ----
        if e["source"] == "fileserver" and e["action"] == "auth" and e["resource"] not in prof.get("file_servers", []):
            flag(e, "Resource", "first-seen internal resource", "HIGH" if e["resource"] in sensitive else "MEDIUM", "Medium",
                 f"{e['resource']} from {e['device']} ({e['src_ip']}); {e['detail'].split(';')[0]}; "
                 f"baseline servers {prof.get('file_servers')}")
        new = findings[before:]
        risk = max((f["risk"] for f in new), key=RISK_ORDER.get, default="INFO")
        conf = "High" if any(f["confidence"] == "High" for f in new) else ("Medium" if new else "High")
        timeline.append({
            "ts": e["ts"], "ist": (e["_t"] + IST).strftime("%H:%M"), "identity": e["user"], "device": e["device"],
            "source": e["src_ip"] or e["source"], "destination": e["resource"] or e["app"] or e["source"].upper(),
            "action": e["action"], "risk": risk, "confidence": conf,
            "evidence": "; ".join(f["kind"] for f in new) or (e["detail"] or "matches baseline")})

    for s in sessions.values():
        fs = [f for f in findings if f["session"] == s["session"]]
        s["dimensions_failed"] = sorted({f["dimension"] for f in fs})
        s["trust"] = "TRUSTED" if not fs else ("NOT THE OWNER" if any(not f["owner_explainable"] for f in fs)
                                               else "UNVERIFIED")
        for k in ("devices", "ips", "countries", "apps"):
            s[k] = sorted(x for x in s[k] if x)
    pivot = next((f for f in findings if not f["owner_explainable"]), None)
    ghost = next((s for s in sessions.values() if s["trust"] != "TRUSTED"), None)
    gdev = set(ghost["devices"]) if ghost else set()
    touched = sorted({e["resource"] for e in today if e["device"] in gdev and e["resource"]} |
                     {e["app"] for e in today if e["device"] in gdev and e["app"]})
    sens_hit = sorted(x for x in touched if x in sensitive)
    files = sum(e["_n"] for e in today if e["device"] in gdev and e["action"] == "file_access")
    grants = [e["app"] for e in today if e["action"] == "app_permission_grant" and e["device"] in gdev]
    dims = sorted({f["dimension"] for f in findings})
    if pivot and sens_hit: decision = "CONTAIN"
    elif len(dims) >= 2: decision = "INVESTIGATE"
    else: decision = "MONITOR"
    answers = {}
    if ghost:
        answers = {
            "WHO": f"{today[0]['user']} — the identity; session {ghost['session']} is assessed as {ghost['trust']}",
            "WHERE": f"{', '.join(ghost['devices'])} via {', '.join(ghost['ips'])} ({'/'.join(ghost['countries'])}); "
                     f"owner on {', '.join(sorted(managed))}",
            "WHEN": f"{(ts(ghost['first']) + IST).strftime('%H:%M')}–{(ts(ghost['last']) + IST).strftime('%H:%M')} IST on {day}",
            "WHAT": ", ".join(touched),
            "HOW": f"valid session context — MFA '{ghost['mfa']}', no new password or MFA event, no malware on the endpoint",
            "IMPACT": f"{files} files read; sensitive resources reached: {', '.join(sens_hit)}; application grants: {', '.join(grants) or 'none'}",
        }
    return {"day": day, "decision": decision, "dimensions_failed": dims, "sessions": list(sessions.values()),
            "pivot_event": pivot, "findings": findings, "timeline": timeline, "answers": answers,
            "exposure": {"files": files, "sensitive_resources": sens_hit, "app_grants": grants},
            "edr_verdict": next((e["result"] for e in today if e["source"] == "edr"), "n/a")}


def render(r):
    out = ["=" * 78, f"GraySentinel SSOU · Ghost Session — session-trust analysis (blue-team view) · {r['day']}",
           "=" * 78, f"Decision: {r['decision']}   ·   dimensions failed: {' + '.join(r['dimensions_failed']) or 'none'}"
           f"   ·   EDR verdict on the endpoint: {r['edr_verdict']}", "", "SESSIONS"]
    for s in r["sessions"]:
        out.append(f"  {s['session']}  {s['trust']:<14} devices={s['devices']} ips={s['ips']} countries={s['countries']} "
                   f"mfa={s['mfa']} failed={s['dimensions_failed']}")
    out.append("\nIDENTITY ATTACK TIMELINE (IST)")
    for t in r["timeline"]:
        out.append(f"  {t['ist']}  {t['risk']:<8} {t['device']:<16} {t['source']:<14} → {t['destination']:<22} "
                   f"{t['action']:<20} conf={t['confidence']:<6} {t['evidence']}")
    p = r["pivot_event"]
    out.append("\nPIVOT EVENT (unusual login → potential identity compromise)")
    out.append(f"  {p['ts']}  {p['kind']} — {p['evidence']}" if p else "  none — every anomaly is still owner-explainable")
    out.append("\nFINDINGS BY DIMENSION")
    for f in r["findings"]:
        out.append(f"  [{f['risk']:<8}] {f['dimension']:<9} {(ts(f['ts']) + IST).strftime('%H:%M')}  {f['kind']} — {f['evidence']}")
    out.append("\nBLUE-TEAM SUCCESS CRITERIA")
    for k, v in r["answers"].items():
        out.append(f"  {k:<7} {v}")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="GraySentinel SSOU Ghost Session blue-team analyzer")
    ap.add_argument("telemetry"); ap.add_argument("context", nargs="?")
    ap.add_argument("--day"); ap.add_argument("--json")
    a = ap.parse_args(argv)
    try:
        events = load(a.telemetry)
        ctx = {}
        if a.context:
            with open(a.context, encoding="utf-8") as f:
                ctx = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr); return 2
    r = analyze(events, ctx, a.day)
    print(render(r))
    if a.json:
        with open(a.json, "w") as f:
            json.dump(r, f, indent=2, default=str)
    return 0 if r["decision"] == "MONITOR" else 1


if __name__ == "__main__":
    sys.exit(main())
