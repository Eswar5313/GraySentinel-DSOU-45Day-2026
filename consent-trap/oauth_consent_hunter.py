#!/usr/bin/env python3
"""
oauth_consent_hunter.py — GraySentinel RIU war-room "Consent Trap".

Defensive CTI/hunt tool. Reads a unified cloud audit export (Entra audit + sign-in + Graph +
Exchange + SharePoint + proxy, one CSV) plus tenant context (JSON) and produces:

  Mission 04  Cloud Application Compromise Hunt Table (NORMAL / SUSPICIOUS / HIGH PRIORITY + why)
  Mission 05  IoC list + the detection hypothesis
              "new OAuth application consent followed by unusual cloud activity"
  Mission 08  affected users, exposure, and what to revoke first

It only reads logs. Python 3.8+, standard library only. It never contacts any tenant or API.

usage: python3 oauth_consent_hunter.py cloud_audit_SYNTHETIC.csv consent_context_SYNTHETIC.json
                                       [--window 60] [--json out.json]
"""
import argparse, csv, json, re, sys
from datetime import datetime, timedelta

DATA_SOURCES = ("exchange_audit", "sharepoint_audit")
IST = timedelta(hours=5, minutes=30)


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


def is_consent(e):
    return e["source"] == "entra_audit" and e["action"] == "Consent to application"


def profile_apps(events, ctx):
    """Static risk attributes of every application that received a consent grant."""
    approved = ctx.get("approved_apps", {})
    risky = set(ctx.get("high_risk_scopes", []))
    bait = ctx.get("trust_bait_words", [])
    users = ctx.get("users", {})
    apps = {}
    for e in events:
        if not is_consent(e):
            continue
        a = apps.setdefault(e["app_id"], {
            "app_id": e["app_id"], "name": e["app_name"], "publisher": e["publisher"],
            "publisher_verified": e["publisher_verified"] == "true", "first_consent": e["ts"],
            "scopes": set(), "consents": [], "reply_domains": set()})
        a["scopes"] |= set(e["scopes"].split())
        a["consents"].append({"ts": e["ts"], "user": e["user"], "type": e["consent_type"],
                              "by_admin": bool(users.get(e["user"], {}).get("admin"))})
        a["reply_domains"] |= set(re.findall(r"https?://([a-z0-9.\-]+)", e.get("detail", "")))
    for aid, a in apps.items():
        first = ts(a["first_consent"])
        seen_before = any(x["app_id"] == aid and x["_t"] < first for x in events)
        hi = sorted(a["scopes"] & risky)
        data = [s for s in hi if s.split(".")[0] in ("Mail", "Files", "Sites")]
        flags = []
        if aid not in approved: flags.append("not on the approved-application list")
        if not seen_before and aid not in approved: flags.append("first-seen application in the tenant")
        if not a["publisher_verified"]: flags.append("publisher not verified")
        if data: flags.append("high-risk data scopes: " + ", ".join(data))
        if data and "offline_access" in a["scopes"]: flags.append("offline_access = access survives the session (refresh token)")
        if any(not c["by_admin"] and c["type"] == "Principal" for c in a["consents"]) and data:
            flags.append("granted by end-user consent, not admin review")
        words = [w for w in bait if w in a["name"].lower()]
        if len(words) >= 2 and not a["publisher_verified"]:
            flags.append("generic trust-bait name (" + ", ".join(words) + ")")
        a["flags"], a["risk_attributes"] = flags, len(flags)
        a["approved"] = aid in approved
        a["scopes"], a["reply_domains"] = sorted(a["scopes"]), sorted(a["reply_domains"])
        a["users"] = sorted({c["user"] for c in a["consents"]})
    return apps


def hunt(events, ctx, window_min=60):
    users = ctx.get("users", {})
    apps = profile_apps(events, ctx)
    risky_ids = {aid for aid, a in apps.items() if not a["approved"] and a["risk_attributes"] >= 3}
    table, state = [], {aid: {"users": set(), "data_anomaly": False} for aid in apps}
    for e in events:
        aid = e.get("app_id")
        if aid not in apps:
            continue
        a, st, why = apps[aid], state[aid], []
        prof = users.get(e["user"], {})
        if aid not in risky_ids:
            if is_consent(e) or e["_t"] >= ts(a["first_consent"]):
                reason = "approved application" if a["approved"] else \
                    "verified publisher, low-risk scope only (" + " ".join(a["scopes"]) + ")"
                table.append(row(e, "NORMAL", [reason]))
            continue
        if is_consent(e):
            why += a["flags"][:4]
            if st["users"] - {e["user"]}:
                why.insert(0, f"second user consenting to the same app (after {', '.join(sorted(st['users']))})")
            level = "HIGH PRIORITY" if (st["users"] - {e["user"]}) or st["data_anomaly"] else "SUSPICIOUS"
            st["users"].add(e["user"])
        else:
            consent_t = next((ts(c["ts"]) for c in a["consents"] if c["user"] == e["user"]), None)
            if consent_t and e["_t"] >= consent_t:
                why.append(f"{round((e['_t'] - consent_t).total_seconds() / 60)} min after consent")
            geo = e.get("country") and prof.get("countries") and e["country"] not in prof["countries"]
            if geo: why.append(f"source {e['src_ip']} in {e['country']} — user baseline {'/'.join(prof['countries'])}")
            anomaly = False
            if e["source"] == "sharepoint_audit" and e.get("object") not in prof.get("sites", []):
                why.append(f"{e['_n']} files on '{e['object']}' — site outside the user's 30-day baseline"); anomaly = True
            if e["source"] == "exchange_audit":
                why.append(f"{e['_n']} mail items via app token (non-interactive)"); anomaly = anomaly or bool(geo)
            multi = len(st["users"]) >= 2
            if multi: why.append(f"same app active for {len(st['users'])} users")
            if anomaly: st["data_anomaly"] = True
            level = "HIGH PRIORITY" if anomaly or multi or (st["data_anomaly"] and e["source"] in DATA_SOURCES) \
                else "SUSPICIOUS"
        table.append(row(e, level, why))

    # ---- detection hypothesis: risky consent followed by unusual cloud activity ----
    detections = []
    for aid in sorted(risky_ids):
        a = apps[aid]
        for c in a["consents"]:
            t0, u = ts(c["ts"]), c["user"]
            prof = users.get(u, {})
            after = [e for e in events if e.get("app_id") == aid and e["user"] == u and not is_consent(e)
                     and t0 <= e["_t"] <= t0 + timedelta(minutes=window_min)]
            first_api = next((e for e in after if e["source"] == "graph_activity"), None)
            mail = [e for e in after if e["source"] == "exchange_audit"]
            files = [e for e in after if e["source"] == "sharepoint_audit"]
            foreign = sorted({e["country"] for e in after if e["country"] not in prof.get("countries", [])})
            new_sites = sorted({e["object"] for e in files if e["object"] not in prof.get("sites", [])})
            delta = lambda e: round((e["_t"] - t0).total_seconds() / 60, 1) if e else None
            detections.append({
                "user": u, "app_id": aid, "app_name": a["name"], "publisher": a["publisher"],
                "permissions": a["scopes"], "consent_ts": c["ts"],
                "source_ips": sorted({e["src_ip"] for e in after}), "countries": foreign,
                "api_requests": sum(e["_n"] for e in after if e["source"] == "graph_activity"),
                "mail_items": sum(e["_n"] for e in mail), "files": sum(e["_n"] for e in files),
                "new_sites": new_sites,
                "consent_to_first_api_min": delta(first_api),
                "consent_to_first_data_min": delta(min(mail + files, key=lambda e: e["_t"]) if mail + files else None),
                "fired": bool(after) and (bool(foreign) or bool(new_sites)),
            })

    # ---- IoCs + delivery evidence ----
    osint = ctx.get("osint_SIMULATED", {})
    iocs, delivery = [], []
    for aid in sorted(risky_ids):
        a = apps[aid]
        act = [e for e in events if e.get("app_id") == aid and not is_consent(e)]
        clicks = [e for e in events if e["source"] == "proxy" and aid in e.get("detail", "")]
        delivery += [{"ts": e["ts"], "user": e["user"], "url": e["object"]} for e in clicks]
        doms = sorted(set(a["reply_domains"]) | {re.sub(r"^https?://([^/]+).*", r"\1", e["object"]) for e in clicks})
        iocs.append({
            "application_name": a["name"], "application_id": aid, "publisher": a["publisher"],
            "publisher_verified": a["publisher_verified"], "redirect_uri_domains": a["reply_domains"],
            "domains": doms, "related_domains_osint": sorted({d for x in doms for d in osint.get(x, {}).get("co_hosted", [])}),
            "source_ips": sorted({e["src_ip"] for e in act}), "countries": sorted({e["country"] for e in act}),
            "permissions": a["scopes"], "consenting_users": a["users"], "first_consent": a["first_consent"]})

    affected = sorted({d["user"] for d in detections})
    multi_user = any(len(apps[aid]["users"]) >= 2 for aid in risky_ids)
    fired = [d for d in detections if d["fired"]]
    if fired and multi_user: assessment, conf = "IDENTITY-BASED INTRUSION VIA OAUTH CONSENT (campaign: multiple users)", "HIGH"
    elif fired: assessment, conf = "LIKELY MALICIOUS OAUTH CONSENT (single user)", "MEDIUM"
    elif risky_ids: assessment, conf = "UNREVIEWED RISKY APPLICATION — no abnormal activity yet", "LOW"
    else: assessment, conf = "NO RISKY CONSENT OBSERVED", "HIGH"
    return {"assessment": assessment, "confidence": conf, "attribution": "none — no evidence ties this to a named actor",
            "hunt_table": table, "applications": {k: v for k, v in apps.items()},
            "detections": detections, "iocs": iocs, "delivery": delivery, "affected_users": affected,
            "revoke_first": [f"delegated grant + refresh tokens: {d['user']} → {d['app_name']}" for d in detections]
                            + [f"disable service principal {i['application_id']} tenant-wide" for i in iocs]}


def row(e, level, why):
    return {"ts": e["ts"], "ist": (e["_t"] + IST).strftime("%d %b %H:%M:%S"), "user": e["user"], "application": e["app_name"],
            "event": e["action"] + (f" ×{e['_n']}" if e["_n"] else ""), "risk": level, "why": "; ".join(why)}


def render(r):
    icon = {"NORMAL": "NORMAL       ", "SUSPICIOUS": "SUSPICIOUS   ", "HIGH PRIORITY": "HIGH PRIORITY"}
    out = ["=" * 78, "GraySentinel RIU · Consent Trap — OAuth consent abuse hunt", "=" * 78,
           f"Assessment: {r['assessment']}", f"Confidence: {r['confidence']} · Attribution: {r['attribution']}",
           f"Affected users: {', '.join(r['affected_users']) or 'none'}", "",
           "CLOUD APPLICATION COMPROMISE HUNT TABLE (activity after each app's first consent; times IST)"]
    shown = [x for x in r["hunt_table"] if x["risk"] != "NORMAL" or "Consent" in x["event"]]
    norm = len(r["hunt_table"]) - len(shown)
    for x in shown:
        out.append(f"  {x['ist']}  {icon[x['risk']]}  {x['user']:<13} {x['application']:<29} {x['event']:<26} — {x['why']}")
    out.append(f"  (+ {norm} NORMAL activity rows of approved applications not listed)")
    out.append("\nAPPLICATION RISK PROFILE")
    for a in r["applications"].values():
        out.append(f"  {a['name']} [{a['app_id']}] publisher={a['publisher']} verified={a['publisher_verified']} "
                   f"risk_attributes={a['risk_attributes']} users={a['users']}")
        for f in a["flags"]:
            out.append(f"     - {f}")
    out.append("\nDETECTION HYPOTHESIS — new OAuth consent followed by unusual cloud activity")
    for d in r["detections"]:
        out.append(f"  fired={d['fired']}  {d['user']} → {d['app_name']}  consent {d['consent_ts']}  "
                   f"first API +{d['consent_to_first_api_min']} min  first data +{d['consent_to_first_data_min']} min  "
                   f"countries={d['countries']}  api={d['api_requests']} mail={d['mail_items']} files={d['files']} "
                   f"new_sites={d['new_sites']}")
    out.append("\nINDICATORS")
    for i in r["iocs"]:
        for k in ("application_name", "application_id", "publisher", "redirect_uri_domains", "domains",
                  "related_domains_osint", "source_ips", "countries", "permissions", "consenting_users"):
            out.append(f"  {k:<22} {i[k]}")
    out.append("\nDELIVERY (lure clicks carrying the same client_id)")
    for d in r["delivery"]:
        out.append(f"  {d['ts']}  {d['user']:<13} {d['url']}")
    out.append("\nREVOKE FIRST")
    for x in r["revoke_first"]:
        out.append(f"  - {x}")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="GraySentinel RIU Consent Trap hunter")
    ap.add_argument("audit"); ap.add_argument("context", nargs="?")
    ap.add_argument("--window", type=int, default=60); ap.add_argument("--json")
    a = ap.parse_args(argv)
    try:
        events = load(a.audit)
        ctx = {}
        if a.context:
            with open(a.context, encoding="utf-8") as f:
                ctx = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr); return 2
    r = hunt(events, ctx, a.window)
    print(render(r))
    if a.json:
        with open(a.json, "w") as f:
            json.dump(r, f, indent=2, default=str)
    return 1 if any(d["fired"] for d in r["detections"]) else 0


if __name__ == "__main__":
    sys.exit(main())
