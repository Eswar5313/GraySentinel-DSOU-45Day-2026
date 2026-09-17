#!/usr/bin/env python3
"""Drill 02 analyzer — Entra ID Sign-in Logs CSV -> 'Timestamp | User | Loc1 → Loc2 | Δt | MFA | Legit? + Why'.
Usage: python3 analyze_impossible_travel.py export.csv [--max-speed 900] [--corp-vpn "Zscaler,Company VPN"]
Uses Latitude/Longitude columns if present (portal export has them), else a built-in mini gazetteer on City."""
import csv, math, argparse, collections
from datetime import datetime

GAZ = {"mumbai":(19.08,72.88),"delhi":(28.61,77.21),"new delhi":(28.61,77.21),"ghaziabad":(28.67,77.42),"noida":(28.54,77.39),
       "gurugram":(28.46,77.03),"bengaluru":(12.97,77.59),"chennai":(13.08,80.27),"hyderabad":(17.39,78.49),"pune":(18.52,73.86),
       "kolkata":(22.57,88.36),"sao paulo":(-23.55,-46.63),"são paulo":(-23.55,-46.63),"london":(51.51,-0.13),"amsterdam":(52.37,4.90),
       "frankfurt":(50.11,8.68),"dubai":(25.20,55.27),"singapore":(1.35,103.82),"new york":(40.71,-74.01),"lagos":(6.52,3.38),
       "moscow":(55.76,37.62),"hong kong":(22.32,114.17),"tokyo":(35.68,139.69),"toronto":(43.65,-79.38),"sydney":(-33.87,151.21)}
VPN_HINTS = ("vpn","proxy","hosting","datacenter","data center","m247","digitalocean","ovh","hetzner","vultr","linode","tor","nord",
             "surfshark","residential","cloud")
REPLAY = ("previously satisfied","claim in the token","satisfied by claim","mfa requirement satisfied")

def col(r,*names):
    for n in names:
        for k in r:
            if k.strip().lower()==n.lower(): return (r[k] or "").strip()
    return ""
def hav(a,b):
    R=6371; p1,p2=math.radians(a[0]),math.radians(b[0]); dp=p2-p1; dl=math.radians(b[1]-a[1])
    h=math.sin(dp/2)**2+math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2; return 2*R*math.asin(math.sqrt(h))
def parse(t):
    for f in ("%Y-%m-%dT%H:%M:%SZ","%Y-%m-%dT%H:%M:%S","%m/%d/%Y, %I:%M:%S %p","%Y-%m-%d %H:%M:%S","%d/%m/%Y %H:%M"):
        try: return datetime.strptime(t,f)
        except ValueError: pass
    return None
def coords(r):
    la,lo=col(r,"Latitude"),col(r,"Longitude")
    if la and lo:
        try: return (float(la),float(lo))
        except ValueError: pass
    loc=col(r,"Location","Country").lower(); city=loc.split(",")[0].strip()
    return GAZ.get(city)

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("csv"); ap.add_argument("--max-speed",type=float,default=900)
    ap.add_argument("--corp-vpn",default="Zscaler,Netskope,Company VPN"); a=ap.parse_args()
    corp={c.strip().lower() for c in a.corp_vpn.split(",")}
    rows=[r for r in csv.DictReader(open(a.csv,encoding="utf-8-sig")) if "success" in col(r,"Status").lower() or not col(r,"Status")]
    by=collections.defaultdict(list)
    for r in rows:
        t=parse(col(r,"Date (UTC)","Date","Created at","Timestamp")); c=coords(r)
        if t and c: by[col(r,"User","Username","User principal name")].append((t,c,r))
    out=[]
    for u,lst in by.items():
        lst.sort(key=lambda x:x[0])
        for (t1,c1,r1),(t2,c2,r2) in zip(lst,lst[1:]):
            if col(r1,"IP address","IP")==col(r2,"IP address","IP"): continue
            km=hav(c1,c2); hrs=(t2-t1).total_seconds()/3600; speed=km/hrs if hrs>0 else 99999
            if km<500 or speed<=a.max_speed: continue
            asn=col(r2,"Autonomous system number","ISP","ASN")
            mfa=col(r2,"Multifactor authentication result","MFA result","Authentication Details","Authentication requirement")
            risk=col(r2,"Risk detail","Risk event types","Risk level during sign-in")
            why=[f"{km:.0f} km in {hrs*60:.0f} min = {speed:.0f} km/h (> {a.max_speed:.0f} km/h flight ceiling)"]; score=2
            al=asn.lower()
            if any(c in al for c in corp): why.append(f"2nd ASN is corporate VPN/SASE ({asn})"); score-=3
            elif any(h in al for h in VPN_HINTS): why.append(f"2nd ASN looks like consumer VPN/proxy/hosting ({asn})"); score+=2
            elif asn: why.append(f"2nd ASN is a plain ISP ({asn}) — residential proxy possible"); score+=1
            ml=mfa.lower()
            if any(k in ml for k in REPLAY): why.append("MFA NOT re-challenged — satisfied by existing token → session replay"); score+=3
            elif "fail" in ml or "denied" in ml: why.append("MFA failed/denied on 2nd sign-in"); score+=1
            elif mfa: why.append(f"fresh MFA on 2nd sign-in ({mfa})"); score-=1
            if risk: why.append(f"Identity Protection: {risk}"); score+=1
            verdict="No" if score>=3 else "Yes"
            out.append((t2.strftime("%Y-%m-%d %H:%MZ"),u,f"{col(r1,'Location','Country')} → {col(r2,'Location','Country')}",
                        f"{hrs*60:.0f} min",mfa or "n/a",verdict,score,"; ".join(why)))
    if not out: print("No impossible-travel pairs found (or missing Latitude/Longitude/Location columns)."); return
    print("Timestamp | User | Location 1 → Location 2 | Time Delta | MFA Status | Was it legit? | Why")
    for o in sorted(out,key=lambda x:-x[6]): print(" | ".join(map(str,o[:6]))+" | "+o[7])
    print(f"\n{len(out)} pairs, {sum(1 for o in out if o[5]=='No')} flagged. For 'No': revoke sessions, reset password, "
          "check newly registered MFA methods, enable token protection + 1 h sign-in frequency.")
if __name__=="__main__": main()
