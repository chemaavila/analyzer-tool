import os
import re
import time
import ipaddress
from pathlib import Path
from datetime import datetime
import requests

# colors
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

ENV_PATH = Path(".env")
NEEDED_KEYS = [
    "VT_API_KEY",
    "ABUSEIPDB_API_KEY",
    "URLSCAN_API_KEY",
    "OTX_API_KEY",
    "XFORCE_API_KEY",
    "XFORCE_API_PASSWORD",
]

# env proccess 
def read_env():
    d = {}
    if ENV_PATH.exists():
        try:
            for line in ENV_PATH.read_text(encoding="utf-8", errors="ignore").splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    k,v = line.split("=",1)
                    d[k.strip()] = v.strip()
        except:
            pass
    return d

def write_env(d):
    lines = []
    for k in NEEDED_KEYS:
        lines.append(f"{k}={d.get(k,'')}")
    try:
        ENV_PATH.write_text("\n".join(lines)+"\n", encoding="utf-8")
    except:
        print("could not save .env")

def ask_keys():
    env = read_env()
    for k,v in env.items():
        os.environ.setdefault(k,v)
    changed = False
    prompts = {
        "VT_API_KEY":"VT api key: ",
        "ABUSEIPDB_API_KEY":"AbuseIPDB key: ",
        "URLSCAN_API_KEY":"urlscan.io key: ",
        "OTX_API_KEY":"OTX key: ",
        "XFORCE_API_KEY":"X-Force user/id: ",
        "XFORCE_API_PASSWORD":"X-Force pass: ",
    }
    for k in NEEDED_KEYS:
        val = (os.getenv(k) or "").strip()
        if (not val) or val.lower().startswith(("http","python","curl","export")):
            newv = input(prompts.get(k,f"{k}: "))
            os.environ[k] = newv
            env[k] = newv
            changed = True
    if changed or not ENV_PATH.exists():
        write_env(env)

ask_keys()

# headers
VT = {"x-apikey": os.getenv("VT_API_KEY","")}
ABUSE = {"Key": os.getenv("ABUSEIPDB_API_KEY",""), "Accept":"application/json"}
URLSCAN = {"API-Key": os.getenv("URLSCAN_API_KEY",""), "Content-Type":"application/json"}
OTX = {"X-OTX-API-KEY": os.getenv("OTX_API_KEY","")}
XF_USER = os.getenv("XFORCE_API_KEY","")
XF_PASS = os.getenv("XFORCE_API_PASSWORD","")

# type detection
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE)
HEX_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")

def only_host(s):
    x = s.strip()
    x = re.sub(r"^https?://","",x,flags=re.IGNORECASE)
    return x.split("/")[0].split("?")[0].split("#")[0]

def is_url(s): return s.lower().startswith(("http://","https://"))
def is_ip(s):
    try: ipaddress.ip_address(s); return True
    except: return False
def is_domain(s):
    return (not is_ip(s)) and DOMAIN_RE.match(s or "") is not None
def is_hash(s): return HEX_RE.match(s or "") is not None

def detect_kind(ioc):
    if is_url(ioc): return "url"
    h = only_host(ioc)
    if is_ip(h): return "ip"
    if is_domain(h): return "domain"
    if is_hash(ioc): return "hash"
    return "unknown"

def colorize(msg):
    m = msg.lower()
    if "malicious" in m or "risky" in m or "in pulses" in m:
        return f"{RED}{msg}{RESET}"
    if "clean" in m or "low risk" in m or "not in pulses" in m:
        return f"{GREEN}{msg}{RESET}"
    return msg

def strip_ansi(s):
    return re.sub(r"\x1b\[[0-9;]*m","",s)

def vt_verdict(val):
    try:
        if is_domain(val):
            url = f"https://www.virustotal.com/api/v3/domains/{val}"
        elif is_hash(val):
            url = f"https://www.virustotal.com/api/v3/files/{val}"
        else:
            return "VT: not applicable"
        r = requests.get(url, headers=VT, timeout=25)
        if r.status_code==200:
            data = r.json().get("data",{})
            stats = (data.get("attributes") or {}).get("last_analysis_stats",{})
            mal = int(stats.get("malicious",0)); susp = int(stats.get("suspicious",0))
            if mal>0 or susp>0:
                return f"VT: ⚠️ Malicious (mal={mal}, susp={susp})"
            else:
                return f"VT: ✅ Clean (mal={mal}, susp={susp})"
        if r.status_code==401: return "VT: unauthorized"
        if r.status_code==429: return "VT: rate limit"
        return f"VT: error {r.status_code}"
    except:
        return "VT: network error"

def vt_rel(kind,val):
    try:
        eps=[]
        if kind=="domain":
            eps=[f"https://www.virustotal.com/api/v3/domains/{val}/relationships/resolutions"]
        elif kind=="ip":
            eps=[f"https://www.virustotal.com/api/v3/ip_addresses/{val}/relationships/resolutions"]
        elif kind=="hash":
            eps=[f"https://www.virustotal.com/api/v3/files/{val}/relationships/contacted_ips"]
        else:
            return "VT Relations: not applicable"
        rel=[]
        for ep in eps:
            r = requests.get(ep, headers=VT, timeout=25)
            if r.status_code==200:
                for d in r.json().get("data",[])[:3]:
                    rid=d.get("id")
                    if rid: rel.append(rid)
        if rel:
            return "VT Relations: found -> " + ", ".join(rel)
        return "VT Relations: none found"
    except:
        return "VT Relations: error"

def abuse_check(ip_):
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers=ABUSE, params={"ipAddress":ip_,"maxAgeInDays":90}, timeout=25)
        if r.status_code==200:
            j = r.json().get("data",{})
            score=int(j.get("abuseConfidenceScore",0)); rep=int(j.get("totalReports",0))
            if score>0 or rep>0:
                return f"AbuseIPDB: ⚠️ Malicious (score={score}, reports={rep})"
            else:
                return f"AbuseIPDB: ✅ Clean (score={score}, reports={rep})"
        if r.status_code==401: return "AbuseIPDB: unauthorized"
        if r.status_code==429: return "AbuseIPDB: rate limit"
        return f"AbuseIPDB: error {r.status_code}"
    except:
        return "AbuseIPDB: error"

def urlscan_check(target):
    try:
        if not URLSCAN.get("API-Key"): return "urlscan: missing key"
        url_to_scan = target if is_url(target) else f"http://{target}"
        sub = requests.post("https://urlscan.io/api/v1/scan/", headers=URLSCAN,
                            json={"url":url_to_scan,"visibility":"public"}, timeout=25)
        if sub.status_code!=200:
            return f"urlscan: error {sub.status_code}"
        result=sub.json().get("result")
        if not result: return "urlscan: submitted"
        for _ in range(5):
            rep=requests.get(result,timeout=25)
            if rep.status_code==200:
                j=rep.json()
                shot=(j.get("task",{}) or {}).get("screenshotURL") or j.get("screenshot")
                if not shot: return "urlscan: no screenshot"
                try:
                    Path("screenshots").mkdir(exist_ok=True)
                    fn = re.sub(r'[^A-Za-z0-9._-]+','_',target)[:50]+".png"
                    img=requests.get(shot,timeout=25)
                    if img.status_code==200:
                        (Path("screenshots")/fn).write_bytes(img.content)
                        return f"urlscan: screenshot saved {fn}"
                except:
                    return "urlscan: save error"
            time.sleep(2)
        return "urlscan: not ready"
    except:
        return "urlscan: error"

def otx_check(kind,val):
    try:
        if not OTX.get("X-OTX-API-KEY"): return "OTX: missing key"
        if kind=="ip": url=f"https://otx.alienvault.com/api/v1/indicators/ip/{val}/general"
        elif kind=="domain": url=f"https://otx.alienvault.com/api/v1/indicators/domain/{val}/general"
        elif kind=="hash": url=f"https://otx.alienvault.com/api/v1/indicators/file/{val}/general"
        else: return "OTX: not applicable"
        r=requests.get(url, headers=OTX, timeout=25)
        if r.status_code==200:
            pulses=(r.json().get("pulse_info") or {}).get("count",0)
            if pulses>0: return f"OTX: ⚠️ In pulses ({pulses})"
            else: return f"OTX: ✅ Not in pulses"
        return f"OTX: error {r.status_code}"
    except:
        return "OTX: error"

def xforce_check(kind,val):
    try:
        if not XF_USER or not XF_PASS: return "X-Force: creds missing"
        if kind=="ip": url=f"https://api.xforce.ibmcloud.com/ipr/{val}"
        elif kind in ("domain","url"):
            tgt=val if is_url(val) else f"http://{val}"
            url=f"https://api.xforce.ibmcloud.com/url/{tgt}"
        elif kind=="hash": url=f"https://api.xforce.ibmcloud.com/malware/{val}"
        else: return "X-Force: not applicable"
        r=requests.get(url, auth=(XF_USER,XF_PASS), timeout=25)
        if r.status_code==200:
            j=r.json()
            score=j.get("score") or (j.get("result",{}) or {}).get("score")
            if score is None: return "X-Force: no score"
            try: risky=float(score)>2
            except: risky=False
            if risky: return f"X-Force: ⚠️ Risky ({score})"
            return f"X-Force: ✅ Low risk ({score})"
        return f"X-Force: error {r.status_code}"
    except:
        return "X-Force: error"

# analysis
def analyze_one(ioc):
    k = detect_kind(ioc)
    rows=[]
    if k=="unknown":
        rows.append((ioc,"UNKNOWN","Analyzer","Unknown type"))
        return rows
    if k=="ip":
        rows.append((ioc,"IP","AbuseIPDB",abuse_check(ioc)))
        rows.append((ioc,"IP","OTX",otx_check("ip",ioc)))
        rows.append((ioc,"IP","X-Force",xforce_check("ip",ioc)))
        rows.append((ioc,"IP","VT-Rel",vt_rel("ip",ioc)))
    elif k in ("domain","url"):
        dom = ioc if k=="domain" else only_host(ioc)
        rows.append((ioc,"DOMAIN","VirusTotal",vt_verdict(dom)))
        rows.append((ioc,"DOMAIN","urlscan.io",urlscan_check(ioc if k=="url" else f"http://{ioc}")))
        rows.append((ioc,"DOMAIN","OTX",otx_check("domain",dom)))
        rows.append((ioc,"DOMAIN","X-Force",xforce_check("domain",ioc)))
        rows.append((ioc,"DOMAIN","VT-Rel",vt_rel("domain",dom)))
    elif k=="hash":
        rows.append((ioc,"HASH","VirusTotal",vt_verdict(ioc)))
        rows.append((ioc,"HASH","OTX",otx_check("hash",ioc)))
        rows.append((ioc,"HASH","X-Force",xforce_check("hash",ioc)))
        rows.append((ioc,"HASH","VT-Rel",vt_rel("hash",ioc)))
    return rows

# table
def print_table(rows,save_txt):
    head=f"{'IOC':30} | {'TYPE':8} | {'SOURCE':10} | RESULT"
    sep="-"*len(head)
    print(head); print(sep)
    lines=[head,sep]
    for ioc,typ,src,res in rows:
        c=colorize(res)
        print(f"{ioc:30} | {typ:8} | {src:10} | {c}")
        lines.append(f"{ioc:30} | {typ:8} | {src:10} | {strip_ansi(c)}")
    if save_txt:
        try:
            fn=f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            Path(fn).write_text("\n".join(lines), encoding="utf-8")
            print("Saved:",fn)
        except:
            print("could not save results")

# main loop
def main():
    print("Analyzer tool")
    print("Example: 8.8.8.8, google.com, http://example.com, d41d8cd98f00b204e9800998ecf8427e")
    while True:
        line=input("Enter IOCs: ").strip()
        if not line:
            print("nothing to analyze")
            continue
        items=[x.strip() for x in line.split(",") if x.strip()]
        rows=[]
        for it in items:
            rows.extend(analyze_one(it))
        save=input("Save to txt? (Y/N): ").strip().upper()=="Y"
        print_table(rows,save_txt=save)
        again=input("Analyze more? (Y/N): ").strip().upper()
        if again!="Y":
            print("bye")
            break

if __name__=="__main__":
    main()

