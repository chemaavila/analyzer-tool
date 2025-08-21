import os
import re
import time
import ipaddress
from pathlib import Path
from datetime import datetime
import requests

# ====== colors (ANSI) ======
RED   = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

# ====== config / .env ======
ENV_PATH = Path(".env")
REQUIRED_KEYS = [
    "VT_API_KEY",
    "ABUSEIPDB_API_KEY",
    "URLSCAN_API_KEY",
    "OTX_API_KEY",
    "XFORCE_API_KEY",
    "XFORCE_API_PASSWORD",
]

# simple validators to avoid bad pastes (like commands)
RE_VALIDATORS = {
    # VirusTotal keys are 64 hex chars
    "VT_API_KEY": re.compile(r"^[A-Fa-f0-9]{64}$"),
    # AbuseIPDB varies; allow 32..128 safe chars
    "ABUSEIPDB_API_KEY": re.compile(r"^[A-Za-z0-9_-]{32,128}$"),
    # urlscan.io looks like a UUID
    "URLSCAN_API_KEY": re.compile(r"^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$"),
    # OTX is usually 64 hex
    "OTX_API_KEY": re.compile(r"^[A-Fa-f0-9]{64}$"),
    # IBM X-Force (user/id) and password: non-empty, no spaces
    "XFORCE_API_KEY": re.compile(r"^[^\s]{3,}$"),
    "XFORCE_API_PASSWORD": re.compile(r"^[^\s].*$"),
}

def _read_env(path: Path) -> dict:
    data = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip()
    return data

def _write_env(path: Path, values: dict) -> None:
    lines = []
    for k in REQUIRED_KEYS:
        v = (values.get(k) or "").replace("\n", "").strip().strip('"').strip("'")
        lines.append(f"{k}={v}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

def _looks_like_command(s: str) -> bool:
    s2 = s.lower()
    return any(w in s2 for w in ["python ", "http://", "https://", "curl ", "export "]) or (" " in s)

def _prompt_key(name: str) -> str:
    hints = {
        "VT_API_KEY": "VirusTotal API key (64 hex chars): ",
        "ABUSEIPDB_API_KEY": "AbuseIPDB API key: ",
        "URLSCAN_API_KEY": "urlscan.io API key (UUID): ",
        "OTX_API_KEY": "AlienVault OTX API key (64 hex): ",
        "XFORCE_API_KEY": "IBM X-Force API key (username/id): ",
        "XFORCE_API_PASSWORD": "IBM X-Force API password: ",
    }
    rx = RE_VALIDATORS.get(name)
    while True:
        val = input(hints.get(name, f"{name}: ")).strip()
        if not val or _looks_like_command(val) or (rx and not rx.match(val)):
            print(f"Value for {name} looks invalid. Please try again.")
            continue
        return val

def ensure_api_keys() -> None:
    # load .env to environment if present
    file_env = _read_env(ENV_PATH)
    for k, v in file_env.items():
        if not os.environ.get(k):
            os.environ[k] = v

    # check each key; if missing or invalid, ask until valid
    changed = False
    merged = {k: os.getenv(k, "") for k in REQUIRED_KEYS}
    for k in REQUIRED_KEYS:
        rx = RE_VALIDATORS.get(k)
        curr = (merged.get(k) or "").strip()
        if not curr or _looks_like_command(curr) or (rx and not rx.match(curr)):
            merged[k] = _prompt_key(k)
            os.environ[k] = merged[k]
            changed = True

    # save .env if anything changed
    if changed or not ENV_PATH.exists():
        _write_env(ENV_PATH, merged)

# ====== run setup for keys ======
ensure_api_keys()

# ====== headers ======
VT_API_KEY             = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY      = os.getenv("ABUSEIPDB_API_KEY", "")
URLSCAN_API_KEY        = os.getenv("URLSCAN_API_KEY", "")
OTX_API_KEY            = os.getenv("OTX_API_KEY", "")
XFORCE_API_KEY         = os.getenv("XFORCE_API_KEY", "")
XFORCE_API_PASSWORD    = os.getenv("XFORCE_API_PASSWORD", "")

vt_headers     = {"x-apikey": VT_API_KEY}
abuse_headers  = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
urlscan_headers= {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
otx_headers    = {"X-OTX-API-KEY": OTX_API_KEY}

# ====== helpers / validators ======
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE)
HEX_RE    = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")

def clean_host(text: str) -> str:
    x = text.strip()
    x = re.sub(r"^https?://", "", x, flags=re.IGNORECASE)
    return x.split("/")[0].split("?")[0].split("#")[0]

def is_url(s: str) -> bool:
    return s.lower().startswith(("http://", "https://"))

def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s); return True
    except ValueError:
        return False

def is_domain(s: str) -> bool:
    return (not is_ip(s)) and (DOMAIN_RE.match(s) is not None)

def is_hash(s: str) -> bool:
    return HEX_RE.match(s or "") is not None

def classify(item: str) -> str:
    if is_url(item): return "url"
    host = clean_host(item)
    if is_ip(host): return "ip"
    if is_domain(host): return "domain"
    if is_hash(item): return "hash"
    return "unknown"

def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:80]

def colorize(verdict: str) -> str:
    t = verdict.lower()
    if any(w in t for w in ["malicious", "risky", "in pulses"]):
        return f"{RED}{verdict}{RESET}"
    if any(w in t for w in ["clean", "low risk", "not in pulses"]):
        return f"{GREEN}{verdict}{RESET}"
    return verdict

def _friendly_http_error(resp) -> str:
    if resp is None:
        return "network error"
    if resp.status_code == 401:
        return "unauthorized (check API key)"
    if resp.status_code == 429:
        return "rate limit (try later)"
    return f"error {resp.status_code}"

# ====== providers ======
def vt_verdict(value: str) -> str:
    try:
        if is_domain(value):
            url = f"https://www.virustotal.com/api/v3/domains/{value}"
        elif is_hash(value):
            url = f"https://www.virustotal.com/api/v3/files/{value}"
        else:
            return "VT: not applicable"
        r = requests.get(url, headers=vt_headers, timeout=25)
        if r.status_code == 200:
            data  = r.json().get("data", {})
            stats = (data.get("attributes") or {}).get("last_analysis_stats", {})
            mal   = int(stats.get("malicious", 0))
            susp  = int(stats.get("suspicious", 0))
            verdict = "⚠️ Malicious" if (mal > 0 or susp > 0) else "✅ Clean"
            return f"VT: {verdict} (mal={mal}, susp={susp})"
        return f"VT: {_friendly_http_error(r)}"
    except Exception:
        return "VT: network error"

def vt_relations(kind: str, value: str) -> str:
    try:
        endpoints = []
        if kind == "domain":
            endpoints = [
                f"https://www.virustotal.com/api/v3/domains/{value}/relationships/resolutions",
                f"https://www.virustotal.com/api/v3/domains/{value}/relationships/communicating_files",
            ]
        elif kind == "ip":
            endpoints = [
                f"https://www.virustotal.com/api/v3/ip_addresses/{value}/relationships/resolutions",
                f"https://www.virustotal.com/api/v3/ip_addresses/{value}/relationships/communicating_files",
            ]
        elif kind == "hash":
            endpoints = [
                f"https://www.virustotal.com/api/v3/files/{value}/relationships/embedded_domains",
                f"https://www.virustotal.com/api/v3/files/{value}/relationships/contacted_ips",
            ]
        else:
            return "VT Relations: not applicable"

        related = []
        for ep in endpoints:
            r = requests.get(ep, headers=vt_headers, timeout=25)
            if r.status_code == 200:
                for d in r.json().get("data", [])[:3]:
                    rid = d.get("id")
                    if rid: related.append(str(rid))
        return "VT Relations: found -> " + ", ".join(related[:6]) if related else "VT Relations: none found"
    except Exception:
        return "VT Relations: network error"

def abuse_check(ip_addr: str) -> str:
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=abuse_headers,
            params={"ipAddress": ip_addr, "maxAgeInDays": 90},
            timeout=25,
        )
        if r.status_code == 200:
            j = r.json().get("data", {})
            score = int(j.get("abuseConfidenceScore", 0))
            rep   = int(j.get("totalReports", 0))
            verdict = "⚠️ Malicious" if (score > 0 or rep > 0) else "✅ Clean"
            return f"AbuseIPDB: {verdict} (score={score}, reports={rep})"
        return f"AbuseIPDB: {_friendly_http_error(r)}"
    except Exception:
        return "AbuseIPDB: network error"

def urlscan_check(target: str) -> str:
    try:
        if not URLSCAN_API_KEY:
            return "urlscan: API key missing"
        url_to_scan = target if is_url(target) else f"http://{target}"
        sub = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=urlscan_headers,
            json={"url": url_to_scan, "visibility": "public"},
            timeout=25,
        )
        if sub.status_code != 200:
            return f"urlscan: {_friendly_http_error(sub)}"
        result_link = sub.json().get("result")
        if not result_link:
            return "urlscan: submitted (no result link)"
        # poll briefly
        for _ in range(8):
            rep = requests.get(result_link, timeout=25)
            if rep.status_code == 200:
                j = rep.json()
                shot = (j.get("task", {}) or {}).get("screenshotURL") or j.get("screenshot")
                if not shot:
                    return "urlscan: no screenshot available"
                try:
                    Path("screenshots").mkdir(exist_ok=True)
                    fname = safe_name(target) + ".png"
                    img = requests.get(shot, timeout=25)
                    if img.status_code == 200 and img.content:
                        (Path("screenshots") / fname).write_bytes(img.content)
                        return f"urlscan: screenshot saved -> screenshots/{fname}"
                    return "urlscan: screenshot URL present but download failed"
                except Exception:
                    return "urlscan: error saving screenshot"
            time.sleep(2)
        return "urlscan: result not ready yet"
    except Exception:
        return "urlscan: network error"

def otx_check(kind: str, indicator: str) -> str:
    try:
        if not OTX_API_KEY:
            return "OTX: API key missing"
        if kind == "ip":
            url = f"https://otx.alienvault.com/api/v1/indicators/ip/{indicator}/general"
        elif kind == "domain":
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general"
        elif kind == "hash":
            url = f"https://otx.alienvault.com/api/v1/indicators/file/{indicator}/general"
        else:
            return "OTX: not applicable"
        r = requests.get(url, headers=otx_headers, timeout=25)
        if r.status_code == 200:
            pulses = (r.json().get("pulse_info") or {}).get("count", 0)
            verdict = "⚠️ In pulses" if pulses > 0 else "✅ Not in pulses"
            return f"OTX: {verdict} (pulses={pulses})"
        return f"OTX: {_friendly_http_error(r)}"
    except Exception:
        return "OTX: network error"

def xforce_check(kind: str, value: str) -> str:
    try:
        if not XFORCE_API_KEY or not XFORCE_API_PASSWORD:
            return "X-Force: API creds missing"
        auth = (XFORCE_API_KEY, XFORCE_API_PASSWORD)
        if kind == "ip":
            url = f"https://api.xforce.ibmcloud.com/ipr/{value}"
        elif kind in ("domain", "url"):
            tgt = value if is_url(value) else f"http://{value}"
            url = f"https://api.xforce.ibmcloud.com/url/{tgt}"
        elif kind == "hash":
            url = f"https://api.xforce.ibmcloud.com/malware/{value}"
        else:
            return "X-Force: not applicable"
        r = requests.get(url, auth=auth, timeout=25)
        if r.status_code == 200:
            j = r.json()
            score = j.get("score") or j.get("result", {}).get("score") or j.get("malware", {}).get("risk")
            if score is None:
                return "X-Force: OK (no score)"
            risky = False
            try:
                risky = float(score) > 2.0
            except Exception:
                pass
            return f"X-Force: {'⚠️ Risky' if risky else '✅ Low risk'} (score={score})"
        return f"X-Force: {_friendly_http_error(r)}"
    except Exception:
        return "X-Force: network error"

# ====== analysis / table ======
def analyze_one(ioc: str):
    kind = classify(ioc)
    rows = []
    if kind == "unknown":
        rows.append((ioc, "UNKNOWN", "Analyzer", "Unknown type"))
        return rows

    if kind == "ip":
        rows.append((ioc, "IP", "AbuseIPDB", abuse_check(ioc)))
        rows.append((ioc, "IP", "OTX",        otx_check("ip", ioc)))
        rows.append((ioc, "IP", "X-Force",    xforce_check("ip", ioc)))
        rows.append((ioc, "IP", "VT-Rel",     vt_relations("ip", ioc)))
    elif kind in ("domain", "url"):
        dom = ioc if kind == "domain" else clean_host(ioc)
        rows.append((ioc, "DOMAIN", "VirusTotal", vt_verdict(dom)))
        rows.append((ioc, "DOMAIN", "urlscan.io", urlscan_check(ioc if kind == "url" else f"http://{ioc}")))
        rows.append((ioc, "DOMAIN", "OTX",        otx_check("domain", dom)))
        rows.append((ioc, "DOMAIN", "X-Force",    xforce_check("domain", ioc)))
        rows.append((ioc, "DOMAIN", "VT-Rel",     vt_relations("domain", dom)))
    elif kind == "hash":
        rows.append((ioc, "HASH", "VirusTotal", vt_verdict(ioc)))
        rows.append((ioc, "HASH", "OTX",        otx_check("hash", ioc)))
        rows.append((ioc, "HASH", "X-Force",    xforce_check("hash", ioc)))
        rows.append((ioc, "HASH", "VT-Rel",     vt_relations("hash", ioc)))
    return rows

def strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", s)

def print_table(all_rows, save_txt: bool):
    header = f"{'IOC':30} | {'TYPE':8} | {'SOURCE':10} | RESULT"
    sep = "-" * len(header)
    lines_color = [header, sep]
    lines_plain = [header, sep]

    for ioc, kind, src, res in all_rows:
        colored = colorize(res)
        line_c = f"{ioc:30} | {kind:8} | {src:10} | {colored}"
        line_p = f"{ioc:30} | {kind:8} | {src:10} | {strip_ansi(colored)}"
        lines_color.append(line_c)
        lines_plain.append(line_p)

    table_color = "\n".join(lines_color)
    print(table_color)

    if save_txt:
        out = Path(f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        out.write_text("\n".join(lines_plain) + "\n", encoding="utf-8")
        print(f"\nSaved: {out}")

# ====== main loop ======
def main():
    print("IOC analyzer (table output)")
    print("Example: 8.8.8.8, google.com, http://example.com, d41d8cd98f00b204e9800998ecf8427e")
    while True:
        line = input("Enter IOCs (comma separated): ").strip()
        items = [x.strip() for x in line.split(",") if x.strip()]
        all_rows = []
        for it in items:
            all_rows.extend(analyze_one(it))
        save = input("Save results to .txt? (Y/N): ").strip().upper() == "Y"
        print_table(all_rows, save_txt=save)
        again = input("Analyze more? (Y/N): ").strip().upper()
        if again != "Y":
            print("Bye!")
            break

if __name__ == "__main__":
    main()
