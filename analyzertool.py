# simple analyzer tool
# this program can check IPs, domains and hashes
# I try to use VirusTotal, AbuseIPDB, Web-check, RDAP and Lookyloo
# comments are in english and explained like I am learning :)

import requests
import ipaddress
import re

# API keys (you need your own)
VT_API_KEY = "bd6bef20f1bcedf5d3e13c841c71cd411f79a73a1ac10e11df5badee06f4cb8e"
ABUSEIPDB_API_KEY = "a69357b25dfeb78a537e1c34a45c06e06d19208b5dc4ad360220f52b8a3992c8466dc31678df1daf"

# headers for the APIs
vt_headers = {"x-apikey": VT_API_KEY}
abuse_headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}

# some regex for domains and hashes
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE)
HEX_RE = re.compile(r"^[A-Fa-f0-9]+$")

# --- helpers to detect element type ---

def clean_element(e: str) -> str:
    # remove http or https if user puts full URL
    e = e.strip()
    e = re.sub(r"^https?://", "", e, flags=re.IGNORECASE)
    e = e.split("/")[0].split("?")[0].split("#")[0]
    return e

def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def is_domain(s: str) -> bool:
    if is_ip(s):
        return False
    return DOMAIN_RE.match(s) is not None

def is_hash(s: str) -> bool:
    if not HEX_RE.match(s or ""):
        return False
    return len(s) in (32, 40, 64)  # MD5, SHA1, SHA256

def classify(e: str) -> str:
    e = clean_element(e)
    if is_ip(e):
        return "ip"
    if is_domain(e):
        return "domain"
    if is_hash(e):
        return "hash"
    return "unknown"

# --- analyzers ---

def analyze_domain_vt(d: str):
    url = f"https://www.virustotal.com/api/v3/domains/{d}"
    r = requests.get(url, headers=vt_headers)
    if r.status_code == 200:
        data = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        mal = stats.get("malicious", 0)
        susp = stats.get("suspicious", 0)
        if mal > 0 or susp > 0:
            print(f"{d} [DOMAIN] -> ⚠️ Malicious (mal={mal}, susp={susp})")
        else:
            print(f"{d} [DOMAIN] -> ✅ Clean")
    else:
        print(f"{d} [DOMAIN] -> error {r.status_code}")

def analyze_hash_vt(h: str):
    url = f"https://www.virustotal.com/api/v3/files/{h}"
    r = requests.get(url, headers=vt_headers)
    if r.status_code == 200:
        data = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        mal = stats.get("malicious", 0)
        susp = stats.get("suspicious", 0)
        if mal > 0 or susp > 0:
            print(f"{h} [HASH] -> ⚠️ Malicious (mal={mal}, susp={susp})")
        else:
            print(f"{h} [HASH] -> ✅ Clean")
    elif r.status_code == 404:
        print(f"{h} [HASH] -> ❓ Not found in VT")
    else:
        print(f"{h} [HASH] -> error {r.status_code}")

def analyze_ip_abuse(ip: str):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    r = requests.get(url, headers=abuse_headers, params=params)
    if r.status_code == 200:
        data = r.json()["data"]
        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        if score > 0 or reports > 0:
            print(f"{ip} [IP] -> ⚠️ Malicious (score={score}, reports={reports})")
        else:
            print(f"{ip} [IP] -> ✅ Clean")
    else:
        print(f"{ip} [IP] -> error {r.status_code}")

# --- main logic ---

def analyze_element(e: str):
    e = clean_element(e)
    t = classify(e)
    if t == "ip":
        analyze_ip_abuse(e)
    elif t == "domain":
        analyze_domain_vt(e)
    elif t == "hash":
        analyze_hash_vt(e)
    else:
        print(f"{e} -> ❓ Unknown type")

def main():
    while True:
        # ask user for input
        data = input("Enter one or more elements (comma separated): ")
        elements = [x.strip() for x in data.split(",") if x.strip()]

        for e in elements:
            analyze_element(e)

        # ask if user wants to continue
        again = input("Do you want to analyze again? (Y/N): ").strip().lower()
        if again != "y":
            print("Bye!")
            break

if __name__ == "__main__":
    main()
