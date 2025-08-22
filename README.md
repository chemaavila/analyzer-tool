
# Analyzer Tool

Is a Python script that can check IPs, domains, URLs and file hashes against different security APIs.

APIs used:
- VirusTotal
- AbuseIPDB
- urlscan.io
- AlienVault OTX
- IBM X-Force

---

## ⚙️ Requirements

- Python 3.8+ installed
- `requests` library (`pip install requests`)

---

## 🔑 API Keys

You need free API keys for the services above.  
The first time you run the script it will ask you for your keys one by one and save them into a `.env` file in the same folder.

---

## ▶️ How to Run

1. Clone this repository:
   
   git clone https://github.com/chemaavila/analyzer-tool.git
   cd analyzer-tool

3. Install dependencies:
 
   pip install requests
  

4. Run the script:
  
   python analyzertool.py
   

5. When it asks for input, type one or more IOCs (indicators of compromise) separated by commas.  
   Examples:
  
   8.8.8.8
   google.com
   http://example.com
   d41d8cd98f00b204e9800998ecf8427e
   

6. After the analysis, it will ask if you want to **save results to a .txt file**.  
   If you say **Y**, a file like `results_20250821_120000.txt` will be created.

---

## 📂 Output

Example of table output:

```
IOC                            | TYPE     | SOURCE     | RESULT
--------------------------------------------------------------------
8.8.8.8                        | IP       | AbuseIPDB  | ✅ Clean (score=0, reports=0)
8.8.8.8                        | IP       | OTX        | ✅ Not in pulses
8.8.8.8                        | IP       | X-Force    | ✅ Low risk (score=0)
google.com                     | DOMAIN   | VirusTotal | ⚠️ Malicious (mal=2, susp=1)
google.com                     | DOMAIN   | urlscan.io | screenshot saved google.com.png
...
```

Malicious results are shown in **red** and clean ones in **green**.

---

## 📝 Notes

- Each API has rate limits. If you get `429` errors, wait a bit and try again.  
- Screenshots from urlscan.io are saved in a `screenshots/` folder.  
- The `.env` file stores your API keys locally.  
