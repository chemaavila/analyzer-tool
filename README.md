ANALYZER TOOL - README (junior style)
======================================

1) What this app does
---------------------
- This is a small console program to check if items are malicious or clean.
- It accepts three kinds of items: IP addresses, domains and file hashes (MD5, SHA1 or SHA256).
- It auto-detects the type of each item.
- For DOMAINS and HASHES it uses VirusTotal (VT). For IPs it uses AbuseIPDB.
- It only prints the result on screen (no files).
- After each run it asks if you want to analyze again: type Y (yes) or N (no). If N, the app exits.

2) Requirements
---------------
- Python 3.9+ installed (works fine with Python 3.13 from Homebrew).
- Internet connection.
- Your own API keys:
  * VirusTotal API key
  * AbuseIPDB API key
- The 'requests' library installed in your project environment.

3) Quick install (macOS / VS Code)
----------------------------------
# open a terminal in your project folder
cd "/Users/youruser/Desktop/analyzer tool"

# create and activate a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# upgrade pip and install the dependency
python -m pip install --upgrade pip
python -m pip install requests

# (Optional) In VS Code: Command Palette -> "Python: Select Interpreter" -> choose the one inside .venv

4) Configure your API keys
--------------------------
Open 'analyzertool.py' and set these variables at the top of the file:
VT_API_KEY = "PUT_YOUR_VT_KEY"
ABUSEIPDB_API_KEY = "PUT_YOUR_ABUSEIPDB_KEY"

5) How to run
-------------
# activate the venv if it's not active
cd "/Users/youruser/Desktop/analyzer tool"
source .venv/bin/activate

# run the program
python analyzertool.py

The app will ask:
- "Enter one or more elements (comma separated):"
  -> you can paste several items separated by commas.

Then it will print one line per item with a simple verdict.

After that:
- "Do you want to analyze again? (Y/N):"
  -> type Y to run again, or N to close the program.

6) Examples
-----------
Input:
  8.8.8.8, google.com, d41d8cd98f00b204e9800998ecf8427e

Possible output:
  8.8.8.8 [IP] -> ✅ Clean
  google.com [DOMAIN] -> ✅ Clean
  d41d8cd98f00b204e9800998ecf8427e [HASH] -> ⚠️ Malicious (mal=XX, susp=YY)

Another run:
  Enter one or more elements (comma separated): 1.2.3.4
  1.2.3.4 [IP] -> ⚠️ Malicious (score=50, reports=10)
  Do you want to analyze again? (Y/N): N
  Bye!

7) Frequent issues (and quick fixes)
------------------------------------
- Error: externally-managed-environment
  => You are using Homebrew Python. Always create a virtualenv (.venv) and install inside it.

- zsh: command not found: python
  => Use 'python3' or activate your virtualenv where 'python' exists.

- The app "hangs" in VS Code
  => Run it in the integrated TERMINAL (not in Debug Console). Or set launch.json with "console": "integratedTerminal".

- 401/403 from the APIs
  => Check your API keys. Make sure you pasted them correctly.

- 429 Too Many Requests
  => You hit the rate limit. Wait a bit and try again. Free API tiers are limited.

8) Notes
--------
- Keep your API keys private. Do not commit them to Git.
- This version is interactive and reads from keyboard.
- If you need a version that loads items from a .txt file or uses Web-Check / RDAP / Lookyloo, ask for the "advanced" version.
