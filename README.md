# Ultimate SSRF Arsenal

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Playwright](https://img.shields.io/badge/Playwright-1.40+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Version](https://img.shields.io/badge/Version-2.0-red.svg)
![Phases](https://img.shields.io/badge/Attack%20Phases-15-orange.svg)

**Advanced Multi‑Target SSRF Exploitation Framework with Intelligent Deduplication**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Phases](#-attack-phases) • [Output](#-output) • [Disclaimer](#-disclaimer)

</div>

---

## 📖 Overview

**Ultimate SSRF Arsenal** is a fully automated Server‑Side Request Forgery (SSRF) testing framework built with Python and Playwright. It features:

- **15 attack phases** covering every known SSRF technique
- **Dynamic endpoint discovery** with parameter extraction
- **Multi‑cloud metadata extraction** (AWS, Azure, GCP, Alibaba, Oracle, DigitalOcean, Huawei, Tencent)
- **Blind SSRF detection** via out‑of‑band callbacks
- **Smart deduplication** that filters noise and shows only actionable findings
- **Protocol smuggling** (file://, gopher://, dict://, ftp://, ldap://, etc.)
- **Multi‑target support** with consolidated reporting

---

## ✨ Features

- 🔍 **Dynamic Discovery** – Crawls 50+ endpoints, extracts parameters from HTML/JS
- 🧠 **15 Attack Phases** – Validation, fuzzing, bypass, cloud metadata, protocol attacks
- 🌐 **Multi‑Target** – Single domain, comma‑separated list, or file input
- 📡 **Blind SSRF** – Real‑time OOB callback detection via Burp Collaborator/Interactsh
- 📊 **Smart Filtering** – Deduplicates findings by endpoint/param, shows only unique vulns
- ⚡ **Rate Limiting** – Configurable delays between requests
- 📄 **JSON Reports** – Full evidence chains with severity classification
- 🎨 **Color Output** – Color‑coded terminal with critical/high/medium/low/info

---

## 📦 Installation

### Prerequisites
- Python 3.8+
- pip

### Steps
```bash
# Clone the repository
git clone https://github.com/KauanCosta2000/ultimate-ssrf-arsenal.git
cd ultimate-ssrf-arsenal

# Install dependencies
pip install playwright

# Install browser
playwright install chromium
🚀 Usage
Basic Run
bash
python ultimate_ssrf_arsenal.py
Interactive Prompts
text
How would you like to provide targets?
  1 - Single domain
  2 - Comma-separated list (e.g., example.com,test.com,site.org)
  3 - File with one domain per line
Choose [1/2/3]: 1

Enter target (e.g., example.com): example.com
Enter your callback host (optional): your-burp-collaborator.net
Delay between requests (seconds) [default 0.5]: 1.0
Quiet Mode (Less Output)
bash
python ultimate_ssrf_arsenal.py --quiet
Examples
Single domain:

bash
python ultimate_ssrf_arsenal.py
# Choose 1 → Enter: example.com
Multiple domains:

bash
python ultimate_ssrf_arsenal.py
# Choose 2 → Enter: shopify.com,gitlab.com,mozilla.org
From file (targets.txt):

text
example.com
api.internal-app.com
admin.dev.io
bash
python ultimate_ssrf_arsenal.py
# Choose 3 → Enter: targets.txt
🧩 Attack Phases
#	Phase	Description
0	Dynamic Discovery	Crawls endpoints, extracts parameters, identifies vulnerable surfaces
1	Endpoint Validation	Confirms SSRF with HTTP/HTTPS/protocol‑relative callbacks
2	Parameter Fuzzing	Tests 90+ SSRF‑prone parameter names
3	Localhost Bypass	20+ representations (decimal, hex, octal, IPv6, dword, DNS wildcards)
4	GCP Metadata	Targets metadata.google.internal with Metadata‑Flavor header
5	Multi‑Cloud Metadata	AWS, Azure, Alibaba, Oracle, DigitalOcean, Huawei, Tencent
6	Internal Services	Elasticsearch, Docker, Kubelet, Vault, Redis, MongoDB, etc.
7	Protocol Attacks	file://, gopher://, dict://, ftp://, ldap://, tftp://
8	Redirect Bypass	URL parser confusion, userinfo injection, fragment smuggling
9	DNS Rebinding	nip.io, localtest.me, lvh.me, vcap.me
10	XXE → SSRF	XML External Entity injection on XML endpoints
11	Encoding Bypass	URL encoding, double encoding, Unicode, backslash tricks
12	CRLF Injection	HTTP header injection, response smuggling
13	URL Fragment Bypass	Advanced #/@ confusion, null byte injection
14	Exotic Protocols	Crafted Redis/Memcached commands via gopher://
📊 Smart Filtering
Instead of 99+ raw findings, the tool automatically:

Groups by unique (endpoint, param)

Keeps highest severity per group

Counts OOB callbacks per endpoint

Flags sensitive data leaks (tokens, keys, credentials)

Prints clean summary

Example Output
text
===================== FILTERED SSRF SUMMARY =====================
Unique vulnerable endpoints/params with BLIND SSRF callbacks:

[CRITICAL] /api/proxy  (url)
  ● OOB Callbacks: 47  |  Sensitive data: YES
  └─ Top pattern: [CRITICAL] Callback URL found in response

[HIGH] /fetch  (file)
  ● OOB Callbacks: 12  |  Sensitive data: NO
  └─ Top pattern: [HIGH] Internal IP (10.x.x.x) leaked

[MEDIUM] /download  (src)
  ● OOB Callbacks: 3  |  Sensitive data: NO
  └─ Top pattern: [MEDIUM] Link-local IP (169.254.x.x) leaked
📁 Output
For each target, a JSON file is created:

text
ssrf_results_<target>_<timestamp>.json
Contains:

Discovered endpoints & parameters

Vulnerable endpoints

All findings with severity, matched patterns, payloads

Blind callback logs with timestamps and headers

Intercepted internal requests

🎯 Use Cases
Bug Bounty – Automated SSRF hunting across programs

Penetration Testing – Internal network mapping, service enumeration

Cloud Auditing – Multi‑cloud metadata extraction, IAM role exploitation

Security Research – Protocol analysis, filter bypass techniques

⚙️ Customization
Add Custom Endpoints
Edit common_paths in phase_0_discovery():

python
common_paths = [
    "/custom-api",
    "/admin/import",
    # ... your paths
]
Add Custom Cloud Provider
Edit cloud_targets in phase_5_all_cloud_metadata():

python
"MyCloud": {
    "hosts": ["metadata.mycloud.internal"],
    "paths": ["latest/meta-data/"],
    "headers": {"X-Custom": "value"}
}
⚠️ Disclaimer
This tool is for educational and authorized security testing only.

Only test targets you own or have written permission to test

Respect bug bounty program policies and rate limits

Do not use for unauthorized access or data theft

The author is not responsible for misuse or damages

Always obtain proper authorization before scanning any target.

📜 License
MIT License – see LICENSE file.

text
MIT License

Copyright (c) 2025 Kauan Costa

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
👤 Author
Kauan Costa (belladonnask)

GitHub: @KauanCosta2000

Repository: ultimate-ssrf-arsenal

🤝 Contributing
Pull requests, issues, and feature requests are welcome!

Fork the repository

Create a feature branch (git checkout -b feature/amazing)

Commit changes (git commit -m 'Add feature')

Push (git push origin feature/amazing)

Open a Pull Request

🔄 Changelog
v2.0
✅ 15 attack phases (up from 9)

✅ Smart deduplication & filtering

✅ Multi‑cloud metadata (7 providers)

✅ XXE, encoding bypass, CRLF, fragment bypass phases

✅ Quiet mode (--quiet)

✅ Fixed JSON serialization

✅ Improved error handling

v1.0
✅ Initial release with 9 phases

✅ Dynamic discovery

✅ Blind SSRF detection

<div align="center">
