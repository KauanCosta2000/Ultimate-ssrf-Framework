📖 Overview
Ultimate SSRF Arsenal is a state‑of‑the‑art, fully automated Server‑Side Request Forgery (SSRF) testing framework built with Python 3.8+ and Playwright. It goes beyond basic SSRF detection by implementing 15 sophisticated attack phases, intelligent endpoint discovery, advanced cloud metadata extraction across all major providers, protocol smuggling, blind SSRF detection via out‑of‑band callbacks, and smart deduplication that filters out noise and shows only what truly matters.

What Makes It Different?
Traditional SSRF Tools	Ultimate SSRF Arsenal
Basic URL fuzzing	Dynamic endpoint discovery + parameter extraction
Single cloud provider	Multi-cloud (AWS, Azure, GCP, Alibaba, Oracle, DigitalOcean, Huawei, Tencent)
No filtering	Smart deduplication by endpoint/param with severity aggregation
Manual triage required	Auto‑filtered summary showing only unique exploitable vectors
Blind SSRF guesswork	OOB callback interception + real‑time confirmation
No protocol attacks	gopher://, dict://, file://, ftp://, ldap://, tftp://, netdoc://, jar:
Basic encoding	URL, Unicode, double encoding, null byte injection, CRLF smuggling
✨ Key Features
🔍 Intelligent Discovery Engine
Automatic crawling of 50+ common API/web paths (/api, /proxy, /fetch, /webhook, etc.)

Dynamic parameter extraction from HTML forms, links, JavaScript, and URL query strings

Multi-method support (GET/POST) with multiple Content‑Types (JSON, form‑urlencoded, multipart)

Smart endpoint ranking based on response codes and content analysis

Vulnerability pre‑screening – identifies potentially exploitable endpoints before launching full attacks

🧠 15 Attack Phases (Complete SSRF Kill Chain)
Phase	Attack Vector	Payloads
0	Dynamic Discovery	50+ paths × 2 methods × 3 content types
1	Endpoint Validation	HTTP/HTTPS/protocol-relative callbacks
2	Parameter Fuzzing	90+ SSRF-prone parameters
3	Localhost Bypass	20+ representations (decimal, hex, octal, IPv6, dword)
4	GCP Metadata	metadata.google.internal with/without Metadata-Flavor header
5	Multi‑Cloud Metadata	AWS, Azure, Alibaba, Oracle, DigitalOcean, Huawei, Tencent
6	Internal Services	Elasticsearch, Docker, Kubelet, Vault, Redis, MongoDB, etc.
7	Protocol Attacks	file://, gopher://, dict://, ftp://, ldap://, tftp://
8	Redirect Bypass	URL parser confusion, userinfo injection, fragment smuggling
9	DNS Rebinding	nip.io, sslip.io, localtest.me, lvh.me, vcap.me
10	XXE → SSRF	XML external entity injection on XML endpoints
11	Encoding Bypass	URL encoding, double encoding, Unicode, backslash tricks
12	CRLF Injection	HTTP header injection, response smuggling
13	URL Fragment Bypass	Advanced #/@ confusion, null byte injection
14	Exotic Protocols	Crafted Redis/Memcached commands via gopher://
📊 Smart Filtering & Deduplication
Automatic grouping by (endpoint, param) combinations

Severity aggregation – keeps highest severity per unique vulnerability

OOB callback counting – shows how many times each endpoint triggered blind SSRF

Sensitive data detection – flags findings with leaked tokens, keys, or credentials

Clean summary output – from 99 raw findings to 3‑5 actionable vulnerabilities

🌐 Multi‑Target Orchestration
Single domain scanning

Comma‑separated lists (example.com,test.com,api.org)

File‑based target loading (one domain per line)

Individual JSON reports per target + consolidated cross‑target summary

Automatic 5‑second cooldown between targets

📡 Blind SSRF Detection
Real‑time out‑of‑band callback interception via Playwright request routing

Supports custom callback hosts: Burp Collaborator, Interactsh, custom VPS, webhook.site

Automatic evidence generation for every received callback

Callback logging with timestamps, HTTP methods, and full headers

Instant terminal alerts when blind SSRF is confirmed

⚡ Performance & Stealth
Configurable rate limiting (delay between requests)

Verbose/Quiet modes (--quiet flag for minimal output)

Timeout control per request

User‑Agent customization support

Error handling – graceful degradation on network failures

📄 Comprehensive Output
Color‑coded terminal output with severity indicators

JSON reports with complete evidence chains

Intercepted request logs (internal metadata calls)

Pattern matching results (access tokens, private keys, internal IPs)

Discovered/vulnerable endpoint inventory

📦 Installation
Prerequisites
Python 3.8 or higher

pip (Python package manager)

Step 1: Clone the Repository
bash
git clone https://github.com/KauanCosta2000/ultimate-ssrf-arsenal.git
cd ultimate-ssrf-arsenal
Step 2: Install Python Dependencies
bash
pip install -r requirements.txt
requirements.txt:

text
playwright>=1.40.0
Step 3: Install Playwright Browser
bash
playwright install chromium
Step 4: Verify Installation
bash
python ultimate_ssrf_arsenal.py --help
🚀 Usage
Basic Usage
bash
python ultimate_ssrf_arsenal.py
You will be interactively prompted for:

Target selection method (single, comma‑separated, file)

Callback host (optional – for blind SSRF detection)

Request delay (seconds between requests)

Command-Line Options
Flag	Description
--quiet or -q	Suppress verbose output (only phase headers + final summary)
Example 1: Single Domain (Verbose)
bash
python ultimate_ssrf_arsenal.py

# Interactive prompts:
# Choose [1/2/3]: 1
# Enter target: example.com
# Enter callback host: abc123.oastify.com
# Delay between requests [default 0.5]: 1.0
Example 2: Multiple Domains (Quiet Mode)
bash
python ultimate_ssrf_arsenal.py --quiet

# Choose [1/2/3]: 2
# Enter domains: shopify.com,gitlab.com,mozilla.org
# Callback host: your-burp-collaborator.net
# Delay: 2.0
Example 3: Targets File
Create targets.txt:

text
example.com
api.internal-app.com
admin.dev-environment.io
bash
python ultimate_ssrf_arsenal.py

# Choose [1/2/3]: 3
# File path: targets.txt
# Callback host: interactsh-server.com
# Delay: 0.5
🧩 Attack Phases (Detailed)
Phase 0 – Dynamic Discovery
Crawls 50+ common endpoints (/api, /proxy, /fetch, /webhook, /graphql, etc.)

Tests GET and POST methods with JSON, form‑urlencoded, and multipart content types

Extracts parameters from HTML <form>, <input>, <a href>, and URL query strings

Identifies potentially SSRF‑vulnerable endpoints based on response codes and content

Optional web crawling to discover additional endpoints from page links

Phase 1 – Endpoint Validation
Validates discovered endpoints with HTTP/HTTPS/protocol‑relative callback payloads

Confirms which endpoints actually make outbound requests to attacker‑controlled hosts

Generates baseline SSRF evidence

Phase 2 – Parameter Fuzzing
Fuzzes 90+ SSRF‑prone parameter names:
url, uri, file, path, image, src, source, link, href, redirect, redirect_uri, return, next, proxy, fetch, download, upload, import, convert, webhook, callback, validate, verify, resolve, read, write, data, content, media, domain, host, ip, socket, and many more...

Identifies which parameters accept URLs and can be exploited

Phase 3 – Localhost Bypass
Tests 20+ localhost representations to bypass IP‑based restrictions:

Type	Examples
Standard	127.0.0.1, localhost
Decimal/Dword	2130706433
Hexadecimal	0x7f000001
Octal	0177.0.0.1
IPv6	[::1], [::ffff:127.0.0.1]
Shortened	127.1, 0
DNS Wildcards	127.0.0.1.nip.io, localtest.me
Phase 4 – GCP Metadata Attack
Targets metadata.google.internal (resolves to 169.254.169.254)

Queries sensitive endpoints:

computeMetadata/v1/instance/service-accounts/default/token

computeMetadata/v1/project/project-id

computeMetadata/v1/instance/?recursive=true

Tests with and without required Metadata-Flavor: Google header

Detects leaked access tokens, service account emails, project IDs

Phase 5 – Multi‑Cloud Metadata Attack
Cloud Provider	Metadata IP/Host	Key Endpoints
AWS	169.254.169.254	IAM security credentials, instance‑id, user‑data
Azure	169.254.169.254	Instance metadata, OAuth2 tokens (with Metadata: true header)
Alibaba	100.100.100.200	Instance metadata, user‑data
Oracle	169.254.169.254	OPC instance metadata
DigitalOcean	169.254.169.254	Droplet metadata (JSON)
Huawei	169.254.169.254	Instance metadata
Tencent	metadata.tencentyun.com	CVM metadata
Phase 6 – Internal Services Scan
Scans 14+ common internal services:

Service	URL Pattern	Default Port
Elasticsearch	http://127.0.0.1:9200	9200
Docker API	http://127.0.0.1:2375	2375
Kubelet API	https://127.0.0.1:10250	10250
HashiCorp Vault	https://127.0.0.1:8200	8200
Consul	http://127.0.0.1:8500	8500
Prometheus	http://127.0.0.1:9090	9090
Grafana	http://127.0.0.1:3000	3000
Jenkins	http://127.0.0.1:8080	8080
Redis	redis://127.0.0.1:6379	6379
Memcached	http://127.0.0.1:11211	11211
MongoDB	http://127.0.0.1:27017	27017
Phase 7 – Protocol Attacks
Exploits alternative URL schemes:

Protocol	Example	Purpose
file://	file:///etc/passwd	Local file disclosure
gopher://	gopher://127.0.0.1:6379/_INFO	Redis interaction
dict://	dict://127.0.0.1:6379/INFO	Service enumeration
ftp://	ftp://127.0.0.1:21/	FTP SSRF
ldap://	ldap://127.0.0.1:389/	LDAP interaction
tftp://	tftp://127.0.0.1:69/	TFTP interaction
Phase 8 – Redirect Bypass
Tests URL parser confusion techniques:

//attacker.com (protocol‑relative)

https://target.com@attacker.com (userinfo injection)

/\attacker.com/test (backslash bypass)

https://attacker.com#@target.com/ (fragment confusion)

https://target.com%23@attacker.com/ (encoded fragment)

Phase 9 – DNS Rebinding
Uses wildcard DNS services to bypass IP allowlists:

nip.io / sslip.io → resolves any IP in hostname

localtest.me → always resolves to 127.0.0.1

lvh.me → localhost wildcard

vcap.me → another localhost wildcard

Phase 10 – XXE → SSRF
Automatically detects XML endpoints (Content‑Type: application/xml)

Injects XXE payloads that trigger out‑of‑band requests

Useful when direct SSRF is blocked but XML parsing is available

Phase 11 – Encoding Bypass
URL encoding (%2f%2f)

Double encoding (%252f%252f)

Backslash injection (http:\\)

Null byte injection (%00)

Unicode normalization tricks

Phase 12 – CRLF Injection
HTTP header injection via %0d%0a sequences

Response smuggling attempts

Header‑based SSRF chaining

Phase 13 – URL Fragment Bypass
http://callback#@target.com/ – fragment vs. userinfo confusion

Multiple @ signs

Encoded # (%23) to bypass filters

Phase 14 – Exotic Protocols
Crafted gopher:// payloads to interact with Redis, Memcached

Raw TCP smuggling via URL schemes

Legacy protocol exploitation

📊 Smart Filtering & Deduplication
Instead of overwhelming you with 99+ raw findings, the tool automatically:

Groups findings by unique (endpoint, param) combinations

Keeps the highest severity per group

Counts OOB callbacks per vulnerable endpoint

Flags sensitive data leaks (tokens, keys, credentials)

Prints a clean summary showing only actionable vulnerabilities

Example: Raw vs. Filtered Output
Before filtering (99 findings):

text
[CRITICAL] Phase 2 → Testing param: url
[CRITICAL] Phase 2 → Testing param: url
[CRITICAL] Phase 3 → Testing 127.0.0.1
[CRITICAL] Phase 3 → Testing localhost
... (95 more lines)
After filtering (3 unique vulnerabilities):

text
===================== FILTERED SSRF SUMMARY =====================
Unique vulnerable endpoints/params with BLIND SSRF callbacks:

[CRITICAL] /api/proxy  (url)
  ● OOB Callbacks: 47  |  Sensitive data: YES
  └─ Top pattern: [CRITICAL] Callback URL found in response (Confirmed SSRF)

[HIGH] /fetch  (file)
  ● OOB Callbacks: 12  |  Sensitive data: NO
  └─ Top pattern: [HIGH] Internal IP (10.x.x.x) leaked

[MEDIUM] /download  (src)
  ● OOB Callbacks: 3  |  Sensitive data: NO
  └─ Top pattern: [MEDIUM] Link-local IP (169.254.x.x) leaked
📁 Output Files
JSON Report Structure
json
{
  "target": "example.com",
  "timestamp": "2025-01-15T14:30:00",
  "callback_host": "your-burp-collaborator.net",
  "total_findings": 47,
  "discovered_endpoints": [
    {
      "path": "/api/proxy",
      "method": "GET",
      "params": ["url", "format", "key"],
      "accepts_url_param": true,
      "response_code": 200,
      "content_type": "application/json"
    }
  ],
  "vulnerable_endpoints": [
    {
      "path": "/api/proxy",
      "method": "GET",
      "params": ["url"]
    }
  ],
  "findings": [
    {
      "phase": "Phase 4 - Cloud Metadata",
      "technique": "Metadata: 169.254.169.254",
      "url": "https://example.com/api/proxy?url=http://169.254.169.254/...",
      "endpoint": "/api/proxy",
      "param": "url",
      "payload": "http://169.254.169.254/latest/meta-data/",
      "status": 200,
      "body_snippet": "...",
      "matched_patterns": ["[CRITICAL] Cloud metadata endpoint accessed"],
      "severity": "critical",
      "out_of_band_hit": true
    }
  ],
  "blind_callbacks": {
    "http://your-burp-collaborator.net/validate-1234": [
      {
        "timestamp": "2025-01-15T14:30:05",
        "method": "GET",
        "headers": {"User-Agent": "Python-urllib/3.9"}
      }
    ]
  },
  "intercepted_requests": [...]
}
Terminal Output Colors
Color	Severity
🔴 Red	Critical
🟡 Yellow	High
🟣 Magenta	Medium
🔵 Blue	Low
🔷 Cyan	Info
🎯 Use Cases
1. Bug Bounty Hunting
Automated reconnaissance across multiple domains

Blind SSRF detection with Burp Collaborator/Interactsh

Cloud metadata extraction for high‑impact reports

Smart filtering to submit only unique, validated findings

2. Penetration Testing
Internal network mapping via SSRF

Service enumeration (databases, caches, internal APIs)

Protocol smuggling to bypass security controls

Chain SSRF with other vulnerabilities (XXE, CRLF)

3. Cloud Security Auditing
Multi‑cloud metadata scanning (AWS, Azure, GCP, Alibaba, etc.)

IAM role credential extraction

Instance metadata enumeration

Cross‑tenant access testing

4. Security Research
Protocol behavior analysis (gopher, dict, file)

DNS rebinding technique testing

URL parser differential analysis

SSRF filter bypass research

⚙️ Advanced Configuration
Adding Custom Endpoints
Edit the common_paths list in phase_0_discovery():

python
common_paths = [
    "/custom-internal-api",
    "/admin/import",
    "/legacy/proxy",
    # ... add your paths here
]
Adding Custom Cloud Providers
Edit cloud_targets in phase_5_all_cloud_metadata():

python
cloud_targets = {
    "MyCustomCloud": {
        "hosts": ["metadata.customcloud.internal"],
        "paths": ["latest/meta-data/"],
        "headers": {"X-Custom-Header": "value"}
    }
}
Adjusting Rate Limits
python
# In __init__ or via interactive prompt
rate_limit_delay = 2.0  # 2 seconds between requests
Custom User-Agent
python
await self.browser.new_context(
    user_agent="Your-Custom-Scanner/1.0"
)
📜 Legal & Ethical Guidelines
✅ DO
Only test targets you own or have written authorization to test

Use on bug bounty programs where SSRF is explicitly in scope

Respect rate limits and program policies

Disclose vulnerabilities responsibly to the target organization

❌ DON'T
Test production systems without explicit permission

Use for unauthorized access or data theft

Run on third‑party services not in scope

Publicly disclose vulnerabilities before they are patched

⚠️ Disclaimer
text
This tool is provided for educational and authorized security testing purposes only.
The author assumes no liability for misuse, damage, or legal consequences.
Always obtain proper written authorization before testing any system.
Use at your own risk.
🛡️ Detection Patterns
The tool automatically detects and classifies the following security issues:

Critical Severity
Cloud access tokens (GCP, AWS, Azure)

IAM role credentials

Private SSH/PGP keys

Service account tokens (Kubernetes)

/etc/passwd file contents

Blind SSRF callbacks confirmed

High Severity
Cloud metadata endpoint access

Internal IP disclosure (10.x, 192.168.x)

PHP/curl SSRF warnings

Project/subscription IDs leaked

K8s namespace disclosure

Medium Severity
Link‑local IP disclosure (169.254.x.x)

SQL error messages leaked

Connection refused errors

Internal service banners

Low Severity
Software version disclosure

Missing metadata headers

🤝 Contributing
We welcome contributions! Here's how you can help:

Ways to Contribute
🐛 Report bugs – Open an issue with detailed reproduction steps

💡 Suggest features – Open an issue with the enhancement tag

🔧 Submit PRs – Fix bugs, add features, improve documentation

🌍 Add cloud providers – Extend the multi‑cloud metadata phase

📝 Improve docs – Fix typos, add examples, translate README

Development Setup
bash
git clone https://github.com/KauanCosta2000/ultimate-ssrf-arsenal.git
cd ultimate-ssrf-arsenal
pip install -r requirements-dev.txt  # includes linters, formatters
Pull Request Process
Fork the repository

Create a feature branch (git checkout -b feature/amazing-feature)

Commit your changes (git commit -m 'Add amazing feature')

Push to the branch (git push origin feature/amazing-feature)

Open a Pull Request

📊 Performance Benchmarks
Target Type	Discovery Time	Full Scan Time	Findings (Raw)	Findings (Filtered)
Single API	~30s	~5 min	20‑50	2‑5
Web App	~2 min	~15 min	50‑150	5‑15
Multi‑Domain (10)	~5 min	~45 min	200‑500	15‑30
Benchmarks with 0.5s delay. Increase delay for stealth.

🔄 Changelog
v2.0 (Current)
✅ Added smart deduplication & filtering

✅ 15 attack phases (up from 9)

✅ Multi‑cloud metadata (7 providers)

✅ XXE → SSRF phase

✅ Encoding bypass phase

✅ CRLF injection phase

✅ URL fragment bypass

✅ Exotic protocol attacks

✅ Quiet mode (--quiet)

✅ Fixed JSON serialization bugs

✅ Improved error handling

v1.0 (Initial)
✅ 9 attack phases

✅ Dynamic discovery

✅ Blind SSRF detection

✅ JSON output

🗺️ Roadmap
Proxy support (SOCKS5, HTTP)

Custom payload files

WebSocket SSRF testing

GraphQL introspection + SSRF

Docker container for easy deployment

CI/CD pipeline integration

Web dashboard for results

API for programmatic scanning

Additional cloud providers (IBM, Linode, Vultr)

SSRF → RCE exploitation modules

❓ FAQ
Q: Can I use this for bug bounty?
A: Yes, but only on programs that explicitly allow SSRF testing and automated tools. Always read the program's policy first. Many programs prohibit automated scanners.

Q: Do I need a callback host?
A: It's optional but highly recommended. Without it, blind SSRF cannot be detected. Use Burp Collaborator (free with Burp Suite Professional), Interactsh (free, self‑hosted), or a simple VPS.

Q: Is this detectable?
A: Yes. It generates significant traffic with many unique payloads. Use with appropriate delay (2‑5 seconds) and only on authorized targets.

Q: Can it cause damage?
A: Potentially. Phases like gopher:// and file:// could interact with internal services. Always test on staging/dev environments first.

Q: Why so many findings?
A: The tool tests every endpoint with many payloads. Use the filtered summary at the end to see only unique, actionable vulnerabilities.

🌟 Acknowledgments
Playwright team for the amazing browser automation library

PortSwigger for Burp Collaborator and SSRF research

ProjectDiscovery for Interactsh

OWASP for SSRF prevention cheatsheet

All security researchers who have contributed SSRF techniques over the years

👤 Author
belladonnask (Kauan Costa)

GitHub: @KauanCosta2000

Tool Repository: ultimate-ssrf-arsenal

📄 License
This project is licensed under the MIT License – see the LICENSE file for details.

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
<div align="center">
⭐ If you find this tool useful, please give it a star on GitHub!
Happy (authorized) hacking! 🛡️

</div>
