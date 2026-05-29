Ultimate SSRF Arsenal – Multi‑Target Automated SSRF Exploitation Framework

[Python 3.8+] [Playwright] [MIT License]

Ultimate SSRF Arsenal is a powerful, dynamic, and fully automated SSRF (Server‑Side Request Forgery) testing framework built with Python and Playwright.  
It features intelligent endpoint discovery, parameter fuzzing, cloud metadata extraction (GCP, AWS, Azure, Kubernetes), protocol smuggling, blind SSRF detection via out‑of‑band callbacks, and multi‑target scanning — all in one comprehensive tool.

✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔍 Dynamic Discovery | Automatically crawls common endpoints, extracts parameters from HTML forms/links, and supports GET/POST with multiple Content‑Types (JSON, form‑urlencoded, multipart). |
| 🧠 9 Attack Phases | Endpoint validation, parameter fuzzing, localhost bypass, cloud metadata (multi‑cloud), internal service scanning, gopher/dict/file protocol attacks, redirect bypass, DNS rebinding. |
| 🌐 Multi‑Target Support | Scan single domains, comma‑separated lists, or load targets from a file. Individual JSON results + consolidated summary. |
| 📡 Blind SSRF Detection | Configure your own callback host (Burp Collaborator, Interactsh, etc.) to catch out‑of‑band requests and confirm blind SSRF. |
| ⚡ Rate Limiting | Configurable delays between requests to avoid detection and respect server limits. |
| 📄 Rich Output | Color‑coded terminal output + JSON results with full evidence (endpoints, parameters, payloads, matched patterns, severity levels) and intercepted request logs. |
| ☁️ Cloud Metadata Extraction | Targets cloud metadata endpoints (GCP, AWS, Azure, etc.) including required headers like Metadata-Flavor. |
| 🔓 Protocol Smuggling | Supports file://, gopher://, dict://, ftp://, redis://, mysql://, etc. |

🎯 Use Cases

- Bug bounty hunters searching for SSRF in web applications.
- Penetration testers auditing internal networks and cloud environments.
- Security researchers trying to extract internal metadata or access internal services.
- Automating SSRF detection across multiple domains.

📦 Installation

1. Clone the repository:
   git clone https://github.com/yourusername/ultimate-ssrf-arsenal.git
   cd ultimate-ssrf-arsenal

2. Install Python dependencies:
   pip install -r requirements.txt

   requirements.txt should contain:
   playwright>=1.40.0

3. Install Playwright browsers:
   playwright install chromium

🚀 Usage

Run the script:
   python ultimate_ssrf_arsenal.py

You will be prompted to choose input method:
   [1] Single domain
   [2] Comma‑separated list (ex: exemplo.com,teste.com,site.org)
   [3] File with one domain per line

Then provide your callback host (optional, for blind SSRF detection) and delay between requests.

Example – single domain:
   Target: example.com
   Callback host: your.burpcollaborator.net
   Delay: 0.5

Example – targets file (targets.txt):
   example.com
   test-site.org
   internal.api.com

🧩 Attack Phases (Detailed)

Phase 0 – Dynamic Discovery
   Crawls common endpoints, tests GET/POST, extracts parameters from HTML, identifies potential SSRF‑vulnerable endpoints.

Phase 1 – Endpoint Validation
   Validates discovered endpoints with callback payloads to confirm SSRF.

Phase 2 – Parameter Fuzzing
   Fuzzes 90+ SSRF‑prone parameter names (url, uri, redirect, fetch, proxy, etc.).

Phase 3 – Localhost Bypass
   Tests 20+ localhost variants (decimal, octal, hex, IPv6, .nip.io, etc.).

Phase 4 – Cloud Metadata (Generic)
   Tries to access cloud metadata endpoints (169.254.169.254, metadata.google.internal, etc.) with and without required headers (e.g., Metadata-Flavor).

Phase 5 – Multi‑Cloud Metadata
   AWS (IAM roles), Azure (instance metadata, OAuth tokens), and others.

Phase 6 – Internal Services
   Scans common internal services (Elasticsearch, Docker, Kubelet, Consul, Vault, Redis, etc.).

Phase 7 – Protocol Attacks
   file:// (LFI), gopher:// (Redis, MySQL, SMTP), dict://.

Phase 8 – Redirect Bypass
   Tests open redirect patterns to chain SSRF.

Phase 9 – DNS Rebinding
   Tries nip.io/sslip.io domains to bypass IP‑based restrictions.

📁 Output

For each target, a JSON file is created:
   ssrf_results_<domain>_YYYYMMDD_HHMMSS.json

It contains:
- Discovered endpoints and parameters
- Vulnerable endpoints
- All findings with severity (critical, high, medium, low, info)
- Matched patterns (e.g., [CRITICAL] Access token leaked, [HIGH] Internal IP disclosed)
- Intercepted requests (internal metadata calls)
- Blind callback hits (out‑of‑band confirmations)

A final consolidated summary is printed to the terminal.

🛡️ Example Findings (Terminal)

[CRITICAL] Phase 4 - Cloud Metadata → Metadata endpoint accessed
  URL: https://example.com/proxy?url=http://169.254.169.254/latest/meta-data/
  Endpoint: /proxy
  Parameter: url
  Payload: http://169.254.169.254/latest/meta-data/
  Status: 200
  ├─ [CRITICAL] Cloud metadata endpoint accessed
  ├─ [HIGH] IAM role credentials leaked

⚙️ Configuration

You can easily modify the script to:
- Add more endpoints to discover (edit common_paths in phase_0_discovery()).
- Change payloads, localhost variants, or cloud metadata paths.
- Adjust timeouts and delays.

📜 Disclaimer

This tool is for educational and authorized security testing purposes only.  
The author is not responsible for any misuse or damage caused by this software.  
Always obtain proper permission before scanning any target.

🤝 Contributing

Pull requests, suggestions, and bug reports are welcome!  
Feel free to open an issue or submit a PR.

📄 License

MIT License – see LICENSE file.

👤 Author

Created by belladonnask  
GitHub: @KauanCosta2000

⭐ Show Your Support

If you find this tool useful, please give it a ⭐ on GitHub and share it with the community!
