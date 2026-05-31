# Ultimate SSRF Arsenal v4.0

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Playwright](https://img.shields.io/badge/Playwright-1.40+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Version](https://img.shields.io/badge/Version-4.0-red.svg)
![AI](https://img.shields.io/badge/AI-Optional-purple.svg)

**Advanced Multi‑Target SSRF Exploitation Framework with Optional AI Integration**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Target Modes](#-target-selection-modes) • [AI](#-ai-integration-optional) • [Roadmap](#-roadmap) • [Disclaimer](#-disclaimer)

</div>

---

## 📖 Overview

**Ultimate SSRF Arsenal** is a fully automated Server‑Side Request Forgery testing framework with **optional AI integration** supporting 6 LLM providers.

### v4.0 Highlights
- 🤖 **Optional AI** - Claude, GPT-4o, Ollama, Gemini, Mistral, DeepSeek
- 🎯 **3 Target Modes** - Single, Comma‑separated, File‑based
- 🛡️ **WAF Detection** - 20+ signatures with bypass suggestions
- 📄 **HTML Reports** - Professional reports with charts
- 📊 **Smart Deduplication** - Noise filtering

---

## ✨ Features

### Core
- Dynamic endpoint discovery (50+ paths)
- 15 attack phases
- Multi‑cloud metadata (AWS, Azure, GCP, Alibaba, Oracle, DO, Huawei, Tencent)
- Protocol smuggling (file://, gopher://, dict://, ftp://, ldap://, tftp://)
- Blind SSRF detection (OOB callbacks)
- DNS rebinding (nip.io, localtest.me, lvh.me)
- Encoding bypass (URL, Unicode, double, null byte)
- CRLF injection
- XXE → SSRF
- Localhost bypass (20+ representations)

### WAF (20+ Signatures)
Cloudflare, AWS WAF, Akamai, Imperva, F5, ModSecurity, Sucuri, Wordfence, Barracuda, Citrix, Fortinet, Radware, Wallarm, DenyAll, Distil, Fastly, Varnish, Google Cloud Armor, Azure WAF, Alibaba Cloud WAF

### AI (Optional - 6 Providers)
- **Smart Payload Generation** - Context‑aware payloads
- **Finding Triage** - Severity & exploitability scoring
- **Exploit Chains** - Multi‑step attack paths
- **Attack Planning** - Comprehensive strategies
- **False Positive Analysis**

---

## 📦 Installation

```bash
git clone https://github.com/KauanCosta2000/ultimate-ssrf-arsenal.git
cd ultimate-ssrf-arsenal
pip install playwright
playwright install chromium

# Optional: AI + Reports
pip install aiohttp jinja2
🚀 Usage
Target Selection
bash
# Single target
python ssrf_arsenal.py --target example.com

# Multiple targets
python ssrf_arsenal.py --targets "example.com,test.com,api.org"

# From file (one per line, # for comments)
python ssrf_arsenal.py --target-file targets.txt

# Interactive mode
python ssrf_arsenal.py
Full Options
bash
python ssrf_arsenal.py --help

Options:
  --target DOMAIN       Single target
  --targets DOMAINS     Comma-separated targets
  --target-file FILE    File with targets
  --callback HOST       Callback for blind SSRF
  --delay SECONDS       Delay between requests (default: 0.5)
  --ai-provider NAME    LLM: claude, openai, ollama, gemini, mistral, deepseek
  --ai-key KEY          API key for cloud AI
  --ai-model MODEL      Specific model name
  --quiet, -q           Less output
  --visible             Show browser window
Examples
bash
# Basic
python ssrf_arsenal.py --target example.com

# Multi-target with callback
python ssrf_arsenal.py --targets "site1.com,site2.com" --callback burp.oastify.com

# From file
python ssrf_arsenal.py --target-file targets.txt --delay 1.0

# Local AI (free)
python ssrf_arsenal.py --target example.com --ai-provider ollama

# Claude
python ssrf_arsenal.py --target example.com --ai-provider claude --ai-key sk-ant-xxx

# OpenAI
python ssrf_arsenal.py --target example.com --ai-provider openai --ai-key sk-xxx

# Full featured
python ssrf_arsenal.py --targets "example.com,test.com" --callback burp.oastify.com --ai-provider ollama

# Quiet mode
python ssrf_arsenal.py --target-file targets.txt --quiet
🤖 AI Setup
Ollama (Free - Local)
bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.1
python ssrf_arsenal.py --target example.com --ai-provider ollama
Cloud Providers
bash
# Claude
--ai-provider claude --ai-key YOUR_KEY

# OpenAI
--ai-provider openai --ai-key YOUR_KEY

# Gemini
--ai-provider gemini --ai-key YOUR_KEY

# Mistral
--ai-provider mistral --ai-key YOUR_KEY

# DeepSeek
--ai-provider deepseek --ai-key YOUR_KEY
🧩 Attack Phases
Phase	Description
WAF Detection	20+ WAF/CDN fingerprints
Discovery	50+ endpoints, param extraction
Validation	Callback confirmation
Parameter Fuzzing	90+ SSRF params
Localhost Bypass	20+ IP representations
GCP Metadata	metadata.google.internal
Multi‑Cloud	7 cloud providers
Internal Services	Redis, Docker, Kubelet, Vault, etc.
Protocol Attacks	file://, gopher://, dict://, ftp://, ldap://
Redirect Bypass	URL parser confusion
DNS Rebinding	nip.io, sslip.io, localtest.me
XXE → SSRF	XML external entity
Encoding Bypass	URL, Unicode, double, null byte
CRLF Injection	Header smuggling
Fragment Bypass	#/@ confusion
Exotic Protocols	Redis/Memcached via gopher
AI Payloads	Smart generation (optional)
AI Triage	Auto‑analysis (optional)
📊 Output
Console
text
[WAF] Detected: Cloudflare (95%)
  Bypass: DNS rebinding, IPv6 notation, Decimal IP

[DISCOVERY] Found 12 endpoints, 34 params

[BASIC] [CRITICAL] /api/proxy → url
  [CRITICAL] Callback in response

[AI] Generated 10 custom payloads
[AI] Risk Assessment: CRITICAL
[AI] Exploit chains: 5 suggested

==================================================
  SCAN COMPLETE - example.com
==================================================
  WAF: Cloudflare
  Endpoints: 12
  Findings: 47 raw / 3 unique
  Callbacks: 15

  [CRITICAL] /api/proxy → url (15 callbacks)
  [HIGH] /fetch → file (3 callbacks)
  
  Report: ssrf_report_example.com_20250115_143000.html
  Results: ssrf_example.com_20250115_143000.json
JSON Report
json
{
  "target": "example.com",
  "waf": {"detected": true, "primary": "Cloudflare", "confidence": 95.0},
  "endpoints": [{"path": "/api/proxy", "method": "GET", "params": ["url"]}],
  "findings": [{
    "phase": "Basic",
    "endpoint": "/api/proxy",
    "param": "url",
    "severity": "critical",
    "out_of_band_hit": true,
    "matched_patterns": ["[CRITICAL] Callback in response"]
  }]
}
HTML Report
Dark theme, gradient header

Severity distribution

WAF details + bypass tips

Vulnerable endpoints table

GraphQL/HTTP2 findings (if any)

Responsive design

🗺️ Roadmap
Performance
Async engine improvements

Proxy support (SOCKS5, HTTP)

Docker container

CI/CD pipeline integration

New Attacks
WebSocket SSRF

gRPC SSRF

SSTI → SSRF chains

Deserialization → SSRF

OAuth/SSO SSRF

Email SSRF (SMTP/IMAP)

PDF generation SSRF

Image processing SSRF (ImageMagick)

WAF Evasion
ML‑powered payload mutation

Advanced encoding chains

HTTP parameter pollution

Reporting
Interactive HTML dashboard

PDF reports

MITRE ATT&CK mapping

CVSS 4.0 calculator

Scan comparison (diff)

Integrations
Burp Suite extension

ZAP plugin

Nuclei template export

Slack/Discord webhooks

Jira/GitHub Issues auto‑create

DefectDojo integration

AI Enhancements
Reinforcement learning

Natural language reports

Fine‑tuned SSRF models

Multi‑agent collaboration

Real‑time AI guidance

Cloud & Container
Kubernetes SSRF

Serverless SSRF (Lambda, Functions)

CDN‑specific tests

API Gateway bypass

Documentation
Video tutorials

Wiki

Community payload repo

CTF challenges

⚠️ Disclaimer
For authorized testing only.

✅ Test only with written permission

✅ Respect bug bounty scopes

❌ No unauthorized access

❌ Author not liable for misuse

📜 License
MIT License - Copyright (c) 2025 Kauan Costa (belladonnask)

text
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
👤 Author
Kauan Costa (belladonnask)

GitHub: @KauanCosta2000

Repo: ultimate-ssrf-arsenal

🤝 Contributing
Fork repo

Create branch (git checkout -b feature/amazing)

Commit (git commit -m 'Add feature')

Push (git push origin feature/amazing)

Open PR

<div align="center">
⭐ Star this repo if it helps you!
Happy (authorized) hacking! 🛡️

</div> ```
