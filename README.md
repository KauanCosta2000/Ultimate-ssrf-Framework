
<br>
# Ultimate SSRF Framework v4.2-experimental

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Playwright](https://img.shields.io/badge/Playwright-Powered-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Version](https://img.shields.io/badge/Version-v4.2--experimental-orange.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)
![AI](https://img.shields.io/badge/AI-Enhanced-purple.svg)
![CI](https://github.com/KauanCosta2000/Ultimate-ssrf-Framework/actions/workflows/python-ci.yml/badge.svg)

### 🛡️ Advanced SSRF Discovery, Validation & Analysis Framework

Built for **Bug Bounty Hunters**, **Pentesters**, **Red Team Operators** and **Security Researchers**.

Automated SSRF discovery, cloud metadata testing, blind SSRF validation, AI-assisted analysis and advanced infrastructure testing.

</div>

---

## 📸 Demo

<div align="center">

![Ultimate SSRF Framework Demo](docs/demo.gif)

</div>

---

# 🚀 Highlights

- 🔍 Automated Endpoint Discovery
- 🎯 Blind SSRF Detection
- ☁️ Cloud Metadata Testing
- 🤖 AI-Assisted Payload Generation
- 🧠 AI-Assisted Finding Triage
- 🌐 Proxy & SOCKS5 Support
- ⚔️ WebSocket SSRF Testing
- ⚙️ gRPC SSRF Testing
- ☸️ Kubernetes SSRF Testing
- ☁️ Serverless SSRF Testing
- 🛡️ WAF Fingerprinting
- 📄 HTML Reporting
- 📊 JSON Reporting
- 🧬 Nuclei Export
- 📡 SIEM (CEF) Export
- 🗺️ Attack Path Mapping

---

# 📖 Overview

Ultimate SSRF Framework is an advanced Server-Side Request Forgery testing framework designed to automate discovery, validation and analysis of SSRF vulnerabilities across modern web applications and cloud environments.

The framework combines:

- Automated Crawling
- Endpoint Discovery
- Blind SSRF Correlation
- Cloud Metadata Testing
- AI-Assisted Analysis
- Infrastructure Fingerprinting
- Reporting & Export Automation

to help researchers identify SSRF attack surfaces faster and more efficiently.

---

# ✨ Features

## 🔎 Discovery Engine

Automatic discovery of:

- Links
- Forms
- Scripts
- Iframes
- API Endpoints
- Internal Routes

Capabilities:

- Dynamic Crawling
- Endpoint Enumeration
- Parameter Extraction
- Multi-Target Scanning

---

## 🎯 SSRF Validation

Supported validation methods:

- Direct SSRF Detection
- Blind SSRF Detection
- Callback Correlation
- Internal Resource Discovery
- Metadata Service Enumeration

Common Parameters Tested:

```text
url
uri
path
file
redirect
target
dest
endpoint
```

---

## ☁️ Cloud Metadata Testing

Supported Providers:

### AWS

```text
169.254.169.254/latest/meta-data
```

### Azure

```text
169.254.169.254/metadata/identity
```

### Google Cloud

```text
metadata.google.internal
```

### Alibaba Cloud

```text
100.100.100.200
```

Automatic Cloud Detection:

- AWS
- Azure
- Google Cloud
- Alibaba Cloud

---

## ⚔️ Advanced Testing Modules

### WebSocket SSRF

- WebSocket Endpoint Discovery
- WebSocket URL Injection
- Blind Callback Validation

### gRPC SSRF

- Reflection Endpoint Testing
- Metadata Leakage Detection
- Blind Callback Validation

### Kubernetes SSRF

- Kubernetes API Discovery
- Internal Service Enumeration
- Namespace Testing

### Serverless SSRF

- AWS Lambda Metadata Testing
- Azure Functions Metadata Testing
- Google Cloud Functions Testing

---

## 🛡️ WAF Fingerprinting

Current Fingerprints:

- Cloudflare
- AWS WAF
- Akamai
- Imperva
- F5 BIG-IP
- Sucuri
- Fastly
- Azure Front Door
- Google Cloud Armor
- FortiWeb

Output Includes:

- WAF Identification
- Confidence Score
- Suggested Bypass Techniques

---

## 🤖 AI Integration

Supported Providers:

- OpenAI
- Claude
- Gemini
- Ollama
- Mistral
- DeepSeek

Capabilities:

### Payload Generation

Generate context-aware SSRF payloads based on:

- Target
- Cloud Provider
- WAF Detection
- Endpoint Context

### Finding Triage

Automatic:

- Risk Assessment
- Finding Prioritization
- Exploitation Suggestions

### Analysis

- SSRF Pattern Recognition
- Context-Aware Recommendations
- Research Assistance

---

# ⚡ Installation

## Clone Repository

```bash
git clone https://github.com/KauanCosta2000/Ultimate-ssrf-Framework.git

cd Ultimate-ssrf-Framework
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

## Install Browser

```bash
playwright install chromium
```

---

# 🚀 Usage

## Single Target

```bash
python ssrf_arsenal.py \
--target example.com
```

---

## Multiple Targets

```bash
python ssrf_arsenal.py \
--targets example.com,test.com,api.example.com
```

---

## Target File

```bash
python ssrf_arsenal.py \
--target-file targets.txt
```

---

## Custom Callback

```bash
python ssrf_arsenal.py \
--target example.com \
--callback your-callback.oastify.com
```

---

# 🌐 Proxy Support

## HTTP Proxy

```bash
python ssrf_arsenal.py \
--target example.com \
--proxy http://127.0.0.1:8080
```

## SOCKS5 Proxy

```bash
python ssrf_arsenal.py \
--target example.com \
--proxy socks5://127.0.0.1:9050
```

## Proxy List

```bash
python ssrf_arsenal.py \
--target example.com \
--proxy-file proxies.txt
```

---

# 🤖 AI Examples

## Ollama

```bash
python ssrf_arsenal.py \
--target example.com \
--ai-provider ollama
```

## OpenAI

```bash
python ssrf_arsenal.py \
--target example.com \
--ai-provider openai \
--ai-key YOUR_API_KEY
```

## Claude

```bash
python ssrf_arsenal.py \
--target example.com \
--ai-provider claude \
--ai-key YOUR_API_KEY
```

---

# 📊 Export Options

## Nuclei Templates

```bash
python ssrf_arsenal.py \
--target example.com \
--export-nuclei
```

Output:

```text
nuclei_example.com.yaml
```

---

## SIEM Export

```bash
python ssrf_arsenal.py \
--target example.com \
--export-siem
```

Output:

```text
siem_example.com.cef
```

---

## JSON API Report

```bash
python ssrf_arsenal.py \
--target example.com \
--export-json-api
```

Output:

```text
api_report_example.com.json
```

---

## Attack Map

```bash
python ssrf_arsenal.py \
--target example.com \
--attack-map
```

Output:

```text
attack_map_example.com.gexf
```

---

# 📄 Reporting

Generated Reports:

### JSON Report

Contains:

- Findings
- Endpoints
- Internal IPs
- Evidence
- Callbacks

### HTML Report

Contains:

- Executive Summary
- Vulnerability Overview
- Severity Breakdown
- Callback Statistics

### SIEM Report

CEF Format:

```text
CEF:0|SSRFFramework|4.2|...
```

---

# 🐳 Docker

Build:

```bash
docker build -t ultimate-ssrf-framework .
```

Run:

```bash
docker run --rm ultimate-ssrf-framework \
--target example.com
```

---

# 🔄 CI/CD

Compatible With:

- GitHub Actions
- GitLab CI
- Jenkins
- Azure Pipelines

---

# ⚠️ Development Status

Version 4.2 introduces several advanced research modules:

- WebSocket SSRF Testing
- gRPC SSRF Testing
- Kubernetes SSRF Testing
- Serverless SSRF Testing
- AI-Assisted Payload Generation
- Attack Path Mapping

These modules are functional and actively evolving as part of ongoing SSRF research and framework development.

---

# 🗺️ Roadmap

## SSRF Research

- HTTP/2 Request Smuggling
- GraphQL SSRF Testing
- DNS Rebinding Enhancements
- Internal Service Fingerprinting
- Cloud Service Discovery Automation

## Integrations

- Burp Suite Extension
- OWASP ZAP Plugin
- Slack Notifications
- Discord Notifications
- Nuclei Workflow Generation

## AI & Analysis

- Automatic Exploit Chains
- Payload Mutation Engine
- Context-Aware Attack Paths
- Automated Impact Assessment

---

# 🌍 Community

Contributions, research ideas and SSRF techniques are welcome.

Areas of interest:

- Cloud Metadata Research
- WebSocket SSRF
- gRPC SSRF
- Kubernetes Security
- WAF Bypass Techniques
- Burp Integrations
- Nuclei Templates

See `CONTRIBUTING.md` for details.

---

# 🤝 Contributing

Before submitting Pull Requests please review:

- CONTRIBUTING.md
- SECURITY.md

Community contributions are welcome.

---

# ⚠️ Disclaimer

This project is intended exclusively for authorized security testing, research and educational purposes.

The author assumes no responsibility for misuse or unauthorized activities performed using this software.

---

# 📜 License

MIT License

Copyright (c) 2025 Kauan Costa

---

# 👤 Author

**Kauan Costa (@belladonnask)**

GitHub: https://github.com/KauanCosta2000

Repository: https://github.com/KauanCosta2000/Ultimate-ssrf-Framework

---

## Contact

- GitHub: https://github.com/KauanCosta2000
- LinkedIn: https://linkedin.com/in/kauan-costa-105b12345

<div align="center">

⭐ Star the repository if you find it useful.

Happy (authorized) hacking! 🛡️

</div>
