# Ultimate SSRF Framework v4.1

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Playwright](https://img.shields.io/badge/Playwright-1.40+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Version](https://img.shields.io/badge/Version-4.1-red.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)
![AI](https://img.shields.io/badge/AI-Enabled-purple.svg)

### 🛡️ Advanced SSRF Discovery, Validation & Exploitation Framework

Built for **Bug Bounty Hunters**, **Pentesters**, **Red Team Operators** and **Security Researchers**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Docker](#-docker) • [Roadmap](#-roadmap) • [Contributing](#-contributing)

</div>

---

# 📸 Demo

<div align="center">

![Ultimate SSRF Framework Demo](docs/demo.gif)

</div>

---

# 🚀 Highlights

* 🔍 50+ SSRF Discovery Paths
* ☁️ Multi-Cloud Metadata Testing
* 🎯 Blind SSRF Detection
* 🧠 AI-Assisted Analysis
* 🌐 Proxy Rotation Support
* ⚡ Async Scanning Engine
* 🐳 Docker Ready
* 🔄 CI/CD Ready
* 📄 HTML Reporting

---

# 📖 Overview

Ultimate SSRF Framework is an advanced Server-Side Request Forgery testing framework designed for modern web applications, cloud environments and security research.

The framework combines traditional SSRF methodologies with automated validation, cloud-aware testing and optional AI-assisted analysis.

---

# ✨ Features

## 🎯 Discovery & Validation

* Dynamic endpoint discovery
* Automatic parameter extraction
* SSRF candidate identification
* Blind SSRF verification
* OAST callback support
* Response analysis

## ☁️ Cloud Testing

Supported providers:

* AWS
* Azure
* Google Cloud
* Oracle Cloud
* DigitalOcean
* Alibaba Cloud
* Huawei Cloud
* Tencent Cloud

## 🌐 Protocol Support

* file://
* gopher://
* ftp://
* ldap://
* dict://
* tftp://

## ⚔️ Advanced Techniques

* DNS Rebinding
* Localhost Bypasses
* CRLF Injection
* XXE → SSRF
* Redirect Bypasses
* URL Parser Confusion
* Encoding Bypasses

## 🤖 AI Integration

Supported Models:

* GPT-4o
* Claude
* Gemini
* Ollama
* DeepSeek
* Mistral

Capabilities:

* Payload Generation
* Finding Triage
* Attack Planning
* Exploit Chain Suggestions
* Report Assistance

---

# ⚡ Installation

```bash
git clone https://github.com/KauanCosta2000/Ultimate-ssrf-Framework.git

cd Ultimate-ssrf-Framework

pip install -r requirements.txt

playwright install chromium
```

---

# 🚀 Usage

### Basic Scan

```bash
python ssrf_arsenal.py --target example.com
```

### HTTP Proxy

```bash
python ssrf_arsenal.py \
--target example.com \
--proxy http://127.0.0.1:8080
```

### SOCKS5 Proxy

```bash
python ssrf_arsenal.py \
--target example.com \
--proxy socks5://127.0.0.1:9050
```

### Proxy Rotation

```bash
python ssrf_arsenal.py \
--target example.com \
--proxy-file proxies.txt
```

---

# ⚔️ Attack Phases

| Phase             | Description                         |
| ----------------- | ----------------------------------- |
| WAF Detection     | WAF and CDN fingerprinting          |
| Discovery         | Endpoint and parameter discovery    |
| Validation        | SSRF confirmation                   |
| Parameter Fuzzing | Parameter mutation                  |
| Localhost Bypass  | Internal network access             |
| Metadata Testing  | Cloud metadata testing              |
| Internal Services | Redis, Docker, Vault, Kubelet       |
| Protocol Attacks  | file://, gopher://, ldap://, ftp:// |
| Redirect Bypass   | URL parser confusion                |
| DNS Rebinding     | Internal targeting                  |
| XXE → SSRF        | XML based SSRF                      |
| Encoding Bypass   | Filter bypasses                     |
| CRLF Injection    | Header manipulation                 |
| Fragment Bypass   | URL fragment confusion              |
| Exotic Protocols  | Advanced protocol abuse             |

---

# 📄 Reporting

Supported Outputs:

* Console Output
* JSON Reports
* HTML Reports

---

# 🐳 Docker

Build:

```bash
docker build -t ultimate-ssrf-framework .
```

Run:

```bash
docker run --rm ultimate-ssrf-framework --target example.com
```

See `Dockerfile` for complete container configuration.

---

# 🔄 CI/CD

Compatible with:

* GitHub Actions
* GitLab CI
* Jenkins
* Custom Pipelines

---

# 🗺️ Roadmap

### SSRF Research

* WebSocket SSRF Testing
* gRPC SSRF Testing
* GraphQL SSRF Discovery
* HTTP/2 Request Smuggling Module
* Blind SSRF Correlation Engine

### Cloud & Infrastructure

* Kubernetes SSRF Module
* Serverless SSRF Testing
* Docker API Discovery
* Internal Service Fingerprinting
* Automatic Cloud Provider Detection

### Integrations

* Burp Suite Extension
* OWASP ZAP Plugin
* Nuclei Template Export
* JSON API Export
* SIEM Integration Support

### AI & Analysis

* AI-Assisted Exploit Chains
* Automatic Attack Path Mapping
* SSRF Impact Scoring
* Payload Mutation Engine

---

# 🌍 Community

Contributions, research ideas and SSRF bypass techniques are welcome.

Interesting areas:

* Cloud Metadata Research
* WAF Bypasses
* WebSocket SSRF
* gRPC SSRF
* Burp Integrations
* Nuclei Templates

---

# 🤝 Contributing

Please review:

* CONTRIBUTING.md
* SECURITY.md

before submitting pull requests.

---

# ⚠️ Disclaimer

This project is intended exclusively for authorized security testing, research and educational purposes.

The author assumes no responsibility for misuse.

---

# 📜 License

MIT License

Copyright (c) 2025 Kauan Costa

---

<div align="center">

⭐ Star the repository if it helps you.

Happy (authorized) hacking! 🛡️

</div>
