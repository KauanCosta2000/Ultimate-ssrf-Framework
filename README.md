# Ultimate SSRF Framework v4.2-experimental

<div align="center">

![Ultimate SSRF Framework Demo](docs/demo.gif)

<br>

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Version](https://img.shields.io/badge/Version-v4.2--experimental-orange.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)
![CI](https://github.com/KauanCosta2000/Ultimate-ssrf-Framework/actions/workflows/python-ci.yml/badge.svg)

A research-focused SSRF testing framework built for bug bounty hunting, penetration testing and application security research.

</div>

---

## Why?

This project started as a collection of SSRF testing scripts I used during bug bounty hunting.

Over time those scripts evolved into a larger framework capable of discovering endpoints, validating SSRF findings, testing cloud metadata services and generating reports from a single workflow.

The goal is simple:

* Discover SSRF attack surfaces faster
* Scan single targets, multiple targets or target lists
* Validate findings with less manual work
* Automate common cloud and infrastructure checks
* Generate useful reports and exports

---

## Features

Current capabilities include:

* Endpoint discovery and crawling
* Blind SSRF validation
* Cloud metadata testing
* WAF fingerprinting
* File-based target scanning
* Multi-target scanning
* WebSocket SSRF testing
* gRPC SSRF testing
* Kubernetes SSRF testing
* Serverless SSRF testing
* AI-assisted payload generation
* AI-assisted finding triage
* Nuclei export
* SIEM (CEF) export
* HTML reporting
* JSON reporting
* Attack map generation

Cloud testing currently supports:

* AWS
* Azure
* Google Cloud Platform
* Alibaba Cloud

---

## Installation

Clone the repository:

```bash
git clone https://github.com/KauanCosta2000/Ultimate-ssrf-Framework.git

cd Ultimate-ssrf-Framework
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Install Playwright browser:

```bash
playwright install chromium
```

Verify installation:

```bash
python ssrf_arsenal.py --help
```

---

## Quick Start

Scan a single target:

```bash
python ssrf_arsenal.py --target example.com
```

Scan multiple targets:

```bash
python ssrf_arsenal.py --targets example.com,test.com
```

Scan targets from a file:

```bash
python ssrf_arsenal.py --target-file targets.txt
```

Use a custom callback server:

```bash
python ssrf_arsenal.py \
--target example.com \
--callback your-callback.oastify.com
```

---

## Proxy Support

HTTP proxy:

```bash
python ssrf_arsenal.py \
--target example.com \
--proxy http://127.0.0.1:8080
```

SOCKS5 proxy:

```bash
python ssrf_arsenal.py \
--target example.com \
--proxy socks5://127.0.0.1:9050
```

Proxy file:

```bash
python ssrf_arsenal.py \
--target example.com \
--proxy-file proxies.txt
```

---

## AI-assisted Workflows

The framework can optionally use LLMs to assist with payload generation and finding analysis.

Supported providers:

* OpenAI
* Claude
* Gemini
* Ollama
* Mistral
* DeepSeek

Example:

```bash
python ssrf_arsenal.py \
--target example.com \
--ai-provider ollama
```

OpenAI example:

```bash
python ssrf_arsenal.py \
--target example.com \
--ai-provider openai \
--ai-key YOUR_API_KEY
```

---

## Advanced Modules

### WebSocket SSRF

* WebSocket endpoint discovery
* URL injection testing
* Callback validation

### gRPC SSRF

* Reflection endpoint testing
* Metadata leakage detection
* Callback validation

### Kubernetes SSRF

* Kubernetes API discovery
* Internal service enumeration
* Namespace probing

### Serverless SSRF

* AWS Lambda testing
* Azure Functions testing
* Google Cloud Functions testing

### WAF Fingerprinting

Current fingerprints include:

* Cloudflare
* AWS WAF
* Akamai
* Imperva
* F5 BIG-IP
* Sucuri
* Fastly
* Azure Front Door
* Google Cloud Armor
* FortiWeb

---

## Reporting

Available output formats:

* JSON
* HTML
* Nuclei Templates
* SIEM (CEF)
* Attack Maps

Generate exports:

```bash
python ssrf_arsenal.py \
--target example.com \
--export-nuclei \
--export-siem \
--attack-map
```

Generated files may include:

```text
report.json
report.html
nuclei_target.yaml
siem_target.cef
attack_map_target.gexf
```

---

## Docker

Build image:

```bash
docker build -t ultimate-ssrf-framework .
```

Run scan:

```bash
docker run --rm ultimate-ssrf-framework \
--target example.com
```

Target file example:

```bash
docker run --rm ultimate-ssrf-framework \
--target-file targets.txt
```

---

## CI/CD

The project includes GitHub Actions workflows for:

* Syntax validation
* Dependency installation checks
* Automated Docker-based scanning workflows

---

## Development Status

Version 4.2 introduces several research-oriented modules including:

* WebSocket SSRF
* gRPC SSRF
* Kubernetes SSRF
* Serverless SSRF
* AI-assisted workflows

These modules are functional and will continue to evolve as new SSRF techniques and testing methodologies are added.

---

## Roadmap

Planned work includes:

* GraphQL SSRF discovery
* HTTP/2 request smuggling research
* Internal service fingerprinting
* DNS rebinding improvements
* Burp Suite extension
* OWASP ZAP integration
* Slack notifications
* Discord notifications

---

## Community

Contributions, bug reports and research ideas are welcome.

Useful areas for contribution:

* Cloud metadata research
* WebSocket SSRF
* gRPC SSRF
* WAF bypass techniques
* Burp integrations
* Nuclei templates
* Internal service fingerprinting

Join the discussion through:

* GitHub Discussions
* Issues
* Pull Requests

---

## Contributing

Please review:

* CONTRIBUTING.md
* SECURITY.md

before opening pull requests.

---

## Author

Developed by Belladonnask

* GitHub: https://github.com/KauanCosta2000
* LinkedIn: https://linkedin.com/in/kauan-costa

MIT License © Kauan Costa

---

## Disclaimer

This project is intended exclusively for authorized security testing, research and educational purposes.

The author assumes no responsibility for misuse or unauthorized activities performed using this software.
