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

## About

Ultimate SSRF Framework started as a collection of SSRF testing scripts I used during bug bounty hunting.

As the project grew, I kept adding the things I found myself doing repeatedly: endpoint discovery, blind SSRF validation, cloud metadata testing, reporting and infrastructure fingerprinting.

The result is a framework that can handle most of the SSRF workflow from a single command line interface.

The main goal is to reduce repetitive work and make it easier to discover, validate and document SSRF findings.

---

## What it can do

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
* HTML reporting
* JSON reporting
* Nuclei export
* SIEM (CEF) export
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

Install Playwright:

```bash
playwright install chromium
```

Verify installation:

```bash
python ssrf_arsenal.py --help
```

---

## Quick Start

Single target:

```bash
python ssrf_arsenal.py --target example.com
```

Multiple targets:

```bash
python ssrf_arsenal.py --targets api.example.com,test.example.com
```

Target file:

```bash
python ssrf_arsenal.py --target-file targets.txt
```

Blind SSRF callback:

```bash
python ssrf_arsenal.py \
--target example.com \
--callback your-callback.oastify.com
```

---

## CLI Reference

Display all available options:

```bash
python ssrf_arsenal.py --help
```

### Target Selection

```text
--target, -t           Single target domain
--targets              Comma-separated targets
--target-file, -f      File containing targets (one target per line)
```

### Callback Server

```text
--callback, -c         Out-of-band callback host
```

### Proxy Support

```text
--proxy, -p            Single proxy URL
--proxy-file           File containing proxy list
--proxy-type           http | socks5
```

### AI Integration

```text
--ai-provider          claude | openai | ollama | gemini | mistral | deepseek | none
--ai-key               API key for cloud AI providers
--ai-model             Specific model name
```

### Feature Control

```text
--no-waf               Disable WAF detection
--no-websocket         Disable WebSocket SSRF tests
--no-grpc              Disable gRPC SSRF tests
--no-k8s               Disable Kubernetes SSRF tests
--no-serverless        Disable Serverless SSRF tests
--no-ai                Disable AI features
```

### Export Options

```text
--export-nuclei        Export Nuclei templates
--export-siem          Export SIEM CEF report
--export-json-api      Export JSON API report
--attack-map           Generate attack path graph
--output, -o           Output directory
```

### Example

```bash
python ssrf_arsenal.py \
--target example.com \
--callback your-callback.oastify.com \
--output reports \
--export-nuclei \
--export-siem \
--export-json-api \
--attack-map
```

### Target Selection

```text
--target, -t           Single target domain

--targets              Comma-separated targets

--target-file, -f      File containing targets
                       (one target per line)
```

### Callback Server

```text
--callback, -c
```

Used for blind SSRF validation.

---

### Proxy Support

```text
--proxy, -p

--proxy-file

--proxy-type
```

Examples:

```bash
python ssrf_arsenal.py \
--target example.com \
--proxy http://127.0.0.1:8080
```

```bash
python ssrf_arsenal.py \
--target example.com \
--proxy socks5://127.0.0.1:9050
```

---

### AI Integration

Supported providers:

```text
claude
openai
ollama
gemini
mistral
deepseek
none
```

Example:

```bash
python ssrf_arsenal.py \
--target example.com \
--ai-provider ollama
```

---

### Feature Control

Disable specific modules:

```text
--no-waf
--no-websocket
--no-grpc
--no-k8s
--no-serverless
--no-ai
```

Example:

```bash
python ssrf_arsenal.py \
--target example.com \
--no-ai \
--no-websocket
```

---

### Output Control

```text
--quiet
--visible
--delay
```

Example:

```bash
python ssrf_arsenal.py \
--target example.com \
--quiet
```

---

### Export Options

```text
--export-nuclei

--export-siem

--export-json-api

--attack-map
```

Example:

```bash
python ssrf_arsenal.py \
--target example.com \
--export-nuclei \
--export-siem \
--attack-map
```

---

## Reporting

The framework can generate:

- HTML Reports
- JSON Reports
- Nuclei Templates
- SIEM CEF Exports
- Attack Maps

Use `--output` to specify where generated files should be saved:

```bash
python ssrf_arsenal.py \
--target example.com \
--output reports \
--export-nuclei \
--export-siem \
--export-json-api \
--attack-map
```

Generated files may include:

```text
reports/
- ssrf_example.com_YYYYMMDD_HHMMSS.json
- ssrf_report_example.com_YYYYMMDD_HHMMSS.html
- nuclei_example.com.yaml
- siem_example.com.cef
- api_report_example.com.json
- attack_map_example.com.gexf
```

Example:

```bash
python ssrf_arsenal.py \
--target example.com \
--export-nuclei \
--export-siem \
--export-json-api \
--attack-map
```

---

## Docker

Build:

```bash
docker build -t ultimate-ssrf-framework .
```

Run:

```bash
docker run --rm ultimate-ssrf-framework \
--target example.com
```

Target file:

```bash
docker run --rm ultimate-ssrf-framework \
--target-file targets.txt
```

---

## Development Status

This project is actively maintained and new modules are added whenever I find interesting SSRF research areas worth exploring.

Current research-focused modules include:

* WebSocket SSRF
* gRPC SSRF
* Kubernetes SSRF
* Serverless SSRF
* AI-assisted workflows

Some of these features are still evolving and will continue to improve over future releases.

---

## Roadmap

Planned work includes:

* GraphQL SSRF discovery
* HTTP/2 request smuggling research
* DNS rebinding improvements
* Internal service fingerprinting
* Burp Suite extension
* OWASP ZAP integration
* Slack notifications
* Discord notifications

---

## Contributing

Bug reports, pull requests and research ideas are always welcome.

Please review:

* CONTRIBUTING.md
* SECURITY.md

before opening a pull request.

---

## Author

Developed by Belladonnask

GitHub:
https://github.com/KauanCosta2000

LinkedIn: 
https://linkedin.com/in/kauan-costa](https://www.linkedin.com/in/kauan-costa-105b12345/

MIT License © Kauan Costa

---

## Disclaimer

This project is intended for authorized security testing, research and educational purposes only.

Use responsibly.
