# Ultimate SSRF Arsenal v4.0

<div align="center">

### Advanced SSRF Discovery, Testing & Validation Framework

Automated Server-Side Request Forgery testing framework built for Bug Bounty Hunters, Penetration Testers, Red Team Operators and Security Researchers.

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Playwright](https://img.shields.io/badge/Playwright-Chromium-green)
![Version](https://img.shields.io/badge/Version-4.0-red)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Active-success)
![AI](https://img.shields.io/badge/AI-Optional-purple)

</div>

---

## Project Status

✅ Active Development

Current Version: v4.0

Implemented Features:

- Multi-target scanning
- Blind SSRF detection
- WAF fingerprinting
- Multi-cloud metadata testing
- HTML reporting
- Multi-LLM integration
- AI payload generation
- AI triage
- Exploit chain suggestions

Ultimate SSRF Arsenal is a fully automated SSRF testing framework designed to discover, validate and analyze Server-Side Request Forgery vulnerabilities across modern web applications.

## Overview

The framework combines:

* Dynamic endpoint discovery
* Blind SSRF detection
* Multi-cloud metadata testing
* Protocol smuggling
* WAF fingerprinting
* Smart finding deduplication
* Multi-target scanning
* JSON & HTML reporting
* Optional AI-assisted analysis

Unlike traditional scanners that rely solely on predefined payloads, Ultimate SSRF Arsenal combines discovery, validation, exploitation and reporting in a single workflow.

---

## Features

### Core Features

* Dynamic endpoint discovery
* Automatic parameter extraction
* Multi-target scanning
* Blind SSRF detection
* Smart finding deduplication
* Severity classification
* JSON reporting
* HTML reporting

### SSRF Testing

* Localhost bypasses
* DNS rebinding
* Protocol smuggling
* Redirect bypasses
* Encoding bypasses
* XXE → SSRF testing
* CRLF injection testing
* Internal service discovery
* Multi-cloud metadata extraction

### Supported Cloud Providers

* AWS
* Azure
* Google Cloud Platform
* Oracle Cloud
* Alibaba Cloud
* Tencent Cloud
* Huawei Cloud
* DigitalOcean

### WAF Fingerprinting

Supports 20+ WAF/CDN signatures including:

* Cloudflare
* AWS WAF
* Akamai
* Imperva
* ModSecurity
* F5 BIG-IP
* Citrix NetScaler
* Fortinet
* Sucuri
* Fastly
* Azure WAF
* Google Cloud Armor
* Alibaba Cloud WAF

Automatic bypass recommendations are provided when available.

---

## AI Integration (Optional)

AI features are completely optional.

The framework works normally even when no AI provider is configured.

### Supported Providers

* Ollama (Local)
* OpenAI
* Claude
* Gemini
* DeepSeek
* Mistral

### AI Capabilities

* Context-aware payload generation
* Automated finding triage
* Exploit chain suggestions
* Attack planning
* False-positive analysis
* Risk assessment

Graceful degradation ensures all core SSRF functionality remains available without AI.

---

## Architecture

```text
Target(s)
    │
    ▼
Discovery Engine
    │
    ▼
SSRF Testing Engine
    │
    ├── Blind SSRF
    ├── Metadata Testing
    ├── Protocol Attacks
    ├── DNS Rebinding
    ├── WAF Detection
    └── AI Assistance
    │
    ▼
Result Processing
    │
    ├── Deduplication
    ├── Severity Analysis
    └── Report Generation
```

---

## Installation

### Requirements

- Python 3.8+
- pip

### requirements.txt

```txt
playwright>=1.40.0
aiohttp>=3.9.0
jinja2>=3.1.0
httpx>=0.27.0
```

### Clone Repository

```bash
git clone https://github.com/KauanCosta2000/Ultimate-SSRF-Arsenal-Multi-Target-Automated-SSRF-Exploitation-Framework.git
cd Ultimate-SSRF-Arsenal-Multi-Target-Automated-SSRF-Exploitation-Framework
```

### Install Dependencies

```bash
pip install -r requirements.txt

playwright install chromium
```

### Dependencies

| Dependency | Required | Purpose |
|------------|-----------|----------|
| playwright | Yes | Browser automation |
| aiohttp | Optional | AI integrations |
| jinja2 | Optional | HTML reports |
| httpx | Optional | Extended HTTP functionality |

---

## Quick Start

### Single Target

```bash
python ssrf_arsenal.py --target example.com
```

### Multiple Targets

```bash
python ssrf_arsenal.py --targets "example.com,test.com,api.org"
```

### Target File

```bash
python ssrf_arsenal.py --target-file targets.txt
```

### Blind SSRF Testing

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your.oastify.com
```

### AI Enabled

```bash
python ssrf_arsenal.py \
  --target example.com \
  --ai-provider ollama
```

---

## Command Line Options

| Option        | Description             |
| ------------- | ----------------------- |
| --target      | Single target           |
| --targets     | Multiple targets        |
| --target-file | File containing targets |
| --callback    | Callback server         |
| --delay       | Request delay           |
| --quiet       | Reduced output          |
| --visible     | Browser visible         |
| --ai-provider | AI provider             |
| --ai-model    | AI model                |
| --ai-key      | Provider API key        |
| --help        | Help menu               |

---

## Attack Phases

| Phase                | Description                      |
| -------------------- | -------------------------------- |
| WAF Detection        | WAF/CDN fingerprinting           |
| Discovery            | Endpoint discovery               |
| Validation           | SSRF validation                  |
| Parameter Fuzzing    | Parameter testing                |
| Localhost Bypass     | Alternate localhost formats      |
| GCP Metadata         | GCP metadata extraction          |
| Multi-Cloud Metadata | Cloud metadata testing           |
| Internal Services    | Internal service discovery       |
| Protocol Attacks     | file://, gopher://, ldap://      |
| Redirect Bypass      | Redirect abuse                   |
| DNS Rebinding        | DNS rebinding attacks            |
| XXE → SSRF           | XML abuse                        |
| Encoding Bypass      | Encoding tricks                  |
| CRLF Injection       | Header injection                 |
| Fragment Bypass      | URL confusion                    |
| Exotic Protocols     | Advanced protocol abuse          |
| AI Payloads          | Context-aware payload generation |
| AI Triage            | Automated vulnerability analysis |

---

## Example Output

```text
[WAF] Detected: Cloudflare (95%)

[DISCOVERY]
Found 12 endpoints

[BASIC]
[CRITICAL] /api/proxy → url

[AI]
Generated 10 custom payloads
Risk Assessment: CRITICAL
Suggested exploit chains: 5

========================================

Target: example.com

Critical Findings: 1
High Findings: 2
Medium Findings: 4

========================================
```

---

## Output Files

Generated artifacts:

```text
reports/

├── ssrf_results_example.json
├── ssrf_report_example.html
```

Reports include:

* Vulnerabilities
* Endpoints
* Parameters
* Callback correlation
* WAF detection
* Evidence
* Severity classification

---

## Use Cases

### Bug Bounty

Automated SSRF discovery across attack surfaces.

### Penetration Testing

Internal network mapping and SSRF validation.

### Cloud Security

Metadata exposure testing and IAM discovery.

### Security Research

Protocol abuse and filter bypass experimentation.

### Red Team Operations

Infrastructure enumeration and attack path analysis.

---

## Roadmap

### Performance

* [ ] Async engine improvements
* [ ] SOCKS5 proxy support
* [ ] HTTP proxy rotation
* [ ] Docker image release
* [ ] CI/CD integration

### New Attack Modules

* [ ] WebSocket SSRF
* [ ] gRPC SSRF
* [ ] OAuth SSRF
* [ ] SSO SSRF
* [ ] PDF generation SSRF
* [ ] Image processing SSRF
* [ ] Deserialization → SSRF

### Reporting

* [ ] Interactive HTML dashboard
* [ ] PDF reports
* [ ] MITRE ATT&CK mapping
* [ ] CVSS 4.0 scoring
* [ ] Historical scan comparison

### Integrations

* [ ] Burp Suite extension
* [ ] OWASP ZAP plugin
* [ ] Nuclei template export
* [ ] Slack notifications
* [ ] Discord notifications
* [ ] Jira integration
* [ ] GitHub Issues integration
* [ ] DefectDojo integration

### AI Enhancements

* [ ] Multi-agent analysis
* [ ] Real-time AI guidance
* [ ] Fine-tuned SSRF model
* [ ] Autonomous payload mutation
* [ ] Natural language reporting

### Cloud & Containers

* [ ] Kubernetes SSRF
* [ ] Serverless SSRF
* [ ] CDN-specific testing
* [ ] API Gateway bypasses

### Documentation

* [ ] Video tutorials
* [ ] Project wiki
* [ ] Community payload repository
* [ ] CTF practice labs

---

## Contributing

Contributions are welcome.

```bash
git checkout -b feature/my-feature

git commit -m "Add new feature"

git push origin feature/my-feature
```

Then open a Pull Request.

---

## Security

Please do not disclose vulnerabilities publicly.

Open a private issue or contact the maintainer directly with:

* Description
* Impact
* Reproduction steps
* Evidence

---

## Disclaimer

This project is intended exclusively for:

* Authorized penetration testing
* Bug bounty programs
* Security research
* Educational purposes

Only test systems you own or have explicit permission to assess.

The author assumes no responsibility for misuse.

---

## License

MIT License

See LICENSE for details.

---

## Author

**Kauan Costa**

GitHub: https://github.com/KauanCosta2000

Alias: belladonnask

---

<div align="center">

⭐ Star this repository if you find it useful.

Happy Hunting.

</div>
