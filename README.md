<div align="center">

# Ultimate SSRF Arsenal

### Automated SSRF Discovery, Exploitation & Validation Framework

A powerful SSRF testing framework built with Python and Playwright that automates endpoint discovery, payload generation, cloud metadata testing, protocol smuggling, blind SSRF detection, and vulnerability validation.

Designed for bug bounty hunters, penetration testers, red teamers, and security researchers.

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Playwright](https://img.shields.io/badge/Playwright-Chromium-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Active-success)

</div>

---

# Features

## Automated SSRF Discovery

- Dynamic crawling and endpoint discovery
- Automatic parameter extraction from HTML and JavaScript
- Identification of SSRF-prone functionality
- Multi-target scanning support

## Advanced SSRF Testing

- 15 attack phases covering modern SSRF techniques
- Blind SSRF detection
- Multi-cloud metadata exploitation
- Protocol smuggling
- Internal service enumeration
- DNS rebinding attacks
- Redirect bypass techniques

## Smart Analysis

- Automatic finding deduplication
- Severity classification
- Sensitive data detection
- Consolidated reporting
- Evidence preservation

## Cloud Metadata Coverage

Supported providers:

- AWS
- Google Cloud Platform (GCP)
- Microsoft Azure
- Alibaba Cloud
- Oracle Cloud
- DigitalOcean
- Huawei Cloud
- Tencent Cloud

## Reporting

- JSON output
- Vulnerability classification
- Payload tracking
- Callback correlation
- Internal request evidence

---

# Installation

## Requirements

- Python 3.8+
- Playwright
- Chromium Browser

## Setup

```bash
git clone https://github.com/KauanCosta2000/ultimate-ssrf-arsenal.git

cd ultimate-ssrf-arsenal

pip install playwright

playwright install chromium
```

---

# Quick Start

Launch the scanner:

```bash
python ultimate_ssrf_arsenal.py
```

You will be prompted to choose how targets are supplied:

```text
1 - Single Domain
2 - Multiple Domains
3 - File Input
```

---

# Usage Examples

## Single Target

```bash
python ultimate_ssrf_arsenal.py
```

```text
Choose [1/2/3]: 1

Target:
example.com
```

---

## Multiple Targets

```text
Choose [1/2/3]: 2

Targets:
example.com,api.example.com,test.example.org
```

---

## File Input

targets.txt

```text
example.com
api.example.com
internal.example.org
```

Run:

```bash
python ultimate_ssrf_arsenal.py
```

```text
Choose [1/2/3]: 3
```

---

## Quiet Mode

```bash
python ultimate_ssrf_arsenal.py --quiet
```

---

# Attack Phases

| Phase | Name | Description |
|---------|---------|---------|
| 0 | Dynamic Discovery | Endpoint and parameter enumeration |
| 1 | Endpoint Validation | SSRF confirmation |
| 2 | Parameter Fuzzing | 90+ SSRF-related parameters |
| 3 | Localhost Bypass | IPv4, IPv6, decimal, octal and dword bypasses |
| 4 | GCP Metadata | Google metadata service testing |
| 5 | Multi-Cloud Metadata | AWS, Azure, Oracle, Alibaba and more |
| 6 | Internal Services | Docker, Kubelet, Vault, Redis, Elasticsearch |
| 7 | Protocol Smuggling | file://, gopher://, dict://, ftp://, ldap:// |
| 8 | Redirect Bypass | Parser confusion and redirect chains |
| 9 | DNS Rebinding | nip.io, localtest.me and related techniques |
| 10 | XXE to SSRF | XML external entity exploitation |
| 11 | Encoding Bypass | Double encoding and Unicode tricks |
| 12 | CRLF Injection | Header manipulation techniques |
| 13 | Fragment Bypass | URL confusion attacks |
| 14 | Exotic Protocols | Redis, Memcached and custom payloads |

---

# Blind SSRF Detection

Supports:

- Burp Collaborator
- Interactsh
- Custom callback servers

Example:

```text
Enter callback host:

xxxxx.oastify.com
```

The framework automatically correlates outbound interactions with discovered vulnerabilities.

---

# Example Results

```text
================ FILTERED SSRF SUMMARY ================

[CRITICAL] /api/proxy (url)

  OOB Callbacks: 47
  Sensitive Data: YES

  Top Finding:
  Callback URL reflected and requested by backend

-------------------------------------------------------

[HIGH] /fetch (file)

  OOB Callbacks: 12
  Sensitive Data: NO

  Top Finding:
  Internal network IP disclosure

-------------------------------------------------------

[MEDIUM] /download (src)

  OOB Callbacks: 3
  Sensitive Data: NO

  Top Finding:
  Link-local IP disclosure
```

---

# Output

For every target scanned:

```text
ssrf_results_<target>_<timestamp>.json
```

Contains:

- Discovered endpoints
- Extracted parameters
- Payloads used
- Vulnerable endpoints
- Blind SSRF evidence
- Callback logs
- Severity classifications
- Internal request traces

---

# Typical Use Cases

## Bug Bounty

Automated SSRF discovery across large attack surfaces.

## Penetration Testing

Internal network mapping and SSRF validation.

## Cloud Security Reviews

Metadata service exposure testing across cloud providers.

## Security Research

Testing SSRF filters, parsers, and bypass techniques.

---

# Customization

## Add Custom Endpoints

```python
common_paths = [
    "/custom-api",
    "/admin/import",
]
```

## Add New Cloud Providers

```python
"MyCloud": {
    "hosts": ["metadata.mycloud.internal"],
    "paths": ["latest/meta-data/"],
    "headers": {
        "X-Custom": "value"
    }
}
```

---

# Legal Disclaimer

This project is intended exclusively for:

- Authorized security assessments
- Bug bounty programs
- Educational purposes
- Research environments

You must obtain proper authorization before testing any target.

The author assumes no responsibility for misuse or damages caused by this software.

---

# Roadmap

### v2.x

- [x] 15 SSRF attack phases
- [x] Multi-cloud metadata testing
- [x] Smart finding deduplication
- [x] Blind SSRF correlation
- [x] XXE → SSRF testing
- [x] Protocol smuggling support

### Upcoming

- [ ] Async scanning engine
- [ ] Automatic WAF fingerprinting
- [ ] HTTP/2 request smuggling module
- [ ] GraphQL SSRF testing
- [ ] HTML report generation
- [ ] Burp Suite extension

---

# Contributing

Contributions are welcome.

```bash
git checkout -b feature/my-feature

git commit -m "Add new feature"

git push origin feature/my-feature
```

Then open a Pull Request.

---

# Author

**Kauan Costa**

- GitHub: https://github.com/KauanCosta2000
- Alias: belladonnask

---

# License

MIT License

Copyright (c) 2026 Kauan Costa

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files to deal in the Software without restriction.

See the LICENSE file for the full license text.

---

<div align="center">

⭐ If this project helped you, consider starring the repository.

</div>
