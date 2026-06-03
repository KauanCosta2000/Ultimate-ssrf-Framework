# Ultimate SSRF Framework v4.2-experimental

<div align="center">

<img src="docs/SSRF%20FRAMEWORK.png" alt="Ultimate SSRF Framework Banner" width="100%">

<br><br>

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Version](https://img.shields.io/badge/Version-v5.0--experimental-orange.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)
![CI](https://github.com/KauanCosta2000/Ultimate-ssrf-Framework/actions/workflows/python-ci.yml/badge.svg)

A research-focused SSRF testing framework built for bug bounty hunting, penetration testing and application security research.

Created and maintained by **belladonnask**.

</div>

---

## Demo

<div align="center">

<img src="docs/demo.gif" alt="Ultimate SSRF Framework Demo" width="100%">

</div>

---
## Banner licensing

Banner created by the designer https://x.com/Fezitooo1 < Go check him out!

## Important read first!!!

Use this project only against systems you own or have explicit authorization to test.

This tool does not automatically prove impact. Findings should always be manually validated before being reported.

Blind SSRF confirmation depends on external OAST, Interactsh or Burp Collaborator logs.

Some modules are experimental and may produce false positives.

`not_confirmed` does not mean the target is safe. It only means the scanner did not confirm SSRF for that specific endpoint, parameter and payload.

Reports may include tested payloads, callback domains, internal IP references and scanned URLs. Review generated files before sharing them publicly.

---

## About

Ultimate SSRF Framework started as a collection of SSRF testing scripts I used during bug bounty hunting.

As the project grew, I kept adding the things I found myself doing repeatedly: endpoint discovery, blind SSRF validation, cloud metadata testing, reporting, WAF fingerprinting, AI-assisted analysis and payload tracking.

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
* Built-in SSRF payload set
* Optional dangerous payload mode
* Per-payload result tracking
* Vulnerability status classification
* Confirmed / not confirmed / error reporting
* WebSocket SSRF testing
* gRPC SSRF testing
* Kubernetes SSRF testing
* Serverless SSRF testing
* AI-assisted payload generation
* AI-assisted finding triage
* Experimental Sheep AI support
* AI payload logging
* HTML reporting
* JSON reporting
* Nuclei export
* SIEM CEF export
* GEXF attack map generation
* Proxy support

Cloud testing currently supports:

* AWS
* Azure
* Google Cloud Platform
* Alibaba Cloud

---

## Experimental modules

The following modules are experimental and should be manually reviewed before relying on their output:

* WebSocket SSRF testing
* gRPC SSRF testing
* Kubernetes SSRF testing
* Serverless SSRF testing
* Sheep AI integration
* Attack map generation
* Nuclei export
* SIEM export

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

### Linux / Kali setup

Some Linux distributions, including Kali, block global `pip install` by default.

Using a virtual environment is recommended:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m playwright install chromium
```

After activating the virtual environment, verify the installation:

```bash
python ssrf_arsenal.py --help
```

---

## Quick Start

Single target:

```bash
python ssrf_arsenal.py --target example.com --callback your-callback.oastify.com
```

Multiple targets:

```bash
python ssrf_arsenal.py --targets api.example.com,test.example.com --callback your-callback.oastify.com
```

Target file:

```bash
python ssrf_arsenal.py --target-file targets.txt --callback your-callback.oastify.com
```

Basic conservative scan:

```bash
python ssrf_arsenal.py \
--target example.com \
--callback your-callback.oastify.com \
--no-ai \
--no-grpc \
--no-websocket \
--no-k8s \
--no-serverless \
--export-json-api
```

---

## OAST / Callback testing

Blind SSRF validation depends on an external callback service such as OASTify, Interactsh or Burp Collaborator.

Example:

```bash
python ssrf_arsenal.py \
--target example.com \
--callback your-callback.oastify.com
```

The framework generates callback payloads such as:

```text
http://basic-123456.your-callback.oastify.com
```

A callback hit is only meaningful if the target server actually performs an outbound request to the generated callback domain.

You can manually test whether your OAST domain is working:

```bash
curl http://manual-test.your-callback.oastify.com
```

This only confirms that your OAST service is receiving requests. It does not prove SSRF.

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
--target-file, -f      File containing targets, one target per line
```

### Callback / OAST

```text
--callback, -c         Out-of-band callback host
--collaborator         Alias for OAST callback host
--burp-collaborator    Burp Collaborator host
```

Example:

```bash
python ssrf_arsenal.py \
--target example.com \
--burp-collaborator abc123.burpcollaborator.net
```

### Proxy Support

```text
--proxy, -p            Single proxy URL
--proxy-file           File containing proxy list
--proxy-type           http | socks5
```

Example with Burp Suite:

```bash
python ssrf_arsenal.py \
--target example.com \
--callback your-callback.oastify.com \
--proxy http://127.0.0.1:8080
```

### AI Integration

```text
--ai-provider          claude | openai | ollama | gemini | mistral | deepseek | sheep | none
--ai-key               API key or provider token
--ai-model             Specific model name
--no-ai                Disable AI features
```

AI-generated payloads and AI triage summaries are helper output, not proof of impact.

Always validate findings manually before submitting a bug bounty report or sending results to a security team.

---

## Ollama

Ollama can be used for local AI-assisted testing.

Example:

```bash
python ssrf_arsenal.py \
--target example.com \
--callback your-callback.oastify.com \
--ai-provider ollama \
--ai-model qwen2.5:1.5b
```

Make sure Ollama is running locally:

```bash
curl http://localhost:11434/api/tags
```

If a model is too large for your system memory, use a smaller model.

Example:

```bash
ollama pull qwen2.5:1.5b
```

---

## Sheep AI Experimental Support

Sheep AI support is experimental and may change in future versions.

Sheep AI is supported through the `sheep` provider.

Read the Sheep API documentation for better usage:

```text
https://sheep.byfranke.com/pages/api
```

Available models:

```text
auto    Lets Sheep choose between Scout and Hunter automatically.
scout   Best for quick answers, short definitions and lightweight explanations.
hunter  Best default option for security analysis, vulnerability triage, logs, APTs and MITRE ATT&CK mapping.
sage    Best for deeper reports, executive summaries, attribution and multi-incident correlation.
```

The Sheep token is passed using `--ai-key` and sent internally through the `X-Sheep-Token` header.

### Using the Sheep token safely

Do not paste your Sheep token directly into commands, scripts, README files or commits.

Use an environment variable instead.

Linux / macOS / Kali:

```bash
export SHEEP_TOKEN="shp_YOUR_TOKEN_HERE"
```

PowerShell:

```powershell
$env:SHEEP_TOKEN="shp_YOUR_TOKEN_HERE"
```

If a Sheep token is accidentally exposed, rotate it immediately.

### Sheep model examples

```bash
python ssrf_arsenal.py --target example.com --callback your-callback.oastify.com --ai-provider sheep --ai-key "$SHEEP_TOKEN" --ai-model auto --export-json-api
```

```bash
python ssrf_arsenal.py --target example.com --callback your-callback.oastify.com --ai-provider sheep --ai-key "$SHEEP_TOKEN" --ai-model scout --export-json-api
```

```bash
python ssrf_arsenal.py --target example.com --callback your-callback.oastify.com --ai-provider sheep --ai-key "$SHEEP_TOKEN" --ai-model hunter --export-json-api
```

```bash
python ssrf_arsenal.py --target example.com --callback your-callback.oastify.com --ai-provider sheep --ai-key "$SHEEP_TOKEN" --ai-model sage --delay 2 --output reports-sheep-sage --no-grpc --no-websocket --no-k8s --no-serverless --export-json-api
```

### AI Payload Logs

When AI is enabled, the framework can save AI-generated payload information into a JSON file.

Example output:

```text
ai_payloads_example.com.json
```

The file may include:

```json
{
  "target": "example.com",
  "provider": "sheep",
  "model": "hunter",
  "ai_generated_payloads": [],
  "all_payloads_used": [],
  "tested_payloads": []
}
```

This helps review which payloads were generated by the model and which ones were actually tested.

---

## Built-in Payloads

The framework ships with a built-in SSRF payload list so you do not have to start every test from scratch.

By default, it uses safer payloads for common SSRF scenarios, including:

* Cloud metadata endpoints
* Localhost and loopback variants
* Internal network ranges
* Alternative IP formats
* DNS helper domains
* Read-only file protocol checks
* Basic gopher and dict probes
* OAST/callback-based validation

There is also an optional dangerous payload mode for more aggressive protocol payloads, such as Redis write attempts or SMTP DATA probes.

Dangerous payloads are disabled by default and should only be used in fully authorized environments:

```bash
python ssrf_arsenal.py \
--target example.com \
--callback your-callback.oastify.com \
--dangerous-payloads
```

In normal bug bounty testing, start without `--dangerous-payloads` and only enable it if the program scope and rules clearly allow that level of testing.

---

## Feature Control

```text
--no-waf               Disable WAF detection
--no-websocket         Disable WebSocket SSRF tests
--no-grpc              Disable gRPC SSRF tests
--no-k8s               Disable Kubernetes SSRF tests
--no-serverless        Disable Serverless SSRF tests
--no-ai                Disable AI features
--dangerous-payloads   Enable dangerous/destructive SSRF payloads
```

---

## Export Options

```text
--export-nuclei        Export Nuclei templates when applicable
--export-siem          Export SIEM CEF report
--export-json-api      Export JSON API report
--attack-map           Generate GEXF attack path graph
--output, -o           Output directory
```

---

## Reporting

The framework can generate multiple report formats for different workflows.

Supported outputs:

```text
.json   Full scan data, including endpoints, evidence, callbacks and tested payloads
.html   Human-readable report with findings and payload attempts
.cef    SIEM-friendly CEF export
.gexf   Attack map graph for visualization tools such as Gephi
.md     Optional AI triage summary when AI is enabled
```

The report tracks each tested payload and classifies every attempt as:

```text
vulnerable       SSRF evidence was confirmed
not_confirmed   The payload was tested, but no SSRF evidence was confirmed
error           The request failed or the scanner hit an execution/runtime error
```

Full reporting example:

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

Generated files may include:

```text
reports/
 - ssrf_example.com_YYYYMMDD_HHMMSS.json
 - ssrf_report_example.com_YYYYMMDD_HHMMSS.html
 - nuclei_example.com.yaml
 - siem_example.com.cef
 - api_report_example.com.json
 - attack_map_example.com.gexf
 - ai_payloads_example.com.json
 - ai_triage_example.com.md
```

Do not enable `--dangerous-payloads` unless you are fully authorized to run aggressive payloads.

---

## JSON Report Behavior

The JSON report includes a clear SSRF status field.

Example:

```json
{
  "is_vulnerable_to_ssrf": false,
  "status": "not_confirmed",
  "attempt_summary": {
    "total": 25,
    "vulnerable": 0,
    "not_confirmed": 25,
    "errors": 0
  }
}
```

When SSRF evidence is confirmed, vulnerable attempts are listed with the tested endpoint, parameter, payload, status code, matched patterns and confidence.

This makes it easier to review what was actually tested instead of only seeing a final pass/fail-style result.

---

## HTML Report

The HTML report is designed for human review.

It includes:

* Target summary
* Scan status
* Cloud detection notes
* Endpoint count
* Raw and unique findings
* Callback count
* Confirmed findings
* Payload attempt table
* Per-payload status
* Evidence or error details

If no SSRF is confirmed, the HTML report still shows tested payloads as `not_confirmed`.

---

## SIEM CEF Export

CEF export can be enabled with:

```bash
python ssrf_arsenal.py \
--target example.com \
--callback your-callback.oastify.com \
--export-siem
```

The generated `.cef` file is useful for SIEM ingestion, internal logging, pipelines and later analysis.

---

## Attack Map

The `--attack-map` option generates a `.gexf` graph file that can be opened in tools like Gephi.

```bash
python ssrf_arsenal.py \
--target example.com \
--callback your-callback.oastify.com \
--attack-map
```

The graph can include relationships between:

* Target host
* Tested endpoints
* Confirmed payloads
* Internal IP references
* Callback evidence

Example output:

```text
attack_map_example.com.gexf
```

The attack map is only a visualization helper. It does not automatically prove impact.

---

## Nuclei Export

Nuclei export can be enabled with:

```bash
python ssrf_arsenal.py \
--target example.com \
--callback your-callback.oastify.com \
--export-nuclei
```

Templates are generated only when applicable evidence exists.

If PyYAML is installed, YAML output is used. Otherwise, JSON output may be generated as fallback.

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

## Helper Scripts

The repository may include helper scripts for common workflows.

Basic scan:

```bash
./basic_scan.sh
```

Proxy scan:

```bash
./proxy_scan.sh
```

AI scan:

```bash
./ai_scan.sh
```

Export-focused scan:

```bash
./export_scan.sh
```

Example with custom variables:

```bash
TARGET=example.com CALLBACK=your-callback.oastify.com ./basic_scan.sh
```

Sheep AI helper example:

```bash
AI_PROVIDER=sheep AI_MODEL=hunter AI_KEY="$SHEEP_TOKEN" ./ai_scan.sh
```

---

## Testing

Run syntax check:

```bash
python -m py_compile ssrf_arsenal.py
```

Run tests:

```bash
python -m pytest -v
```

GitHub Actions can be used to run CI automatically on push and pull requests.

---

## Development Status

This project is actively maintained and new modules are added whenever I find interesting SSRF research areas worth exploring.

Current research-focused modules include:

* WebSocket SSRF
* gRPC SSRF
* Kubernetes SSRF
* Serverless SSRF
* AI-assisted workflows
* Sheep AI integration
* Payload attempt tracking
* Multi-format reporting

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
* Better AI-assisted triage templates
* Better report diffing between scans

---

## Contributing

Bug reports, pull requests and research ideas are always welcome.

Please review:

* CONTRIBUTING.md
* SECURITY.md

before opening a pull request.

---

## Limitations

* The scanner cannot prove that a target is safe.
* Lack of callback does not prove lack of SSRF.
* Some findings may be false positives and require manual validation.
* Some applications block outbound requests or sanitize payloads before execution.
* Some modules are experimental and may require tuning.
* AI output may be incomplete, noisy or wrong.
* Payload behavior should be reviewed before testing sensitive environments.

---

## Responsible Use

This project is intended for:

* Authorized penetration testing
* Bug bounty programs where testing is allowed
* Internal security assessments
* Controlled lab environments
* Research and learning

Do not use this tool against systems without permission.

---

## Author

Developed by **belladonnask**.

GitHub:
https://github.com/KauanCosta2000

LinkedIn:
https://www.linkedin.com/in/kauan-costa-105b12345/

---

## License

Licensed by **belladonnask**.

MIT License © Kauan Costa

See the repository license file for details.

---

## Disclaimer

This project is intended for authorized security testing, research and educational purposes only.

Use responsibly.
