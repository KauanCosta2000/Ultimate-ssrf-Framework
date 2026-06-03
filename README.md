# Ultimate SSRF Framework v5.0-experimental

<div align="center">

<img src="docs/SSRF%20FRAMEWORK.png" alt="Ultimate SSRF Framework Banner" width="100%">

<br><br>

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Version](https://img.shields.io/badge/Version-v5.0--experimental-orange.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)
![CI](https://github.com/KauanCosta2000/Ultimate-ssrf-Framework/actions/workflows/python-ci.yml/badge.svg)

<br>

A WAF-aware SSRF discovery, validation and analysis framework built for authorized bug bounty hunting, penetration testing and application security research.

Created and maintained by **belladonnask**.

</div>

---

## Demo

<div align="center">

<img src="docs/demo.gif" alt="Ultimate SSRF Framework Demo" width="100%">

</div>

---

## Banner Credits

Project banner designed by **Fezito**.

X / Twitter: https://x.com/Fezitooo1

---

## Important read first!!!

Use this project only against systems you own or have explicit authorization to test.

This tool does not automatically prove impact. Findings should always be manually validated before being reported.

Blind SSRF confirmation depends on external OAST, Interactsh or Burp Collaborator logs.

Some modules are experimental and may produce false positives.

`not_confirmed` does not mean the target is safe. It only means the scanner did not confirm SSRF for that specific endpoint, parameter and payload.

Reports may include tested payloads, callback domains, internal IP references, AI-generated output and scanned URLs. Review generated files before sharing them publicly.

---

## About

Ultimate SSRF Framework started as a collection of SSRF testing scripts used during bug bounty research.

As the project grew, it became a framework for endpoint discovery, blind SSRF validation, cloud metadata testing, WAF fingerprinting, payload tracking, reporting, attack path mapping and optional AI-assisted analysis.

Version 5.0 introduces a more WAF-aware testing flow, expanded experimental modules, better per-payload reporting and support for AI-suggested safe checks.

The goal is simple: reduce repetitive SSRF testing work and make it easier to discover, validate and document findings in authorized environments.

---

## What it can do

Current capabilities include:

* Endpoint discovery and crawling
* Blind SSRF validation
* Cloud metadata testing
* Expanded WAF fingerprinting
* WAF-aware bypass suggestions
* File-based target scanning
* Multi-target scanning
* Single-target parameter selection with `--param`
* Built-in SSRF payload set
* Optional dangerous payload mode
* Per-payload result tracking
* Vulnerability status classification
* Confirmed / not confirmed / error reporting
* WebSocket SSRF testing
* gRPC SSRF testing
* Kubernetes SSRF testing
* Kubernetes ingress SSRF checks
* Serverless SSRF testing
* GraphQL SSRF testing
* API schema bypass checks
* Service mesh SSRF checks
* Bot evasion testing
* AI-assisted payload generation
* AI-assisted finding triage
* AI-Suggested Safe Checks
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
* Kubernetes ingress testing
* Serverless SSRF testing
* GraphQL SSRF testing
* API schema bypass checks
* Service mesh checks
* Bot evasion checks
* Sheep AI integration
* AI-Suggested Safe Checks
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
--no-graphql \
--no-api-schema \
--no-mesh \
--no-bot-evasion \
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
--param                Specific parameter to test on a single target
```

### Single target with a specific parameter

Use `--param` when you already know which parameter should be tested.

```bash
python ssrf_arsenal.py \
--target example.com \
--param redirect_url \
--callback your-callback.oastify.com
```

`--param` is intended for single-target testing only.

For mass scanning with `--targets` or `--target-file`, omit `--param` and let the framework discover parameters automatically.

---

## Callback / OAST Options

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

---

## Proxy Support

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

---

## AI Integration

```text
--ai-provider          claude | openai | ollama | gemini | mistral | deepseek | sheep | none
--ai-key               API key or provider token
--ai-model             Specific model name
--no-ai                Disable AI features
```

AI-generated payloads and AI triage summaries are helper output, not proof of impact.

Always validate findings manually before submitting a bug bounty report or sending results to a security team.

Supported providers:

* OpenAI
* Claude
* Gemini
* Ollama
* Mistral
* DeepSeek
* Sheep AI
* None / Disabled

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

Alternative variable:

```bash
export SHEEP_API_TOKEN="shp_YOUR_TOKEN_HERE"
```

PowerShell:

```powershell
$env:SHEEP_TOKEN="shp_YOUR_TOKEN_HERE"
```

If a Sheep token is accidentally exposed, rotate it immediately.

### Sheep model examples

Auto:

```bash
python ssrf_arsenal.py --target example.com --callback your-callback.oastify.com --ai-provider sheep --ai-key "$SHEEP_TOKEN" --ai-model auto --export-json-api
```

Scout:

```bash
python ssrf_arsenal.py --target example.com --callback your-callback.oastify.com --ai-provider sheep --ai-key "$SHEEP_TOKEN" --ai-model scout --export-json-api
```

Hunter:

```bash
python ssrf_arsenal.py --target example.com --callback your-callback.oastify.com --ai-provider sheep --ai-key "$SHEEP_TOKEN" --ai-model hunter --export-json-api
```

Sage:

```bash
python ssrf_arsenal.py --target example.com --callback your-callback.oastify.com --ai-provider sheep --ai-key "$SHEEP_TOKEN" --ai-model sage --delay 2 --output reports-sheep-sage --no-grpc --no-websocket --no-k8s --no-serverless --export-json-api
```

---

## AI Payload Logs

When AI is enabled, the framework may save AI-generated payload information into a JSON file.

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
  "ai_usage": {
    "provider": "sheep",
    "model_requested": "hunter",
    "served_by": "hunter",
    "tokens_used": 1234
  },
  "ai_error": null,
  "ai_generated_payloads": [],
  "all_payloads_used": [],
  "tested_payloads": []
}
```

This helps review which payloads were generated by the model and which ones were actually tested.

---

## AI-Suggested Safe Checks

When AI is enabled, the framework can ask the selected model to suggest additional safe checks based on discovered endpoints and parameters.

The AI does not execute arbitrary commands or free-form exploits. It only returns structured JSON suggestions, and the framework executes checks from an allowlist.

Allowed issue types:

```text
ssrf
open_redirect
cors_misconfig
header_injection
path_traversal_readonly
information_disclosure
authz_review
```

Results may be classified as:

```text
vulnerable              Confirmed SSRF evidence
suspected_other_issue   Potential non-SSRF issue requiring manual validation
manual_review           Needs human review
not_confirmed           No evidence confirmed
error                   Request or runtime error
```

AI-suggested checks are helper output and must be manually validated before being reported.

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
--no-graphql           Disable GraphQL SSRF tests
--no-api-schema        Disable API schema bypass checks
--no-mesh              Disable service mesh SSRF checks
--no-bot-evasion       Disable bot evasion checks
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
- ai_suggestions_example.com.json
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
* Finding count
* Callback count
* Confirmed findings
* Payload attempt table
* Per-payload status
* Evidence or error details
* AI-suggested safe checks

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
* AI-suggested checks

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

## WAF-Aware Testing

Version 5.0 includes expanded WAF fingerprinting and WAF-aware testing context.

The framework can identify signals from multiple WAFs and security layers, including:

* Cloudflare
* AWS WAF
* Akamai
* Fastly
* Imperva
* F5 BIG-IP
* Azure Front Door / WAF
* Google Cloud Armor
* Sucuri
* Barracuda
* Fortinet FortiWeb
* Radware AppWall
* Citrix NetScaler / ADC WAF
* Wallarm
* DataDome
* HUMAN / PerimeterX
* Kong API Gateway
* Apigee
* ModSecurity / OWASP CRS

WAF bypass suggestions are informational and should be manually reviewed before use.

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

## Suggested Workflow

A safe first run usually looks like this:

```bash
python ssrf_arsenal.py \
--target example.com \
--callback your-callback.oastify.com \
--delay 2 \
--output reports-example \
--no-ai \
--no-grpc \
--no-websocket \
--no-k8s \
--no-serverless \
--no-graphql \
--no-api-schema \
--no-mesh \
--no-bot-evasion \
--export-json-api
```

Then review the report.

If you have authorization and want deeper testing, enable additional modules and exports:

```bash
python ssrf_arsenal.py \
--target example.com \
--callback your-callback.oastify.com \
--delay 2 \
--output reports-example \
--export-json-api \
--export-nuclei \
--export-siem \
--attack-map
```

If you want AI-assisted testing:

```bash
python ssrf_arsenal.py \
--target example.com \
--callback your-callback.oastify.com \
--ai-provider sheep \
--ai-key "$SHEEP_TOKEN" \
--ai-model auto \
--output reports-ai \
--export-json-api
```

---

## Limitations

* The scanner cannot prove that a target is safe.
* Lack of callback does not prove lack of SSRF.
* Some findings may be false positives and require manual validation.
* Some applications block outbound requests or sanitize payloads before execution.
* Some modules are experimental and may require tuning.
* AI output may be incomplete, noisy or wrong.
* Payload behavior should be reviewed before testing sensitive environments.
* WAF bypass suggestions are informational and not proof of vulnerability.
* AI-suggested safe checks are not automatically valid findings.

---

## Development Status

This project is actively maintained and new modules are added whenever I find interesting SSRF research areas worth exploring.

Current research-focused modules include:

* WebSocket SSRF
* gRPC SSRF
* Kubernetes SSRF
* Kubernetes ingress checks
* Serverless SSRF
* GraphQL SSRF
* API schema bypass checks
* Service mesh checks
* Bot evasion checks
* AI-assisted workflows
* Sheep AI integration
* Payload attempt tracking
* Multi-format reporting

Some of these features are still evolving and will continue to improve over future releases.

---

## Roadmap

Planned work includes:

* Better GraphQL SSRF discovery
* HTTP/2 request smuggling research
* DNS rebinding improvements
* Internal service fingerprinting
* Burp Suite extension
* OWASP ZAP integration
* Slack notifications
* Discord notifications
* Better AI-assisted triage templates
* Better report diffing between scans
* More WAF signatures
* Better false-positive reduction

---

## Contributing

Bug reports, pull requests and research ideas are always welcome.

Please review:

* CONTRIBUTING.md
* SECURITY.md

before opening a pull request.

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
