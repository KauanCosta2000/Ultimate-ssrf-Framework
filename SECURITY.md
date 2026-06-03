# Security Policy

## Responsible Use

Ultimate SSRF Framework is intended for authorized security testing, bug bounty research, penetration testing, internal security assessments and controlled lab environments.

Do not use this project against systems you do not own or do not have explicit permission to test.

This tool may generate payloads, callback URLs, scan reports and AI-assisted output. Always review the generated content before sharing it publicly or submitting it to a security team.

---

## Supported Versions

This project is experimental and actively developed.

| Version           | Status                   |
| ----------------- | ------------------------ |
| v5.x experimental | Supported                |
| v4.x experimental | Legacy / limited support |
| Older versions    | Not supported            |

Security fixes and important safety improvements should target the latest version whenever possible.

---

## Reporting a Security Issue

If you find a security issue in this project, please report it responsibly.

You can contact the maintainer through:

* GitHub Issues, for non-sensitive bugs
* GitHub Security Advisories, for sensitive security reports
* Direct contact through the maintainer profile when needed

Maintainer:

```text
belladonnask
GitHub: https://github.com/KauanCosta2000
LinkedIn: https://www.linkedin.com/in/kauan-costa-105b12345/
```

Please do not publicly disclose sensitive vulnerabilities until there has been time to review and fix the issue.

---

## What to Include in a Report

When reporting a security issue, include as much useful detail as possible:

* A clear summary of the issue
* Affected file, function, module or feature
* Steps to reproduce
* Expected behavior
* Actual behavior
* Impact
* Suggested fix, if available
* Logs, screenshots or proof of concept, if safe to share

Do not include real third-party credentials, private tokens or sensitive data from systems you do not own.

---

## Sensitive Data Handling

Generated reports may contain sensitive testing data, including:

* Tested URLs
* Callback domains
* Payloads
* Internal IP references
* HTTP response snippets
* AI-generated payloads
* AI triage output
* Possible tokens or secrets accidentally reflected by a target

Review all generated files before sharing them publicly.

Common generated files may include:

```text
ssrf_*.json
ssrf_report_*.html
api_report_*.json
siem_*.cef
attack_map_*.gexf
ai_payloads_*.json
ai_suggestions_*.json
ai_triage_*.md
nuclei_*.yaml
```

Do not commit real scan reports from third-party targets unless you are sure they contain no sensitive information.

---

## API Keys and Tokens

Never commit API keys, Sheep tokens, OpenAI keys, Claude keys, Gemini keys, Mistral keys, DeepSeek keys, Burp Collaborator secrets or OAST tokens.

Use environment variables instead.

Example for Sheep AI:

```bash
export SHEEP_TOKEN="shp_YOUR_TOKEN_HERE"
```

Alternative:

```bash
export SHEEP_API_TOKEN="shp_YOUR_TOKEN_HERE"
```

PowerShell:

```powershell
$env:SHEEP_TOKEN="shp_YOUR_TOKEN_HERE"
```

If a token is accidentally exposed, rotate it immediately.

The project should redact Sheep tokens beginning with `shp_` from runtime errors whenever possible, but users should still avoid pasting secrets into logs, reports, issues or screenshots.

---

## Dangerous Payloads

Dangerous payloads must remain disabled by default.

The `--dangerous-payloads` flag may include aggressive or destructive SSRF payloads such as Redis write attempts, SMTP DATA probes or other protocol-level payloads.

Use this flag only in fully authorized environments where the rules of engagement explicitly allow that level of testing.

Do not enable dangerous payloads by default in pull requests.

Do not add destructive payloads to the default payload list.

---

## AI Safety Notes

AI features are optional and experimental.

The framework may use AI for:

* Payload generation
* Finding triage
* AI-suggested safe checks
* Context-aware analysis

AI output is not proof of vulnerability.

AI-suggested checks must be manually reviewed before being treated as valid findings.

The AI should not execute arbitrary commands or free-form exploits. It should only return structured suggestions, and the framework should execute checks from a controlled allowlist.

Allowed AI-suggested check categories may include:

```text
ssrf
open_redirect
cors_misconfig
header_injection
path_traversal_readonly
information_disclosure
authz_review
```

Do not submit changes that turn the AI into an unrestricted autonomous exploitation agent.

---

## Safe Testing Expectations

Contributors should keep the project safe for legitimate security research.

Expected behavior:

* Non-destructive tests by default
* Callback-based SSRF validation
* Manual validation before reporting
* Clear `vulnerable`, `not_confirmed`, `manual_review`, `suspected_other_issue` and `error` classifications
* Reports generated even when SSRF is not confirmed
* Dangerous behavior gated behind explicit flags
* No hardcoded secrets
* No malware, persistence, credential theft or destructive automation

---

## Out-of-Scope Contributions

The following contributions are not accepted:

* Malware
* Persistence mechanisms
* Credential theft tooling
* Destructive payloads enabled by default
* Automated exploitation without user control
* Unauthorized access helpers
* Real third-party secrets or tokens
* Payloads designed mainly for damage instead of validation
* Code that bypasses authorization boundaries without a legitimate testing context

---

## Dependency Security

Dependencies should be kept minimal and reviewed before being added.

Current expected dependency areas include:

* Playwright for browser automation
* aiohttp/httpx for HTTP clients
* Jinja2 for HTML reporting
* PyYAML for Nuclei export
* NetworkX for GEXF attack map generation
* pytest for tests

If a dependency is added, explain why it is needed.

---

## Reporting Generated Findings

Before submitting a finding to a bug bounty program or security team:

* Confirm the target is in scope
* Confirm testing was authorized
* Confirm the callback evidence is real
* Confirm the endpoint and parameter are correct
* Confirm impact manually
* Remove unrelated payload attempts from the final report
* Avoid overstating `not_confirmed` results
* Do not claim a target is safe based only on scanner output

`not_confirmed` means only that the framework did not confirm SSRF for that specific payload, endpoint and parameter.

---

## Disclosure Timeline

For security issues in this project, the maintainer will try to:

* Acknowledge the report
* Reproduce the issue
* Prepare a fix when applicable
* Credit the reporter if desired
* Release the fix through the repository

Response time may vary because this is an independent research project.

---

## Disclaimer

This project is provided for authorized security testing and educational purposes only.

The maintainer is not responsible for misuse of the tool.

Use responsibly.
