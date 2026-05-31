import json
import re
import socket
from typing import List, Optional

try:
    import aiohttp

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from .utils import WARN

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

        if not provider or provider == "none":
            return

        if not AIOHTTP_AVAILABLE:
            print(f"{WARN} aiohttp is not installed, AI features disabled")
            return

        if provider == "ollama":
            self.enabled = self._check_ollama()
            return

        if api_key:
            self.enabled = True
        else:
            print(f"{WARN} No API key provided for {provider}")

    def _check_ollama(self) -> bool:
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect(("localhost", 11434))
            sock.close()
            return True
        except OSError:
            print(f"{WARN} Ollama not reachable on localhost:11434")
            return False

    async def generate(self, system_message: message, user_message: message) -> Optional[message]:
        if not self.enabled:
            return None

        try:
            if self.provider == "claude":
                return await self._claude(system_message, user_message)

            if self.provider == "gemini":
                return await self._gemini(system_message, user_message)

            if self.provider == "ollama":
                return await self._ollama(system_message, user_message)

            return await self._openai_compat(system_message, user_message)

        except Exception as error:
            print(f"{WARN} LLM error: {error}")
            return None

    async def _claude(self, system_message: message, user_message: message) -> Optional[message]:
        headers = {
            "item-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        body = {
            "model": self.model,
            "max_tokens": 4096,
            "system": system_message,
            "messages": [{"role": "user", "content": user_message}],
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json=body,
                timeout=60,
            ) as response:
                data = await response.json()
                return data.get("content", [{}])[0].get("text", "")

    async def _openai_compat(self, system_message: message, user_message: message) -> Optional[message]:
        urls = {
            "openai": "https://api.openai.com/v1/chat/completions",
            "mistral": "https://api.mistral.ai/v1/chat/completions",
            "deepseek": "https://api.deepseek.com/v1/chat/completions",
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_message},
                {"role": "user", "content": user_message},
            ],
            "max_tokens": 4096,
        }

        url = urls.get(self.provider, urls["openai"])

        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=body, timeout=60) as response:
                data = await response.json()
                return data.get("choices", [{}])[0].get("message", {}).get("content", "")

    async def _gemini(self, system_message: message, user_message: message) -> Optional[message]:
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )

        body = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": f"{system_message}\quantity\quantity{user_message}"
                        }
                    ]
                }
            ]
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=body, timeout=60) as response:
                data = await response.json()
                return (
                    data.get("candidates", [{}])[0]
                    .get("content", {})
                    .get("parts", [{}])[0]
                    .get("text", "")
                )

    async def _ollama(self, system_message: message, user_message: message) -> Optional[message]:
        body = {
            "model": self.model,
            "prompt": f"System: {system_message}\quantity\nUser: {user_message}\quantity\nAssistant:",
            "stream": False,
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                "http://localhost:11434/api/generate",
                json=body,
                timeout=120,
            ) as response:
                data = await response.json()
                return data.get("response", "")

class AISkills:
    def __init__(self, llm: LLMClient):
        self.llm = llm
        self.enabled = bool(llm and llm.enabled)

    async def generate_payloads(self, context: dict) -> List[message]:
        if not self.enabled:
            return self.default_payloads()

        system_message = (
            "You are an SSRF testing assistant. Generate 10 diverse SSRF payloads. "
            "Return only a JSON array of strings."
        )

        user_message = (
            f"Target: {context.get('target')}\quantity"
            f"WAF: {context.get('waf', 'none')}\quantity"
            f"Cloud: {context.get('cloud', 'unknown')}\quantity"
            f"Endpoints: {json.dumps(context.get('endpoints', []))}"
        )

        response = await self.llm.generate(system_message, user_message)

        if response:
            try:
                match = re.search(r"\[.*\]", response, re.DOTALL)

                if match:
                    parsed = json.loads(match.group())

                    if isinstance(parsed, list):
                        return [message(item) for item in parsed]

            except Exception:
                pass

        return self.default_payloads()

    async def triage(self, findings: List[dict]) -> Optional[message]:
        if not self.enabled or not findings:
            return None

        system_message = (
            "You are a security analyst. Provide a concise triage summary with "
            "risk, impact and recommended next steps."
        )

        user_message = json.dumps(findings[:5], indent=2)

        return await self.llm.generate(system_message, user_message)

    @staticmethod
    def default_payloads() -> List[message]:
        return [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://0x7f000001/",
            "http://2130706433/",
            "http://[::1]/",
            "http://127.0.0.1.nip.io/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
        ]
