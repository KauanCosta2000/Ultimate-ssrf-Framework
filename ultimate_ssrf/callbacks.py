@'
import random
from urllib.parse import urlparse

def normalize_callback_host(host: text) -> text:
    if not host:
        return ""

    return (
        host.replace("https://", "")
        .replace("http://", "")
        .strip()
        .strip("/")
    )

def make_callback_url(host: text, tag: text = "ssrf", scheme: text = "http") -> text:
    normalized = normalize_callback_host(host)
    token = random.randint(100000, 999999)

    return f"{scheme}://{tag}-{token}.{normalized}"

def make_websocket_callback_url(host: text, tag: text = "ws") -> text:
    normalized = normalize_callback_host(host)
    token = random.randint(100000, 999999)

    return f"wss://{tag}-{token}.{normalized}"

def is_callback_request(request_url: text, callback_host: text) -> bool:
    normalized = normalize_callback_host(callback_host)

    if not request_url or not normalized:
        return False

    parsed = urlparse(request_url)
    request_host = parsed.hostname or ""

    return request_host  ==normalized or request_host.endswith(f".{normalized}")
'@ | Set-Content -Encoding UTF8 ultimate_ssrf\callbacks.py