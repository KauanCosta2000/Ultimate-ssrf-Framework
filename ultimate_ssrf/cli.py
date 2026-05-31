import argparse


def setup_argparse():
    parser = argparse.ArgumentParser(
        description="Ultimate SSRF Framework v4.2-experimental",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("--target", "-t", help="Single target domain")
    target_group.add_argument("--targets", help="Comma-separated targets")
    target_group.add_argument("--target-file", "-f", help="File with targets (one per line)")

    parser.add_argument("--callback", "-c", help="OOB callback host")
    parser.add_argument("--collaborator", help="Alias for --callback / OAST host")
    parser.add_argument("--burp-collaborator", help="Burp Collaborator host")
    parser.add_argument("--delay", "-d", type=float, default=0.5)
    parser.add_argument("--quiet", "-q", action="store_true")
    parser.add_argument("--visible", action="store_true")

    proxy_group = parser.add_argument_group("Proxy Support")
    proxy_group.add_argument("--proxy", "-p", help="Single proxy URL (used for the entire scan)")
    proxy_group.add_argument("--proxy-file", help="File with proxy list (one proxy per scan)")
    proxy_group.add_argument("--proxy-type", choices=["http", "socks5"], default="http")

    ai_group = parser.add_argument_group("AI Integration (Optional)")
    ai_group.add_argument(
        "--ai-provider",
        choices=["claude", "openai", "ollama", "gemini", "mistral", "deepseek", "none"],
    )
    ai_group.add_argument("--ai-key", help="API key for cloud AI")
    ai_group.add_argument("--ai-model", help="Specific model name")

    feature_group = parser.add_argument_group("Feature Control")
    feature_group.add_argument("--no-waf", action="store_true", help="Disable WAF detection")
    feature_group.add_argument("--no-websocket", action="store_true", help="Disable WebSocket SSRF tests")
    feature_group.add_argument("--no-grpc", action="store_true", help="Disable gRPC SSRF tests")
    feature_group.add_argument("--no-k8s", action="store_true", help="Disable Kubernetes SSRF tests")
    feature_group.add_argument("--no-serverless", action="store_true", help="Disable serverless SSRF tests")
    feature_group.add_argument("--no-ai", action="store_true", help="Disable AI features")

    export_group = parser.add_argument_group("Export Options")
    export_group.add_argument("--export-nuclei", action="store_true", help="Export Nuclei templates")
    export_group.add_argument("--export-siem", action="store_true", help="Export CEF for SIEM")
    export_group.add_argument("--export-json-api", action="store_true", help="Export JSON API report")
    export_group.add_argument("--attack-map", action="store_true", help="Generate attack path graph")
    export_group.add_argument("--output", "-o", default=".", help="Output directory")

    return parser