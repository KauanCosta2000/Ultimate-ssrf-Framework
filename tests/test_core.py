import json
from argparse import Namespace
from pathlib import Path

from ssrf_arsenal import SSRFEvidence, TargetManager, UltimateSSRFFramework, WAFFingerprinter

def args_for_tests(tmp_path=None, **changes):
    args = {
        "callback": "https://abc.oastify.com/",
        "collaborator": None,
        "burp_collaborator": None,
        "delay": 0,
        "quiet": True,
        "visible": False,
        "proxy": None,
        "proxy_file": None,
        "proxy_type": "http",
        "no_waf": False,
        "no_websocket": True,
        "no_grpc": True,
        "no_k8s": True,
        "no_serverless": True,
        "no_ai": True,
        "export_nuclei": False,
        "export_siem": False,
        "export_json_api": False,
        "attack_map": False,
        "output": str(tmp_path or Path(".")),
        "ai_provider": None,
        "ai_key": None,
        "ai_model": None,
    }
    args.update(changes)
    return Namespace(**args)

def new_framework(tmp_path, **changes):
    return UltimateSSRFFramework("example.com", args_for_tests(tmp_path, **changes))

def test_clean_target_strips_scheme_path_and_query():
    assert TargetManager._clean("https://example.com/path?id=1")  == "example.com"

def test_clean_target_handles_spaces():
    assert TargetManager._clean("  http://api.example.com/test  ")  == "api.example.com"

def test_clean_target_returns_none_for_empty_value():
    assert TargetManager._clean("") is None

def test_target_args_accept_single_target():
    args = Namespace(target="https://example.com/path", targets=None, target_file=None)

    assert TargetManager.from_args(args)  == ["example.com"]

def test_target_args_accept_comma_list():
    args = Namespace(target=None, targets="https://a.example.com,b.example.com/path", target_file=None)

    assert TargetManager.from_args(args)  == ["a.example.com", "b.example.com"]

def test_waf_fingerprint_detects_cloudflare():
    result = WAFFingerprinter().fingerprint(headers={"cf-ray": "abc123"}, body="", cookies={})

    assert result["detected"] is True
    assert result["primary"]  == "Cloudflare"

def test_waf_fingerprint_detects_aws_waf():
    result = WAFFingerprinter().fingerprint(headers={"data-amzn-requestid": "123"}, body="", cookies={})

    assert result["detected"] is True
    assert result["primary"]  == "AWS WAF"

def test_waf_fingerprint_returns_empty_result_without_signals():
    result = WAFFingerprinter().fingerprint(headers={}, body="", cookies={})

    assert result["detected"] is False
    assert result["primary"] is None

def test_callback_host_is_normalized(tmp_path):
    framework = new_framework(tmp_path)

    assert framework._callback_host()  == "abc.oastify.com"

def test_callback_url_uses_tag_and_oast_host(tmp_path):
    framework = new_framework(tmp_path)

    callback_url = framework.make_callback_url("basic")

    assert callback_url.startswith("http://basic-")
    assert callback_url.endswith(".abc.oastify.com")

def test_callback_context_can_be_found_later(tmp_path):
    framework = new_framework(tmp_path)
    payload = "http://basic-123456.abc.oastify.com"

    framework._register_callback_context(
        payload=payload,
        endpoint="/api",
        param="url",
        phase="Basic",
        technique="param url",
    )

    found = framework._find_callback_context("basic-123456.abc.oastify.com")

    assert found["endpoint"]  == "/api"
    assert found["param"]  == "url"
    assert found["payload"]  == payload

def test_callback_context_matches_nested_callback_hosts(tmp_path):
    framework = new_framework(tmp_path)
    payload = "http://token.abc.oastify.com"

    framework._register_callback_context(
        payload=payload,
        endpoint="/fetch",
        param="uri",
        phase="Basic",
        technique="param uri",
    )

    found = framework._find_callback_context("nested.token.abc.oastify.com")

    assert found["endpoint"]  == "/fetch"
    assert found["param"]  == "uri"

def test_dedup_keeps_worst_severity_and_oob_count(tmp_path):
    framework = new_framework(tmp_path)

    framework.evidence.append(
        SSRFEvidence(
            phase="Basic",
            technique="param url",
            url="https://example.com/api?url=data",
            endpoint="/api",
            param="url",
            payload="http://a.oastify.com",
            status=200,
            body_snippet="",
            matched_patterns=["[HIGH] Cloud metadata"],
            severity="high",
        )
    )
    framework.evidence.append(
        SSRFEvidence(
            phase="Basic",
            technique="param url",
            url="https://example.com/api?url=temp",
            endpoint="/api",
            param="url",
            payload="http://b.oastify.com",
            status=200,
            body_snippet="",
            matched_patterns=["[CRITICAL] OOB callback host requested"],
            severity="critical",
            out_of_band_hit=True,
        )
    )

    grouped = framework._dedup()

    assert len(grouped) == 1
    assert grouped[("/api", "url")]["max_sev"]  == "critical"
    assert grouped[("/api", "url")]["oob"]  == 1

def test_json_api_export_writes_a_small_summary(tmp_path):
    framework = new_framework(tmp_path, export_json_api=True)
    framework.cloud = ["AWS"]
    framework.callbacks["basic-123456.abc.oastify.com"].append(
        {"url": "http://basic-123456.abc.oastify.com"}
    )

    framework.export_json_api()

    report = tmp_path / "api_report_example.com.json"
    data = json.loads(report.read_text())

    assert report.exists()
    assert data["target"]  == "example.com"
    assert data["cloud"]  == ["AWS"]
    assert data["callbacks"]  == 1
