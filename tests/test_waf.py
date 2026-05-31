from ultimate_ssrf.waf import WAFFingerprinter

def test_cloudflare_detection():
    waf = WAFFingerprinter()

    result = waf.fingerprint(
        headers={"cf-ray": "abc123"},
        body="",
        cookies={}
    )

    assert result["detected"] is True
    assert result["primary"] == "Cloudflare"

def test_no_waf_detection():
    waf = WAFFingerprinter()

    result = waf.fingerprint(
        headers={},
        body="normal response",
        cookies={}
    )

    assert result["detected"] is False