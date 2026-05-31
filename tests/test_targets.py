from ultimate_ssrf.targets import TargetManager

def test_clean_domain_with_https():
    assert TargetManager._clean("https://example.com/path") == "example.com"

def test_clean_domain_with_http():
    assert TargetManager._clean("http://example.com/test") == "example.com"

def test_clean_plain_domain():
    assert TargetManager._clean("example.com") == "example.com"

def test_clean_empty_domain():
    assert TargetManager._clean("") is None