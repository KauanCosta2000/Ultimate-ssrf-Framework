from ultimate_ssrf.cli import setup_argparse

def test_cli_accepts_single_target():
    parser = setup_argparse()
    args = parser.parse_args(["--target", "example.com"])

    assert args.target =="example.com"
    assert args.targets is None
    assert args.target_file is None

def test_cli_accepts_multiple_targets():
    parser = setup_argparse()
    args = parser.parse_args(["--targets", "example.com,api.example.com"])

    assert args.targets =="example.com,api.example.com"
    assert args.target is None
    assert args.target_file is None

def test_cli_accepts_target_file():
    parser = setup_argparse()
    args = parser.parse_args(["--target-file", "targets.txt"])

    assert args.target_file =="targets.txt"
    assert args.target is None
    assert args.targets is None

def test_cli_accepts_output_directory():
    parser = setup_argparse()
    args = parser.parse_args(["--target", "example.com", "--output", "reports"])

    assert args.output =="reports"

def test_cli_accepts_callback_options():
    parser = setup_argparse()

    args = parser.parse_args(
        [
            "--target",
            "example.com",
            "--callback",
            "abc.oastify.com",
        ]
    )

    assert args.callback =="abc.oastify.com"

def test_cli_accepts_burp_collaborator_option():
    parser = setup_argparse()

    args = parser.parse_args(
        [
            "--target",
            "example.com",
            "--burp-collaborator",
            "abc.burpcollaborator.net",
        ]
    )

    assert args.burp_collaborator =="abc.burpcollaborator.net"

def test_cli_accepts_ai_provider():
    parser = setup_argparse()

    args = parser.parse_args(
        [
            "--target",
            "example.com",
            "--ai-provider",
            "ollama",
            "--ai-model",
            "xploiter/the-xploiter:latest",
        ]
    )

    assert args.ai_provider =="ollama"
    assert args.ai_model =="xploiter/the-xploiter:latest"

def test_cli_accepts_export_flags():
    parser = setup_argparse()

    args = parser.parse_args(
        [
            "--target",
            "example.com",
            "--export-nuclei",
            "--export-siem",
            "--export-json-api",
            "--attack-map",
        ]
    )

    assert args.export_nuclei is True
    assert args.export_siem is True
    assert args.export_json_api is True
    assert args.attack_map is True