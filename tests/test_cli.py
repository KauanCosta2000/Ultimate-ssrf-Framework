from ssrf_arsenal import setup_argparse


def test_cli_has_target_option():
    parser = setup_argparse()
    args = parser.parse_args(["--target", "example.com"])

    assert args.target == "example.com"


def test_cli_has_output_option():
    parser = setup_argparse()
    args = parser.parse_args(["--target", "example.com", "--output", "reports"])

    assert args.output == "reports"