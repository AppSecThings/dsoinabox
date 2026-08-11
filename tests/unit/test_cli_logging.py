"""Unit tests for CLI logging verbosity flags."""

from __future__ import annotations

import logging

import pytest

from dsoinabox import cli
from dsoinabox.cli import build_parser, main, resolve_log_level


def test_resolve_log_level_defaults_to_info():
    assert resolve_log_level(verbose=False, quiet=False) == logging.INFO


def test_resolve_log_level_verbose_sets_debug():
    assert resolve_log_level(verbose=True, quiet=False) == logging.DEBUG


def test_resolve_log_level_quiet_sets_warning():
    assert resolve_log_level(verbose=False, quiet=True) == logging.WARNING


def test_parser_accepts_verbose_flag():
    args = build_parser().parse_args(["--verbose"])
    assert args.verbose is True
    assert args.quiet is False


def test_parser_accepts_quiet_flag():
    args = build_parser().parse_args(["--quiet"])
    assert args.quiet is True
    assert args.verbose is False


def test_parser_rejects_verbose_and_quiet_together():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--verbose", "--quiet"])


def test_tool_versions_exits_before_scan_setup(monkeypatch, capsys):
    version_functions = (
        "syft_show_version",
        "grype_show_version",
        "trufflehog_show_version",
        "opengrep_show_version",
        "checkov_show_version",
    )
    for function_name in version_functions:
        monkeypatch.setattr(
            cli,
            function_name,
            lambda name=function_name: print(name.removesuffix("_show_version")),
        )

    def fail_scan_setup():
        pytest.fail("tool version output should bypass scan setup")

    monkeypatch.setattr(cli, "is_running_in_docker", fail_scan_setup)
    monkeypatch.setattr(cli, "read_env_overrides", fail_scan_setup)

    assert main(["--tool_versions"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        f"dsoinabox {cli.__version__}",
        "syft",
        "grype",
        "trufflehog",
        "opengrep",
        "checkov",
    ]
