"""Unit tests for CLI logging verbosity flags."""

from __future__ import annotations

import logging

import pytest

from dsoinabox.cli import build_parser, resolve_log_level


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
