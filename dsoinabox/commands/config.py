"""``dsoinabox config`` subcommands: init."""

from __future__ import annotations

import argparse
import logging
import os

from ..utils.config import CONFIG_ENV_VAR, DEFAULT_CONFIG_FILE, resolve_config_path, write_default_config
from ..utils.environment import is_running_in_docker
from . import EXIT_OK

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dsoinabox config", description="Manage the repository runtime config.")
    sub = parser.add_subparsers(dest="action", required=True)
    init = sub.add_parser("init", help=f"write a starter {DEFAULT_CONFIG_FILE} and exit (never overwrites)")
    init.add_argument("--source", default=None, help="repository root (default: /scan_target in Docker, else .)")
    init.add_argument("--config_file", "--config-file", dest="config_file", default=None,
                      help=f"path to write (default {DEFAULT_CONFIG_FILE} under --source; env {CONFIG_ENV_VAR})")
    return parser


def init_config(*, source: str | None, config_file: str | None) -> int:
    source = source or os.environ.get("DSOINABOX_SOURCE") or ("/scan_target" if is_running_in_docker() else ".")
    explicit = config_file or os.environ.get(CONFIG_ENV_VAR)
    path = resolve_config_path(source=source, explicit_path=explicit)
    if write_default_config(path, overwrite=False):
        logger.info(f"Created starter config at: {path}")
    else:
        logger.info(f"Config already exists, not overwriting: {path}")
    return EXIT_OK


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    return init_config(source=args.source, config_file=args.config_file)
