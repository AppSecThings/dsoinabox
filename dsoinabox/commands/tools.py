"""``dsoinabox tools`` subcommands: versions, help."""

from __future__ import annotations

import argparse
import logging

from .. import __version__
from ..scanners.base import ScannerError
from ..scanners.iac import checkov
from ..scanners.sast import opengrep
from ..scanners.sbom import syft
from ..scanners.sca import grype
from ..scanners.secrets import trufflehog
from . import EXIT_OK, EXIT_SCANNER, EXIT_USAGE

logger = logging.getLogger(__name__)

TOOL_MODULES = {
    "trufflehog": trufflehog,
    "opengrep": opengrep,
    "syft": syft,
    "grype": grype,
    "checkov": checkov,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dsoinabox tools", description="Inspect the bundled scanners.")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("versions", help="print dsoinabox and every scanner version")
    h = sub.add_parser("help", help="print a scanner's own --help output")
    h.add_argument("tool", choices=sorted(TOOL_MODULES))
    return parser


def show_versions() -> int:
    print(f"dsoinabox {__version__}")
    try:
        for module in TOOL_MODULES.values():
            module.show_version()
    except ScannerError as exc:
        logger.error(f"Version check failed: {exc}")
        return EXIT_SCANNER
    return EXIT_OK


def show_tool_help(tool: str) -> int:
    module = TOOL_MODULES.get(tool)
    if module is None:
        logger.error(f"Unknown tool: {tool}")
        return EXIT_USAGE
    try:
        module.show_help()
    except ScannerError as exc:
        logger.error(f"{tool} help failed: {exc}")
        return EXIT_SCANNER
    return EXIT_OK


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    if args.action == "versions":
        return show_versions()
    if args.action == "help":
        return show_tool_help(args.tool)
    return EXIT_USAGE
