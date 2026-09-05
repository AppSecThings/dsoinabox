"""dsoinabox cli implementation"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import sys
from collections.abc import Callable

from . import __version__
from .console import print_findings, print_summary
from .model import ScanOptions, parse_threshold
from .policy import EXIT_POLICY, EXIT_SCANNER, EXIT_USAGE
from .run import UsageError, run_scan
from .scanners.registry import TOOL_ORDER
from .utils.config import (
    CONFIG_ENV_VAR,
    DEFAULT_CONFIG_FILE,
    MERGEABLE_KEYS,
    load_config_file,
    normalize_show_findings,
    read_env_overrides,
    resolve_config_path,
)
from .utils.deterministic import utcnow
from .utils.environment import is_running_in_docker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger()
default_waiver_file = ".dsoinabox_waivers.yaml"
default_repo_config_file = DEFAULT_CONFIG_FILE

def resolve_log_level(*, verbose: bool, quiet: bool) -> int:
    """resolve log level from verbosity flags."""
    if verbose:
        return logging.DEBUG
    if quiet:
        return logging.WARNING
    return logging.INFO

def configure_logging(*, verbose: bool, quiet: bool) -> None:
    """configure root logger verbosity for this run."""
    level = resolve_log_level(verbose=verbose, quiet=quiet)
    logger.setLevel(level)

class KebabAliasParser(argparse.ArgumentParser):
    """ArgumentParser that accepts ``--foo-bar`` for every ``--foo_bar`` option.

    The snake_case spelling stays the documented one; the kebab-case twin is a
    hidden alias with the same destination, so help output stays uncluttered
    and no existing invocation changes.
    """

    def add_argument(self, *names, **kwargs):
        action = super().add_argument(*names, **kwargs)
        if kwargs.get("action") == "version" or kwargs.get("action") == "help":
            return action
        aliases = [n.replace("_", "-") for n in names if n.startswith("--") and "_" in n]
        aliases = [a for a in aliases if a not in names and a not in self._option_string_actions]
        if not aliases:
            return action
        alias_kwargs = dict(kwargs)
        alias_kwargs["help"] = argparse.SUPPRESS
        alias_kwargs["dest"] = action.dest
        alias_kwargs["default"] = argparse.SUPPRESS
        super().add_argument(*aliases, **alias_kwargs)
        return action


def build_parser() -> argparse.ArgumentParser:
    """build top-level arg parser"""
    parser = KebabAliasParser(
        prog="dsoinabox scan",
        description=(
            "Run the bundled AppSec scanners against a source tree and produce unified reports. "
            "`dsoinabox scan` is the default command: `dsoinabox -t all` and `dsoinabox scan -t all` are equivalent."
        ),
        epilog=SUBCOMMAND_OVERVIEW,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="show the app version and exit.",
    )

    # legacy aliases kept for one release; the subcommands are the documented form
    parser.add_argument("--tool_versions", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--init-config", "--init_config", action="store_true", dest="init_config", help=argparse.SUPPRESS)
    
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="enable verbose logging (DEBUG level).",
    )
    verbosity_group.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="reduce logging output (WARNING level and above).",
    )

    # tool selection
    parser.add_argument(
        "--tools", "-t",
        dest="tools",
        action="store",
        default="all",
        help="tools to run. comma-separated list: trufflehog, opengrep, syft, grype, checkov. can also use categories: SAST, SBOM, SECRET, SCA, IAC. default is all",
    )

    parser.add_argument(
        "--report_directory",
        action="store",
        default=None,  # set based on docker detection
        help=(
            "directory for generated reports. default is './reports'. relative paths are resolved "
            "from the current working directory. if running in docker and '/reports' is available, "
            "reports are copied there"
        ),
    )

    # trufflehog
    parser.add_argument("--trufflehog_help", action="store_true", help=argparse.SUPPRESS)

    parser.add_argument(
        "--trufflehog_args",
        action="store",
        help="extra args to pass to trufflehog",
    )

    # opengrep
    parser.add_argument("--opengrep_help", action="store_true", help=argparse.SUPPRESS)

    parser.add_argument(
        "--opengrep_args",
        action="store",
        help="extra args to pass to opengrep",
    )

    # syft
    parser.add_argument("--syft_help", action="store_true", help=argparse.SUPPRESS)

    parser.add_argument(
        "--syft_args",
        action="store",
        help="extra args to pass to syft",
    )

    # grype
    parser.add_argument("--grype_help", action="store_true", help=argparse.SUPPRESS)

    parser.add_argument(
        "--grype_args",
        action="store",
        help="extra args to pass to grype",
    )

    # checkov
    parser.add_argument("--checkov_help", action="store_true", help=argparse.SUPPRESS)

    parser.add_argument(
        "--checkov_args",
        action="store",
        help="extra args to pass to checkov",
    )

    parser.add_argument(
        "--config_file",
        action="store",
        default=None,
        help=(
            f"path to runtime config file (YAML). default is '{default_repo_config_file}' "
            f"relative to --source. env override: {CONFIG_ENV_VAR}."
        ),
    )

    parser.add_argument(
        "--source",
        action="store",
        default=None,  # set based on docker detection
        help="path to code to scan. default is '/scan_target' in docker, current directory ('.') when run directly",
    )

    parser.add_argument(
        "--project_id",
        action="store",
        default=None,
        help="explicit project identifier (required for non-git directories). "
             "if not provided, will be derived from git remote or initial commit.",
    )

    # failure threshold for scan
    # should be one of: "none" or "info", "low", "medium", "high", "critical"
    '''
    opengrep severities:
        new rules: Low, Medium, High, Critical
        old rules: Error=High, Warning=Medium, Info=Low
    '''
    parser.add_argument(
        "--failure_threshold",
        action="store",
        default="none",
        help="policy gate: exit 1 when unwaived findings at or above this severity exist. one of: none, info, low, medium, high, critical. default none. secrets are gated by --fail_on_secrets instead.",
    )

    parser.add_argument(
        "--report_threshold",
        action="store",
        default="none",
        help="hide findings below this severity from generated reports and the console table. does not affect the exit code. one of: none, info, low, medium, high, critical. default none (show everything).",
    )

    #fail on secrets if found
    parser.add_argument(
        "--fail_on_secrets",
        action="store_true",
        help="fail the scan if any secrets are found.",
    )

    parser.add_argument(
        "--show_findings",
        type=normalize_show_findings,
        default="false",
        nargs='?',
        const="true",
        help="list active findings in the terminal after the summary: false (default), true (compact table) or full (details).",
    )

    parser.add_argument(
        "--scan_timeout",
        type=int,
        default=1800,
        help="seconds each scanner may run before it is treated as failed (exit 2). default 1800.",
    )

    parser.add_argument(
        "--fail_fast",
        action="store_true",
        default=False,
        help="stop launching scanners after the first scanner failure. default: run everything and report failures.",
    )

    
    parser.add_argument(
        "--waiver_file",
        action="store",
        default=default_waiver_file,
        help="path to waiver file (YAML format). if provided, findings matching waiver fingerprints will be marked as waived.",
    )

    parser.add_argument(
        "--waiver_grace_days",
        type=int,
        default=0,
        help="keep expired waivers active for this many extra days after expires_at, flagged as expiring. default 0.",
    )

    parser.add_argument(
        "--output", "-o",
        action="store",
        default="html",
        help="output format(s). comma-separated: html, jenkins_html, json, ndjson, sarif, cyclonedx, spdx "
             "(the last two write the Syft SBOM as a standalone file). default is html.",
    )

    parser.add_argument(
        "--tool_output",
        action="store_true",
        default=False,
        help="if True, keep tool output files in tools_output subdirectory. default is False (tool outputs are deleted after report generation).",
    )

    parser.add_argument(
        "--report_name",
        action="store",
        default=None,
        help="base file name for generated reports (default 'dsoinabox_unified_report_<timestamp>'). "
             "a copy of the run is always available under <report_directory>/latest/.",
    )

    parser.add_argument(
        "--baseline",
        action="store",
        default=None,
        help="benchmark/baseline file (relative to --source unless absolute). findings are classified new or known "
             "against it; combine with --fail_on new to gate only regressions.",
    )

    parser.add_argument(
        "--fail_on",
        action="store",
        default="all",
        choices=["all", "new"],
        help="which unwaived findings the policy gate considers: all (default) or only those new since --baseline.",
    )

    parser.add_argument(
        "--benchmark",
        action="store_true",
        default=False,
        help="if True, generate benchmark.yaml file with all findings from all tools. benchmark entries will have type 'benchmark'.",
    )

    return parser

def parse_cli_overrides(argv: list[str]) -> dict[str, object]:
    """parse only explicitly provided CLI values (suppress parser defaults)."""
    parser = build_parser()
    for action in parser._actions:
        if action.dest in {"help"}:
            continue
        action.default = argparse.SUPPRESS
    parsed = parser.parse_args(argv)
    return vars(parsed)


SUBCOMMAND_OVERVIEW = """\
subcommands:
  scan                 run scanners and build reports (default when the first argument is a flag)
  waivers validate     check a waiver file for schema, expired and duplicate entries
  waivers migrate      rewrite a waiver file to the current schema, preserving comments
  baseline update      refresh a benchmark/baseline file from a JSON report
  config init          write a starter .dsoinabox.yaml
  tools versions       print dsoinabox and scanner versions
  tools help <tool>    print a scanner's own help

run `dsoinabox <subcommand> --help` for details.
"""


def _subcommands() -> dict[str, Callable[[list[str]], int]]:
    from .commands import baseline as baseline_cmd
    from .commands import config as config_cmd
    from .commands import tools as tools_cmd
    from .commands import waivers as waivers_cmd

    return {
        "scan": scan_main,
        "waivers": waivers_cmd.main,
        "baseline": baseline_cmd.main,
        "config": config_cmd.main,
        "tools": tools_cmd.main,
    }


def main(argv: list[str] | None = None) -> int:
    """app entrypoint. Dispatches to a subcommand; a leading flag means `scan`.

    Returns an exit code instead of calling sys.exit().
    """
    if argv is None:
        argv = sys.argv[1:]
    argv = list(argv)

    if not argv:
        build_parser().print_help()
        return 0

    commands = _subcommands()
    if argv[0] in commands:
        return commands[argv[0]](argv[1:])
    if not argv[0].startswith("-"):
        logger.error(f"Unknown command '{argv[0]}'. Expected one of: {', '.join(commands)} (or flags for scan).")
        return EXIT_USAGE
    # legacy flat invocation: every flag belongs to scan
    return scan_main(argv)


def _legacy_flag_notice(flag: str, replacement: str) -> None:
    logger.warning(f"{flag} is deprecated and will be removed in a future release; use `dsoinabox {replacement}`")


def scan_main(argv: list[str]) -> int:
    """`dsoinabox scan` implementation."""
    from .commands import config as config_cmd
    from .commands import tools as tools_cmd

    parser = build_parser()

    if not argv:
        parser.print_help()
        return 0

    #parse args and explicit CLI overrides
    args = parser.parse_args(argv)
    configure_logging(verbose=args.verbose, quiet=args.quiet)

    if args.tool_versions:
        _legacy_flag_notice("--tool_versions", "tools versions")
        return tools_cmd.show_versions()

    for tool_name in ("trufflehog", "opengrep", "syft", "grype", "checkov"):
        if getattr(args, f"{tool_name}_help", False):
            _legacy_flag_notice(f"--{tool_name}_help", f"tools help {tool_name}")
            return tools_cmd.show_tool_help(tool_name)

    cli_overrides = parse_cli_overrides(argv)

    # Detect Docker environment and set defaults
    in_docker = is_running_in_docker()
    if in_docker:
        logger.debug("Detected Docker environment")
    else:
        logger.debug("Running outside Docker container")
    
    env_overrides = read_env_overrides()

    # Resolve source first so config file lookup works from repo root
    source_for_config = cli_overrides.get("source") or env_overrides.get("source")
    if source_for_config is None:
        source_for_config = "/scan_target" if in_docker else "."

    config_file_override = cli_overrides.get("config_file") or env_overrides.get("config_file")
    config_path = resolve_config_path(
        source=str(source_for_config),
        explicit_path=str(config_file_override) if config_file_override else None,
    )
    config_values: dict[str, object] = {}
    if config_path.exists():
        try:
            config_values = load_config_file(config_path)
            logger.info(f"Loaded runtime config: {config_path}")
        except Exception as e:
            logger.error(f"Failed to load config file {config_path}: {e}")
            return EXIT_USAGE
    elif config_file_override:
        logger.error(f"Configured runtime config file was not found: {config_path}")
        return EXIT_USAGE

    merged_values: dict[str, object] = {}
    merged_values.update(config_values)
    merged_values.update(env_overrides)
    merged_values.update(cli_overrides)
    for key in MERGEABLE_KEYS:
        if key in merged_values:
            setattr(args, key, merged_values[key])

    if args.init_config:
        _legacy_flag_notice("--init-config", "config init")
        return config_cmd.init_config(
            source=str(source_for_config),
            config_file=str(config_file_override) if config_file_override else None,
        )

    # Set default source path based on environment
    if args.source is None:
        args.source = "/scan_target" if in_docker else "."
        logger.info(f"Using default source path: {args.source}")

    # Set default report directory based on environment
    if args.report_directory is None:
        args.report_directory = "reports"
        logger.info(f"Using default report directory: {args.report_directory}")

    # Relative report_directory is resolved from the invocation directory, not from --source
    if not os.path.isabs(args.report_directory):
        args.report_directory = os.path.join(os.getcwd(), args.report_directory)

    # Each run gets its own timestamped directory so parallel CI jobs never collide
    timestamp = utcnow().strftime('%Y_%m_%dT%H_%M_%S')
    report_directory = os.path.join(args.report_directory, f"dsoinabox_{timestamp}")
    logger.info(f"Using timestamped report directory: {report_directory}")

    try:
        failure_threshold = parse_threshold(args.failure_threshold)
        report_threshold = parse_threshold(args.report_threshold)
    except ValueError as exc:
        logger.error(str(exc))
        return EXIT_USAGE

    tools = [t.strip().lower() for t in str(args.tools).split(",") if t.strip()]
    outputs = [fmt.strip().lower() for fmt in str(args.output).split(",") if fmt.strip()]
    tool_args = {tool: getattr(args, f"{tool}_args", None) for tool in TOOL_ORDER}

    options = ScanOptions(
        source=args.source,
        report_directory=report_directory,
        timestamp=timestamp,
        project_id=args.project_id,
        tools=tools or ["all"],
        failure_threshold=failure_threshold,
        report_threshold=report_threshold,
        fail_on_secrets=bool(args.fail_on_secrets),
        waiver_file=args.waiver_file or None,
        waiver_file_is_default=(args.waiver_file == default_waiver_file),
        waiver_grace_days=int(args.waiver_grace_days or 0),
        outputs=outputs or ["html"],
        keep_tool_output=bool(args.tool_output),
        report_name=args.report_name or None,
        base_report_directory=args.report_directory,
        baseline=args.baseline or None,
        fail_on=args.fail_on or "all",
        benchmark=bool(args.benchmark),
        tool_args=tool_args,
        scan_timeout=int(args.scan_timeout) if args.scan_timeout else None,
        fail_fast=bool(args.fail_fast),
    )

    try:
        run = run_scan(options)
    except UsageError as exc:
        logger.error(str(exc))
        return EXIT_USAGE

    # Docker: copy the timestamped directory to the /reports mount when present
    if in_docker and os.path.exists("/reports"):
        logger.info("Copying reports to /reports mount")
        shutil.copytree(run.report_directory, os.path.join("/reports", os.path.basename(run.report_directory)))

    show = normalize_show_findings(args.show_findings)
    if show != "false":
        print_findings(run, show)
    print_summary(run, options)

    if run.policy.scanner_failures:
        logger.error(f"One or more scanners failed: {', '.join(run.policy.scanner_failures)} (exit code {EXIT_SCANNER})")
    elif run.policy.exit_code == EXIT_POLICY:
        logger.error("All scans completed, but the policy gate failed, so exiting with a non-zero exit code")
    else:
        logger.info("All scans completed successfully.")
    return run.policy.exit_code
