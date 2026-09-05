"""``dsoinabox waivers`` subcommands: validate, migrate."""

from __future__ import annotations

import argparse
import logging

from ..fingerprints.registry import fingerprint_version_status
from ..waivers.loader import load_waiver_file
from ..waivers.migrate import load_fingerprint_aliases, migrate_file, parse_version_arg
from ..waivers.schema import CURRENT_SCHEMA_VERSION, SUPPORTED_SCHEMA_VERSIONS
from ..waivers.validate import validate_waiver_set
from . import EXIT_OK, EXIT_POLICY, EXIT_USAGE

logger = logging.getLogger("dsoinabox.waivers")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dsoinabox waivers",
        description="Inspect and maintain waiver and benchmark files.",
    )
    sub = parser.add_subparsers(dest="action", required=True)

    v = sub.add_parser("validate", help="check a waiver file: schema version, expired and duplicate entries")
    v.add_argument("paths", nargs="+", metavar="PATH")
    v.add_argument("--strict", action="store_true", help="exit 1 if any warning, expired or duplicate entry is found")
    v.add_argument("--soon-days", "--soon_days", dest="soon_days", type=int, default=30,
                   help="report entries expiring within this many days (default 30)")

    m = sub.add_parser("migrate", help=f"rewrite a waiver file to schema {CURRENT_SCHEMA_VERSION}, preserving comments")
    m.add_argument("paths", nargs="+", metavar="PATH")
    target = m.add_mutually_exclusive_group()
    target.add_argument("--in-place", "--in_place", dest="in_place", action="store_true",
                        help="overwrite the file, keeping a .bak copy next to it")
    target.add_argument("--output", "-o", metavar="PATH", help="write the migrated file here (single input only)")
    m.add_argument("--dry-run", "--dry_run", dest="dry_run", action="store_true", help="print a diff and change nothing")
    m.add_argument("--from-report", "--from_report", dest="from_report", metavar="REPORT.json", default=None,
                   help="also rewrite legacy fingerprints using the fingerprint_aliases recorded in a dsoinabox JSON report")
    m.add_argument("--to", metavar="VERSION", type=parse_version_arg, default=None,
                   help=f"stop at this schema version (default {CURRENT_SCHEMA_VERSION}; supported: {', '.join(SUPPORTED_SCHEMA_VERSIONS)})")
    return parser


def _validate(args: argparse.Namespace) -> int:
    worst = EXIT_OK
    for path in args.paths:
        try:
            ws = load_waiver_file(path)
        except FileNotFoundError as exc:
            print(f"{path}: {exc}")
            worst = max(worst, EXIT_USAGE)
            continue
        except ValueError as exc:
            print(f"{path}: invalid: {exc}")
            worst = max(worst, EXIT_POLICY)
            continue
        report = validate_waiver_set(ws, soon_days=args.soon_days)
        for i, entry in enumerate(ws.finding_waivers):
            status = fingerprint_version_status(entry.fingerprint)
            if status == "legacy":
                report.warnings.append(f"finding_waivers[{i}] uses a legacy fingerprint version: {entry.fingerprint}")
            elif status == "unsupported":
                report.warnings.append(f"finding_waivers[{i}] uses an unsupported fingerprint version: {entry.fingerprint}")
            elif status == "unknown":
                report.warnings.append(f"finding_waivers[{i}] fingerprint is not in <tool>:<version>:<TIER>:... form: {entry.fingerprint}")
        print("\n".join(report.lines()))
        if args.strict and not report.ok:
            worst = max(worst, EXIT_POLICY)
    return worst


def _migrate(args: argparse.Namespace) -> int:
    if args.output and len(args.paths) > 1:
        print("--output accepts a single input file")
        return EXIT_USAGE
    aliases: dict[str, str] | None = None
    if args.from_report:
        try:
            aliases = load_fingerprint_aliases(args.from_report)
        except (OSError, ValueError) as exc:
            print(f"{args.from_report}: {exc}")
            return EXIT_USAGE
        print(f"{args.from_report}: {len(aliases)} fingerprint alias(es) loaded")
    worst = EXIT_OK
    for path in args.paths:
        try:
            result = migrate_file(
                path, to_version=args.to, in_place=args.in_place, output=args.output, dry_run=args.dry_run,
                aliases=aliases,
            )
        except FileNotFoundError as exc:
            print(f"{path}: {exc}")
            worst = max(worst, EXIT_USAGE)
            continue
        except ValueError as exc:
            print(f"{path}: cannot migrate: {exc}")
            worst = max(worst, EXIT_POLICY)
            continue

        if not result.changed:
            print(f"{path}: already at schema {result.to_version}; nothing to do")
            if args.in_place or args.output:
                # scripted use: make "nothing happened" visible
                worst = max(worst, EXIT_POLICY)
            continue

        for note in result.notes:
            print(f"{path}: {note}")
        if args.dry_run or not (args.in_place or args.output):
            print(result.diff, end="")
            if not args.dry_run:
                print(f"{path}: no output requested; use --in-place or --output to write (schema {result.from_version} -> {result.to_version})")
            continue
        where = result.output_path
        print(f"{path}: migrated schema {result.from_version} -> {result.to_version}, wrote {where}")
        if result.backup_path:
            print(f"{path}: backup at {result.backup_path}")
    return worst


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.action == "validate":
        return _validate(args)
    if args.action == "migrate":
        return _migrate(args)
    parser.print_help()
    return EXIT_USAGE
