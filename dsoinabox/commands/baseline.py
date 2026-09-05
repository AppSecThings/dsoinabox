"""``dsoinabox baseline`` subcommands: update."""

from __future__ import annotations

import argparse
import json

from ..utils.deterministic import utcnow
from ..waivers.migrate import update_baseline_file
from ..waivers.models import format_datetime, parse_datetime
from . import EXIT_OK, EXIT_POLICY, EXIT_USAGE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dsoinabox baseline", description="Maintain benchmark/baseline files.")
    sub = parser.add_subparsers(dest="action", required=True)
    u = sub.add_parser("update", help="add the active findings of a JSON report to a baseline file")
    u.add_argument("--from", dest="report", required=True, metavar="REPORT.json", help="dsoinabox JSON report to read findings from")
    u.add_argument("--file", "-f", default="benchmark.yaml", help="baseline file to update (created if missing)")
    u.add_argument("--prune", action="store_true", help="drop baseline entries that did not match any finding in the report")
    u.add_argument("--expires", default=None, metavar="DATE",
                   help="set benchmark_expires_at (YYYY-MM-DD or ISO 8601) so the whole baseline must be revalidated by then")
    u.add_argument("--include-waived", "--include_waived", dest="include_waived", action="store_true",
                   help="also add waived findings (default: active findings only)")
    u.add_argument("--dry-run", "--dry_run", dest="dry_run", action="store_true", help="print the result and change nothing")
    return parser


def _update(args: argparse.Namespace) -> int:
    try:
        with open(args.report, encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"{args.report}: {exc}")
        return EXIT_USAGE
    findings = report.get("findings") if isinstance(report, dict) else None
    if not isinstance(findings, list):
        print(f"{args.report}: no normalized findings list; regenerate the report with this version of dsoinabox")
        return EXIT_USAGE

    fingerprints: list[str] = []
    seen_any: set[str] = set()
    for f in findings:
        if not isinstance(f, dict):
            continue
        fps = f.get("fingerprints") or {}
        values = [v for v in fps.values() if isinstance(v, str) and v] + [v for v in (f.get("legacy_fingerprints") or []) if isinstance(v, str)]
        seen_any.update(values)
        if f.get("waived") and not args.include_waived:
            continue
        primary = None
        for key in ("secret", "rule", "pkg", "ctx", "exact", "ctx_soft"):
            if fps.get(key):
                primary = fps[key]
                break
        if primary:
            fingerprints.append(primary)

    expires = None
    if args.expires:
        parsed = parse_datetime(args.expires)
        expires = format_datetime(parsed) if parsed else None
        if expires is None:
            print(f"--expires: could not parse {args.expires!r}")
            return EXIT_USAGE

    try:
        result = update_baseline_file(
            args.file,
            fingerprints=fingerprints,
            seen_fingerprints=seen_any,
            prune=args.prune,
            expires_at=expires,
            created_at=format_datetime(utcnow()),
            dry_run=args.dry_run,
        )
    except ValueError as exc:
        print(f"{args.file}: {exc}")
        return EXIT_POLICY
    for note in result.notes:
        print(f"{args.file}: {note}")
    if args.dry_run:
        print(result.migrated_text, end="")
    elif result.changed:
        print(f"{args.file}: wrote {result.output_path}")
    else:
        print(f"{args.file}: already up to date")
    return EXIT_OK


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    if args.action == "update":
        return _update(args)
    return EXIT_USAGE
