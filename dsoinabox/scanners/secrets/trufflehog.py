from __future__ import annotations

import json
import os

from ..base import BaseScanner, ScannerError


class TrufflehogScanner(BaseScanner):
    """trufflehog scanner for secret detection."""

    def __init__(self):
        super().__init__("trufflehog", help_command="help")

    def run_scan(
        self,
        source_path: str,
        extra_tool_args: str | list[str] | tuple[str, ...] | None = "",
        report_directory: str = "reports",
        timeout: int | None = None,
        git_repo=True,
        verify: bool = False,
    ) -> list:
        """run the trufflehog cli scan. verification is opt-in because it contacts the credential's provider."""
        target = ["git", f"file://{source_path}"] if git_repo else ["filesystem", source_path]
        args = [*target, "--no-update", "-j"]
        if not verify:
            args.insert(len(target), "--no-verification")
        args.extend(self._parse_extra_tool_args(extra_tool_args))
        result = self._run_command(args, timeout=timeout)
        if result.returncode == 0:
            records = []
            for line in result.stdout.splitlines():
                if line.strip():
                    parsed = json.loads(line)
                    #handle case where output is a single json array (e.g., "[]")
                    if isinstance(parsed, list):
                        records.extend(parsed)
                    else:
                        records.append(parsed)
            self._write_json_report(records, report_directory, "trufflehog.json")
            return records
        else:
            raise ScannerError(f"TruffleHog scan failed: {result.stderr}")

    def _write_json_report(self, data: dict | list, report_directory: str, filename: str) -> None:
        """write json report to file."""
        os.makedirs(report_directory, exist_ok=True)
        with open(f"{report_directory}/{filename}", "w") as fd:
            json.dump(data, fd, indent=4)


#module-level functions for backward compatibility
_scanner = TrufflehogScanner()
show_version = _scanner.show_version
show_help = _scanner.show_help
run_scan = _scanner.run_scan
