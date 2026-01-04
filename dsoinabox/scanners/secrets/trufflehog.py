from __future__ import annotations

import json
import os
from ..base import BaseScanner, ScannerError


class TrufflehogScanner(BaseScanner):
    """trufflehog scanner for secret detection."""

    def __init__(self):
        super().__init__("trufflehog", help_command="help")

    def run_scan(self, source_path: str, extra_tool_args: str = "", report_directory: str = "reports", git_repo = True) -> dict:
        """run the trufflehog cli scan."""
        if git_repo:
            args = f"git file://{source_path} --no-verification --no-update -j"
        else:
            args = f"filesystem {source_path} --no-verification --no-update -j"
        if extra_tool_args:
            args += f" {extra_tool_args}"
        result = self._run_command(args)
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
