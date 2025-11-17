"""wrapper functions to interact with the opengrep cli.

opengrep (the semgrep successor) is expected to be installed in the execution
environment. these helpers encapsulate subprocess invocation details.
"""

from __future__ import annotations

import json
import os
import sys
from ..base import BaseScanner, ScannerError


class OpengrepScanner(BaseScanner):
    """opengrep scanner for sast analysis."""

    def __init__(self):
        super().__init__("opengrep", help_command="scan --help")

    def show_version(self) -> None:
        """print the installed opengrep version to stdout."""
        result = self._run_command("--version")
        if result.returncode == 0:
            print("Opengrep version: " + result.stdout.strip())
        else:
            sys.stderr.write(result.stderr)
            raise ScannerError(f"opengrep version check failed: {result.stderr}")

    def run_scan(self, source_path: str, extra_tool_args: str = "", report_directory: str = "reports") -> dict:
        """run the opengrep cli scan."""
        args = f"scan --json-output={report_directory}/opengrep.json --config auto {source_path}"
        if extra_tool_args:
            args += f" {extra_tool_args}"
        result = self._run_command(args)
        if result.returncode == 0:
            with open(f"{report_directory}/opengrep.json", "r") as fd:
                json_results = json.load(fd)
            self._write_json_report(json_results, report_directory, "opengrep.json")
            return json_results
        else:
            raise ScannerError(f"OpenGrep scan failed: {result.stderr}")

    def _write_json_report(self, data: dict | list, report_directory: str, filename: str) -> None:
        """write json report to file."""
        os.makedirs(report_directory, exist_ok=True)
        with open(f"{report_directory}/{filename}", "w") as fd:
            json.dump(data, fd, indent=4)


#module-level functions for backward compatibility
_scanner = OpengrepScanner()
show_version = _scanner.show_version
show_help = _scanner.show_help
run_scan = _scanner.run_scan
