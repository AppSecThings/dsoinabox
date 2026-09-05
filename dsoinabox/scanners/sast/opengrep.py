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

    def run_scan(
        self,
        source_path: str,
        extra_tool_args: str | list[str] | tuple[str, ...] | None = "",
        report_directory: str = "reports",
    ) -> dict:
        """run the opengrep cli scan."""
        args = [
            "scan",
            "--json",
            "--config",
            "auto",
            source_path,
        ]
        args.extend(self._parse_extra_tool_args(extra_tool_args))
        # Capture bytes and decode them ourselves instead of using OpenGrep's
        # locale-dependent --json-output file writer. PYTHONIOENCODING controls
        # the child stream even for bundled Python distributions.
        result = self._run_command(
            args,
            env={"PYTHONIOENCODING": "utf-8"},
            text=False,
        )
        stdout = result.stdout.decode("utf-8") if isinstance(result.stdout, bytes) else result.stdout
        stderr = result.stderr.decode("utf-8", errors="replace") if isinstance(result.stderr, bytes) else result.stderr
        if result.returncode == 0:
            json_results = json.loads(stdout)
            self._write_json_report(json_results, report_directory, "opengrep.json")
            return json_results
        else:
            raise ScannerError(f"OpenGrep scan failed: {stderr}")

    def _write_json_report(self, data: dict | list, report_directory: str, filename: str) -> None:
        """write json report to file."""
        os.makedirs(report_directory, exist_ok=True)
        with open(f"{report_directory}/{filename}", "w", encoding="utf-8") as fd:
            json.dump(data, fd, indent=4)


#module-level functions for backward compatibility
_scanner = OpengrepScanner()
show_version = _scanner.show_version
show_help = _scanner.show_help
run_scan = _scanner.run_scan
