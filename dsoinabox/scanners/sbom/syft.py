from __future__ import annotations

import json
import os
from ..base import BaseScanner, ScannerError


class SyftScanner(BaseScanner):
    """syft scanner for sbom generation."""

    def __init__(self):
        super().__init__("syft", help_command="help")

    def run_scan(self, source_path: str, extra_tool_args: str = "", report_directory: str = "reports") -> dict:
        """run the syft cli scan."""
        args = f"scan dir:{source_path} -o json -q"
        if extra_tool_args:
            args += f" {extra_tool_args}"
        result = self._run_command(args)
        if result.returncode == 0:
            json_result = json.loads(result.stdout.strip())
            self._write_json_report(json_result, report_directory, "syft.json")
            return json_result
        else:
            raise ScannerError(f"Syft scan failed: {result.stderr}")

    def _write_json_report(self, data: dict | list, report_directory: str, filename: str) -> None:
        """write json report to file."""
        os.makedirs(report_directory, exist_ok=True)
        with open(f"{report_directory}/{filename}", "w") as fd:
            json.dump(data, fd, indent=4)


#module-level functions for backward compatibility
_scanner = SyftScanner()
show_version = _scanner.show_version
show_help = _scanner.show_help
run_scan = _scanner.run_scan
dir_scan = run_scan  #alias for backward compatibility
