from __future__ import annotations

import json
import os
from ..base import BaseScanner, ScannerError


class GrypeScanner(BaseScanner):
    """grype scanner for sca vulnerability scanning."""

    def __init__(self):
        super().__init__("grype", help_command="help")

    def run_scan(self, source_path: str, extra_tool_args: str = "", report_directory: str = "reports") -> dict:
        """run the grype cli scan."""
        #check for syft.json in report_directory (could be tools_output or reports)
        syft_json_path = os.path.join(report_directory, "syft.json")
        if os.path.exists(syft_json_path):
            args = f"sbom:{syft_json_path} -o json"
        else:
            args = f"dir:{source_path} -o json"

        if extra_tool_args:
            args += f" {extra_tool_args}"
        result = self._run_command(args)
        if result.returncode == 0:
            json_result = json.loads(result.stdout.strip())
            self._write_json_report(json_result, report_directory, "grype.json")
            return json_result
        else:
            raise ScannerError(f"Grype scan failed: {result.stderr}")

    def _write_json_report(self, data: dict | list, report_directory: str, filename: str) -> None:
        """write json report to file."""
        os.makedirs(report_directory, exist_ok=True)
        with open(f"{report_directory}/{filename}", "w") as fd:
            json.dump(data, fd, indent=4)


#module-level functions for backward compatibility
_scanner = GrypeScanner()
show_version = _scanner.show_version
show_help = _scanner.show_help
run_scan = _scanner.run_scan
