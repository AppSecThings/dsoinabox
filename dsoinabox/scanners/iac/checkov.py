from __future__ import annotations

import json
import os
import shutil
from ..base import BaseScanner, ScannerError


class CheckovScanner(BaseScanner):
    """checkov scanner for iac security scanning."""

    def __init__(self):
        super().__init__("checkov", help_command="--help")

    def run_scan(self, source_path: str, extra_tool_args: str = "", report_directory: str = "reports") -> dict:
        """run the checkov cli scan."""
        os.makedirs(report_directory, exist_ok=True)
        
        #checkov treats --output-file-path as a directory
        #files are created as "results_<output_type>.<output_type>" in that directory
        checkov_output_dir = os.path.join(report_directory, "checkov")
        
        if os.path.exists(checkov_output_dir):
            shutil.rmtree(checkov_output_dir)
        
        checkov_output_dir_abs = os.path.abspath(checkov_output_dir)
        
        args = f"--soft-fail --quiet -d {source_path} --output sarif --output-file-path {checkov_output_dir_abs}"
        if extra_tool_args:
            args += f" {extra_tool_args}"
        result = self._run_command(args)
        
        if result.returncode == 0:
            #checkov creates files in the output directory as "results_sarif.sarif"
            sarif_data = None
            if os.path.exists(checkov_output_dir_abs) and os.path.isdir(checkov_output_dir_abs):
                for filename in os.listdir(checkov_output_dir_abs):
                    source_file = os.path.join(checkov_output_dir_abs, filename)
                    if os.path.isfile(source_file):
                        _, ext = os.path.splitext(filename)
                        dest_filename = f"checkov{ext}"
                        dest_file = os.path.join(report_directory, dest_filename)
                        shutil.move(source_file, dest_file)
                        
                        if ext == ".sarif":
                            with open(dest_file, "r") as fd:
                                sarif_data = json.load(fd)
                
                shutil.rmtree(checkov_output_dir_abs)
            
            if sarif_data:
                return sarif_data
            else:
                raise ScannerError(f"Checkov scan completed but SARIF file not found in {checkov_output_dir_abs}")
        else:
            raise ScannerError(f"Checkov scan failed: {result.stderr}")

    def _write_json_report(self, data: dict | list, report_directory: str, filename: str) -> None:
        """write json report to file."""
        with open(f"{report_directory}/{filename}", "w") as fd:
            json.dump(data, fd, indent=4)


#module-level functions for backward compatibility
_scanner = CheckovScanner()
show_version = _scanner.show_version
show_help = _scanner.show_help
run_scan = _scanner.run_scan

