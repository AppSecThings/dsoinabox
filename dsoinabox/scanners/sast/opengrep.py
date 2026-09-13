"""wrapper functions to interact with the opengrep cli.

opengrep (the semgrep successor) is expected to be installed in the execution
environment. these helpers encapsulate subprocess invocation details.
"""

from __future__ import annotations

import json
import os
import re
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
        timeout: int | None = None,
        opengrep_rules: str | list[str] | tuple[str, ...] | None = None,
    ) -> dict:
        """run the opengrep cli scan."""
        if opengrep_rules is None:
            rule_sources = ["auto"]
        elif isinstance(opengrep_rules, str):
            rule_sources = [item.strip() for item in opengrep_rules.split(",") if item.strip()] or ["auto"]
        else:
            rule_sources = [str(item) for item in opengrep_rules] or ["auto"]
        args = [
            "scan",
            "--json",
        ]
        for rule_source in rule_sources:
            args.extend(["--config", rule_source])
        args.append(source_path)
        args.extend(self._parse_extra_tool_args(extra_tool_args))
        # Capture bytes and decode them ourselves instead of using OpenGrep's
        # locale-dependent --json-output file writer. PYTHONIOENCODING controls
        # the child stream even for bundled Python distributions.
        result = self._run_command(
            args,
            env={"PYTHONIOENCODING": "utf-8"},
            text=False,
            timeout=timeout,
        )
        stdout = result.stdout.decode("utf-8") if isinstance(result.stdout, bytes) else result.stdout
        stderr = result.stderr.decode("utf-8", errors="replace") if isinstance(result.stderr, bytes) else result.stderr
        if result.returncode == 0:
            json_results = json.loads(stdout)
            self._write_json_report(json_results, report_directory, "opengrep.json")
            return json_results
        else:
            if rule_sources == ["auto"] and self._is_auto_network_error(stderr):
                original = self._network_error_line(stderr)
                raise ScannerError(
                    "OpenGrep could not download rules from semgrep.dev (--config auto needs outbound network access). "
                    "Set --opengrep_rules / DSOINABOX_OPENGREP_RULES / opengrep_rules to a local rules directory "
                    f"or file to run offline. Original error: {original}"
                )
            raise ScannerError(f"OpenGrep scan failed: {stderr}")

    @staticmethod
    def _is_auto_network_error(stderr: str) -> bool:
        signatures = (
            "semgrep.dev",
            "HTTPSConnectionPool",
            "Max retries exceeded",
            "ConnectionError",
            "NewConnectionError",
            "Name or service not known",
            "Temporary failure in name resolution",
        )
        lowered = stderr.lower()
        return any(signature.lower() in lowered for signature in signatures)

    @staticmethod
    def _network_error_line(stderr: str) -> str:
        lines = [line.strip() for line in stderr.splitlines() if line.strip()]
        preferred = next(
            (line for line in lines if re.search(r"HTTPSConnectionPool|semgrep\.dev", line, re.IGNORECASE)),
            None,
        )
        return preferred or (lines[0] if lines else "")

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
