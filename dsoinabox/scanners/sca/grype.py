from __future__ import annotations

import json
import os

from ..base import BaseScanner, ScannerError


class GrypeScanner(BaseScanner):
    """grype scanner for sca vulnerability scanning."""

    def __init__(self):
        super().__init__("grype", help_command="help")

    def run_scan(
        self,
        source_path: str,
        extra_tool_args: str | list[str] | tuple[str, ...] | None = "",
        report_directory: str = "reports",
        timeout: int | None = None,
        db_mode: str = "auto",
    ) -> dict:
        """run the grype cli scan. db_mode=offline disables DB auto-update and fails clearly without a cached DB."""
        #check for syft.json in report_directory (could be tools_output or reports)
        syft_json_path = os.path.join(report_directory, "syft.json")
        if os.path.exists(syft_json_path):
            args = [f"sbom:{syft_json_path}", "-o", "json"]
        else:
            args = [f"dir:{source_path}", "-o", "json"]
        args.extend(self._parse_extra_tool_args(extra_tool_args))
        env = {"GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_DB_VALIDATE_AGE": "false"} if db_mode == "offline" else None
        result = self._run_command(args, timeout=timeout, env=env)
        if result.returncode == 0:
            json_result = json.loads(result.stdout.strip())
            self._write_json_report(json_result, report_directory, "grype.json")
            return json_result
        stderr = result.stderr if isinstance(result.stderr, str) else result.stderr.decode("utf-8", "replace")
        low = stderr.lower()
        if db_mode == "offline" and ("db" in low or "database" in low) and any(k in low for k in ("not found", "no vulnerability database", "unable to load", "does not exist")):
            raise ScannerError(
                "Grype scan failed: no vulnerability database is cached and --grype_db offline forbids downloading one. "
                "Pre-populate the cache (grype db update) or mount a cache volume. Original error: " + stderr.strip()
            )
        raise ScannerError(f"Grype scan failed: {stderr}")

    def db_status(self, timeout: int | None = 60) -> str:
        """one-line summary of the vulnerability database (built date), best effort."""
        result = self._run_command(["db", "status", "-o", "json"], timeout=timeout)
        if result.returncode != 0:
            return ""
        text = result.stdout if isinstance(result.stdout, str) else result.stdout.decode("utf-8", "replace")
        try:
            data = json.loads(text)
        except ValueError:
            first = next((line.strip() for line in text.splitlines() if "built" in line.lower()), "")
            return first[:120]
        if not isinstance(data, dict):
            return ""
        built = data.get("built") or data.get("Built") or ""
        schema = data.get("schemaVersion") or data.get("schema") or ""
        return (f"built {built}" + (f" (schema {schema})" if schema else "")) if built else ""

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
db_status = _scanner.db_status
