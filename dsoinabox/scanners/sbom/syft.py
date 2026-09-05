from __future__ import annotations

import json
import os

from ..base import BaseScanner, ScannerError


class SyftScanner(BaseScanner):
    """syft scanner for sbom generation."""

    def __init__(self):
        super().__init__("syft", help_command="help")

    def run_scan(
        self,
        source_path: str,
        extra_tool_args: str | list[str] | tuple[str, ...] | None = "",
        report_directory: str = "reports",
        timeout: int | None = None,
    ) -> dict:
        """run the syft cli scan."""
        args = ["scan", f"dir:{source_path}", "-o", "json", "-q"]
        args.extend(self._parse_extra_tool_args(extra_tool_args))
        result = self._run_command(args, timeout=timeout)
        if result.returncode == 0:
            json_result = json.loads(result.stdout.strip())
            self._write_json_report(json_result, report_directory, "syft.json")
            return json_result
        else:
            raise ScannerError(f"Syft scan failed: {result.stderr}")

    SBOM_FORMATS = {"cyclonedx": ("cyclonedx-json", "sbom.cdx.json"), "spdx": ("spdx-json", "sbom.spdx.json")}

    def convert(self, syft_json_path: str, output_path: str, fmt: str, timeout: int | None = None) -> str:
        """convert a saved syft JSON document into CycloneDX or SPDX JSON using `syft convert`."""
        if fmt not in self.SBOM_FORMATS:
            raise ScannerError(f"Unsupported SBOM format: {fmt}. Supported: {', '.join(self.SBOM_FORMATS)}")
        syft_format, _ = self.SBOM_FORMATS[fmt]
        result = self._run_command(["convert", syft_json_path, "-o", f"{syft_format}={output_path}", "-q"], timeout=timeout)
        if result.returncode != 0:
            raise ScannerError(f"Syft convert to {fmt} failed: {result.stderr}")
        if not os.path.exists(output_path):
            # some fakes/older syft versions print to stdout instead of writing the file
            text = result.stdout if isinstance(result.stdout, str) else result.stdout.decode("utf-8", "replace")
            if not text.strip():
                raise ScannerError(f"Syft convert to {fmt} produced no output")
            with open(output_path, "w", encoding="utf-8") as fd:
                fd.write(text)
        return output_path

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
convert = _scanner.convert
dir_scan = run_scan  #alias for backward compatibility
