"""Terminal output for a scan: the summary block and optional findings listing."""

from __future__ import annotations

import os
import sys
import textwrap
from typing import TextIO

from .model import SEVERITY_ORDER, Finding, ScanOptions, ScanRun

PREFIX = "[dsoinabox]"

_COLORS = {
    "critical": "\033[95m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
    "info": "\033[90m",
    "unknown": "\033[90m",
    "ok": "\033[92m",
    "fail": "\033[91m",
    "reset": "\033[0m",
}


def _use_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _paint(text: str, key: str, color: bool) -> str:
    if not color:
        return text
    return f"{_COLORS.get(key, '')}{text}{_COLORS['reset']}"


def summary_lines(run: ScanRun, options: ScanOptions, *, color: bool = False) -> list[str]:
    lines: list[str] = []
    lines.append(f"{PREFIX} dsoinabox {run.dsoinabox_version}  project={run.project_id}  source={run.source}")

    tool_bits: list[str] = []
    for r in run.results:
        version = f" {r.tool_version}" if r.tool_version else ""
        if r.status == "ok":
            tool_bits.append(f"{r.tool}{version} ({r.duration_s:.1f}s)")
        elif r.status == "skipped":
            tool_bits.append(_paint(f"{r.tool} (skipped)", "medium", color))
        else:
            tool_bits.append(_paint(f"{r.tool}{version} (FAILED)", "fail", color))
    lines.append(f"{PREFIX} tools: {', '.join(tool_bits) if tool_bits else 'none'}")
    for r in run.results:
        if r.status == "failed":
            first = (r.error or "").strip().splitlines()
            lines.append(f"{PREFIX}   {r.tool}: {first[0] if first else 'failed'}")

    counts = run.severity_counts()
    count_bits = [f"{sev.value}={_paint(str(counts[sev.value]), sev.value, color) if counts[sev.value] else counts[sev.value]}" for sev in SEVERITY_ORDER if sev.value != "unknown"]
    if counts.get("unknown"):
        count_bits.append(f"unknown={counts['unknown']}")
    lines.append(f"{PREFIX} findings: {' '.join(count_bits)}")

    ws = run.waiver_summary
    if ws:
        by_type = ", ".join(f"{k}={v}" for k, v in sorted(ws["waived_by_type"].items()))
        waived = f"{ws['waived']}" + (f" ({by_type})" if by_type else "")
        extras = []
        if ws.get("expired_matches"):
            extras.append(_paint(f"expired={ws['expired_matches']}", "medium", color))
        if ws.get("expiring_matches"):
            extras.append(f"expiring={ws['expiring_matches']}")
        if ws.get("unused_count"):
            extras.append(f"unused={ws['unused_count']}")
        if ws.get("deprecated_schema"):
            extras.append(_paint(f"schema={ws['schema_version']} (deprecated, run `dsoinabox waivers migrate`)", "medium", color))
        lines.append(f"{PREFIX} waived: {waived}{'  ' + '  '.join(extras) if extras else ''}  (from {ws.get('file')})")
    if run.hidden_by_report_threshold:
        lines.append(
            f"{PREFIX} hidden from reports by report_threshold={options.report_threshold.value if options.report_threshold else 'none'}: "
            f"{run.hidden_by_report_threshold}"
        )
    if run.report_paths:
        lines.append(f"{PREFIX} reports:")
        for path in run.report_paths:
            lines.append(f"  - {path}")
        if run.latest_directory:
            lines.append(f"{PREFIX} latest: {run.latest_directory}")

    policy = run.policy
    verdict_bits = [
        f"failure_threshold={policy.failure_threshold.value if policy.failure_threshold else 'none'}",
        f"fail_on_secrets={'true' if policy.fail_on_secrets else 'false'}",
    ]
    if policy.threshold_exceeded:
        detail = ", ".join(f"{k}={v}" for k, v in sorted(policy.failing_by_tool.items()))
        verdict_bits.append(_paint(f"threshold exceeded ({detail})", "fail", color))
    if policy.secrets_failed:
        verdict_bits.append(_paint(f"secrets found ({policy.secrets_found})", "fail", color))
    if policy.scanner_failures:
        verdict_bits.append(_paint(f"scanner failures ({', '.join(policy.scanner_failures)})", "fail", color))
    verdict = _paint("PASS", "ok", color) if policy.exit_code == 0 else _paint("FAIL", "fail", color)
    lines.append(f"{PREFIX} policy: {' '.join(verdict_bits)} -> {verdict}")
    lines.append(f"{PREFIX} exit_code={policy.exit_code}")
    return lines


def print_summary(run: ScanRun, options: ScanOptions, *, stream: TextIO | None = None) -> None:
    stream = stream or sys.stdout
    for line in summary_lines(run, options, color=_use_color(stream)):
        print(line, file=stream)


def _truncate(text: str, width: int) -> str:
    text = text.replace("\n", " ")
    return text if len(text) <= width else text[: width - 1] + "…"


def findings_table_lines(findings: list[Finding], *, color: bool = False) -> list[str]:
    if not findings:
        return [f"{PREFIX} no active findings"]
    rows = sorted(findings, key=lambda f: (list(SEVERITY_ORDER).index(f.severity), f.tool, f.rule_id, f.path, f.start_line))
    header = f"{'SEVERITY':<9} {'TOOL':<10} {'RULE / ID':<44} {'LOCATION':<48} FINGERPRINT"
    lines = [header, "-" * len(header)]
    for f in rows:
        sev = _paint(f"{f.severity.value:<9}", f.severity.value, color)
        lines.append(
            f"{sev} {f.tool:<10} {_truncate(f.rule_id, 44):<44} {_truncate(f.location, 48):<48} {f.primary_fingerprint}"
        )
    return lines


def findings_detail_lines(findings: list[Finding]) -> list[str]:
    lines: list[str] = []
    for f in sorted(findings, key=lambda f: (list(SEVERITY_ORDER).index(f.severity), f.tool, f.rule_id, f.path)):
        lines.append("######### Finding Details ##########")
        lines.append(f"Tool: {f.tool} ({f.category})")
        lines.append(f"Severity: {f.severity.value}" + (f" (tool: {f.original_severity})" if f.original_severity else ""))
        lines.append(f"Rule-ID: {f.rule_id}")
        if f.message:
            lines.append(f"Description: {_truncate(f.message, 500)}")
        if f.location:
            lines.append(f"Path: {f.location}")
        if f.package:
            fix = ", ".join(f.package.fix_versions) or "none"
            lines.append(f"Package: {f.package.name}@{f.package.version} ({f.package.type})  fix: {fix}")
        if f.location_status:
            lines.append(f"Location-Status: {f.location_status}")
        if f.references:
            lines.append(f"Reference: {f.references[0]}")
        if f.snippet:
            lines.append("---------- Finding Snippet ----------")
            lines.append(textwrap.indent(f.snippet.rstrip(), "    "))
        lines.append("---------- Fingerprints -------------")
        for key, value in f.fingerprints.items():
            lines.append(f"Fingerprint-{key.upper()}: {value}")
        lines.append("")
    return lines or [f"{PREFIX} no active findings"]


def print_findings(run: ScanRun, mode: str, *, stream: TextIO | None = None) -> None:
    stream = stream or sys.stdout
    findings = run.active_findings
    if mode == "full":
        for line in findings_detail_lines(findings):
            print(line, file=stream)
    else:
        for line in findings_table_lines(findings, color=_use_color(stream)):
            print(line, file=stream)
    print(file=stream)
