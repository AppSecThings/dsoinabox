"""Console summary and findings listing (W4.4)."""

from __future__ import annotations

from datetime import datetime, timezone

from dsoinabox.console import findings_detail_lines, findings_table_lines, summary_lines
from dsoinabox.model import Finding, Package, PolicyResult, ScanOptions, ScanResult, ScanRun, Severity


def _run():
    findings = [
        Finding(tool="opengrep", category="sast", rule_id="python.lang.security.audit.dangerous-system-call", severity=Severity.high,
                path="src/app.py", start_line=7, fingerprints={"rule": "og:1:RULE:x:abc"}, message="os.system", snippet="os.system(x)"),
        Finding(tool="opengrep", category="sast", rule_id="r2", severity=Severity.low, path="a.py", waived=True, fingerprints={"rule": "og:1:RULE:r2:a"}),
        Finding(tool="grype", category="sca", rule_id="CVE-2024-1", severity=Severity.critical, package=Package(name="requests", version="2.0", type="python", fix_versions=["2.1"]),
                fingerprints={"pkg": "gy:1:PKG:CVE-2024-1:abc"}),
    ]
    run = ScanRun(
        started_at=datetime(2026, 9, 5, tzinfo=timezone.utc), dsoinabox_version="1.0.0", timestamp="t", project_id="github.com/x/y",
        source="/scan_target", report_directory="/r",
        results=[
            ScanResult(tool="opengrep", category="sast", findings=findings[:2], duration_s=12.34, tool_version="1.9.0"),
            ScanResult(tool="grype", category="sca", findings=findings[2:], duration_s=3.0, tool_version="0.80"),
            ScanResult(tool="checkov", category="iac", status="failed", error="checkov exited 2\nstack...", duration_s=1.0),
        ],
        waiver_summary={"waived": 1, "waived_by_type": {"false_positive": 1}, "expired_matches": 1, "expiring_matches": 0,
                        "unused_count": 2, "unused": ["finding_waivers[1]", "benchmark[0]"], "schema_version": "1.0",
                        "deprecated_schema": True, "file": "/scan_target/.dsoinabox_waivers.yaml"},
        report_paths=["/r/report.html", "/r/report.sarif"],
        hidden_by_report_threshold=4,
    )
    run.policy = PolicyResult(failure_threshold=Severity.high, fail_on_secrets=True, report_threshold=Severity.low,
                              threshold_exceeded=True, failing_by_tool={"opengrep": 1, "grype": 1}, scanner_failures=["checkov"], exit_code=2)
    return run


def test_summary_block_has_every_advertised_line():
    run = _run()
    text = "\n".join(summary_lines(run, ScanOptions(source="/scan_target", report_directory="/r", timestamp="t", report_threshold=Severity.low)))
    assert "[dsoinabox] dsoinabox 1.0.0  project=github.com/x/y  source=/scan_target" in text
    assert "tools: opengrep 1.9.0 (12.3s), grype 0.80 (3.0s), checkov (FAILED)" in text
    assert "  checkov: checkov exited 2" in text
    assert "findings: critical=1 high=1 medium=0 low=0 info=0" in text  # waived low excluded
    assert "waived: 1 (false_positive=1)  expired=1  unused=2  schema=1.0 (deprecated" in text
    assert "hidden from reports by report_threshold=low: 4" in text
    assert "reports:\n  - /r/report.html\n  - /r/report.sarif" in text
    assert "policy: failure_threshold=high fail_on_secrets=true threshold exceeded (grype=1, opengrep=1) scanner failures (checkov) -> FAIL" in text
    assert text.endswith("[dsoinabox] exit_code=2")


def test_summary_passing_run_is_short():
    run = _run()
    run.results = run.results[:1]
    run.results[0].findings = []
    run.waiver_summary = None
    run.report_paths = []
    run.hidden_by_report_threshold = 0
    run.policy = PolicyResult()
    text = "\n".join(summary_lines(run, ScanOptions(source="/s", report_directory="/r", timestamp="t")))
    assert "-> PASS" in text and "waived:" not in text and "hidden" not in text and "exit_code=0" in text


def test_table_orders_by_severity_and_skips_nothing_it_is_given():
    run = _run()
    lines = findings_table_lines(run.active_findings)
    assert lines[0].startswith("SEVERITY")
    assert lines[2].startswith("critical") and "grype" in lines[2] and "gy:1:PKG:CVE-2024-1:abc" in lines[2]
    assert lines[3].startswith("high") and "src/app.py:7" in lines[3]
    assert len(lines) == 4  # header, rule, two active findings


def test_detail_lines_include_snippet_and_package():
    run = _run()
    text = "\n".join(findings_detail_lines(run.active_findings))
    assert "Package: requests@2.0 (python)  fix: 2.1" in text
    assert "    os.system(x)" in text
    assert "Fingerprint-RULE: og:1:RULE:x:abc" in text


def test_empty_table():
    assert findings_table_lines([]) == ["[dsoinabox] no active findings"]
