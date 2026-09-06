"""Policy gate (W3.4, W4.2)."""

from __future__ import annotations

from datetime import datetime, timezone

from dsoinabox.model import Finding, ScanOptions, ScanResult, ScanRun, Severity
from dsoinabox.policy import EXIT_OK, EXIT_POLICY, EXIT_SCANNER, evaluate


def _f(tool, category, sev, waived=False):
    return Finding(tool=tool, category=category, rule_id="r", severity=sev, waived=waived)


def _run(*results):
    return ScanRun(started_at=datetime(2026, 1, 1, tzinfo=timezone.utc), dsoinabox_version="t", timestamp="t",
                   project_id="p", source="/s", report_directory="/r", results=list(results))


def _opts(**kw):
    base = dict(source="/s", report_directory="/r", timestamp="t")
    base.update(kw)
    return ScanOptions(**base)


def test_no_threshold_passes_with_findings():
    run = _run(ScanResult(tool="opengrep", category="sast", findings=[_f("opengrep", "sast", Severity.critical)]))
    assert evaluate(run, _opts()).exit_code == EXIT_OK


def test_threshold_counts_only_active_findings_at_or_above():
    run = _run(ScanResult(tool="opengrep", category="sast", findings=[
        _f("opengrep", "sast", Severity.high), _f("opengrep", "sast", Severity.medium), _f("opengrep", "sast", Severity.critical, waived=True)]))
    p = evaluate(run, _opts(failure_threshold=Severity.high))
    assert p.exit_code == EXIT_POLICY and p.failing_by_tool == {"opengrep": 1}
    assert evaluate(run, _opts(failure_threshold=Severity.critical)).exit_code == EXIT_OK


def test_secrets_are_gated_by_fail_on_secrets_not_threshold():
    run = _run(ScanResult(tool="trufflehog", category="secret", findings=[_f("trufflehog", "secret", Severity.high)]))
    assert evaluate(run, _opts(failure_threshold=Severity.low)).exit_code == EXIT_OK
    p = evaluate(run, _opts(fail_on_secrets=True))
    assert p.exit_code == EXIT_POLICY and p.secrets_found == 1 and p.secrets_failed


def test_waived_secret_does_not_fail():
    run = _run(ScanResult(tool="trufflehog", category="secret", findings=[_f("trufflehog", "secret", Severity.high, waived=True)]))
    assert evaluate(run, _opts(fail_on_secrets=True)).exit_code == EXIT_OK


def test_scanner_failure_outranks_policy():
    run = _run(
        ScanResult(tool="grype", category="sca", status="failed", error="boom"),
        ScanResult(tool="opengrep", category="sast", findings=[_f("opengrep", "sast", Severity.critical)]),
    )
    p = evaluate(run, _opts(failure_threshold=Severity.low))
    assert p.exit_code == EXIT_SCANNER and p.scanner_failures == ["grype"] and p.threshold_exceeded


def test_unknown_severity_never_trips_gate():
    run = _run(ScanResult(tool="grype", category="sca", findings=[_f("grype", "sca", Severity.unknown)]))
    assert evaluate(run, _opts(failure_threshold=Severity.info)).exit_code == EXIT_OK
