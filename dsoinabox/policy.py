"""Policy gate: decides the exit code from normalized findings and scanner status.

Reports are never trimmed by the gate. ``report_threshold`` (a separate,
optional filter) controls what reports show.
"""

from __future__ import annotations

from .model import PolicyResult, ScanOptions, ScanRun, Severity, severity_at_or_above

EXIT_OK = 0
EXIT_POLICY = 1
EXIT_SCANNER = 2
EXIT_USAGE = 3


def evaluate(run: ScanRun, options: ScanOptions) -> PolicyResult:
    result = PolicyResult(
        failure_threshold=options.failure_threshold,
        fail_on_secrets=options.fail_on_secrets,
        report_threshold=options.report_threshold,
        fail_on=options.fail_on,
    )
    only_new = options.fail_on == "new" and options.baseline is not None
    threshold: Severity | None = options.failure_threshold
    failing: dict[str, int] = {}
    secrets = 0
    for scan in run.results:
        for finding in scan.active_findings:
            if only_new and finding.baseline_status == "known":
                continue
            if finding.category == "secret":
                secrets += 1
                continue
            if threshold is not None and severity_at_or_above(finding.severity, threshold):
                failing[scan.tool] = failing.get(scan.tool, 0) + 1
    result.failing_by_tool = failing
    result.threshold_exceeded = bool(failing)
    result.secrets_found = secrets
    result.secrets_failed = bool(options.fail_on_secrets and secrets)
    result.scanner_failures = [scan.tool for scan in run.results if scan.status == "failed"]

    if result.scanner_failures:
        result.exit_code = EXIT_SCANNER
    elif result.threshold_exceeded or result.secrets_failed:
        result.exit_code = EXIT_POLICY
    else:
        result.exit_code = EXIT_OK
    return result
