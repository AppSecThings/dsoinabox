"""SARIF 2.1.0 output built from a normalized ``ScanRun``.

One ``run`` per scanner. Compared with the legacy raw-dict formatter this adds
real tool versions, ``invocations`` (including failures), ``suppressions`` with
the waiver reason, ``security-severity`` on rules, repo-relative URIs anchored
at ``%SRCROOT%``, ``automationDetails`` so several uploads do not collide, and a
stable ``partialFingerprints`` set for alert de-duplication.
"""

from __future__ import annotations

from typing import Any

from ..model import Finding, ScanResult, ScanRun, Severity

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

TOOL_INFO: dict[str, dict[str, str]] = {
    "trufflehog": {"name": "TruffleHog", "informationUri": "https://github.com/trufflesecurity/trufflehog"},
    "opengrep": {"name": "OpenGrep", "informationUri": "https://github.com/opengrep/opengrep"},
    "grype": {"name": "Grype", "informationUri": "https://github.com/anchore/grype"},
    "checkov": {"name": "Checkov", "informationUri": "https://github.com/bridgecrewio/checkov"},
    "syft": {"name": "Syft", "informationUri": "https://github.com/anchore/syft"},
}

_LEVEL = {
    Severity.critical: "error",
    Severity.high: "error",
    Severity.medium: "warning",
    Severity.low: "note",
    Severity.info: "note",
    Severity.unknown: "warning",
}
# GitHub reads security-severity as a CVSS-like score to bucket alerts
_SECURITY_SEVERITY = {
    Severity.critical: "9.5",
    Severity.high: "8.0",
    Severity.medium: "5.5",
    Severity.low: "3.0",
    Severity.info: "1.0",
    Severity.unknown: "5.5",
}


def _text(value: str, limit: int = 1000) -> str:
    value = (value or "").strip()
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _rule(finding: Finding) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": finding.rule_id,
        "name": finding.rule_id,
        "shortDescription": {"text": _text(finding.title or finding.rule_id, 200)},
        "defaultConfiguration": {"level": _LEVEL[finding.severity]},
        "properties": {
            "security-severity": _SECURITY_SEVERITY[finding.severity],
            "tags": ["security", finding.category],
        },
    }
    if finding.message:
        rule["fullDescription"] = {"text": _text(finding.message)}
    if finding.references:
        rule["helpUri"] = finding.references[0]
    return rule


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL[finding.severity],
        "message": {"text": _text(finding.message or finding.title or f"Finding from {finding.tool}")},
    }
    if finding.path:
        region: dict[str, Any] = {}
        if finding.start_line > 0:
            region["startLine"] = finding.start_line
            if finding.end_line > finding.start_line:
                region["endLine"] = finding.end_line
        if finding.snippet and finding.category != "secret":
            region["snippet"] = {"text": _text(finding.snippet, 500)}
        location: dict[str, Any] = {
            "physicalLocation": {"artifactLocation": {"uri": finding.path, "uriBaseId": "%SRCROOT%"}},
        }
        if region:
            location["physicalLocation"]["region"] = region
        result["locations"] = [location]

    partial = {k: v for k, v in finding.fingerprints.items() if v}
    if partial:
        # a stable key GitHub prefers for de-duplication across line moves
        primary = finding.primary_fingerprint
        if primary:
            partial.setdefault("primaryLocationLineHash", primary)
        result["partialFingerprints"] = partial

    if finding.waived and finding.waived_by:
        justification = finding.waived_by.get("reason") or finding.waived_by.get("type") or "waived"
        result["suppressions"] = [{
            "kind": "external",
            "status": "accepted",
            "justification": _text(str(justification), 500),
        }]

    properties: dict[str, Any] = {
        "tool": finding.tool,
        "category": finding.category,
        "severity": finding.severity.value,
    }
    if finding.original_severity:
        properties["original_severity"] = finding.original_severity
    if finding.waived:
        properties["waived"] = True
        properties["waived_by"] = finding.waived_by
    if finding.expired_waivers:
        properties["expired_waivers"] = finding.expired_waivers
    if finding.baseline_status:
        properties["baseline_status"] = finding.baseline_status
    if finding.package:
        properties["package"] = finding.package.model_dump()
    if finding.location_status:
        properties["location_status"] = finding.location_status
    if finding.legacy_fingerprints:
        properties["legacy_fingerprints"] = finding.legacy_fingerprints
    result["properties"] = properties
    return result


def _invocation(scan: ScanResult, run: ScanRun) -> dict[str, Any]:
    inv: dict[str, Any] = {
        "executionSuccessful": scan.status == "ok",
        "startTimeUtc": run.started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if run.finished_at:
        inv["endTimeUtc"] = run.finished_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    if scan.status != "ok":
        inv["toolExecutionNotifications"] = [{
            "level": "error",
            "message": {"text": _text(scan.error or scan.status)},
        }]
    return inv


def _sarif_run(scan: ScanResult, run: ScanRun) -> dict[str, Any]:
    info = TOOL_INFO.get(scan.tool, {"name": scan.tool})
    driver: dict[str, Any] = {"name": info["name"]}
    if scan.tool_version:
        driver["version"] = scan.tool_version
    if info.get("informationUri"):
        driver["informationUri"] = info["informationUri"]

    rules: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    for finding in scan.findings:
        if finding.rule_id not in index:
            index[finding.rule_id] = len(rules)
            rules.append(_rule(finding))
        results.append(_result(finding, index[finding.rule_id]))
    if rules:
        driver["rules"] = rules

    sarif_run: dict[str, Any] = {
        "tool": {"driver": driver},
        "automationDetails": {"id": f"dsoinabox/{scan.tool}/"},
        "invocations": [_invocation(scan, run)],
        "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///", "description": {"text": "repository root (--source)"}}},
        "results": results,
        "properties": {
            "dsoinabox_version": run.dsoinabox_version,
            "project_id": run.project_id,
            "status": scan.status,
            "duration_s": round(scan.duration_s, 3),
        },
    }
    if run.git_info and run.git_info.get("origin_url"):
        # SARIF requires repositoryUri; a repository without a remote gets no provenance block
        vc: dict[str, Any] = {"repositoryUri": run.git_info["origin_url"]}
        if run.git_info.get("last_commit_id"):
            vc["revisionId"] = run.git_info["last_commit_id"]
        if run.git_info.get("branch"):
            vc["branch"] = run.git_info["branch"]
        sarif_run["versionControlProvenance"] = [vc]
    elif run.git_info and (run.git_info.get("last_commit_id") or run.git_info.get("branch")):
        sarif_run["properties"]["git"] = {k: v for k, v in run.git_info.items() if v}
    return sarif_run


def convert_run_to_sarif(run: ScanRun) -> dict[str, Any]:
    runs = [_sarif_run(scan, run) for scan in run.results if scan.category != "sbom"]
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": runs}
