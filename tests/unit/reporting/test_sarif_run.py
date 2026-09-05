"""SARIF built from the normalized run (W6.2): schema-valid, faithful, GitHub-friendly."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from dsoinabox.model import Finding, Package, ScanResult, ScanRun, Severity
from dsoinabox.reporting.sarif_run import convert_run_to_sarif

SCHEMA = Path(__file__).resolve().parents[2] / "fixtures" / "schemas" / "sarif-schema-2.1.0.json"


def _run() -> ScanRun:
    findings = [
        Finding(tool="opengrep", category="sast", rule_id="py.dangerous", title="Dangerous call", message="os.system used",
                severity=Severity.high, original_severity="ERROR", path="src/app.py", start_line=7, end_line=9, snippet="os.system(x)",
                fingerprints={"rule": "og:1:RULE:py.dangerous:aaa", "exact": "og:1:EXACT:py.dangerous:bbb:1:2", "ctx": "og:1:CTX:py.dangerous:ccc:ddd"},
                references=["https://rules.example/py.dangerous"]),
        Finding(tool="opengrep", category="sast", rule_id="py.dangerous", message="again", severity=Severity.high, path="src/b.py", start_line=3,
                fingerprints={"rule": "og:1:RULE:py.dangerous:aaa"}, waived=True,
                waived_by={"kind": "finding_waiver", "ref": "finding_waivers[0]", "type": "false_positive", "reason": "sanitized upstream", "fingerprint": "og:1:RULE:py.dangerous:aaa"}),
        Finding(tool="grype", category="sca", rule_id="CVE-2024-1", title="CVE-2024-1 in requests@2.0", message="CVE-2024-1: bad", severity=Severity.critical,
                path="requirements.txt", paths=["requirements.txt"], package=Package(name="requests", version="2.0", type="python", fix_versions=["2.1"]),
                fingerprints={"pkg": "gy:1:PKG:CVE-2024-1:eee"}, baseline_status="new"),
        Finding(tool="trufflehog", category="secret", rule_id="AWS", title="AWS secret", message="AWS access key detected. Redacted: AKIA****",
                severity=Severity.high, path="config/secrets.yaml", start_line=5, snippet="should-not-appear", location_status="FOUND_EXACT",
                fingerprints={"secret": "th:1:SECRET:AWS:fff"}),
    ]
    run = ScanRun(
        started_at=datetime(2026, 9, 5, 10, 0, tzinfo=timezone.utc), finished_at=datetime(2026, 9, 5, 10, 5, tzinfo=timezone.utc),
        dsoinabox_version="1.0.0", timestamp="t", project_id="github.com/x/y", source="/scan_target", report_directory="/r",
        git_info={"origin_url": "https://github.com/x/y", "branch": "main", "last_commit_id": "abc123"},
        results=[
            ScanResult(tool="opengrep", category="sast", findings=findings[:2], tool_version="1.9.0", duration_s=2.5),
            ScanResult(tool="grype", category="sca", findings=[findings[2]], tool_version="0.80.0"),
            ScanResult(tool="trufflehog", category="secret", findings=[findings[3]], tool_version="3.88.0"),
            ScanResult(tool="checkov", category="iac", status="failed", error="checkov exited 2: boom", tool_version="3.2.0"),
            ScanResult(tool="syft", category="sbom", raw={"artifacts": []}),
        ],
    )
    return run


def test_validates_against_official_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA.read_text())
    jsonschema.validate(convert_run_to_sarif(_run()), schema)


def test_runs_tools_and_versions():
    sarif = convert_run_to_sarif(_run())
    drivers = {r["tool"]["driver"]["name"]: r["tool"]["driver"] for r in sarif["runs"]}
    assert set(drivers) == {"OpenGrep", "Grype", "TruffleHog", "Checkov"}  # syft has no findings run
    assert drivers["OpenGrep"]["version"] == "1.9.0" and drivers["OpenGrep"]["informationUri"].startswith("https://")
    ids = [r["automationDetails"]["id"] for r in sarif["runs"]]
    assert ids == ["dsoinabox/opengrep/", "dsoinabox/grype/", "dsoinabox/trufflehog/", "dsoinabox/checkov/"]


def test_invocations_reflect_failures():
    sarif = convert_run_to_sarif(_run())
    by = {r["tool"]["driver"]["name"]: r for r in sarif["runs"]}
    assert by["OpenGrep"]["invocations"][0]["executionSuccessful"] is True
    failed = by["Checkov"]["invocations"][0]
    assert failed["executionSuccessful"] is False
    assert "boom" in failed["toolExecutionNotifications"][0]["message"]["text"]
    assert by["Checkov"]["results"] == []


def test_results_rules_locations_and_fingerprints():
    sarif = convert_run_to_sarif(_run())
    og = next(r for r in sarif["runs"] if r["tool"]["driver"]["name"] == "OpenGrep")
    assert len(og["tool"]["driver"]["rules"]) == 1
    rule = og["tool"]["driver"]["rules"][0]
    assert rule["id"] == "py.dangerous" and rule["properties"]["security-severity"] == "8.0" and rule["helpUri"].startswith("https://")
    first = og["results"][0]
    assert first["ruleIndex"] == 0 and first["level"] == "error"
    loc = first["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"] == {"uri": "src/app.py", "uriBaseId": "%SRCROOT%"}
    assert loc["region"] == {"startLine": 7, "endLine": 9, "snippet": {"text": "os.system(x)"}}
    assert first["partialFingerprints"]["rule"] == "og:1:RULE:py.dangerous:aaa"
    assert first["partialFingerprints"]["primaryLocationLineHash"] == "og:1:RULE:py.dangerous:aaa"
    assert og["originalUriBaseIds"]["%SRCROOT%"]["uri"] == "file:///"
    assert og["versionControlProvenance"][0] == {"repositoryUri": "https://github.com/x/y", "revisionId": "abc123", "branch": "main"}


def test_waived_finding_is_suppressed_with_justification():
    sarif = convert_run_to_sarif(_run())
    og = next(r for r in sarif["runs"] if r["tool"]["driver"]["name"] == "OpenGrep")
    waived = og["results"][1]
    assert waived["suppressions"] == [{"kind": "external", "status": "accepted", "justification": "sanitized upstream"}]
    assert waived["properties"]["waived"] is True and waived["properties"]["waived_by"]["type"] == "false_positive"
    assert "suppressions" not in og["results"][0]


def test_secret_snippet_is_never_emitted():
    sarif = convert_run_to_sarif(_run())
    th = next(r for r in sarif["runs"] if r["tool"]["driver"]["name"] == "TruffleHog")
    assert "should-not-appear" not in json.dumps(th)
    assert th["results"][0]["properties"]["location_status"] == "FOUND_EXACT"


def test_grype_carries_package_and_baseline_status():
    sarif = convert_run_to_sarif(_run())
    gy = next(r for r in sarif["runs"] if r["tool"]["driver"]["name"] == "Grype")
    props = gy["results"][0]["properties"]
    assert props["package"]["name"] == "requests" and props["baseline_status"] == "new"
    assert gy["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "9.5"


def test_repo_without_remote_is_still_schema_valid():
    jsonschema = pytest.importorskip("jsonschema")
    run = _run()
    run.git_info = {"repo_name": "local", "origin_url": "", "branch": "main", "last_commit_id": "abc123"}
    sarif = convert_run_to_sarif(run)
    jsonschema.validate(sarif, json.loads(SCHEMA.read_text()))
    assert "versionControlProvenance" not in sarif["runs"][0]
    assert sarif["runs"][0]["properties"]["git"]["branch"] == "main"
