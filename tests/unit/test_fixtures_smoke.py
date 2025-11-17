"""smoke test to verify fixtures and fake_runner work correctly"""

import json
from dsoinabox.utils import runner


def test_fake_runner_opengrep(fake_runner):
    """test that fake_runner returns opengrep JSON output"""
    returncode, stdout, stderr = runner.run_cmd(["opengrep", "scan", "--json-output", "reports/opengrep.json", "src"])
    
    assert returncode == 0
    assert stderr == ""
    
    # parse JSON output
    data = json.loads(stdout)
    
    # verify it's opengrep format
    assert "results" in data
    assert isinstance(data["results"], list)
    
    # verify we have some findings
    assert len(data["results"]) > 0
    
    # verify findings have expected structure
    for result in data["results"]:
        assert "check_id" in result or "rule_id" in result
        assert "path" in result
        assert "extra" in result
        # severity should be in extra dict
        assert "severity" in result.get("extra", {})
    
    # verify we have findings with different severities
    severities = [r.get("extra", {}).get("severity", "").upper() for r in data["results"]]
    assert "HIGH" in severities or "ERROR" in severities
    assert "MEDIUM" in severities or "WARNING" in severities
    assert "LOW" in severities or "INFO" in severities


def test_fake_runner_trufflehog(fake_runner):
    """test that fake_runner returns trufflehog JSON output (line-by-line)"""
    returncode, stdout, stderr = runner.run_cmd(["trufflehog", "git", "file:///path/to/repo", "--no-verification", "-j"])
    
    assert returncode == 0
    assert stderr == ""
    
    # trufflehog returns line-by-line JSON
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    assert len(lines) > 0
    
    # parse each line as JSON
    findings = []
    for line in lines:
        finding = json.loads(line)
        findings.append(finding)
    
    # verify findings structure
    assert len(findings) > 0
    for finding in findings:
        assert "DetectorName" in finding
        assert "Raw" in finding or "RawV2" in finding
        assert "SourceMetadata" in finding


def test_fake_runner_grype(fake_runner):
    """test that fake_runner returns grype JSON output"""
    returncode, stdout, stderr = runner.run_cmd(["grype", "dir:/path/to/project", "-o", "json"])
    
    assert returncode == 0
    assert stderr == ""
    
    # parse JSON output
    data = json.loads(stdout)
    
    # verify it's grype format
    assert "matches" in data
    assert isinstance(data["matches"], list)
    
    # verify we have some matches
    assert len(data["matches"]) > 0
    
    # verify matches have expected structure
    for match in data["matches"]:
        assert "vulnerability" in match
        assert "artifact" in match
        vuln = match["vulnerability"]
        assert "id" in vuln
        assert "severity" in vuln
    
    # verify we have different severity levels
    severities = [m["vulnerability"]["severity"] for m in data["matches"]]
    assert "CRITICAL" in severities
    assert "HIGH" in severities
    assert "MEDIUM" in severities


def test_fake_runner_unknown_scanner(fake_runner):
    """test that fake_runner returns empty JSON for unknown scanners"""
    returncode, stdout, stderr = runner.run_cmd(["unknown-tool", "arg1", "arg2"])
    
    assert returncode == 0
    assert stderr == ""
    assert stdout == "{}"

