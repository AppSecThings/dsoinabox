import os
import json
import pytest
from pathlib import Path


def pytest_sessionfinish(session, exitstatus):
    """make pytest exit successfully when no tests collected"""
    if exitstatus == 5:  # no tests collected
        session.exitstatus = 0


@pytest.fixture(autouse=True)
def env_sanitized(monkeypatch):
    """sanitize env vars for consistent test execution
    
    sets TZ=UTC, scrubs CI env vars, fixes locale if needed
    """
    # set timezone to UTC
    monkeypatch.setenv("TZ", "UTC")
    
    # scrub CI env vars that might affect test behavior
    ci_vars = [
        "CI", "CONTINUOUS_INTEGRATION", "BUILD_NUMBER", "BUILD_ID",
        "JENKINS_URL", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI",
        "TRAVIS", "APPVEYOR", "TEAMCITY_VERSION", "BAMBOO_BUILDKEY",
        "GO_PIPELINE_NAME", "GO_STAGE_NAME", "GO_JOB_NAME",
        "SYSTEM_TEAMFOUNDATIONCOLLECTIONURI", "TF_BUILD",
        "BITBUCKET_BUILD_NUMBER", "CODEBUILD_BUILD_ID",
        "HEROKU_TEST_RUN_ID", "SEMAPHORE", "SHIPPABLE",
    ]
    for var in ci_vars:
        monkeypatch.delenv(var, raising=False)
    
    # fix locale for consistent output
    for var in ["LANG", "LC_ALL", "LC_CTYPE", "LC_NUMERIC", "LC_TIME"]:
        if var not in os.environ:
            monkeypatch.setenv(var, "C.UTF-8")


@pytest.fixture
def tmp_project(tmp_path):
    """temporary project directory for tests"""
    return tmp_path


@pytest.fixture
def golden_dir():
    """path to tests/fixtures directory"""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def fake_runner(golden_dir, monkeypatch):
    """monkeypatch run_cmd to return canned outputs from fixture files
    
    returns outputs from tests/fixtures/scanner_outputs/ based on first token
    of command (e.g. "opengrep", "trufflehog", "grype")
    
    returns (0, stdout_json, "") where stdout_json is JSON from fixture file
    """
    scanner_outputs_dir = golden_dir / "scanner_outputs"
    
    def _fake_run_cmd(cmd, *, cwd=None, env=None, timeout=None, text=True, check=False):
        """fake run_cmd that returns canned outputs"""
        if not cmd:
            if text:
                return (1, "", "Empty command")
            else:
                return (1, b"", b"Empty command")
        
        # extract first token (scanner name)
        scanner_name = cmd[0].lower()
        
        # handle git commands - return empty success
        if scanner_name == "git":
            if text:
                return (0, "", "")
            else:
                return (0, b"", b"")
        
        # handle opengrep specially - writes to file via --json-output
        if scanner_name == "opengrep" and "--json-output=" in " ".join(cmd):
            # extract output file path from command
            for arg in cmd:
                if arg.startswith("--json-output="):
                    output_file = arg.split("=", 1)[1]
                    # create file with results structure
                    output_dir = os.path.dirname(output_file)
                    if output_dir:
                        os.makedirs(output_dir, exist_ok=True)
                    fixture_path = scanner_outputs_dir / "opengrep.json"
                    if fixture_path.exists():
                        with open(fixture_path, "r") as f:
                            fixture_data = json.load(f)
                        with open(output_file, "w") as f:
                            json.dump(fixture_data, f)
                    else:
                        with open(output_file, "w") as f:
                            f.write('{"results": []}')
                    break
            if text:
                return (0, "", "")
            else:
                return (0, b"", b"")
        
        # handle checkov specially - writes SARIF files to directory
        if scanner_name == "checkov" and "--output-file-path" in " ".join(cmd):
            # extract output directory path from command
            cmd_str = " ".join(cmd)
            if "--output-file-path" in cmd_str:
                # find output directory path
                parts = cmd_str.split("--output-file-path")
                if len(parts) > 1:
                    output_dir = parts[1].strip().split()[0]
                    os.makedirs(output_dir, exist_ok=True)
                    # create SARIF file
                    sarif_file = os.path.join(output_dir, "results_sarif.sarif")
                    fixture_path = scanner_outputs_dir / "checkov.json"
                    if fixture_path.exists():
                        with open(fixture_path, "r") as f:
                            fixture_data = json.load(f)
                        # convert checkov JSON to SARIF if needed
                        sarif_data = {
                            "version": "2.1.0",
                            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                            "runs": []
                        }
                        with open(sarif_file, "w") as f:
                            json.dump(sarif_data, f)
                    else:
                        with open(sarif_file, "w") as f:
                            json.dump({
                                "version": "2.1.0",
                                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                                "runs": []
                            }, f)
            if text:
                return (0, "", "")
            else:
                return (0, b"", b"")
        
        # map scanner names to fixture files
        scanner_map = {
            "opengrep": "opengrep.json",
            "trufflehog": "trufflehog.json",
            "grype": "grype.json",
            "checkov": "checkov.json",
            "syft": "syft.json",
            "semgrep": "opengrep.json",  # semgrep uses opengrep format
            "bandit": "bandit.json",
            "trivy": "trivy.json",
        }
        
        fixture_file = scanner_map.get(scanner_name)
        if not fixture_file:
            # default: return empty success
            if text:
                return (0, "{}", "")
            else:
                return (0, b"{}", b"")
        
        fixture_path = scanner_outputs_dir / fixture_file
        if not fixture_path.exists():
            # if fixture doesn't exist, return empty success
            if text:
                return (0, "{}", "")
            else:
                return (0, b"{}", b"")
        
        # read and return fixture content
        with open(fixture_path, "r") as f:
            fixture_data = json.load(f)
        
        # trufflehog expects line-by-line JSON (one JSON object per line)
        if scanner_name == "trufflehog" and isinstance(fixture_data, list):
            stdout_json = "\n".join(json.dumps(item) for item in fixture_data)
        else:
            # return as single JSON string
            stdout_json = json.dumps(fixture_data)
        
        if text:
            return (0, stdout_json, "")
        else:
            return (0, stdout_json.encode(), b"")
    
    # monkeypatch run_cmd in all modules where it's imported
    # necessary because python creates local references on import
    import dsoinabox.utils.runner
    import dsoinabox.scanners.base
    import dsoinabox.utils.git
    import dsoinabox.reporting.trufflehog
    import dsoinabox.reporting.opengrep
    
    monkeypatch.setattr(dsoinabox.utils.runner, "run_cmd", _fake_run_cmd)
    monkeypatch.setattr(dsoinabox.scanners.base, "run_cmd", _fake_run_cmd)
    monkeypatch.setattr(dsoinabox.utils.git, "run_cmd", _fake_run_cmd)
    monkeypatch.setattr(dsoinabox.reporting.trufflehog, "run_cmd", _fake_run_cmd)
    monkeypatch.setattr(dsoinabox.reporting.opengrep, "run_cmd", _fake_run_cmd)
    
    # mock check_tool_available to always return True for tests
    # allows tests to run without requiring actual tools installed
    import dsoinabox.utils.environment
    import dsoinabox.cli
    monkeypatch.setattr(dsoinabox.utils.environment, "check_tool_available", lambda tool_name: True)
    monkeypatch.setattr(dsoinabox.cli, "check_tool_available", lambda tool_name: True)
    
    return _fake_run_cmd

