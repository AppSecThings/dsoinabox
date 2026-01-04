"""integration tests for cli exit codes and error handling"""

from __future__ import annotations

import pytest
import os
import json
import yaml
from pathlib import Path
from unittest.mock import patch

from dsoinabox.cli import main


@pytest.mark.integration
class TestCLIExitCodes:
    """test cli exit codes for various scenarios"""
    
    def test_cli_exit_code_no_findings_passes(self, tmp_project, fake_runner, monkeypatch):
        """test that cli exits 0 when no findings above threshold"""
        source_dir = tmp_project / "source"
        source_dir.mkdir()
        (source_dir / "test.py").write_text("print('hello')\n")
        
        # ensure reports directory exists
        reports_dir = tmp_project / "reports"
        reports_dir.mkdir(exist_ok=True)
        
        # fake_runner fixture already patches run_cmd, but we need to override it
        # to return empty results. since modules import run_cmd directly, we need to
        # patch it at the module level where it's used
        def empty_runner(cmd, *, cwd=None, env=None, timeout=None, text=True, check=False):
            if not cmd:
                if text:
                    return (1, "", "")
                else:
                    return (1, b"", b"")
            # return empty JSON for scanner commands, empty string for git commands
            if cmd[0] == "git":
                if text:
                    return (0, "", "")
                else:
                    return (0, b"", b"")
            # handle opengrep specially - writes to file via --json-output
            if cmd[0] == "opengrep" and "--json-output=" in " ".join(cmd):
                # extract output file path from command
                for arg in cmd:
                    if arg.startswith("--json-output="):
                        output_file = arg.split("=", 1)[1]
                        # create file with empty results structure
                        os.makedirs(os.path.dirname(output_file), exist_ok=True)
                        with open(output_file, "w") as f:
                            f.write('{"results": []}')
                        break
            # handle checkov specially - writes SARIF files to directory
            if cmd[0] == "checkov" and "--output-file-path" in " ".join(cmd):
                # extract output directory path from command
                cmd_str = " ".join(cmd)
                if "--output-file-path" in cmd_str:
                    # find output directory path
                    parts = cmd_str.split("--output-file-path")
                    if len(parts) > 1:
                        output_dir = parts[1].strip().split()[0]
                        os.makedirs(output_dir, exist_ok=True)
                        # create empty SARIF file
                        sarif_file = os.path.join(output_dir, "results_sarif.sarif")
                        with open(sarif_file, "w") as f:
                            json.dump({"version": "2.1.0", "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", "runs": []}, f)
            # return empty JSON for all scanner commands
            if text:
                return (0, "{}", "")
            else:
                return (0, b"{}", b"")
        
        # patch at source module and all places where it's imported
        # necessary because python creates local references on import
        import dsoinabox.utils.runner
        import dsoinabox.scanners.base
        import dsoinabox.utils.git
        import dsoinabox.reporting.trufflehog
        import dsoinabox.reporting.opengrep
        
        monkeypatch.setattr(dsoinabox.utils.runner, "run_cmd", empty_runner)
        monkeypatch.setattr(dsoinabox.scanners.base, "run_cmd", empty_runner)
        monkeypatch.setattr(dsoinabox.utils.git, "run_cmd", empty_runner)
        monkeypatch.setattr(dsoinabox.reporting.trufflehog, "run_cmd", empty_runner)
        monkeypatch.setattr(dsoinabox.reporting.opengrep, "run_cmd", empty_runner)
        
        exit_code = main([
            "--source", str(source_dir),
            "--output", "json",
            "--report_directory", str(reports_dir),
            "--failure_threshold", "high",
            "--show_findings", "False",
            "--project_id", "test-project",
        ])
        
        assert exit_code == 0, "Should pass when no findings above threshold"
    
    def test_cli_exit_code_tool_failure_returns_1(self, tmp_project, monkeypatch):
        """test that cli exits 1 when tool subprocess fails"""
        source_dir = tmp_project / "source"
        source_dir.mkdir()
        (source_dir / "test.py").write_text("print('hello')\n")
        
        # mock run_cmd to simulate tool failure
        def failing_runner(cmd, *, cwd=None, env=None, timeout=None, text=True, check=False):
            if not cmd:
                if text:
                    return (1, "", "")
                else:
                    return (1, b"", b"")
            if cmd[0] in ["opengrep", "trufflehog", "grype", "checkov", "syft"]:
                if text:
                    return (1, "", "tool not found or failed")
                else:
                    return (1, b"", b"tool not found or failed")
            if text:
                return (0, "{}", "")
            else:
                return (0, b"{}", b"")
        
        # patch at source module and all places where it's imported
        import dsoinabox.utils.runner
        import dsoinabox.scanners.base
        import dsoinabox.utils.git
        import dsoinabox.reporting.trufflehog
        import dsoinabox.reporting.opengrep
        
        monkeypatch.setattr(dsoinabox.utils.runner, "run_cmd", failing_runner)
        monkeypatch.setattr(dsoinabox.scanners.base, "run_cmd", failing_runner)
        monkeypatch.setattr(dsoinabox.utils.git, "run_cmd", failing_runner)
        monkeypatch.setattr(dsoinabox.reporting.trufflehog, "run_cmd", failing_runner)
        monkeypatch.setattr(dsoinabox.reporting.opengrep, "run_cmd", failing_runner)
        
        exit_code = main([
            "--source", str(source_dir),
            "--output", "json",
            "--report_directory", str(tmp_project / "reports"),
            "--show_findings", "False",
            "--project_id", "test-project",
        ])
        
        assert exit_code == 1, "Should exit 1 when tool fails"
    
    def test_cli_exit_code_missing_source_returns_1(self, tmp_project, fake_runner):
        """test that cli exits 1 when source directory doesn't exist"""
        nonexistent_source = tmp_project / "nonexistent"
        
        exit_code = main([
            "--source", str(nonexistent_source),
            "--output", "json",
            "--report_directory", str(tmp_project / "reports"),
            "--show_findings", "False",
        ])
        
        assert exit_code == 1, "Should exit 1 when source directory doesn't exist"
    
    def test_cli_exit_code_invalid_waiver_returns_1(self, tmp_project, fake_runner):
        """test that cli exits 1 when waiver file is invalid"""
        source_dir = tmp_project / "source"
        source_dir.mkdir()
        (source_dir / "test.py").write_text("print('hello')\n")
        
        # create invalid waiver file (missing required fields)
        waiver_file = source_dir / "invalid_waivers.yaml"
        waiver_data = {
            "schema_version": "1.0",
            "finding_waivers": [
                {
                    # Missing fingerprint and type
                    "reason": "Invalid waiver"
                }
            ]
        }
        
        with open(waiver_file, 'w') as f:
            yaml.dump(waiver_data, f)
        
        exit_code = main([
            "--source", str(source_dir),
            "--output", "json",
            "--report_directory", str(tmp_project / "reports"),
            "--waiver_file", "invalid_waivers.yaml",
            "--show_findings", "False",
            "--project_id", "test-project",
        ])
        
        assert exit_code == 1, "Should exit 1 when waiver file is invalid"
    
    def test_cli_exit_code_nonexistent_waiver_file_returns_1(self, tmp_project, fake_runner):
        """test that cli exits 1 when specified waiver file doesn't exist"""
        source_dir = tmp_project / "source"
        source_dir.mkdir()
        (source_dir / "test.py").write_text("print('hello')\n")
        
        exit_code = main([
            "--source", str(source_dir),
            "--output", "json",
            "--report_directory", str(tmp_project / "reports"),
            "--waiver_file", "nonexistent_waivers.yaml",
            "--show_findings", "False",
            "--project_id", "test-project",
        ])
        
        assert exit_code == 1, "Should exit 1 when specified waiver file doesn't exist"
    
    def test_cli_exit_code_default_waiver_file_missing_ok(self, tmp_project, fake_runner):
        """test that cli exits 0 when default waiver file is missing (not specified)"""
        source_dir = tmp_project / "source"
        source_dir.mkdir()
        (source_dir / "test.py").write_text("print('hello')\n")
        
        exit_code = main([
            "--source", str(source_dir),
            "--output", "json",
            "--report_directory", str(tmp_project / "reports"),
            # No --waiver_file specified (uses default .dsoinabox_waivers.yaml)
            "--show_findings", "False",
            "--project_id", "test-project",
        ])
        
        # should succeed even if default waiver file doesn't exist
        assert exit_code == 0, "Should pass when default waiver file is missing"
    
    def test_cli_exit_code_threshold_exceeded_returns_1(self, tmp_project, fake_runner):
        """test that cli exits 1 when failure threshold is exceeded"""
        source_dir = tmp_project / "source"
        source_dir.mkdir()
        (source_dir / "test.py").write_text("print('hello')\n")
        
        exit_code = main([
            "--source", str(source_dir),
            "--output", "json",
            "--report_directory", str(tmp_project / "reports"),
            "--failure_threshold", "high",
            "--show_findings", "False",
            "--project_id", "test-project",
        ])
        
        # fixture data contains HIGH severity findings, so should fail
        assert exit_code == 1, "Should exit 1 when threshold exceeded"
    
    def test_cli_exit_code_fail_on_secrets_returns_1(self, tmp_project, fake_runner):
        """test that cli exits 1 when --fail_on_secrets and secrets are found"""
        source_dir = tmp_project / "source"
        source_dir.mkdir()
        (source_dir / "test.py").write_text("print('hello')\n")
        
        exit_code = main([
            "--source", str(source_dir),
            "--output", "json",
            "--report_directory", str(tmp_project / "reports"),
            "--fail_on_secrets",
            "--show_findings", "False",
            "--project_id", "test-project",
        ])
        
        # fixture data contains secrets, so should fail
        assert exit_code == 1, "Should exit 1 when secrets found and --fail_on_secrets is set"
    
    def test_cli_exit_code_fail_on_secrets_no_secrets_passes(self, tmp_project, monkeypatch):
        """test that cli exits 0 when --fail_on_secrets but no secrets found"""
        source_dir = tmp_project / "source"
        source_dir.mkdir()
        (source_dir / "test.py").write_text("print('hello')\n")
        
        # mock run_cmd to return empty trufflehog results
        def empty_trufflehog_runner(cmd, **kwargs):
            if not cmd:
                if kwargs.get("text", True):
                    return (1, "", "")
                else:
                    return (1, b"", b"")
            if cmd[0] == "trufflehog":
                if kwargs.get("text", True):
                    return (0, "[]", "")  # Empty list
                else:
                    return (0, b"[]", b"")
            if cmd[0] == "git":
                if kwargs.get("text", True):
                    return (0, "", "")
                else:
                    return (0, b"", b"")
            # Handle opengrep specially - it writes to a file via --json-output argument
            if cmd[0] == "opengrep" and "--json-output=" in " ".join(cmd):
                for arg in cmd:
                    if arg.startswith("--json-output="):
                        output_file = arg.split("=", 1)[1]
                        output_dir = os.path.dirname(output_file)
                        if output_dir:
                            os.makedirs(output_dir, exist_ok=True)
                        with open(output_file, "w") as f:
                            f.write('{"results": []}')
                        break
                if kwargs.get("text", True):
                    return (0, "", "")
                else:
                    return (0, b"", b"")
            # Handle checkov specially - it writes SARIF files to a directory
            if cmd[0] == "checkov" and "--output-file-path" in " ".join(cmd):
                cmd_str = " ".join(cmd)
                if "--output-file-path" in cmd_str:
                    parts = cmd_str.split("--output-file-path")
                    if len(parts) > 1:
                        output_dir = parts[1].strip().split()[0]
                        os.makedirs(output_dir, exist_ok=True)
                        sarif_file = os.path.join(output_dir, "results_sarif.sarif")
                        with open(sarif_file, "w") as f:
                            json.dump({
                                "version": "2.1.0",
                                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                                "runs": []
                            }, f)
                if kwargs.get("text", True):
                    return (0, "", "")
                else:
                    return (0, b"", b"")
            if kwargs.get("text", True):
                return (0, "{}", "")
            else:
                return (0, b"{}", b"")
        
        # patch at source module and all places where it's imported
        import dsoinabox.utils.runner
        import dsoinabox.scanners.base
        import dsoinabox.utils.git
        import dsoinabox.reporting.trufflehog
        import dsoinabox.reporting.opengrep
        
        monkeypatch.setattr(dsoinabox.utils.runner, "run_cmd", empty_trufflehog_runner)
        monkeypatch.setattr(dsoinabox.scanners.base, "run_cmd", empty_trufflehog_runner)
        monkeypatch.setattr(dsoinabox.utils.git, "run_cmd", empty_trufflehog_runner)
        monkeypatch.setattr(dsoinabox.reporting.trufflehog, "run_cmd", empty_trufflehog_runner)
        monkeypatch.setattr(dsoinabox.reporting.opengrep, "run_cmd", empty_trufflehog_runner)
        
        # mock check_tool_available to always return True for tests
        import dsoinabox.utils.environment
        import dsoinabox.cli
        monkeypatch.setattr(dsoinabox.utils.environment, "check_tool_available", lambda tool_name: True)
        monkeypatch.setattr(dsoinabox.cli, "check_tool_available", lambda tool_name: True)
        
        exit_code = main([
            "--source", str(source_dir),
            "--output", "json",
            "--report_directory", str(tmp_project / "reports"),
            "--fail_on_secrets",
            "--show_findings", "False",
            "--project_id", "test-project",
        ])
        
        assert exit_code == 0, "Should pass when no secrets found even with --fail_on_secrets"

