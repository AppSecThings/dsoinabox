"""integration tests for cli exit codes and error handling"""

from __future__ import annotations

import json
import os

import pytest
import yaml

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
        import dsoinabox.reporting.opengrep
        import dsoinabox.reporting.trufflehog
        import dsoinabox.scanners.base
        import dsoinabox.utils.git
        import dsoinabox.utils.project_id
        import dsoinabox.utils.runner
        
        monkeypatch.setattr(dsoinabox.utils.runner, "run_cmd", empty_runner)
        monkeypatch.setattr(dsoinabox.scanners.base, "run_cmd", empty_runner)
        monkeypatch.setattr(dsoinabox.utils.git, "run_cmd", empty_runner)
        monkeypatch.setattr(
            dsoinabox.utils.project_id,
            "run_git_cmd",
            lambda args, *, repo_path=None, cwd=None, text=True, check=False: empty_runner(
                ["git"] + list(args), cwd=cwd, text=text, check=check
            ),
        )
        monkeypatch.setattr(
            dsoinabox.reporting.trufflehog,
            "run_git_cmd",
            lambda args, *, repo_path=None, cwd=None, text=True, check=False: empty_runner(
                ["git"] + list(args), cwd=cwd, text=text, check=check
            ),
        )
        monkeypatch.setattr(
            dsoinabox.reporting.opengrep,
            "run_git_cmd",
            lambda args, *, repo_path=None, cwd=None, text=True, check=False: empty_runner(
                ["git"] + list(args), cwd=cwd, text=text, check=check
            ),
        )
        
        exit_code = main([
            "--source", str(source_dir),
            "--output", "json",
            "--report_directory", str(reports_dir),
            "--failure_threshold", "high",
            "--show_findings", "False",
            "--project_id", "test-project",
        ])
        
        assert exit_code == 0, "Should pass when no findings above threshold"
    
    def test_cli_exit_code_tool_failure_returns_2(self, tmp_project, monkeypatch):
        """test that cli exits 2 (scanner failure) when tool subprocess fails, after writing reports"""
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
        import dsoinabox.reporting.opengrep
        import dsoinabox.reporting.trufflehog
        import dsoinabox.scanners.base
        import dsoinabox.utils.git
        import dsoinabox.utils.project_id
        import dsoinabox.utils.runner
        
        monkeypatch.setattr(dsoinabox.utils.runner, "run_cmd", failing_runner)
        monkeypatch.setattr(dsoinabox.scanners.base, "run_cmd", failing_runner)
        monkeypatch.setattr(dsoinabox.utils.git, "run_cmd", failing_runner)
        monkeypatch.setattr(
            dsoinabox.utils.project_id,
            "run_git_cmd",
            lambda args, *, repo_path=None, cwd=None, text=True, check=False: failing_runner(
                ["git"] + list(args), cwd=cwd, text=text, check=check
            ),
        )
        monkeypatch.setattr(
            dsoinabox.reporting.trufflehog,
            "run_git_cmd",
            lambda args, *, repo_path=None, cwd=None, text=True, check=False: failing_runner(
                ["git"] + list(args), cwd=cwd, text=text, check=check
            ),
        )
        monkeypatch.setattr(
            dsoinabox.reporting.opengrep,
            "run_git_cmd",
            lambda args, *, repo_path=None, cwd=None, text=True, check=False: failing_runner(
                ["git"] + list(args), cwd=cwd, text=text, check=check
            ),
        )
        
        exit_code = main([
            "--source", str(source_dir),
            "--output", "json",
            "--report_directory", str(tmp_project / "reports"),
            "--show_findings", "False",
            "--project_id", "test-project",
        ])
        
        assert exit_code == 2, "Should exit 2 when a scanner fails"
        json_files = list((tmp_project / "reports").rglob("dsoinabox_unified_report_*.json"))
        assert json_files, "reports are still written when a scanner fails"
        meta = json.loads(json_files[0].read_text())["metadata"]
        assert meta["policy"]["scanner_failures"]
        assert all(s["status"] == "failed" for s in meta["scanners"])
    
    def test_cli_exit_code_missing_source_returns_3(self, tmp_project, fake_runner):
        """test that cli exits 1 when source directory doesn't exist"""
        nonexistent_source = tmp_project / "nonexistent"
        
        exit_code = main([
            "--source", str(nonexistent_source),
            "--output", "json",
            "--report_directory", str(tmp_project / "reports"),
            "--show_findings", "False",
        ])
        
        assert exit_code == 3, "Should exit 3 (usage) when source directory doesn't exist"
    
    def test_cli_exit_code_invalid_waiver_returns_3(self, tmp_project, fake_runner):
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
        
        assert exit_code == 3, "Should exit 3 (usage) when waiver file is invalid"
    
    def test_cli_exit_code_nonexistent_waiver_file_returns_3(self, tmp_project, fake_runner):
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
        
        assert exit_code == 3, "Should exit 3 (usage) when specified waiver file doesn't exist"
    
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
        import dsoinabox.reporting.opengrep
        import dsoinabox.reporting.trufflehog
        import dsoinabox.scanners.base
        import dsoinabox.utils.git
        import dsoinabox.utils.project_id
        import dsoinabox.utils.runner
        
        monkeypatch.setattr(dsoinabox.utils.runner, "run_cmd", empty_trufflehog_runner)
        monkeypatch.setattr(dsoinabox.scanners.base, "run_cmd", empty_trufflehog_runner)
        monkeypatch.setattr(dsoinabox.utils.git, "run_cmd", empty_trufflehog_runner)
        monkeypatch.setattr(
            dsoinabox.utils.project_id,
            "run_git_cmd",
            lambda args, *, repo_path=None, cwd=None, text=True, check=False: empty_trufflehog_runner(
                ["git"] + list(args), cwd=cwd, text=text, check=check
            ),
        )
        monkeypatch.setattr(
            dsoinabox.reporting.trufflehog,
            "run_git_cmd",
            lambda args, *, repo_path=None, cwd=None, text=True, check=False: empty_trufflehog_runner(
                ["git"] + list(args), cwd=cwd, text=text, check=check
            ),
        )
        monkeypatch.setattr(
            dsoinabox.reporting.opengrep,
            "run_git_cmd",
            lambda args, *, repo_path=None, cwd=None, text=True, check=False: empty_trufflehog_runner(
                ["git"] + list(args), cwd=cwd, text=text, check=check
            ),
        )
        
        # mock check_tool_available to always return True for tests
        import dsoinabox.cli
        import dsoinabox.utils.environment
        monkeypatch.setattr(dsoinabox.utils.environment, "check_tool_available", lambda tool_name: True)
        
        exit_code = main([
            "--source", str(source_dir),
            "--output", "json",
            "--report_directory", str(tmp_project / "reports"),
            "--fail_on_secrets",
            "--show_findings", "False",
            "--project_id", "test-project",
        ])
        
        assert exit_code == 0, "Should pass when no secrets found even with --fail_on_secrets"

    def test_cli_failure_threshold_gates_but_does_not_trim_reports(self, tmp_project, fake_runner, monkeypatch):
        """below-threshold findings never fail the gate; they stay in reports unless --report_threshold hides them"""
        source_dir = tmp_project / "source"
        source_dir.mkdir()
        (source_dir / "test.py").write_text("print('hello')\n")

        import dsoinabox.cli

        def opengrep_low_only(_source, _extra_args, _output_dir, **_kw):
            return {
                "results": [
                    {
                        "check_id": "test.rule.medium",
                        "path": "test.py",
                        "start": {"line": 1, "col": 1},
                        "end": {"line": 1, "col": 5},
                        "extra": {"severity": "MEDIUM", "message": "below threshold"},
                    }
                ]
            }

        def grype_low_only(_source, _extra_args, _output_dir, **_kw):
            return {
                "matches": [
                    {
                        "artifact": {
                            "name": "pkg",
                            "version": "1.0.0",
                            "type": "python",
                            "locations": [{"path": "requirements.txt"}],
                        },
                        "vulnerability": {
                            "id": "CVE-2024-0001",
                            "severity": "MEDIUM",
                            "namespace": "nvd",
                        },
                    }
                ],
                "source": {"type": "directory", "target": str(source_dir)},
            }

        import dsoinabox.scanners.sast.opengrep
        import dsoinabox.scanners.sca.grype
        monkeypatch.setattr(dsoinabox.scanners.sast.opengrep, "run_scan", opengrep_low_only)
        monkeypatch.setattr(dsoinabox.scanners.sca.grype, "run_scan", grype_low_only)

        exit_code = main([
            "--source", str(source_dir),
            "--output", "json",
            "--report_directory", str(tmp_project / "reports"),
            "--tools", "opengrep,grype",
            "--failure_threshold", "high",
            "--show_findings", "False",
            "--project_id", "test-project",
        ])

        assert exit_code == 0, "Should pass when all findings are below threshold"

        json_files = list((tmp_project / "reports").rglob("dsoinabox_unified_report_*.json"))
        assert json_files, "Unified JSON report should be generated"

        with open(json_files[0], "r") as f:
            report = json.load(f)

        # the gate ignores them, the report keeps them
        assert len(report["opengrep_data"]["results"]) == 1
        assert len(report["grype_data"]["matches"]) == 1
        assert report["metadata"]["hidden_by_report_threshold"] == 0
        assert report["metadata"]["policy"]["exit_code"] == 0

        # --report_threshold hides them from the report and says so
        exit_code = main([
            "--source", str(source_dir),
            "--output", "json",
            "--report_directory", str(tmp_project / "reports2"),
            "--tools", "opengrep,grype",
            "--failure_threshold", "high",
            "--report_threshold", "high",
            "--show_findings", "False",
            "--project_id", "test-project",
        ])
        assert exit_code == 0
        trimmed = json.loads(next((tmp_project / "reports2").rglob("dsoinabox_unified_report_*.json")).read_text())
        assert trimmed["opengrep_data"]["results"] == []
        assert trimmed["grype_data"]["matches"] == []
        assert trimmed["metadata"]["hidden_by_report_threshold"] == 2
