"""cli smoke tests for main flow"""

import json
import os
import subprocess

import pytest

from dsoinabox.cli import main


@pytest.mark.integration
def test_cli_scan_basic_flow(tmp_project, fake_runner, monkeypatch):
    """test basic cli scan flow with JSON output"""
    # create temporary source directory
    source_dir = tmp_project / "source"
    source_dir.mkdir()
    
    # create minimal file to scan
    (source_dir / "test.py").write_text("print('hello')\n")
    
    # run cli
    exit_code = main([
        "--source", str(source_dir),
        "--output", "json",
        "--report_directory", str(tmp_project / "reports"),
        "--show_findings", "False",
        "--project_id", "test-project",
    ])
    
    # assert exit code is 0
    assert exit_code == 0, f"Expected exit code 0, got {exit_code}"
    
    # find generated report file
    report_dir = tmp_project / "reports"
    assert report_dir.exists(), "Report directory should exist"
    
    # find JSON report file
    json_files = list(report_dir.rglob("dsoinabox_unified_report_*.json"))
    assert len(json_files) > 0, "Should generate at least one JSON report file"
    
    # parse and validate JSON
    report_file = json_files[0]
    with open(report_file, 'r') as f:
        report_data = json.load(f)
    
    # assert report structure
    assert "metadata" in report_data, "Report should have metadata"
    assert "scan_timestamp" in report_data["metadata"], "Metadata should have scan_timestamp"
    assert "git_repo_info" in report_data["metadata"], "Metadata should have git_repo_info"
    
    # assert consolidated findings exist (at least one scanner data key)
    scanner_data_keys = ["trufflehog_data", "opengrep_data", "syft_data", "grype_data", "checkov_data"]
    has_findings = any(
        report_data.get(key) is not None 
        for key in scanner_data_keys
    )
    assert has_findings, "Report should contain consolidated findings from at least one scanner"


@pytest.mark.integration
def test_cli_scan_with_specific_output_path(tmp_project, fake_runner, monkeypatch):
    """test cli scan with explicit output path"""
    source_dir = tmp_project / "source"
    source_dir.mkdir()
    (source_dir / "test.py").write_text("print('hello')\n")
    
    report_dir = tmp_project / "reports"
    
    exit_code = main([
        "--source", str(source_dir),
        "--output", "json",
        "--report_directory", str(report_dir),
        "--show_findings", "False",
        "--project_id", "test-project",
    ])
    
    assert exit_code == 0
    assert report_dir.exists()
    
    # verify JSON report was created
    json_files = list(report_dir.rglob("dsoinabox_unified_report_*.json"))
    assert len(json_files) > 0
    
    # verify JSON is valid
    with open(json_files[0], 'r') as f:
        data = json.load(f)
        assert isinstance(data, dict)
        assert "metadata" in data


@pytest.mark.integration
def test_cli_relative_report_directory_uses_invocation_directory(
    tmp_project, fake_runner, monkeypatch
):
    """Relative report paths resolve from the invocation directory, not the source."""
    invocation_dir = tmp_project / "invocation"
    invocation_dir.mkdir()
    source_dir = tmp_project / "source"
    source_dir.mkdir()
    (source_dir / "test.py").write_text("print('hello')\n")
    monkeypatch.chdir(invocation_dir)

    exit_code = main([
        "--source", str(source_dir),
        "--output", "json",
        "--report_directory", "reports",
        "--show_findings", "False",
        "--project_id", "test-project",
    ])

    assert exit_code == 0
    assert list(
        (invocation_dir / "reports").rglob("dsoinabox_unified_report_*.json")
    )
    assert not (source_dir / "reports").exists()


@pytest.mark.integration
def test_cli_scan_non_git_directory(tmp_project, fake_runner, monkeypatch):
    """test that scanning a non-git directory works correctly."""
    source_dir = tmp_project / "source"
    source_dir.mkdir()
    (source_dir / "test.py").write_text("print('hello')\n")
    # Note: source_dir is not a git repo, so is_git() will return False
    # and trufflehog will use filesystem mode
    
    exit_code = main([
        "--source", str(source_dir),
        "--output", "json",
        "--report_directory", str(tmp_project / "reports"),
        "--show_findings", "False",
        "--project_id", "test-project",
    ])
    
    assert exit_code == 0
    
    # Verify report was generated
    report_dir = tmp_project / "reports"
    json_files = list(report_dir.rglob("dsoinabox_unified_report_*.json"))
    assert len(json_files) > 0, "Should generate JSON report for non-git directory"

    with open(json_files[0], "r") as f:
        report_data = json.load(f)
    assert report_data["metadata"]["git_repo_info"] is None


@pytest.mark.integration
def test_cli_scan_ndjson_output(tmp_project, fake_runner, monkeypatch):
    """test basic cli scan flow with NDJSON output."""
    source_dir = tmp_project / "source"
    source_dir.mkdir()
    (source_dir / "test.py").write_text("print('hello')\n")

    exit_code = main([
        "--source", str(source_dir),
        "--output", "ndjson",
        "--report_directory", str(tmp_project / "reports"),
        "--show_findings", "False",
        "--project_id", "test-project",
    ])

    assert exit_code == 0

    report_dir = tmp_project / "reports"
    ndjson_files = list(report_dir.rglob("dsoinabox_unified_report_*.ndjson"))
    assert len(ndjson_files) > 0, "Should generate at least one NDJSON report file"

    with open(ndjson_files[0], "r") as f:
        lines = [line.strip() for line in f if line.strip()]

    assert len(lines) > 0, "NDJSON report should contain at least one line"
    first_line = json.loads(lines[0])
    assert first_line.get("type") == "metadata", "First NDJSON line should be metadata"


@pytest.mark.integration
def test_cli_does_not_run_git_config_global(tmp_project, monkeypatch):
    """Ensure CLI never executes git config --global during normal run."""
    source_dir = tmp_project / "source"
    source_dir.mkdir()
    (source_dir / "test.py").write_text("print('hello')\n")

    seen_commands: list[list[str]] = []

    def tracked_runner(cmd, *, cwd=None, env=None, timeout=None, text=True, check=False):
        seen_commands.append(list(cmd))
        if not cmd:
            return (1, "" if text else b"", "Empty command" if text else b"Empty command")
        if cmd[0] == "opengrep" and "--json-output=" in " ".join(cmd):
            for arg in cmd:
                if arg.startswith("--json-output="):
                    output_file = arg.split("=", 1)[1]
                    os.makedirs(os.path.dirname(output_file), exist_ok=True)
                    with open(output_file, "w") as f:
                        f.write('{"results": []}')
                    break
            return (0, "" if text else b"", "" if text else b"")
        if cmd[0] == "checkov" and "--output-file-path" in " ".join(cmd):
            cmd_str = " ".join(cmd)
            output_dir = cmd_str.split("--output-file-path", 1)[1].strip().split()[0]
            os.makedirs(output_dir, exist_ok=True)
            with open(os.path.join(output_dir, "results_sarif.sarif"), "w") as f:
                json.dump({"version": "2.1.0", "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", "runs": []}, f)
            return (0, "" if text else b"", "" if text else b"")
        return (0, "{}" if text else b"{}", "" if text else b"")

    def tracked_git_runner(args, *, repo_path=None, cwd=None, text=True, check=False):
        return tracked_runner(["git"] + list(args), cwd=cwd, text=text, check=check)

    import dsoinabox.cli
    import dsoinabox.reporting.opengrep
    import dsoinabox.reporting.trufflehog
    import dsoinabox.scanners.base
    import dsoinabox.utils.environment
    import dsoinabox.utils.git
    import dsoinabox.utils.project_id
    import dsoinabox.utils.runner

    monkeypatch.setattr(dsoinabox.utils.runner, "run_cmd", tracked_runner)
    monkeypatch.setattr(dsoinabox.scanners.base, "run_cmd", tracked_runner)
    monkeypatch.setattr(dsoinabox.utils.git, "run_cmd", tracked_runner)
    monkeypatch.setattr(dsoinabox.utils.project_id, "run_git_cmd", tracked_git_runner)
    monkeypatch.setattr(dsoinabox.reporting.trufflehog, "run_git_cmd", tracked_git_runner)
    monkeypatch.setattr(dsoinabox.reporting.opengrep, "run_git_cmd", tracked_git_runner)
    monkeypatch.setattr(dsoinabox.utils.environment, "check_tool_available", lambda tool_name: True)
    monkeypatch.setattr(dsoinabox.cli, "check_tool_available", lambda tool_name: True)

    exit_code = main([
        "--source", str(source_dir),
        "--output", "json",
        "--report_directory", str(tmp_project / "reports"),
        "--show_findings", "False",
        "--project_id", "test-project",
    ])

    assert exit_code == 0
    assert not any(
        len(cmd) >= 3 and cmd[0] == "git" and cmd[1] == "config" and cmd[2] == "--global"
        for cmd in seen_commands
    )


@pytest.mark.integration
def test_cli_git_repo_metadata_still_resolves(tmp_project, monkeypatch):
    """Git metadata and derived project ID should still work for git sources."""
    source_dir = tmp_project / "source"
    source_dir.mkdir()
    (source_dir / "test.py").write_text("print('hello')\n")

    subprocess.run(["git", "init"], cwd=source_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=source_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=source_dir, check=True)
    subprocess.run(["git", "remote", "add", "origin", "https://github.com/acme/repo.git"], cwd=source_dir, check=True, capture_output=True)
    subprocess.run(["git", "add", "test.py"], cwd=source_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=source_dir, check=True, capture_output=True)

    import dsoinabox.cli
    import dsoinabox.utils.environment

    monkeypatch.setattr(dsoinabox.utils.environment, "check_tool_available", lambda tool_name: True)
    monkeypatch.setattr(dsoinabox.cli, "check_tool_available", lambda tool_name: True)
    monkeypatch.setattr(dsoinabox.cli, "syft_dir_scan", lambda source, extra_args, out_dir: {"artifacts": []})

    exit_code = main([
        "--source", str(source_dir),
        "--tools", "syft",
        "--output", "json",
        "--report_directory", str(tmp_project / "reports"),
        "--show_findings", "False",
    ])

    assert exit_code == 0
    json_files = list((tmp_project / "reports").rglob("dsoinabox_unified_report_*.json"))
    assert len(json_files) > 0
    with open(json_files[0], "r") as f:
        report_data = json.load(f)

    git_repo_info = report_data["metadata"]["git_repo_info"]
    assert git_repo_info is not None
    assert git_repo_info["origin_url"] == "https://github.com/acme/repo"
    assert git_repo_info["last_commit_id"]
