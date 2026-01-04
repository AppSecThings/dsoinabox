"""cli smoke tests for main flow"""

import json
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

