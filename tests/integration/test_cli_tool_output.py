"""CLI tests for --tool_output flag."""

import json
import pytest
from pathlib import Path

from dsoinabox.cli import main


@pytest.mark.integration
def test_cli_tool_output_default_false(tmp_project, fake_runner, monkeypatch):
    """Test that tools_output directory is deleted by default (--tool_output False)."""
    source_dir = tmp_project / "source"
    source_dir.mkdir()
    (source_dir / "test.py").write_text("print('hello')\n")
    
    exit_code = main([
        "--source", str(source_dir),
        "--output", "json",
        "--report_directory", str(tmp_project / "reports"),
        "--show_findings", "False",
        "--project_id", "test-project",
    ])
    
    assert exit_code == 0
    
    report_dir = tmp_project / "reports"
    # tools_output is in the timestamped subdirectory
    timestamped_dirs = [d for d in report_dir.iterdir() if d.is_dir() and d.name.startswith("dsoinabox_")]
    if timestamped_dirs:
        tools_output_dir = timestamped_dirs[0] / "tools_output"
        # tools_output directory should not exist (deleted after report generation)
        assert not tools_output_dir.exists(), "tools_output directory should be deleted when --tool_output is False"


@pytest.mark.integration
def test_cli_tool_output_true_preserves_files(tmp_project, fake_runner, monkeypatch):
    """Test that --tool_output True keeps tool output files."""
    source_dir = tmp_project / "source"
    source_dir.mkdir()
    (source_dir / "test.py").write_text("print('hello')\n")
    
    exit_code = main([
        "--source", str(source_dir),
        "--output", "json",
        "--report_directory", str(tmp_project / "reports"),
        "--tool_output",
        "--show_findings", "False",
        "--project_id", "test-project",
    ])
    
    assert exit_code == 0
    
    report_dir = tmp_project / "reports"
    # tools_output is in the timestamped subdirectory
    timestamped_dirs = [d for d in report_dir.iterdir() if d.is_dir() and d.name.startswith("dsoinabox_")]
    assert len(timestamped_dirs) > 0, "Should have timestamped report directory"
    tools_output_dir = timestamped_dirs[0] / "tools_output"
    
    # tools_output directory should exist
    assert tools_output_dir.exists(), "tools_output directory should exist when --tool_output is True"
    
    # Verify some tool output files exist (at least one scanner should have written a file)
    # The exact files depend on which tools ran, but we should have at least one
    tool_files = list(tools_output_dir.glob("*.json")) + list(tools_output_dir.glob("*.sarif"))
    assert len(tool_files) > 0, "Should have at least one tool output file in tools_output directory"


@pytest.mark.integration
def test_cli_tool_output_with_multi_output(tmp_project, fake_runner, monkeypatch):
    """Test that --tool_output works with multi-format output."""
    source_dir = tmp_project / "source"
    source_dir.mkdir()
    (source_dir / "test.py").write_text("print('hello')\n")
    
    exit_code = main([
        "--source", str(source_dir),
        "--output", "json,html,sarif",
        "--report_directory", str(tmp_project / "reports"),
        "--tool_output",
        "--show_findings", "False",
        "--project_id", "test-project",
    ])
    
    assert exit_code == 0
    
    report_dir = tmp_project / "reports"
    # tools_output is in the timestamped subdirectory
    timestamped_dirs = [d for d in report_dir.iterdir() if d.is_dir() and d.name.startswith("dsoinabox_")]
    assert len(timestamped_dirs) > 0, "Should have timestamped report directory"
    tools_output_dir = timestamped_dirs[0] / "tools_output"
    
    # tools_output directory should exist
    assert tools_output_dir.exists(), "tools_output directory should exist when --tool_output is True"
    
    # Verify reports were generated in main directory
    json_files = list(report_dir.rglob("dsoinabox_unified_report_*.json"))
    html_files = list(report_dir.rglob("dsoinabox_unified_report_*.html"))
    sarif_files = list(report_dir.rglob("dsoinabox_unified_report_*.sarif"))
    
    assert len(json_files) > 0, "Should generate JSON report"
    assert len(html_files) > 0, "Should generate HTML report"
    assert len(sarif_files) > 0, "Should generate SARIF report"
    
    # Verify tool outputs are in tools_output directory, not in main report directory
    tool_output_files = list(tools_output_dir.glob("*.json")) + list(tools_output_dir.glob("*.sarif"))
    assert len(tool_output_files) > 0, "Tool output files should be in tools_output directory"

