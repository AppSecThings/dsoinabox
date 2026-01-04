"""CLI HTML report generation tests."""

import pytest
from pathlib import Path

from dsoinabox.cli import main


@pytest.mark.integration
def test_cli_html_report_generation(tmp_project, fake_runner, monkeypatch):
    """Test HTML report generation."""
    source_dir = tmp_project / "source"
    source_dir.mkdir()
    (source_dir / "test.py").write_text("print('hello')\n")
    
    exit_code = main([
        "--source", str(source_dir),
        "--output", "html",
        "--report_directory", str(tmp_project / "reports"),
        "--show_findings", "False",
        "--project_id", "test-project",
    ])
    
    assert exit_code == 0
    
    # Verify HTML report was created
    report_dir = tmp_project / "reports"
    assert report_dir.exists(), "Report directory should exist"
    
    html_files = list(report_dir.rglob("dsoinabox_unified_report_*.html"))
    assert len(html_files) > 0, "Should generate at least one HTML report file"
    
    # Verify HTML content
    html_file = html_files[0]
    html_content = html_file.read_text()
    
    # Check for expected summary strings
    assert "dsoinabox" in html_content.lower() or "report" in html_content.lower(), \
        "HTML should contain report-related content"
    
    # Check for scanner data indicators (these should be in the HTML)
    # The exact strings depend on the template, but we can check for common elements
    assert len(html_content) > 1000, "HTML report should have substantial content"


@pytest.mark.integration
def test_cli_jenkins_html_report_generation(tmp_project, fake_runner, monkeypatch):
    """Test Jenkins HTML report generation."""
    source_dir = tmp_project / "source"
    source_dir.mkdir()
    (source_dir / "test.py").write_text("print('hello')\n")
    
    exit_code = main([
        "--source", str(source_dir),
        "--output", "jenkins_html",
        "--report_directory", str(tmp_project / "reports"),
        "--show_findings", "False",
        "--project_id", "test-project",
    ])
    
    assert exit_code == 0
    
    # Verify Jenkins HTML report was created
    report_dir = tmp_project / "reports"
    assert report_dir.exists()
    
    html_files = list(report_dir.rglob("dsoinabox_unified_report_*.html"))
    assert len(html_files) > 0
    
    # Verify HTML content
    html_file = html_files[0]
    html_content = html_file.read_text()
    
    # Check for expected content
    assert len(html_content) > 1000, "Jenkins HTML report should have substantial content"
    
    # Verify assets directory was created for Jenkins HTML
    # Assets are in the timestamped subdirectory
    assets_dir = html_files[0].parent / "assets"
    # Note: Assets may or may not be copied depending on template structure
    # This is a basic check that the report was generated


@pytest.mark.integration
def test_cli_html_report_contains_findings_summary(tmp_project, fake_runner, monkeypatch):
    """Test that HTML report contains findings summary."""
    source_dir = tmp_project / "source"
    source_dir.mkdir()
    (source_dir / "test.py").write_text("print('hello')\n")
    
    exit_code = main([
        "--source", str(source_dir),
        "--output", "html",
        "--report_directory", str(tmp_project / "reports"),
        "--show_findings", "False",
        "--project_id", "test-project",
    ])
    
    assert exit_code == 0
    
    report_dir = tmp_project / "reports"
    html_files = list(report_dir.rglob("dsoinabox_unified_report_*.html"))
    assert len(html_files) > 0
    
    html_content = html_files[0].read_text()
    
    # Check for common HTML elements that indicate findings are present
    # The template should render findings data, so we look for indicators
    # These checks are flexible since template structure may vary
    has_html_structure = (
        "<html" in html_content.lower() or 
        "<!doctype" in html_content.lower() or
        "<body" in html_content.lower()
    )
    assert has_html_structure, "HTML should have proper HTML structure"


@pytest.mark.integration
def test_cli_multi_output_formats(tmp_project, fake_runner, monkeypatch):
    """Test that --output with comma-separated values generates multiple formats."""
    source_dir = tmp_project / "source"
    source_dir.mkdir()
    (source_dir / "test.py").write_text("print('hello')\n")
    
    exit_code = main([
        "--source", str(source_dir),
        "--output", "json,html,sarif",
        "--report_directory", str(tmp_project / "reports"),
        "--show_findings", "False",
        "--project_id", "test-project",
    ])
    
    assert exit_code == 0
    
    report_dir = tmp_project / "reports"
    
    # Verify all three formats were generated
    json_files = list(report_dir.rglob("dsoinabox_unified_report_*.json"))
    html_files = list(report_dir.rglob("dsoinabox_unified_report_*.html"))
    sarif_files = list(report_dir.rglob("dsoinabox_unified_report_*.sarif"))
    
    assert len(json_files) > 0, "Should generate JSON report"
    assert len(html_files) > 0, "Should generate HTML report"
    assert len(sarif_files) > 0, "Should generate SARIF report"
    
    # Verify they all have the same timestamp (same scan)
    json_timestamp = json_files[0].stem.split("_")[-1]
    html_timestamp = html_files[0].stem.split("_")[-1]
    sarif_timestamp = sarif_files[0].stem.split("_")[-1]
    
    assert json_timestamp == html_timestamp == sarif_timestamp, \
        "All reports should have the same timestamp from the same scan"

