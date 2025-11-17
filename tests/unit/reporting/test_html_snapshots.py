"""Snapshot tests for HTML report generation."""

from __future__ import annotations

import pytest
import os
import re
from pathlib import Path
from syrupy import SnapshotAssertion

from dsoinabox.reporting.report_builder import report_builder
from dsoinabox.utils.deterministic import normalize_path


def normalize_html_for_snapshot(html_content: str) -> str:
    """Normalize HTML content for snapshot comparison.
    
    - Replace timestamps with <TIMESTAMP>
    - Normalize absolute paths to <ROOT>/...
    - Remove version-specific details if any
    """
    # Normalize timestamps (format: 2024_01_15T10_30_00 or ISO 8601)
    html_content = re.sub(
        r'\d{4}_\d{2}_\d{2}T\d{2}_\d{2}_\d{2}',
        '<TIMESTAMP>',
        html_content
    )
    html_content = re.sub(
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?',
        '<TIMESTAMP>',
        html_content
    )
    
    # Normalize absolute paths
    # Match common path patterns in HTML
    html_content = re.sub(
        r'/[A-Za-z0-9_\-/\\]+\.(py|json|yaml|yml|html)',
        lambda m: normalize_path(m.group(0)),
        html_content
    )
    
    # Normalize Windows paths if present
    html_content = re.sub(
        r'[A-Z]:\\[A-Za-z0-9_\-\\]+\.(py|json|yaml|yml|html)',
        lambda m: normalize_path(m.group(0)),
        html_content
    )
    
    return html_content


@pytest.fixture
def sample_findings_data(golden_dir):
    """Load sample findings from fixtures."""
    import json
    
    findings = {}
    
    # Load opengrep
    opengrep_path = golden_dir / "scanner_outputs" / "opengrep.json"
    if opengrep_path.exists():
        with open(opengrep_path) as f:
            findings["opengrep"] = json.load(f)
    
    # Load grype
    grype_path = golden_dir / "scanner_outputs" / "grype.json"
    if grype_path.exists():
        with open(grype_path) as f:
            findings["grype"] = json.load(f)
    
    # Load trufflehog
    trufflehog_path = golden_dir / "scanner_outputs" / "trufflehog.json"
    if trufflehog_path.exists():
        with open(trufflehog_path) as f:
            findings["trufflehog"] = json.load(f)
    
    # Load checkov
    checkov_path = golden_dir / "scanner_outputs" / "checkov.json"
    if checkov_path.exists():
        with open(checkov_path) as f:
            findings["checkov"] = json.load(f)
    
    return findings


@pytest.fixture
def sample_git_repo_info():
    """Sample git repository info."""
    return {
        "repo_name": "test-repo",
        "origin_url": "https://github.com/example/repo.git",
        "branch": "main",
        "last_commit_id": "abc123def456",
        "last_commit_date": "2025-01-15T12:00:00Z"
    }


class TestHTMLReportSnapshots:
    """Snapshot tests for HTML report generation."""
    
    def test_html_report_snapshot(
        self, tmp_project, sample_findings_data, sample_git_repo_info, snapshot: SnapshotAssertion
    ):
        """Snapshot test for HTML report format."""
        output_dir = str(tmp_project / "reports")
        os.makedirs(output_dir, exist_ok=True)
        
        report_builder(
            output_dir=output_dir,
            timestamp="2024_01_15T10_30_00",
            git_repo_info=sample_git_repo_info,
            data=(
                sample_findings_data.get("trufflehog"),
                sample_findings_data.get("opengrep"),
                None,  # syft_data
                sample_findings_data.get("grype"),
                sample_findings_data.get("checkov"),
            ),
            output_format="html"
        )
        
        # Find generated HTML file
        html_files = list(Path(output_dir).glob("*.html"))
        assert len(html_files) == 1
        
        with open(html_files[0], 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Normalize for snapshot
        normalized_html = normalize_html_for_snapshot(html_content)
        
        assert normalized_html == snapshot
    
    def test_jenkins_html_report_snapshot(
        self, tmp_project, sample_findings_data, sample_git_repo_info, snapshot: SnapshotAssertion
    ):
        """Snapshot test for Jenkins HTML report format."""
        output_dir = str(tmp_project / "reports")
        os.makedirs(output_dir, exist_ok=True)
        
        report_builder(
            output_dir=output_dir,
            timestamp="2024_01_15T10_30_00",
            git_repo_info=sample_git_repo_info,
            data=(
                sample_findings_data.get("trufflehog"),
                sample_findings_data.get("opengrep"),
                None,  # syft_data
                sample_findings_data.get("grype"),
                sample_findings_data.get("checkov"),
            ),
            output_format="jenkins_html"
        )
        
        # Find generated HTML file
        html_files = list(Path(output_dir).glob("*.html"))
        assert len(html_files) == 1
        
        with open(html_files[0], 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Normalize for snapshot
        normalized_html = normalize_html_for_snapshot(html_content)
        
        assert normalized_html == snapshot
    
    def test_html_report_empty_findings(self, tmp_project, sample_git_repo_info):
        """Test that HTML report handles empty findings gracefully."""
        output_dir = str(tmp_project / "reports")
        os.makedirs(output_dir, exist_ok=True)
        
        report_builder(
            output_dir=output_dir,
            timestamp="2024_01_15T10_30_00",
            git_repo_info=sample_git_repo_info,
            data=(
                None,  # trufflehog_data
                None,  # opengrep_data
                None,  # syft_data
                None,  # grype_data
                None,  # checkov_data
            ),
            output_format="html"
        )
        
        # Should generate HTML file without crashing
        html_files = list(Path(output_dir).glob("*.html"))
        assert len(html_files) == 1
        
        with open(html_files[0], 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Should contain some HTML structure
        assert "<html" in html_content.lower() or "<!doctype" in html_content.lower()
    
    def test_html_report_mixed_empty_findings(
        self, tmp_project, sample_findings_data, sample_git_repo_info
    ):
        """Test that HTML report handles mixed empty/non-empty findings."""
        output_dir = str(tmp_project / "reports")
        os.makedirs(output_dir, exist_ok=True)
        
        report_builder(
            output_dir=output_dir,
            timestamp="2024_01_15T10_30_00",
            git_repo_info=sample_git_repo_info,
            data=(
                sample_findings_data.get("trufflehog"),  # Has data
                None,  # opengrep_data empty
                None,  # syft_data empty
                sample_findings_data.get("grype"),  # Has data
                None,  # checkov_data empty
            ),
            output_format="html"
        )
        
        # Should generate HTML file without crashing
        html_files = list(Path(output_dir).glob("*.html"))
        assert len(html_files) == 1
        
        with open(html_files[0], 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Should contain some HTML structure
        assert "<html" in html_content.lower() or "<!doctype" in html_content.lower()

