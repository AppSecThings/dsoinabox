"""Unit tests for HTML template rendering."""

import json
import os
import re
import pytest
from pathlib import Path
from syrupy import SnapshotAssertion
from jinja2 import Environment, FileSystemLoader

from dsoinabox.reporting.report_builder import report_builder
from dsoinabox.utils.deterministic import normalize_path


def normalize_html_output(html: str) -> str:
    """Normalize HTML output for snapshot testing.
    
    Removes or normalizes:
    - Timestamps
    - Versions
    - Machine-specific paths
    - Random IDs or hashes
    """
    # Normalize timestamps (ISO format, date format, etc.)
    html = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[.\d]*Z?', '<TIMESTAMP>', html)
    html = re.sub(r'\d{4}_\d{2}_\d{2}T\d{2}_\d{2}_\d{2}', '<TIMESTAMP>', html)
    html = re.sub(r'\d{4}-\d{2}-\d{2}', '<DATE>', html)
    
    # Normalize absolute paths - paths should already be normalized by report_builder
    # to <ROOT>/... format, so we just need to replace that pattern
    html = re.sub(r'<ROOT>[^\s<>"\']+', '<PATH>', html)
    # Also handle any remaining absolute paths that weren't normalized
    html = re.sub(r'/[^\s<>"\']+\.(py|js|ts|yaml|yml|json|tf|md|txt|html)', '<PATH>', html)
    html = re.sub(r'[A-Z]:\\[^\s<>"\']+', '<PATH>', html)  # Windows paths
    
    # Normalize version numbers in text (but keep in data attributes if needed)
    # Match version patterns like "v1.2.3" or "1.2.3"
    html = re.sub(r'\bv?\d+\.\d+\.\d+[-\w]*\b', '<VERSION>', html)
    
    # Normalize commit hashes
    html = re.sub(r'\b[0-9a-f]{7,40}\b', '<HASH>', html)
    
    # Normalize file sizes or other numeric patterns that might vary
    # (be careful not to remove line numbers)
    
    # Remove whitespace differences (normalize to single spaces, but preserve structure)
    html = re.sub(r' +', ' ', html)
    html = re.sub(r'\n\s*\n\s*\n+', '\n\n', html)
    
    return html


def create_normalization_filter(env: Environment):
    """Add a Jinja filter to normalize values in templates."""
    def normalize_value(value):
        """Normalize a value for template rendering."""
        if isinstance(value, str):
            # Normalize timestamps
            if re.match(r'^\d{4}-\d{2}-\d{2}', value) or re.match(r'^\d{4}_\d{2}_\d{2}', value):
                return '<TIMESTAMP>'
            # Normalize absolute paths
            if os.path.isabs(value):
                return os.path.basename(value) or '<PATH>'
        return value
    
    env.filters['normalize'] = normalize_value
    return env


@pytest.fixture
def sample_normalized_findings(golden_dir):
    """Load sample normalized findings from fixtures."""
    findings = {}
    
    # Load opengrep data
    opengrep_path = golden_dir / "scanner_outputs" / "opengrep.json"
    if opengrep_path.exists():
        with open(opengrep_path) as f:
            findings["opengrep"] = json.load(f)
    else:
        findings["opengrep"] = None
    
    # Load grype data
    grype_path = golden_dir / "scanner_outputs" / "grype.json"
    if grype_path.exists():
        with open(grype_path) as f:
            findings["grype"] = json.load(f)
    else:
        findings["grype"] = None
    
    # Load trufflehog data
    trufflehog_path = golden_dir / "scanner_outputs" / "trufflehog.json"
    if trufflehog_path.exists():
        with open(trufflehog_path) as f:
            findings["trufflehog"] = json.load(f)
    else:
        findings["trufflehog"] = None
    
    # Load checkov data
    checkov_path = golden_dir / "scanner_outputs" / "checkov.json"
    if checkov_path.exists():
        with open(checkov_path) as f:
            findings["checkov"] = json.load(f)
    else:
        findings["checkov"] = None
    
    # Load syft data if available
    syft_path = golden_dir / "scanner_outputs" / "syft.json"
    if syft_path.exists():
        with open(syft_path) as f:
            findings["syft"] = json.load(f)
    else:
        findings["syft"] = None
    
    return findings


@pytest.fixture
def sample_git_repo_info():
    """Sample git repository info."""
    return {
        "remote_url": "https://github.com/example/repo.git",
        "branch": "main",
        "commit": "abc123def456",
        "commit_message": "Test commit"
    }


class TestHTMLTemplateRendering:
    """Test HTML template rendering."""
    
    def test_unified_report_html_renders(
        self, tmp_project, sample_normalized_findings, sample_git_repo_info
    ):
        """Test that unified HTML report renders without errors."""
        output_dir = str(tmp_project / "reports")
        os.makedirs(output_dir, exist_ok=True)
        
        report_builder(
            output_dir=output_dir,
            timestamp="2024_01_15T10_30_00",
            git_repo_info=sample_git_repo_info,
            data=(
                sample_normalized_findings.get("trufflehog"),
                sample_normalized_findings.get("opengrep"),
                sample_normalized_findings.get("syft"),
                sample_normalized_findings.get("grype"),
                sample_normalized_findings.get("checkov"),
            ),
            output_format="html"
        )
        
        report_files = list(Path(output_dir).glob("*.html"))
        assert len(report_files) == 1
        
        # Check that HTML is valid (contains expected structure)
        html_content = report_files[0].read_text()
        assert "<!DOCTYPE html>" in html_content or "<html" in html_content
        assert "</html>" in html_content
    
    def test_unified_report_html_snapshot(
        self, tmp_project, sample_normalized_findings, sample_git_repo_info, snapshot: SnapshotAssertion
    ):
        """Snapshot test for unified HTML report."""
        output_dir = str(tmp_project / "reports")
        os.makedirs(output_dir, exist_ok=True)
        
        report_builder(
            output_dir=output_dir,
            timestamp="2024_01_15T10_30_00",
            git_repo_info=sample_git_repo_info,
            data=(
                sample_normalized_findings.get("trufflehog"),
                sample_normalized_findings.get("opengrep"),
                sample_normalized_findings.get("syft"),
                sample_normalized_findings.get("grype"),
                sample_normalized_findings.get("checkov"),
            ),
            output_format="html"
        )
        
        report_files = list(Path(output_dir).glob("*.html"))
        assert len(report_files) == 1
        
        html_content = report_files[0].read_text()
        normalized = normalize_html_output(html_content)
        
        assert normalized == snapshot
    
    def test_unified_report_html_includes_waiver_data(
        self, tmp_project, sample_normalized_findings, sample_git_repo_info
    ):
        """Test that waiver data is stored in HTML report."""
        output_dir = str(tmp_project / "reports")
        os.makedirs(output_dir, exist_ok=True)
        
        waiver_data = {
            "schema_version": "1.0",
            "meta": {"created_at": "2024-01-15T10:00:00Z"},
            "finding_waivers": [
                {
                    "fingerprint": "test-fingerprint-1",
                    "type": "false_positive",
                    "reason": "Test reason"
                }
            ],
            "benchmark": [
                {
                    "fingerprint": "test-benchmark-1",
                    "type": "benchmark"
                }
            ]
        }
        
        report_builder(
            output_dir=output_dir,
            timestamp="2024_01_15T10_30_00",
            git_repo_info=sample_git_repo_info,
            data=(
                sample_normalized_findings.get("trufflehog"),
                sample_normalized_findings.get("opengrep"),
                sample_normalized_findings.get("syft"),
                sample_normalized_findings.get("grype"),
                sample_normalized_findings.get("checkov"),
            ),
            output_format="html",
            waiver_data=waiver_data
        )
        
        report_files = list(Path(output_dir).glob("*.html"))
        assert len(report_files) == 1
        
        html_content = report_files[0].read_text()
        
        # Check that waiver data is stored in hidden script tag
        assert 'id="existing-waiver-data"' in html_content
        assert "test-fingerprint-1" in html_content
        assert "test-benchmark-1" in html_content
        assert "finding_waivers" in html_content
        assert "benchmark" in html_content
    
    def test_unified_report_html_without_waiver_data(
        self, tmp_project, sample_normalized_findings, sample_git_repo_info
    ):
        """Test that HTML report works without waiver data."""
        output_dir = str(tmp_project / "reports")
        os.makedirs(output_dir, exist_ok=True)
        
        report_builder(
            output_dir=output_dir,
            timestamp="2024_01_15T10_30_00",
            git_repo_info=sample_git_repo_info,
            data=(
                sample_normalized_findings.get("trufflehog"),
                sample_normalized_findings.get("opengrep"),
                sample_normalized_findings.get("syft"),
                sample_normalized_findings.get("grype"),
                sample_normalized_findings.get("checkov"),
            ),
            output_format="html",
            waiver_data=None
        )
        
        report_files = list(Path(output_dir).glob("*.html"))
        assert len(report_files) == 1
        
        html_content = report_files[0].read_text()
        
        # Check that HTML is valid even without waiver data
        assert "<!DOCTYPE html>" in html_content or "<html" in html_content
        assert "</html>" in html_content
    
    def test_jenkins_html_renders(
        self, tmp_project, sample_normalized_findings, sample_git_repo_info
    ):
        """Test that Jenkins HTML report renders without errors."""
        output_dir = str(tmp_project / "reports")
        os.makedirs(output_dir, exist_ok=True)
        
        report_builder(
            output_dir=output_dir,
            timestamp="2024_01_15T10_30_00",
            git_repo_info=sample_git_repo_info,
            data=(
                sample_normalized_findings.get("trufflehog"),
                sample_normalized_findings.get("opengrep"),
                sample_normalized_findings.get("syft"),
                sample_normalized_findings.get("grype"),
                sample_normalized_findings.get("checkov"),
            ),
            output_format="jenkins_html"
        )
        
        report_files = list(Path(output_dir).glob("*.html"))
        assert len(report_files) == 1
        
        html_content = report_files[0].read_text()
        assert "<!DOCTYPE html>" in html_content or "<html" in html_content
        assert "</html>" in html_content
    
    def test_jenkins_html_snapshot(
        self, tmp_project, sample_normalized_findings, sample_git_repo_info, snapshot: SnapshotAssertion
    ):
        """Snapshot test for Jenkins HTML report."""
        output_dir = str(tmp_project / "reports")
        os.makedirs(output_dir, exist_ok=True)
        
        report_builder(
            output_dir=output_dir,
            timestamp="2024_01_15T10_30_00",
            git_repo_info=sample_git_repo_info,
            data=(
                sample_normalized_findings.get("trufflehog"),
                sample_normalized_findings.get("opengrep"),
                sample_normalized_findings.get("syft"),
                sample_normalized_findings.get("grype"),
                sample_normalized_findings.get("checkov"),
            ),
            output_format="jenkins_html"
        )
        
        report_files = list(Path(output_dir).glob("*.html"))
        assert len(report_files) == 1
        
        html_content = report_files[0].read_text()
        normalized = normalize_html_output(html_content)
        
        assert normalized == snapshot


class TestIndividualHTMLTemplates:
    """Test individual HTML template rendering."""
    
    @pytest.fixture
    def templates_dir(self):
        """Get the templates directory."""
        return Path(__file__).parent.parent.parent.parent / "dsoinabox" / "reporting" / "templates"
    
    def test_grype_template_renders(
        self, templates_dir, sample_normalized_findings, sample_git_repo_info
    ):
        """Test that Grype HTML template renders."""
        template_dir = templates_dir / "html"
        env = Environment(loader=FileSystemLoader(str(template_dir)))
        env.filters['tojson'] = lambda value: json.dumps(value)
        template = env.get_template("default_grype.html")
        
        rendered = template.render(
            grype_data=sample_normalized_findings.get("grype"),
            git_repo_info=sample_git_repo_info
        )
        
        # Individual templates render sections, not full HTML documents
        assert "<section" in rendered and "grype-section" in rendered
    
    def test_grype_template_snapshot(
        self, templates_dir, sample_normalized_findings, sample_git_repo_info, snapshot: SnapshotAssertion
    ):
        """Snapshot test for Grype HTML template."""
        template_dir = templates_dir / "html"
        env = Environment(loader=FileSystemLoader(str(template_dir)))
        env.filters['tojson'] = lambda value: json.dumps(value)
        template = env.get_template("default_grype.html")
        
        rendered = template.render(
            grype_data=sample_normalized_findings.get("grype"),
            git_repo_info=sample_git_repo_info
        )
        
        normalized = normalize_html_output(rendered)
        assert normalized == snapshot
    
    def test_opengrep_template_renders(
        self, templates_dir, sample_normalized_findings, sample_git_repo_info
    ):
        """Test that OpenGrep HTML template renders."""
        template_dir = templates_dir / "html"
        env = Environment(loader=FileSystemLoader(str(template_dir)))
        env.filters['tojson'] = lambda value: json.dumps(value)
        template = env.get_template("default_opengrep.html")
        
        rendered = template.render(
            opengrep_data=sample_normalized_findings.get("opengrep"),
            git_repo_info=sample_git_repo_info
        )
        
        # Individual templates render sections, not full HTML documents
        assert "<section" in rendered and "opengrep-section" in rendered
    
    def test_opengrep_template_snapshot(
        self, templates_dir, sample_normalized_findings, sample_git_repo_info, snapshot: SnapshotAssertion
    ):
        """Snapshot test for OpenGrep HTML template."""
        template_dir = templates_dir / "html"
        env = Environment(loader=FileSystemLoader(str(template_dir)))
        env.filters['tojson'] = lambda value: json.dumps(value)
        template = env.get_template("default_opengrep.html")
        
        rendered = template.render(
            opengrep_data=sample_normalized_findings.get("opengrep"),
            git_repo_info=sample_git_repo_info
        )
        
        normalized = normalize_html_output(rendered)
        assert normalized == snapshot
    
    def test_trufflehog_template_renders(
        self, templates_dir, sample_normalized_findings, sample_git_repo_info
    ):
        """Test that Trufflehog HTML template renders."""
        template_dir = templates_dir / "html"
        env = Environment(loader=FileSystemLoader(str(template_dir)))
        env.filters['tojson'] = lambda value: json.dumps(value)
        template = env.get_template("default_trufflehog.html")
        
        rendered = template.render(
            trufflehog_data=sample_normalized_findings.get("trufflehog"),
            git_repo_info=sample_git_repo_info
        )
        
        # Individual templates render sections, not full HTML documents
        assert "<section" in rendered and "trufflehog-section" in rendered
    
    def test_trufflehog_template_snapshot(
        self, templates_dir, sample_normalized_findings, sample_git_repo_info, snapshot: SnapshotAssertion
    ):
        """Snapshot test for Trufflehog HTML template."""
        template_dir = templates_dir / "html"
        env = Environment(loader=FileSystemLoader(str(template_dir)))
        env.filters['tojson'] = lambda value: json.dumps(value)
        template = env.get_template("default_trufflehog.html")
        
        rendered = template.render(
            trufflehog_data=sample_normalized_findings.get("trufflehog"),
            git_repo_info=sample_git_repo_info
        )
        
        normalized = normalize_html_output(rendered)
        assert normalized == snapshot
    
    def test_checkov_template_renders(
        self, templates_dir, sample_normalized_findings, sample_git_repo_info
    ):
        """Test that Checkov HTML template renders."""
        template_dir = templates_dir / "html"
        env = Environment(loader=FileSystemLoader(str(template_dir)))
        env.filters['tojson'] = lambda value: json.dumps(value)
        template = env.get_template("default_checkov.html")
        
        rendered = template.render(
            checkov_data=sample_normalized_findings.get("checkov"),
            git_repo_info=sample_git_repo_info
        )
        
        # Individual templates render sections, not full HTML documents
        assert "<section" in rendered and "checkov-section" in rendered
    
    def test_checkov_template_snapshot(
        self, templates_dir, sample_normalized_findings, sample_git_repo_info, snapshot: SnapshotAssertion
    ):
        """Snapshot test for Checkov HTML template."""
        template_dir = templates_dir / "html"
        env = Environment(loader=FileSystemLoader(str(template_dir)))
        env.filters['tojson'] = lambda value: json.dumps(value)
        template = env.get_template("default_checkov.html")
        
        rendered = template.render(
            checkov_data=sample_normalized_findings.get("checkov"),
            git_repo_info=sample_git_repo_info
        )
        
        normalized = normalize_html_output(rendered)
        assert normalized == snapshot
    
    def test_jenkins_grype_template_snapshot(
        self, templates_dir, sample_normalized_findings, sample_git_repo_info, snapshot: SnapshotAssertion
    ):
        """Snapshot test for Jenkins Grype HTML template."""
        template_dir = templates_dir / "jenkins_html"
        env = Environment(loader=FileSystemLoader(str(template_dir)))
        env.filters['tojson'] = lambda value: json.dumps(value)
        template = env.get_template("default_grype.html")
        
        rendered = template.render(
            grype_data=sample_normalized_findings.get("grype"),
            git_repo_info=sample_git_repo_info
        )
        
        normalized = normalize_html_output(rendered)
        assert normalized == snapshot
    
    def test_jenkins_opengrep_template_snapshot(
        self, templates_dir, sample_normalized_findings, sample_git_repo_info, snapshot: SnapshotAssertion
    ):
        """Snapshot test for Jenkins OpenGrep HTML template."""
        template_dir = templates_dir / "jenkins_html"
        env = Environment(loader=FileSystemLoader(str(template_dir)))
        env.filters['tojson'] = lambda value: json.dumps(value)
        template = env.get_template("default_opengrep.html")
        
        rendered = template.render(
            opengrep_data=sample_normalized_findings.get("opengrep"),
            git_repo_info=sample_git_repo_info
        )
        
        normalized = normalize_html_output(rendered)
        assert normalized == snapshot

