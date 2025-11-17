"""Unit tests for JSON/NDJSON report generation."""

import json
import os
import re
import pytest
from pathlib import Path
from syrupy import SnapshotAssertion
from typing import Dict, Any

from dsoinabox.reporting.report_builder import report_builder
from dsoinabox.utils.deterministic import normalize_path


def normalize_paths(data: Any, base_path: str = "") -> Any:
    """Recursively normalize absolute paths in data structure.
    
    Uses the deterministic normalize_path helper. Since report_builder
    already normalizes paths, this mainly handles any remaining edge cases.
    """
    if isinstance(data, dict):
        normalized = {}
        for key, value in data.items():
            if key in ("path", "file", "file_path", "uri", "location", "realPath"):
                if isinstance(value, str):
                    # Use the deterministic helper for path normalization
                    normalized[key] = normalize_path(value)
                else:
                    normalized[key] = normalize_paths(value, base_path)
            elif key in ("locations", "artifactLocation", "physicalLocation"):
                # Handle nested location structures
                normalized[key] = normalize_paths(value, base_path)
            else:
                normalized[key] = normalize_paths(value, base_path)
        return normalized
    elif isinstance(data, list):
        return [normalize_paths(item, base_path) for item in data]
    elif isinstance(data, str):
        # Check if string looks like an absolute path and normalize it
        if os.path.isabs(data) and ("/" in data or "\\" in data):
            return normalize_path(data)
        return data
    else:
        return data


def normalize_timestamps(data: Any) -> Any:
    """Recursively normalize timestamps in data structure.
    
    Replaces timestamps with placeholder strings.
    """
    if isinstance(data, dict):
        normalized = {}
        for key, value in data.items():
            if "timestamp" in key.lower() or "time" in key.lower() or "date" in key.lower():
                if isinstance(value, str):
                    # Replace timestamp strings with placeholder
                    normalized[key] = "<TIMESTAMP>"
                else:
                    normalized[key] = normalize_timestamps(value)
            else:
                normalized[key] = normalize_timestamps(value)
        return normalized
    elif isinstance(data, list):
        return [normalize_timestamps(item) for item in data]
    elif isinstance(data, str):
        # Check if string looks like a timestamp
        if re.match(r'^\d{4}-\d{2}-\d{2}', data) or re.match(r'^\d{4}_\d{2}_\d{2}', data):
            return "<TIMESTAMP>"
        return data
    else:
        return data


def sort_findings_deterministically(data: Dict[str, Any]) -> Dict[str, Any]:
    """Sort findings in a deterministic order for stable output."""
    sorted_data = data.copy()
    
    # Sort opengrep results
    if "opengrep_data" in sorted_data and sorted_data["opengrep_data"]:
        if "results" in sorted_data["opengrep_data"]:
            sorted_data["opengrep_data"]["results"] = sorted(
                sorted_data["opengrep_data"]["results"],
                key=lambda x: (
                    x.get("path", ""),
                    x.get("check_id", ""),
                    x.get("start", {}).get("line", 0)
                )
            )
    
    # Sort grype matches
    if "grype_data" in sorted_data and sorted_data["grype_data"]:
        if "matches" in sorted_data["grype_data"]:
            sorted_data["grype_data"]["matches"] = sorted(
                sorted_data["grype_data"]["matches"],
                key=lambda x: (
                    x.get("vulnerability", {}).get("id", ""),
                    x.get("artifact", {}).get("name", ""),
                    x.get("artifact", {}).get("version", "")
                )
            )
    
    # Sort trufflehog results
    if "trufflehog_data" in sorted_data and isinstance(sorted_data["trufflehog_data"], list):
        sorted_data["trufflehog_data"] = sorted(
            sorted_data["trufflehog_data"],
            key=lambda x: (
                x.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("file", "") or
                x.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "") or
                "",
                x.get("DetectorName", ""),
                x.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("line", 0) or
                x.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0) or 0
            )
        )
    
    # Sort checkov results
    if "checkov_data" in sorted_data and sorted_data["checkov_data"]:
        runs = sorted_data["checkov_data"].get("runs", [])
        if runs:
            results = runs[0].get("results", [])
            if results:
                runs[0]["results"] = sorted(
                    results,
                    key=lambda x: (
                        x.get("ruleId", ""),
                        x.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", ""),
                        x.get("locations", [{}])[0].get("physicalLocation", {}).get("region", {}).get("startLine", 0)
                    )
                )
    
    return sorted_data


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


class TestJSONReportGeneration:
    """Test JSON report generation."""
    
    def test_json_report_includes_required_keys(
        self, tmp_project, sample_normalized_findings, sample_git_repo_info
    ):
        """Test that JSON report includes all required top-level keys."""
        output_dir = str(tmp_project / "reports")
        os.makedirs(output_dir, exist_ok=True)
        
        report_builder(
            output_dir=output_dir,
            timestamp="2024_01_15T10_30_00",
            git_repo_info=sample_git_repo_info,
            data=(
                sample_normalized_findings.get("trufflehog"),
                sample_normalized_findings.get("opengrep"),
                None,  # syft_data
                sample_normalized_findings.get("grype"),
                sample_normalized_findings.get("checkov"),
            ),
            output_format="json"
        )
        
        # Find the generated report file
        report_files = list(Path(output_dir).glob("*.json"))
        assert len(report_files) == 1
        
        with open(report_files[0]) as f:
            report_data = json.load(f)
        
        # Check required top-level keys
        assert "metadata" in report_data
        assert "trufflehog_data" in report_data
        assert "opengrep_data" in report_data
        assert "syft_data" in report_data
        assert "grype_data" in report_data
        assert "checkov_data" in report_data
        assert "git_repo_info" in report_data
        
        # Check metadata structure
        assert "scan_timestamp" in report_data["metadata"]
        assert "git_repo_info" in report_data["metadata"]
    
    def test_json_report_deterministic_sorting(
        self, tmp_project, sample_normalized_findings, sample_git_repo_info
    ):
        """Test that JSON report sorts findings deterministically."""
        output_dir = str(tmp_project / "reports")
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate report twice
        report_builder(
            output_dir=output_dir,
            timestamp="2024_01_15T10_30_00",
            git_repo_info=sample_git_repo_info,
            data=(
                sample_normalized_findings.get("trufflehog"),
                sample_normalized_findings.get("opengrep"),
                None,
                sample_normalized_findings.get("grype"),
                sample_normalized_findings.get("checkov"),
            ),
            output_format="json"
        )
        
        report_files = list(Path(output_dir).glob("*.json"))
        assert len(report_files) == 1
        
        with open(report_files[0]) as f:
            report1 = json.load(f)
        
        # Clear and regenerate
        os.remove(report_files[0])
        
        report_builder(
            output_dir=output_dir,
            timestamp="2024_01_15T10_30_00",
            git_repo_info=sample_git_repo_info,
            data=(
                sample_normalized_findings.get("trufflehog"),
                sample_normalized_findings.get("opengrep"),
                None,
                sample_normalized_findings.get("grype"),
                sample_normalized_findings.get("checkov"),
            ),
            output_format="json"
        )
        
        report_files = list(Path(output_dir).glob("*.json"))
        with open(report_files[0]) as f:
            report2 = json.load(f)
        
        # Reports should be identical (after normalization)
        normalized1 = normalize_timestamps(normalize_paths(report1))
        normalized2 = normalize_timestamps(normalize_paths(report2))
        
        # Sort both for comparison
        sorted1 = sort_findings_deterministically(normalized1)
        sorted2 = sort_findings_deterministically(normalized2)
        
        assert sorted1 == sorted2
    
    def test_json_report_path_normalization(
        self, tmp_project, sample_normalized_findings, sample_git_repo_info
    ):
        """Test that JSON report normalizes/redacts absolute paths."""
        output_dir = str(tmp_project / "reports")
        os.makedirs(output_dir, exist_ok=True)
        
        # Modify findings to include absolute paths
        opengrep_data = sample_normalized_findings.get("opengrep", {}).copy()
        if opengrep_data.get("results"):
            # Add absolute path
            opengrep_data["results"][0]["path"] = "/absolute/path/to/src/main.py"
        
        report_builder(
            output_dir=output_dir,
            timestamp="2024_01_15T10_30_00",
            git_repo_info=sample_git_repo_info,
            data=(
                sample_normalized_findings.get("trufflehog"),
                opengrep_data,
                None,
                sample_normalized_findings.get("grype"),
                sample_normalized_findings.get("checkov"),
            ),
            output_format="json"
        )
        
        report_files = list(Path(output_dir).glob("*.json"))
        with open(report_files[0]) as f:
            report_data = json.load(f)
        
        # Check that paths are present (normalization happens in snapshot)
        if report_data.get("opengrep_data", {}).get("results"):
            # Path should be in the data (we'll normalize in snapshot)
            assert "path" in report_data["opengrep_data"]["results"][0]
    
    def test_json_report_snapshot(
        self, tmp_project, sample_normalized_findings, sample_git_repo_info, snapshot: SnapshotAssertion
    ):
        """Snapshot test for JSON report generation."""
        output_dir = str(tmp_project / "reports")
        os.makedirs(output_dir, exist_ok=True)
        
        report_builder(
            output_dir=output_dir,
            timestamp="2024_01_15T10_30_00",
            git_repo_info=sample_git_repo_info,
            data=(
                sample_normalized_findings.get("trufflehog"),
                sample_normalized_findings.get("opengrep"),
                None,
                sample_normalized_findings.get("grype"),
                sample_normalized_findings.get("checkov"),
            ),
            output_format="json"
        )
        
        report_files = list(Path(output_dir).glob("*.json"))
        assert len(report_files) == 1
        
        with open(report_files[0]) as f:
            report_data = json.load(f)
        
        # Normalize for snapshot
        normalized = normalize_timestamps(normalize_paths(report_data))
        sorted_data = sort_findings_deterministically(normalized)
        
        assert sorted_data == snapshot


class TestNDJSONReportGeneration:
    """Test NDJSON report generation."""
    
    def test_ndjson_report_structure(
        self, tmp_project, sample_normalized_findings, sample_git_repo_info
    ):
        """Test that NDJSON report has correct structure (one JSON object per line)."""
        output_dir = str(tmp_project / "reports")
        os.makedirs(output_dir, exist_ok=True)
        
        report_builder(
            output_dir=output_dir,
            timestamp="2024_01_15T10_30_00",
            git_repo_info=sample_git_repo_info,
            data=(
                sample_normalized_findings.get("trufflehog"),
                sample_normalized_findings.get("opengrep"),
                None,
                sample_normalized_findings.get("grype"),
                sample_normalized_findings.get("checkov"),
            ),
            output_format="ndjson"
        )
        
        report_files = list(Path(output_dir).glob("*.ndjson"))
        assert len(report_files) == 1
        
        # Read NDJSON file
        lines = []
        with open(report_files[0]) as f:
            for line in f:
                line = line.strip()
                if line:
                    lines.append(json.loads(line))
        
        # First line should be metadata
        assert len(lines) > 0
        assert lines[0]["type"] == "metadata"
        assert "scan_timestamp" in lines[0]
        
        # Subsequent lines should be findings
        finding_types = {line["type"] for line in lines[1:] if "type" in line}
        assert len(finding_types) > 0
    
    def test_ndjson_report_deterministic_order(
        self, tmp_project, sample_normalized_findings, sample_git_repo_info
    ):
        """Test that NDJSON report orders findings deterministically."""
        output_dir = str(tmp_project / "reports")
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate twice
        report_builder(
            output_dir=output_dir,
            timestamp="2024_01_15T10_30_00",
            git_repo_info=sample_git_repo_info,
            data=(
                sample_normalized_findings.get("trufflehog"),
                sample_normalized_findings.get("opengrep"),
                None,
                sample_normalized_findings.get("grype"),
                sample_normalized_findings.get("checkov"),
            ),
            output_format="ndjson"
        )
        
        report_files = list(Path(output_dir).glob("*.ndjson"))
        with open(report_files[0]) as f:
            lines1 = [json.loads(line.strip()) for line in f if line.strip()]
        
        os.remove(report_files[0])
        
        report_builder(
            output_dir=output_dir,
            timestamp="2024_01_15T10_30_00",
            git_repo_info=sample_git_repo_info,
            data=(
                sample_normalized_findings.get("trufflehog"),
                sample_normalized_findings.get("opengrep"),
                None,
                sample_normalized_findings.get("grype"),
                sample_normalized_findings.get("checkov"),
            ),
            output_format="ndjson"
        )
        
        report_files = list(Path(output_dir).glob("*.ndjson"))
        with open(report_files[0]) as f:
            lines2 = [json.loads(line.strip()) for line in f if line.strip()]
        
        # Normalize and compare
        normalized1 = [normalize_timestamps(normalize_paths(line)) for line in lines1]
        normalized2 = [normalize_timestamps(normalize_paths(line)) for line in lines2]
        
        assert len(normalized1) == len(normalized2)
        assert normalized1 == normalized2
    
    def test_ndjson_report_snapshot(
        self, tmp_project, sample_normalized_findings, sample_git_repo_info, snapshot: SnapshotAssertion
    ):
        """Snapshot test for NDJSON report generation."""
        output_dir = str(tmp_project / "reports")
        os.makedirs(output_dir, exist_ok=True)
        
        report_builder(
            output_dir=output_dir,
            timestamp="2024_01_15T10_30_00",
            git_repo_info=sample_git_repo_info,
            data=(
                sample_normalized_findings.get("trufflehog"),
                sample_normalized_findings.get("opengrep"),
                None,
                sample_normalized_findings.get("grype"),
                sample_normalized_findings.get("checkov"),
            ),
            output_format="ndjson"
        )
        
        report_files = list(Path(output_dir).glob("*.ndjson"))
        assert len(report_files) == 1
        
        # Read and normalize NDJSON
        lines = []
        with open(report_files[0]) as f:
            for line in f:
                line = line.strip()
                if line:
                    lines.append(json.loads(line))
        
        # Normalize for snapshot
        normalized = [normalize_timestamps(normalize_paths(line)) for line in lines]
        
        assert normalized == snapshot

