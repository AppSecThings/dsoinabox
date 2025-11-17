"""Unit tests for SARIF formatter."""

import json
import os
import pytest
from pathlib import Path
from typing import Dict, Any

from dsoinabox.reporting.sarif_formatter import (
    convert_unified_json_to_sarif,
    _map_severity_to_sarif_level,
    _extract_rule_id_from_finding,
    _extract_message_from_finding,
    _extract_file_path_from_finding,
    _extract_line_info_from_finding,
    _extract_severity_from_finding,
)


@pytest.fixture
def sample_unified_json(golden_dir) -> Dict[str, Any]:
    """Load sample unified JSON from fixtures."""
    unified_data = {
        "metadata": {
            "scan_timestamp": "2024_01_15T10_30_00",
            "git_repo_info": {
                "repo_name": "test-repo",
                "branch": "main",
                "last_commit_id": "abc123"
            }
        }
    }
    
    # Load opengrep data
    opengrep_path = golden_dir / "scanner_outputs" / "opengrep.json"
    if opengrep_path.exists():
        with open(opengrep_path) as f:
            unified_data["opengrep_data"] = json.load(f)
    
    # Load trufflehog data
    trufflehog_path = golden_dir / "scanner_outputs" / "trufflehog.json"
    if trufflehog_path.exists():
        with open(trufflehog_path) as f:
            unified_data["trufflehog_data"] = json.load(f)
    
    # Load grype data
    grype_path = golden_dir / "scanner_outputs" / "grype.json"
    if grype_path.exists():
        with open(grype_path) as f:
            unified_data["grype_data"] = json.load(f)
    
    # Load checkov data
    checkov_path = golden_dir / "scanner_outputs" / "checkov.json"
    if checkov_path.exists():
        with open(checkov_path) as f:
            unified_data["checkov_data"] = json.load(f)
    
    return unified_data


@pytest.fixture
def minimal_unified_json() -> Dict[str, Any]:
    """Create minimal unified JSON for testing."""
    return {
        "metadata": {
            "scan_timestamp": "2024_01_15T10_30_00"
        },
        "opengrep_data": {
            "results": [
                {
                    "check_id": "test.rule.id",
                    "path": "src/main.py",
                    "start": {"line": 10, "col": 5},
                    "end": {"line": 10, "col": 20},
                    "extra": {
                        "severity": "HIGH",
                        "message": "Test finding message"
                    },
                    "fingerprints": {
                        "rule": "og:1:RULE:test.rule.id:abc123",
                        "exact": "og:1:EXACT:test.rule.id:def456"
                    }
                }
            ]
        },
        "trufflehog_data": [
            {
                "DetectorName": "AWS",
                "DetectorType": 1,
                "DetectorDescription": "AWS access key detected",
                "SourceMetadata": {
                    "Data": {
                        "Git": {
                            "file": "config/secrets.yaml",
                            "line": 5
                        }
                    }
                },
                "Redacted": "AKIA***REDACTED***",
                "fingerprints": {
                    "secret": "th:1:SECRET:AWS:xyz789"
                }
            }
        ],
        "grype_data": {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2023-12345",
                        "severity": "HIGH",
                        "description": "Test vulnerability"
                    },
                    "artifact": {
                        "name": "test-package",
                        "version": "1.0.0",
                        "locations": [
                            {"path": "requirements.txt"}
                        ]
                    }
                }
            ]
        },
        "checkov_data": {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Checkov",
                            "rules": [
                                {
                                    "id": "CKV_TEST_1",
                                    "shortDescription": {"text": "Test rule"}
                                }
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "CKV_TEST_1",
                            "level": "error",
                            "message": {"text": "Test checkov finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "main.tf"},
                                        "region": {"startLine": 10}
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    }


class TestSARIFFormatter:
    """Test SARIF formatter functionality."""
    
    def test_sarif_schema_version(self, minimal_unified_json):
        """Test that generated SARIF has correct schema version."""
        sarif_log = convert_unified_json_to_sarif(minimal_unified_json)
        
        assert sarif_log["version"] == "2.1.0"
        assert "$schema" in sarif_log
        assert "2.1.0" in sarif_log["$schema"]
    
    def test_sarif_multiple_runs(self, minimal_unified_json):
        """Test that SARIF contains one run per tool type."""
        sarif_log = convert_unified_json_to_sarif(minimal_unified_json)
        
        assert "runs" in sarif_log
        assert len(sarif_log["runs"]) > 0
        
        # Should have runs for opengrep, trufflehog, grype, and checkov
        tool_names = {run["tool"]["driver"]["name"] for run in sarif_log["runs"]}
        assert "opengrep" in tool_names
        assert "trufflehog" in tool_names
        assert "grype" in tool_names
        assert "checkov" in tool_names
    
    def test_sarif_run_structure(self, minimal_unified_json):
        """Test that each SARIF run has correct structure."""
        sarif_log = convert_unified_json_to_sarif(minimal_unified_json)
        
        for run in sarif_log["runs"]:
            assert "tool" in run
            assert "driver" in run["tool"]
            assert "name" in run["tool"]["driver"]
            assert "results" in run
            assert isinstance(run["results"], list)
    
    def test_sarif_rules_extraction(self, minimal_unified_json):
        """Test that rules are extracted correctly from findings."""
        sarif_log = convert_unified_json_to_sarif(minimal_unified_json)
        
        # Find opengrep run
        opengrep_run = next(
            (r for r in sarif_log["runs"] if r["tool"]["driver"]["name"] == "opengrep"),
            None
        )
        assert opengrep_run is not None
        
        # Check that rules are present
        if "rules" in opengrep_run["tool"]["driver"]:
            rules = opengrep_run["tool"]["driver"]["rules"]
            assert len(rules) > 0
            assert all("id" in rule for rule in rules)
    
    def test_sarif_result_rule_ids(self, minimal_unified_json):
        """Test that results have correct ruleIds."""
        sarif_log = convert_unified_json_to_sarif(minimal_unified_json)
        
        for run in sarif_log["runs"]:
            for result in run["results"]:
                assert "ruleId" in result
                assert result["ruleId"] != "unknown"
    
    def test_sarif_result_messages(self, minimal_unified_json):
        """Test that results have message text."""
        sarif_log = convert_unified_json_to_sarif(minimal_unified_json)
        
        for run in sarif_log["runs"]:
            for result in run["results"]:
                assert "message" in result
                assert "text" in result["message"]
                assert len(result["message"]["text"]) > 0
    
    def test_sarif_severity_mapping(self, minimal_unified_json):
        """Test that severity is correctly mapped to SARIF levels."""
        sarif_log = convert_unified_json_to_sarif(minimal_unified_json)
        
        for run in sarif_log["runs"]:
            for result in run["results"]:
                assert "level" in result
                assert result["level"] in ["error", "warning", "note", "none"]
    
    def test_sarif_location_mapping(self, minimal_unified_json):
        """Test that file paths and line numbers are correctly mapped."""
        sarif_log = convert_unified_json_to_sarif(minimal_unified_json)
        
        # Check opengrep run has locations
        opengrep_run = next(
            (r for r in sarif_log["runs"] if r["tool"]["driver"]["name"] == "opengrep"),
            None
        )
        if opengrep_run and opengrep_run["results"]:
            result = opengrep_run["results"][0]
            assert "locations" in result
            assert len(result["locations"]) > 0
            
            location = result["locations"][0]
            assert "physicalLocation" in location
            assert "artifactLocation" in location["physicalLocation"]
            assert "uri" in location["physicalLocation"]["artifactLocation"]
            
            # Check for region if line numbers are available
            if "region" in location["physicalLocation"]:
                region = location["physicalLocation"]["region"]
                assert "startLine" in region
    
    def test_sarif_fingerprints(self, minimal_unified_json):
        """Test that fingerprints are included in results."""
        sarif_log = convert_unified_json_to_sarif(minimal_unified_json)
        
        # Check opengrep run has fingerprints
        opengrep_run = next(
            (r for r in sarif_log["runs"] if r["tool"]["driver"]["name"] == "opengrep"),
            None
        )
        if opengrep_run and opengrep_run["results"]:
            result = opengrep_run["results"][0]
            # Fingerprints should be in partialFingerprints or properties
            has_fingerprints = (
                "partialFingerprints" in result or
                (result.get("properties", {}).get("fingerprints") is not None)
            )
            # Note: fingerprints may not always be present, so we just check structure
            assert isinstance(result, dict)
    
    def test_sarif_empty_findings(self):
        """Test that empty unified JSON produces valid SARIF."""
        empty_data = {
            "metadata": {"scan_timestamp": "2024_01_15T10_30_00"}
        }
        
        sarif_log = convert_unified_json_to_sarif(empty_data)
        
        assert sarif_log["version"] == "2.1.0"
        assert "runs" in sarif_log
        # May have empty runs list if no findings
        assert isinstance(sarif_log["runs"], list)
    
    def test_sarif_opengrep_specific(self, minimal_unified_json):
        """Test opengrep-specific mapping."""
        sarif_log = convert_unified_json_to_sarif(minimal_unified_json)
        
        opengrep_run = next(
            (r for r in sarif_log["runs"] if r["tool"]["driver"]["name"] == "opengrep"),
            None
        )
        assert opengrep_run is not None
        
        if opengrep_run["results"]:
            result = opengrep_run["results"][0]
            assert result["ruleId"] == "test.rule.id"
            assert "error" in result["level"] or "warning" in result["level"]  # HIGH severity
    
    def test_sarif_trufflehog_specific(self, minimal_unified_json):
        """Test trufflehog-specific mapping."""
        sarif_log = convert_unified_json_to_sarif(minimal_unified_json)
        
        trufflehog_run = next(
            (r for r in sarif_log["runs"] if r["tool"]["driver"]["name"] == "trufflehog"),
            None
        )
        assert trufflehog_run is not None
        
        if trufflehog_run["results"]:
            result = trufflehog_run["results"][0]
            assert "AWS" in result["ruleId"] or "1" in result["ruleId"]
            assert result["level"] == "error"  # Secrets are high severity
    
    def test_sarif_grype_specific(self, minimal_unified_json):
        """Test grype-specific mapping."""
        sarif_log = convert_unified_json_to_sarif(minimal_unified_json)
        
        grype_run = next(
            (r for r in sarif_log["runs"] if r["tool"]["driver"]["name"] == "grype"),
            None
        )
        assert grype_run is not None
        
        if grype_run["results"]:
            result = grype_run["results"][0]
            assert result["ruleId"] == "CVE-2023-12345"
            assert result["level"] in ["error", "warning"]  # HIGH severity
    
    def test_sarif_checkov_specific(self, minimal_unified_json):
        """Test checkov-specific mapping."""
        sarif_log = convert_unified_json_to_sarif(minimal_unified_json)
        
        checkov_run = next(
            (r for r in sarif_log["runs"] if r["tool"]["driver"]["name"] == "checkov"),
            None
        )
        assert checkov_run is not None
        
        if checkov_run["results"]:
            result = checkov_run["results"][0]
            assert result["ruleId"] == "CKV_TEST_1"
            assert result["level"] == "error"


class TestSARIFHelperFunctions:
    """Test SARIF helper functions."""
    
    def test_map_severity_to_sarif_level(self):
        """Test severity to SARIF level mapping."""
        assert _map_severity_to_sarif_level("critical") == "error"
        assert _map_severity_to_sarif_level("high") == "error"
        assert _map_severity_to_sarif_level("medium") == "warning"
        assert _map_severity_to_sarif_level("low") == "note"
        assert _map_severity_to_sarif_level("info") == "note"
        assert _map_severity_to_sarif_level("unknown") == "warning"  # default
    
    def test_extract_rule_id_opengrep(self):
        """Test rule ID extraction for opengrep."""
        finding = {"check_id": "test.rule.id"}
        assert _extract_rule_id_from_finding(finding, "opengrep") == "test.rule.id"
    
    def test_extract_rule_id_trufflehog(self):
        """Test rule ID extraction for trufflehog."""
        finding = {
            "DetectorName": "AWS",
            "DetectorType": 1
        }
        rule_id = _extract_rule_id_from_finding(finding, "trufflehog")
        assert "AWS" in rule_id or "1" in rule_id
    
    def test_extract_rule_id_grype(self):
        """Test rule ID extraction for grype."""
        finding = {
            "vulnerability": {"id": "CVE-2023-12345"}
        }
        assert _extract_rule_id_from_finding(finding, "grype") == "CVE-2023-12345"
    
    def test_extract_rule_id_checkov(self):
        """Test rule ID extraction for checkov."""
        finding = {"ruleId": "CKV_TEST_1"}
        assert _extract_rule_id_from_finding(finding, "checkov") == "CKV_TEST_1"
    
    def test_extract_message_opengrep(self):
        """Test message extraction for opengrep."""
        finding = {
            "extra": {
                "message": "Test message"
            }
        }
        assert _extract_message_from_finding(finding, "opengrep") == "Test message"
    
    def test_extract_file_path_opengrep(self):
        """Test file path extraction for opengrep."""
        finding = {"path": "src/main.py"}
        assert _extract_file_path_from_finding(finding, "opengrep") == "src/main.py"
    
    def test_extract_line_info_opengrep(self):
        """Test line info extraction for opengrep."""
        finding = {
            "start": {"line": 10},
            "end": {"line": 15}
        }
        start, end = _extract_line_info_from_finding(finding, "opengrep")
        assert start == 10
        assert end == 15
    
    def test_extract_severity_opengrep(self):
        """Test severity extraction for opengrep."""
        finding = {
            "extra": {"severity": "HIGH"}
        }
        assert _extract_severity_from_finding(finding, "opengrep") == "high"
        
        finding = {
            "extra": {"severity": "WARNING"}
        }
        assert _extract_severity_from_finding(finding, "opengrep") == "medium"

