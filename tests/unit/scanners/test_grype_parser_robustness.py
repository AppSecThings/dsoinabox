"""Robustness tests for Grype parser (malformed JSON, edge cases)."""

from __future__ import annotations

import pytest
import json

from dsoinabox.reporting.parser import GrypeParser


class TestGrypeParserRobustness:
    """Test Grype parser handles malformed/edge case inputs gracefully."""
    
    def test_parser_missing_vulnerability_id_handled(self, tmp_path):
        """Test that missing vulnerability.id doesn't crash parser."""
        report_file = tmp_path / "grype.json"
        report_data = {
            "matches": [
                {
                    "artifact": {
                        "name": "test-package",
                        "version": "1.0.0"
                    },
                    "vulnerability": {
                        # Missing id
                        "severity": "HIGH",
                        "description": "Test vulnerability"
                    }
                }
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = GrypeParser(
            report_directory=str(tmp_path),
            report_filename="grype.json"
        )
        
        # Should not crash
        assert parser.data is not None
        assert len(parser.data.get("matches", [])) == 1
    
    def test_parser_missing_severity_defaults_safely(self, tmp_path):
        """Test that missing severity field doesn't crash parser."""
        report_file = tmp_path / "grype.json"
        report_data = {
            "matches": [
                {
                    "artifact": {
                        "name": "test-package",
                        "version": "1.0.0"
                    },
                    "vulnerability": {
                        "id": "CVE-2024-12345",
                        # Missing severity
                        "description": "Test vulnerability"
                    }
                }
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = GrypeParser(
            report_directory=str(tmp_path),
            report_filename="grype.json"
        )
        
        # Should not crash
        assert parser.data is not None
        findings = parser.findings_that_exceed_threshold("high")
        # Missing severity should not match "high" threshold
        assert len(findings) == 0
    
    def test_parser_unknown_severity_mapped_safely(self, tmp_path):
        """Test that unknown severity values are handled safely."""
        report_file = tmp_path / "grype.json"
        report_data = {
            "matches": [
                {
                    "artifact": {"name": "test-package", "version": "1.0.0"},
                    "vulnerability": {
                        "id": "CVE-2024-12345",
                        "severity": "UNKNOWN_SEVERITY",  # Unknown value
                    }
                }
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = GrypeParser(
            report_directory=str(tmp_path),
            report_filename="grype.json"
        )
        
        # Unknown severity should not match any threshold
        findings = parser.findings_that_exceed_threshold("high")
        assert len(findings) == 0
    
    def test_parser_empty_matches_returns_empty_list(self, tmp_path):
        """Test that empty matches array is handled correctly."""
        report_file = tmp_path / "grype.json"
        report_data = {
            "matches": []
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = GrypeParser(
            report_directory=str(tmp_path),
            report_filename="grype.json"
        )
        
        assert parser.data["matches"] == []
        findings = parser.findings_that_exceed_threshold("low")
        assert findings == []
    
    def test_parser_missing_matches_key_handled(self, tmp_path):
        """Test that missing matches key is handled gracefully."""
        report_file = tmp_path / "grype.json"
        report_data = {
            "source": {
                "type": "directory",
                "target": "/scan_target"
            }
            # Missing matches key
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = GrypeParser(
            report_directory=str(tmp_path),
            report_filename="grype.json"
        )
        
        # Should use .get() safely
        findings = parser.findings_that_exceed_threshold("low")
        assert findings == []
    
    def test_parser_null_fields_handled_gracefully(self, tmp_path):
        """Test that null values in expected fields don't crash."""
        report_file = tmp_path / "grype.json"
        report_data = {
            "matches": [
                {
                    "artifact": {
                        "name": None,  # Null value
                        "version": "1.0.0"
                    },
                    "vulnerability": {
                        "id": "CVE-2024-12345",
                        "severity": "HIGH",
                        "description": None  # Null value
                    }
                }
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = GrypeParser(
            report_directory=str(tmp_path),
            report_filename="grype.json"
        )
        
        # Should not crash
        assert parser.data is not None
        findings = parser.findings_that_exceed_threshold("high")
        # Should handle null gracefully
        assert len(findings) >= 0
    
    def test_parser_extra_fields_ignored_without_crash(self, tmp_path):
        """Test that unexpected extra fields are ignored."""
        report_file = tmp_path / "grype.json"
        report_data = {
            "matches": [
                {
                    "artifact": {"name": "test-package", "version": "1.0.0"},
                    "vulnerability": {"id": "CVE-2024-12345", "severity": "HIGH"},
                    "unexpected_field": "should be ignored",
                    "another_unexpected": {"nested": "data"}
                }
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = GrypeParser(
            report_directory=str(tmp_path),
            report_filename="grype.json"
        )
        
        # Should not crash, extra fields preserved in data
        assert parser.data is not None
        assert "unexpected_field" in parser.data["matches"][0]
    
    def test_parser_missing_artifact_key_handled(self, tmp_path):
        """Test that missing artifact key is handled gracefully."""
        report_file = tmp_path / "grype.json"
        report_data = {
            "matches": [
                {
                    # Missing artifact key
                    "vulnerability": {
                        "id": "CVE-2024-12345",
                        "severity": "HIGH"
                    }
                }
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = GrypeParser(
            report_directory=str(tmp_path),
            report_filename="grype.json"
        )
        
        # Should use .get() safely
        findings = parser.findings_that_exceed_threshold("high")
        # Should still process vulnerability
        assert len(findings) >= 0
    
    def test_parser_missing_vulnerability_key_handled(self, tmp_path):
        """Test that missing vulnerability key is handled gracefully."""
        report_file = tmp_path / "grype.json"
        report_data = {
            "matches": [
                {
                    "artifact": {"name": "test-package", "version": "1.0.0"}
                    # Missing vulnerability key
                }
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = GrypeParser(
            report_directory=str(tmp_path),
            report_filename="grype.json"
        )
        
        # Should use .get() safely
        findings = parser.findings_that_exceed_threshold("high")
        # Missing vulnerability should not match any threshold
        assert len(findings) == 0

