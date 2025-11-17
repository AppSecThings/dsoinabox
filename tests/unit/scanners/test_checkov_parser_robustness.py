"""Robustness tests for Checkov parser (malformed JSON, edge cases)."""

from __future__ import annotations

import pytest
import json

from dsoinabox.reporting.parser import CheckovParser


class TestCheckovParserRobustness:
    """Test Checkov parser handles malformed/edge case inputs gracefully."""
    
    def test_parser_empty_runs_returns_empty(self, tmp_path):
        """Test that empty runs array is handled correctly."""
        report_file = tmp_path / "checkov.json"
        report_data = {
            "runs": []
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = CheckovParser(
            report_directory=str(tmp_path),
            report_filename="checkov.json"
        )
        
        results = parser._get_results_from_sarif()
        assert results == []
        findings = parser.findings_that_exceed_threshold("high")
        assert findings == []
    
    def test_parser_missing_runs_key_handled(self, tmp_path):
        """Test that missing runs key is handled gracefully."""
        report_file = tmp_path / "checkov.json"
        report_data = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema.json"
            # Missing runs key
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = CheckovParser(
            report_directory=str(tmp_path),
            report_filename="checkov.json"
        )
        
        # Should use .get() safely
        results = parser._get_results_from_sarif()
        assert results == []
    
    def test_parser_missing_results_key_in_run_handled(self, tmp_path):
        """Test that missing results key in run is handled."""
        report_file = tmp_path / "checkov.json"
        report_data = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "checkov"
                        }
                    }
                    # Missing results key
                }
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = CheckovParser(
            report_directory=str(tmp_path),
            report_filename="checkov.json"
        )
        
        results = parser._get_results_from_sarif()
        assert results == []
    
    def test_parser_missing_rule_id_handled(self, tmp_path):
        """Test that missing ruleId doesn't crash parser."""
        report_file = tmp_path / "checkov.json"
        report_data = {
            "runs": [
                {
                    "results": [
                        {
                            # Missing ruleId
                            "level": "error",
                            "message": {
                                "text": "Test finding"
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "src/file.py"
                                        },
                                        "region": {
                                            "startLine": 10
                                        }
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = CheckovParser(
            report_directory=str(tmp_path),
            report_filename="checkov.json"
        )
        
        # Should not crash
        assert parser.data is not None
        findings = parser.findings_that_exceed_threshold("high")
        # Missing ruleId shouldn't prevent threshold check
        assert len(findings) >= 0
    
    def test_parser_null_fields_handled_gracefully(self, tmp_path):
        """Test that null values in expected fields don't crash."""
        report_file = tmp_path / "checkov.json"
        report_data = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": None,  # Null value
                            "level": "error",
                            "message": None,  # Null value
                            "locations": []
                        }
                    ]
                }
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = CheckovParser(
            report_directory=str(tmp_path),
            report_filename="checkov.json"
        )
        
        # Should not crash
        assert parser.data is not None
        findings = parser.findings_that_exceed_threshold("high")
        # Should handle null gracefully
        assert len(findings) >= 0
    
    def test_parser_extra_fields_ignored_without_crash(self, tmp_path):
        """Test that unexpected extra fields are ignored."""
        report_file = tmp_path / "checkov.json"
        report_data = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "CKV_AWS_123",
                            "level": "error",
                            "message": {"text": "Test finding"},
                            "unexpected_field": "should be ignored",
                            "another_unexpected": {"nested": "data"}
                        }
                    ]
                }
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = CheckovParser(
            report_directory=str(tmp_path),
            report_filename="checkov.json"
        )
        
        # Should not crash, extra fields preserved in data
        assert parser.data is not None
        assert "unexpected_field" in parser.data["runs"][0]["results"][0]
    
    def test_parser_empty_results_array_handled(self, tmp_path):
        """Test that empty results array is handled correctly."""
        report_file = tmp_path / "checkov.json"
        report_data = {
            "runs": [
                {
                    "results": []
                }
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = CheckovParser(
            report_directory=str(tmp_path),
            report_filename="checkov.json"
        )
        
        results = parser._get_results_from_sarif()
        assert results == []
        findings = parser.findings_that_exceed_threshold("low")
        assert findings == []

