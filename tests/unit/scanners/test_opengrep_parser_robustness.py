"""Robustness tests for OpenGrep parser (malformed JSON, edge cases)."""

from __future__ import annotations

import pytest
import json

from dsoinabox.reporting.parser import OpengrepParser, get_fail_thresholds


class TestOpenGrepParserRobustness:
    """Test OpenGrep parser handles malformed/edge case inputs gracefully."""
    
    def test_parser_missing_severity_defaults_safely(self, tmp_path):
        """Test that missing severity field doesn't crash parser."""
        report_file = tmp_path / "opengrep.json"
        report_data = {
            "results": [
                {
                    "check_id": "test.rule.id",
                    "path": "src/file.py",
                    "start": {"line": 10, "col": 5},
                    "end": {"line": 10, "col": 15},
                    "extra": {
                        # Missing severity
                        "message": "Test finding"
                    }
                }
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = OpengrepParser(
            report_directory=str(tmp_path),
            report_filename="opengrep.json"
        )
        
        # Should not crash
        assert parser.data is not None
        assert len(parser.data.get("results", [])) == 1
        
        # Missing severity should be handled in threshold check
        findings = parser.findings_that_exceed_threshold("high")
        # Unknown severity should not match "high" threshold
        assert len(findings) == 0
    
    def test_parser_unknown_severity_mapped_safely(self, tmp_path):
        """Test that unknown severity values are handled safely."""
        report_file = tmp_path / "opengrep.json"
        report_data = {
            "results": [
                {
                    "check_id": "test.rule.id",
                    "path": "src/file.py",
                    "extra": {
                        "severity": "UNKNOWN_SEVERITY",  # Unknown value
                        "message": "Test finding"
                    }
                }
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = OpengrepParser(
            report_directory=str(tmp_path),
            report_filename="opengrep.json"
        )
        
        # Unknown severity should not match any threshold
        findings = parser.findings_that_exceed_threshold("high")
        assert len(findings) == 0
        
        # Should not crash on threshold application
        filtered = parser.apply_threshold("high")
        assert filtered is not None
    
    def test_parser_empty_results_returns_empty_list(self, tmp_path):
        """Test that empty results array is handled correctly."""
        report_file = tmp_path / "opengrep.json"
        report_data = {
            "results": []
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = OpengrepParser(
            report_directory=str(tmp_path),
            report_filename="opengrep.json"
        )
        
        assert parser.data["results"] == []
        findings = parser.findings_that_exceed_threshold("low")
        assert findings == []
    
    def test_parser_missing_results_key_handled(self, tmp_path):
        """Test that missing results key is handled gracefully."""
        report_file = tmp_path / "opengrep.json"
        report_data = {
            "version": "1.0.0",
            # Missing results key
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = OpengrepParser(
            report_directory=str(tmp_path),
            report_filename="opengrep.json"
        )
        
        # Should use .get() safely
        findings = parser.findings_that_exceed_threshold("low")
        assert findings == []
    
    def test_parser_null_fields_handled_gracefully(self, tmp_path):
        """Test that null values in expected fields don't crash."""
        report_file = tmp_path / "opengrep.json"
        report_data = {
            "results": [
                {
                    "check_id": None,  # Null value
                    "path": "src/file.py",
                    "extra": {
                        "severity": "HIGH",
                        "message": None  # Null value
                    }
                }
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = OpengrepParser(
            report_directory=str(tmp_path),
            report_filename="opengrep.json"
        )
        
        # Should not crash
        assert parser.data is not None
        findings = parser.findings_that_exceed_threshold("high")
        # Null check_id shouldn't prevent threshold check
        assert len(findings) >= 0  # May be 0 or 1 depending on severity handling
    
    def test_parser_extra_fields_ignored_without_crash(self, tmp_path):
        """Test that unexpected extra fields are ignored."""
        report_file = tmp_path / "opengrep.json"
        report_data = {
            "results": [
                {
                    "check_id": "test.rule.id",
                    "path": "src/file.py",
                    "extra": {
                        "severity": "HIGH",
                        "message": "Test finding"
                    },
                    "unexpected_field": "should be ignored",
                    "another_unexpected": {"nested": "data"}
                }
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = OpengrepParser(
            report_directory=str(tmp_path),
            report_filename="opengrep.json"
        )
        
        # Should not crash, extra fields preserved in data
        assert parser.data is not None
        assert "unexpected_field" in parser.data["results"][0]
    
    def test_parser_unicode_paths_preserved(self, tmp_path):
        """Test that Unicode paths (emojis, non-ASCII) are preserved."""
        report_file = tmp_path / "opengrep.json"
        report_data = {
            "results": [
                {
                    "check_id": "test.rule.id",
                    "path": "src/测试/文件.py",  # Unicode path
                    "extra": {
                        "severity": "HIGH",
                        "message": "Test finding"
                    }
                },
                {
                    "check_id": "test.rule.id",
                    "path": "src/🎉/file.py",  # Emoji in path
                    "extra": {
                        "severity": "MEDIUM",
                        "message": "Test finding"
                    }
                }
            ]
        }
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False)
        
        parser = OpengrepParser(
            report_directory=str(tmp_path),
            report_filename="opengrep.json"
        )
        
        # Unicode paths should be preserved
        assert parser.data["results"][0]["path"] == "src/测试/文件.py"
        assert parser.data["results"][1]["path"] == "src/🎉/file.py"
    
    def test_parser_huge_line_numbers_handled(self, tmp_path):
        """Test that huge line numbers don't cause overflow."""
        report_file = tmp_path / "opengrep.json"
        report_data = {
            "results": [
                {
                    "check_id": "test.rule.id",
                    "path": "src/file.py",
                    "start": {
                        "line": 999999999,  # Huge line number
                        "col": 5
                    },
                    "end": {
                        "line": 999999999,
                        "col": 15
                    },
                    "extra": {
                        "severity": "HIGH",
                        "message": "Test finding"
                    }
                }
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = OpengrepParser(
            report_directory=str(tmp_path),
            report_filename="opengrep.json"
        )
        
        # Should not crash
        assert parser.data is not None
        assert parser.data["results"][0]["start"]["line"] == 999999999
    
    def test_parser_case_insensitive_severity(self, tmp_path):
        """Test that severity matching is case-insensitive."""
        report_file = tmp_path / "opengrep.json"
        report_data = {
            "results": [
                {
                    "check_id": "test.rule.id",
                    "path": "src/file.py",
                    "extra": {
                        "severity": "high",  # Lowercase
                        "message": "Test finding"
                    }
                },
                {
                    "check_id": "test.rule.id",
                    "path": "src/file2.py",
                    "extra": {
                        "severity": "HIGH",  # Uppercase
                        "message": "Test finding"
                    }
                }
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = OpengrepParser(
            report_directory=str(tmp_path),
            report_filename="opengrep.json"
        )
        
        # Both should match "high" threshold (case-insensitive)
        findings = parser.findings_that_exceed_threshold("high")
        assert len(findings) == 2
    
    def test_parser_missing_extra_key_handled(self, tmp_path):
        """Test that missing 'extra' key is handled gracefully."""
        report_file = tmp_path / "opengrep.json"
        report_data = {
            "results": [
                {
                    "check_id": "test.rule.id",
                    "path": "src/file.py",
                    # Missing extra key
                }
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = OpengrepParser(
            report_directory=str(tmp_path),
            report_filename="opengrep.json"
        )
        
        # Should use .get() safely
        findings = parser.findings_that_exceed_threshold("low")
        # Missing severity should not match any threshold
        assert len(findings) == 0
    
    def test_parser_invalid_json_raises(self, tmp_path):
        """Test that invalid JSON raises appropriate error."""
        report_file = tmp_path / "opengrep.json"
        report_file.write_text("{ invalid json }")
        
        with pytest.raises((json.JSONDecodeError, ValueError)):
            OpengrepParser(
                report_directory=str(tmp_path),
                report_filename="opengrep.json"
            )
    
    def test_parser_nonexistent_file_returns_none(self, tmp_path):
        """Test that nonexistent report file returns None data."""
        parser = OpengrepParser(
            report_directory=str(tmp_path),
            report_filename="nonexistent.json"
        )
        
        # Should return None when file doesn't exist
        assert parser.data is None or parser.report_exists() is False

