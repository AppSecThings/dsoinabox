"""Robustness tests for Trufflehog parser (malformed JSON, edge cases)."""

from __future__ import annotations

import pytest
import json

from dsoinabox.reporting.parser import TrufflehogParser


class TestTrufflehogParserRobustness:
    """Test Trufflehog parser handles malformed/edge case inputs gracefully."""
    
    def test_parser_empty_list_returns_empty(self, tmp_path):
        """Test that empty findings list is handled correctly."""
        report_file = tmp_path / "trufflehog.json"
        report_data = []  # Trufflehog uses list format
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f)
        
        parser = TrufflehogParser(
            report_directory=str(tmp_path),
            report_filename="trufflehog.json",
            data=report_data
        )
        
        assert parser.data == []
        findings = parser.findings_that_exceed_threshold("none")
        assert findings == []
    
    def test_parser_missing_detector_name_handled(self, tmp_path):
        """Test that missing DetectorName doesn't crash parser."""
        report_data = [
            {
                "RawV2": "secret_value",
                "SourceMetadata": {
                    "Data": {
                        "Git": {
                            "file": "src/file.py",
                            "line": 10
                        }
                    }
                }
                # Missing DetectorName
            }
        ]
        
        parser = TrufflehogParser(
            report_directory=str(tmp_path),
            report_filename="trufflehog.json",
            data=report_data
        )
        
        # Should not crash
        assert parser.data is not None
        assert len(parser.data) == 1
    
    def test_parser_missing_raw_fields_handled(self, tmp_path):
        """Test that missing Raw/RawV2 fields are handled."""
        report_data = [
            {
                "DetectorName": "URI",
                "SourceMetadata": {
                    "Data": {
                        "Git": {
                            "file": "src/file.py",
                            "line": 10
                        }
                    }
                }
                # Missing Raw and RawV2
            }
        ]
        
        parser = TrufflehogParser(
            report_directory=str(tmp_path),
            report_filename="trufflehog.json",
            data=report_data
        )
        
        # Should not crash
        assert parser.data is not None
    
    def test_parser_missing_source_metadata_handled(self, tmp_path):
        """Test that missing SourceMetadata is handled gracefully."""
        report_data = [
            {
                "DetectorName": "URI",
                "RawV2": "secret_value"
                # Missing SourceMetadata
            }
        ]
        
        parser = TrufflehogParser(
            report_directory=str(tmp_path),
            report_filename="trufflehog.json",
            data=report_data
        )
        
        # Should not crash
        assert parser.data is not None
        
        # get_trufflehog_file_path should handle missing metadata
        with pytest.raises(ValueError, match="Unable to determine file path"):
            parser.get_trufflehog_file_path(report_data[0])
    
    def test_parser_null_fields_handled_gracefully(self, tmp_path):
        """Test that null values in expected fields don't crash."""
        report_data = [
            {
                "DetectorName": None,  # Null value
                "RawV2": "secret_value",
                "SourceMetadata": {
                    "Data": {
                        "Git": {
                            "file": None,  # Null value
                            "line": 10
                        }
                    }
                }
            }
        ]
        
        parser = TrufflehogParser(
            report_directory=str(tmp_path),
            report_filename="trufflehog.json",
            data=report_data
        )
        
        # Should not crash
        assert parser.data is not None
    
    def test_parser_extra_fields_ignored_without_crash(self, tmp_path):
        """Test that unexpected extra fields are ignored."""
        report_data = [
            {
                "DetectorName": "URI",
                "RawV2": "secret_value",
                "SourceMetadata": {
                    "Data": {
                        "Git": {
                            "file": "src/file.py",
                            "line": 10
                        }
                    }
                },
                "unexpected_field": "should be ignored",
                "another_unexpected": {"nested": "data"}
            }
        ]
        
        parser = TrufflehogParser(
            report_directory=str(tmp_path),
            report_filename="trufflehog.json",
            data=report_data
        )
        
        # Should not crash, extra fields preserved in data
        assert parser.data is not None
        assert "unexpected_field" in parser.data[0]
    
    def test_parser_filesystem_source_handled(self, tmp_path):
        """Test that Filesystem source metadata is handled."""
        report_data = [
            {
                "DetectorName": "URI",
                "RawV2": "secret_value",
                "SourceMetadata": {
                    "Data": {
                        "Filesystem": {
                            "file_path": "src/file.py",
                            "base_path": "/scan_target",
                            "line": 10
                        }
                    }
                }
            }
        ]
        
        parser = TrufflehogParser(
            report_directory=str(tmp_path),
            report_filename="trufflehog.json",
            data=report_data
        )
        
        # Should extract path from Filesystem metadata
        file_path = parser.get_trufflehog_file_path(report_data[0])
        assert file_path is not None
        assert "file.py" in file_path or "<ROOT>" in file_path

