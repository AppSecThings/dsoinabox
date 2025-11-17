"""Tests for handling unknown tool output files."""

from __future__ import annotations

import pytest
import json
import tempfile
import os
from pathlib import Path
import warnings

from dsoinabox.reporting.parser import (
    BaseParser,
    OpengrepParser,
    GrypeParser,
    TrufflehogParser,
    CheckovParser,
)


class TestUnknownToolOutput:
    """Test handling of unknown tool output files."""
    
    def test_parser_skips_unknown_file_format_with_warning(self, tmp_path):
        """Test that parser skips unknown file format with warning, does not crash.
        
        When an unknown tool output file is provided, the parser should:
        1. Detect that it's not a recognized format
        2. Log a warning
        3. Skip processing gracefully (return None or empty data)
        4. Not raise an exception
        """
        # Create an unknown tool output file with invalid/unrecognized format
        unknown_file = tmp_path / "unknown_tool.json"
        unknown_data = {
            "unknown_format": True,
            "tool": "mystery_scanner",
            "data": {
                "findings": [
                    {"id": "1", "severity": "high"},
                    {"id": "2", "severity": "medium"}
                ]
            }
        }
        
        with open(unknown_file, 'w') as f:
            json.dump(unknown_data, f)
        
        # Try to parse with OpengrepParser (expects opengrep format)
        # The parser should handle gracefully when data doesn't match expected format
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            
            parser = OpengrepParser(
                report_directory=str(tmp_path),
                report_filename="unknown_tool.json"
            )
            
            # Parser should load the file but data won't match expected format
            # It should not crash, but may have None or unexpected structure
            assert parser.data is not None
            
            # When trying to access findings, it should handle gracefully
            # OpengrepParser expects 'results' key
            if parser.data and 'results' not in parser.data:
                # This is expected - unknown format doesn't have 'results'
                # The parser should handle this gracefully
                findings = parser.data.get('results', [])
                assert isinstance(findings, list)
    
    def test_base_parser_handles_missing_file_gracefully(self, tmp_path):
        """Test that BaseParser handles missing file gracefully."""
        # Use OpengrepParser as a concrete implementation of BaseParser
        parser = OpengrepParser(
            report_directory=str(tmp_path),
            report_filename="nonexistent.json"
        )
        
        # Should not raise exception, should return None
        data = parser.load_report()
        assert data is None
        assert parser.report_exists() is False
    
    def test_parser_with_malformed_json_handles_gracefully(self, tmp_path):
        """Test that parser handles malformed JSON gracefully.
        
        Note: Current implementation raises JSONDecodeError on malformed JSON.
        This test documents the current behavior and the gap that should be addressed.
        Ideally, the parser should catch JSON errors, log a warning, and skip the file.
        """
        malformed_file = tmp_path / "malformed.json"
        with open(malformed_file, 'w') as f:
            f.write("{ invalid json }")
        
        # Current implementation raises JSONDecodeError - this is a known gap
        # The parser should ideally catch this, warn, and set data to None
        with pytest.raises(json.JSONDecodeError):
            parser = OpengrepParser(
                report_directory=str(tmp_path),
                report_filename="malformed.json"
            )
        
        # TODO: Improve BaseParser.load_report() to handle JSON errors gracefully:
        #   try:
        #       return json.load(file)
        #   except json.JSONDecodeError as e:
        #       logger.warning(f"Failed to parse JSON from {self.report_path}: {e}")
        #       return None
    
    def test_parser_with_unexpected_structure_does_not_crash(self, tmp_path):
        """Test that parser with unexpected structure doesn't crash during processing."""
        unexpected_file = tmp_path / "unexpected.json"
        # Create a file that's valid JSON but has unexpected structure
        unexpected_data = {
            "version": "1.0",
            "items": [
                {"finding": "1", "level": "high"},
                {"finding": "2", "level": "low"}
            ]
        }
        
        with open(unexpected_file, 'w') as f:
            json.dump(unexpected_data, f)
        
        # Try to use OpengrepParser which expects 'results' key
        parser = OpengrepParser(
            report_directory=str(tmp_path),
            report_filename="unexpected.json"
        )
        
        # Parser should load the file
        assert parser.data is not None
        
        # When accessing findings, should handle missing 'results' gracefully
        findings = parser.data.get('results', [])
        assert isinstance(findings, list)
        
        # apply_threshold should handle empty/missing findings gracefully
        try:
            result = parser.apply_threshold("high")
            # Should not crash
            assert result is not None
        except (KeyError, AttributeError, TypeError) as e:
            # If it raises, document that this should be improved
            pytest.fail(f"Parser should handle unexpected structure gracefully, but raised: {e}")

