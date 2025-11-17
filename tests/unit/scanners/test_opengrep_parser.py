"""Unit tests for OpenGrep (SAST) parser/normalizer."""

import json
import pytest
from pathlib import Path
from syrupy import SnapshotAssertion

from dsoinabox.reporting.opengrep import fingerprint_findings


@pytest.fixture
def opengrep_fixture(golden_dir):
    """Load OpenGrep fixture JSON."""
    fixture_path = golden_dir / "scanner_outputs" / "opengrep.json"
    with open(fixture_path) as f:
        return json.load(f)


@pytest.fixture
def tmp_source_dir(tmp_path):
    """Create a temporary source directory with sample files for fingerprinting."""
    # The fixture uses paths like "src/main.py", so we need src/ subdirectory
    source_dir = tmp_path
    src_dir = source_dir / "src"
    src_dir.mkdir()
    
    # Create sample files referenced in the fixture
    (src_dir / "main.py").write_text("""import tempfile

def process_data(user_input):
    data = user_input
    temp_file = tempfile.mkstemp()
    return data
""")
    
    (src_dir / "utils.py").write_text("""import hashlib

def hash_password(password):
    key = hashlib.md5(password.encode()).hexdigest()
    return key
""")
    
    return str(source_dir)


class TestOpenGrepParserNormalization:
    """Test OpenGrep parser normalization and fingerprinting."""
    
    def test_fingerprint_findings_adds_fingerprints(self, opengrep_fixture, tmp_source_dir):
        """Test that fingerprint_findings adds fingerprints to all findings."""
        result = fingerprint_findings(opengrep_fixture, tmp_source_dir)
        
        assert "results" in result
        assert len(result["results"]) > 0
        
        for finding in result["results"]:
            assert "fingerprints" in finding
            assert isinstance(finding["fingerprints"], dict)
            assert "rule" in finding["fingerprints"]
            assert "exact" in finding["fingerprints"]
            assert "ctx" in finding["fingerprints"]
    
    def test_fingerprint_format(self, opengrep_fixture, tmp_source_dir):
        """Test that fingerprints follow the expected format."""
        result = fingerprint_findings(opengrep_fixture, tmp_source_dir)
        
        for finding in result["results"]:
            fps = finding["fingerprints"]
            
            # Rule fingerprint format: og:1:RULE:<rule_id>:<hmac>[:R:<repo_hint>]
            assert fps["rule"].startswith("og:1:RULE:")
            
            # Exact fingerprint format: og:1:EXACT:<rule_id>:<file_sha>:<start_b>:<end_b>[:R:<repo_hint>]
            assert fps["exact"].startswith("og:1:EXACT:")
            
            # Context fingerprint format: og:1:CTX:<rule_id>:<path_sha>:<context_hash>[:R:<repo_hint>]
            assert fps["ctx"].startswith("og:1:CTX:")
    
    def test_normalized_schema_fields(self, opengrep_fixture, tmp_source_dir):
        """Test that findings have all normalized schema fields."""
        result = fingerprint_findings(opengrep_fixture, tmp_source_dir)
        
        for finding in result["results"]:
            # Required fields from original schema
            assert "check_id" in finding or "rule_id" in finding
            assert "path" in finding
            assert "extra" in finding
            
            # Severity should be in extra
            assert "severity" in finding.get("extra", {})
            
            # Fingerprints (added by normalizer)
            assert "fingerprints" in finding
            assert isinstance(finding["fingerprints"], dict)
    
    @pytest.mark.parametrize("field", [
        "check_id",
        "path",
        "extra",
    ])
    def test_required_fields_present(self, opengrep_fixture, tmp_source_dir, field):
        """Test that required fields are present in findings."""
        result = fingerprint_findings(opengrep_fixture, tmp_source_dir)
        
        for finding in result["results"]:
            if field == "extra":
                assert field in finding
            else:
                # check_id might be rule_id in some formats
                if field == "check_id":
                    assert "check_id" in finding or "rule_id" in finding
                else:
                    assert field in finding
    
    def test_severity_values(self, opengrep_fixture, tmp_source_dir):
        """Test that severity values are normalized correctly."""
        result = fingerprint_findings(opengrep_fixture, tmp_source_dir)
        
        valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "ERROR", "WARNING", "INFO"}
        
        for finding in result["results"]:
            severity = finding.get("extra", {}).get("severity", "").upper()
            # Severity should be one of the valid values (case-insensitive check)
            assert severity in valid_severities or severity == ""
    
    def test_snapshot_normalized_findings(self, opengrep_fixture, tmp_source_dir, snapshot: SnapshotAssertion):
        """Snapshot test for normalized findings (golden example)."""
        result = fingerprint_findings(opengrep_fixture, tmp_source_dir)
        
        # Extract normalized findings for snapshot
        normalized = []
        for finding in result["results"]:
            normalized.append({
                "tool": "opengrep",
                "rule_id": finding.get("check_id") or finding.get("rule_id", "unknown"),
                "severity": finding.get("extra", {}).get("severity", "unknown"),
                "file": finding.get("path", ""),
                "line": finding.get("start", {}).get("line") or finding.get("line"),
                "message": finding.get("message", ""),
                "fingerprint": finding.get("fingerprints", {}).get("rule", ""),
                "extras": {
                    "check_id": finding.get("check_id"),
                    "end_line": finding.get("end", {}).get("line"),
                }
            })
        
        assert normalized == snapshot


class TestOpenGrepParserEdgeCases:
    """Test edge cases for OpenGrep parser."""
    
    def test_empty_results(self, tmp_source_dir):
        """Test handling of empty results."""
        empty_data = {
            "version": "1.0.0",
            "results": [],
            "paths": {"scanned": []},
            "errors": []
        }
        
        result = fingerprint_findings(empty_data, tmp_source_dir)
        
        assert "results" in result
        assert len(result["results"]) == 0
    
    def test_missing_extra_field(self, tmp_source_dir):
        """Test handling of findings with missing extra field."""
        source_dir = tmp_source_dir
        test_file = Path(source_dir) / "src" / "file.py"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("test code here\n")
        
        data_with_missing_extra = {
            "version": "1.0.0",
            "results": [
                {
                    "check_id": "test.rule.id",
                    "path": "src/file.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 10},
                    # Missing "extra" field
                }
            ]
        }
        
        # Should not raise an error, but may have issues with severity
        result = fingerprint_findings(data_with_missing_extra, source_dir)
        
        assert len(result["results"]) == 1
        finding = result["results"][0]
        # Fingerprints should still be added
        assert "fingerprints" in finding
    
    def test_unknown_severity_string(self, tmp_source_dir):
        """Test handling of unknown severity strings."""
        source_dir = tmp_source_dir
        test_file = Path(source_dir) / "src" / "file.py"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("test code\n")
        
        data_with_unknown_severity = {
            "version": "1.0.0",
            "results": [
                {
                    "check_id": "test.rule.id",
                    "path": "src/file.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 10},
                    "extra": {
                        "severity": "UNKNOWN_SEVERITY_XYZ",
                        "message": "Test finding",
                        "lines": "test code"
                    }
                }
            ]
        }
        
        result = fingerprint_findings(data_with_unknown_severity, source_dir)
        
        assert len(result["results"]) == 1
        finding = result["results"][0]
        # Should still process and add fingerprints
        assert "fingerprints" in finding
        # Unknown severity should be preserved
        assert finding.get("extra", {}).get("severity") == "UNKNOWN_SEVERITY_XYZ"
    
    def test_missing_path_field(self, tmp_source_dir):
        """Test handling of findings with missing path field."""
        data_with_missing_path = {
            "version": "1.0.0",
            "results": [
                {
                    "check_id": "test.rule.id",
                    # Missing "path" field
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 10},
                    "extra": {
                        "severity": "HIGH",
                        "message": "Test finding"
                    }
                }
            ]
        }
        
        # Should handle gracefully and mark as unlocatable
        result = fingerprint_findings(data_with_missing_path, tmp_source_dir)
        assert len(result["results"]) == 1
        finding = result["results"][0]
        # Should have fingerprints with unlocatable markers
        assert "fingerprints" in finding
        assert finding["fingerprints"]["exact"].endswith("<unlocatable>")
        assert finding["fingerprints"]["ctx"].endswith("<unlocatable>")
    
    def test_missing_start_end_fields(self, tmp_source_dir):
        """Test handling of findings with missing start/end fields."""
        source_dir = tmp_source_dir
        test_file = Path(source_dir) / "src" / "test.py"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("test code here")
        
        data_with_missing_span = {
            "version": "1.0.0",
            "results": [
                {
                    "check_id": "test.rule.id",
                    "path": "src/test.py",
                    # Missing "start" and "end" fields
                    "extra": {
                        "severity": "HIGH",
                        "message": "Test finding",
                        "lines": "test code"
                    }
                }
            ]
        }
        
        # Should handle gracefully, using snippet to locate
        result = fingerprint_findings(data_with_missing_span, source_dir)
        
        assert len(result["results"]) == 1
        finding = result["results"][0]
        # Fingerprints should still be added (may use fallback logic)
        assert "fingerprints" in finding


class TestOpenGrepParserRobustness:
    """Test robustness against schema drift and unexpected fields."""
    
    def test_unexpected_top_level_fields(self, opengrep_fixture, tmp_source_dir):
        """Test that unexpected top-level fields are ignored."""
        data_with_extra = opengrep_fixture.copy()
        data_with_extra["unexpected_field"] = "should be ignored"
        data_with_extra["another_unexpected"] = {"nested": "data"}
        
        result = fingerprint_findings(data_with_extra, tmp_source_dir)
        
        # Should still process normally
        assert "results" in result
        assert len(result["results"]) > 0
        
        # Unexpected fields may or may not be preserved (implementation dependent)
        # But processing should not fail
    
    def test_unexpected_finding_fields(self, opengrep_fixture, tmp_source_dir):
        """Test that unexpected fields in findings are preserved but don't break processing."""
        data_with_extra = opengrep_fixture.copy()
        if data_with_extra["results"]:
            data_with_extra["results"][0]["unexpected_field"] = "should be preserved"
            data_with_extra["results"][0]["nested_unexpected"] = {"key": "value"}
        
        result = fingerprint_findings(data_with_extra, tmp_source_dir)
        
        # Should still process normally
        assert len(result["results"]) > 0
        
        # Unexpected fields should be preserved
        if result["results"]:
            assert "unexpected_field" in result["results"][0]
            assert "nested_unexpected" in result["results"][0]
            # Fingerprints should still be added
            assert "fingerprints" in result["results"][0]
    
    def test_schema_drift_in_extra(self, tmp_source_dir):
        """Test handling of schema drift in extra field."""
        source_dir = tmp_source_dir
        test_file = Path(source_dir) / "src" / "test.py"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("test code")
        
        data_with_drift = {
            "version": "1.0.0",
            "results": [
                {
                    "check_id": "test.rule.id",
                    "path": "src/test.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 10},
                    "extra": {
                        "severity": "HIGH",
                        "message": "Test finding",
                        "lines": "test code",
                        # Unexpected fields in extra
                        "new_field_v2": "new value",
                        "metadata_v3": {"new": "structure"}
                    }
                }
            ]
        }
        
        result = fingerprint_findings(data_with_drift, source_dir)
        
        # Should process successfully
        assert len(result["results"]) == 1
        finding = result["results"][0]
        assert "fingerprints" in finding
        
        # New fields should be preserved
        assert "new_field_v2" in finding.get("extra", {})
        assert "metadata_v3" in finding.get("extra", {})
    
    def test_null_values(self, tmp_source_dir):
        """Test handling of null values in fields."""
        source_dir = tmp_source_dir
        test_file = Path(source_dir) / "src" / "test.py"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("test code")
        
        data_with_nulls = {
            "version": "1.0.0",
            "results": [
                {
                    "check_id": "test.rule.id",
                    "path": "src/test.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 10},
                    "extra": {
                        "severity": "HIGH",
                        "message": None,  # Null message
                        "lines": "test code",
                        "metavars": None  # Null metavars
                    }
                }
            ]
        }
        
        result = fingerprint_findings(data_with_nulls, source_dir)
        
        # Should handle nulls gracefully
        assert len(result["results"]) == 1
        finding = result["results"][0]
        assert "fingerprints" in finding

