"""Unit tests for Grype (SCA) parser/normalizer."""

import json
import pytest
from pathlib import Path

from dsoinabox.reporting.grype import fingerprint_findings


@pytest.fixture
def grype_fixture(golden_dir):
    """Load Grype fixture JSON."""
    fixture_path = golden_dir / "scanner_outputs" / "grype.json"
    with open(fixture_path) as f:
        return json.load(f)


class TestGrypeParserNormalization:
    """Test Grype parser normalization and fingerprinting."""
    
    def test_fingerprint_findings_adds_fingerprints(self, grype_fixture):
        """Test that fingerprint_findings adds fingerprints to all matches."""
        result = fingerprint_findings(grype_fixture)
        
        assert "matches" in result
        assert len(result["matches"]) > 0
        
        for match in result["matches"]:
            assert "fingerprints" in match
            assert isinstance(match["fingerprints"], dict)
            assert "pkg" in match["fingerprints"]
            assert "exact" in match["fingerprints"]
            assert "ctx" in match["fingerprints"]
    
    def test_fingerprint_format(self, grype_fixture):
        """Test that fingerprints follow the expected format."""
        result = fingerprint_findings(grype_fixture)
        
        for match in result["matches"]:
            fps = match["fingerprints"]
            
            # PKG fingerprint format: gy:1:PKG:<vuln_id>:<hmac>[:R:<repo_hint>]
            assert fps["pkg"].startswith("gy:1:PKG:")
            
            # EXACT fingerprint format: gy:1:EXACT:<vuln_id>:<src8>:<locs8>:<pver8>[:R:<repo_hint>]
            assert fps["exact"].startswith("gy:1:EXACT:")
            
            # CTX fingerprint format: gy:1:CTX:<vuln_id>:<pkg8>:<ctx16>[:R:<repo_hint>]
            assert fps["ctx"].startswith("gy:1:CTX:")
    
    def test_normalized_schema_fields(self, grype_fixture):
        """Test that matches have all normalized schema fields."""
        result = fingerprint_findings(grype_fixture)
        
        for match in result["matches"]:
            # Required fields from original schema
            assert "vulnerability" in match
            assert "artifact" in match
            
            vuln = match["vulnerability"]
            assert "id" in vuln
            assert "severity" in vuln
            
            artifact = match["artifact"]
            assert "name" in artifact
            assert "version" in artifact
            assert "type" in artifact
            
            # Fingerprints (added by normalizer)
            assert "fingerprints" in match
            assert isinstance(match["fingerprints"], dict)
    
    @pytest.mark.parametrize("field", [
        "vulnerability",
        "artifact",
    ])
    def test_required_fields_present(self, grype_fixture, field):
        """Test that required fields are present in matches."""
        result = fingerprint_findings(grype_fixture)
        
        for match in result["matches"]:
            assert field in match
    
    def test_severity_values(self, grype_fixture):
        """Test that severity values are present and valid."""
        result = fingerprint_findings(grype_fixture)
        
        valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "NEGLIGIBLE", "UNKNOWN"}
        
        for match in result["matches"]:
            severity = match.get("vulnerability", {}).get("severity", "").upper()
            # Severity should be one of the valid values or empty
            assert severity in valid_severities or severity == ""
    
    def test_vulnerability_id_format(self, grype_fixture):
        """Test that vulnerability IDs are present and formatted correctly."""
        result = fingerprint_findings(grype_fixture)
        
        for match in result["matches"]:
            vuln_id = match.get("vulnerability", {}).get("id", "")
            # Should be a CVE or similar identifier
            assert vuln_id != ""
            # Typically starts with CVE- or similar
            assert len(vuln_id) > 0


class TestGrypeParserEdgeCases:
    """Test edge cases for Grype parser."""
    
    def test_empty_matches(self):
        """Test handling of empty matches."""
        empty_data = {
            "matches": [],
            "source": {
                "type": "directory",
                "target": {
                    "userInput": "/path/to/project"
                }
            }
        }
        
        result = fingerprint_findings(empty_data)
        
        assert "matches" in result
        assert len(result["matches"]) == 0
    
    def test_missing_vulnerability_field(self):
        """Test handling of matches with missing vulnerability field."""
        data_with_missing_vuln = {
            "matches": [
                {
                    "artifact": {
                        "name": "test-package",
                        "version": "1.0.0",
                        "type": "python"
                    }
                    # Missing "vulnerability" field
                }
            ]
        }
        
        # Should handle gracefully
        result = fingerprint_findings(data_with_missing_vuln)
        
        assert len(result["matches"]) == 1
        match = result["matches"][0]
        # Fingerprints should still be added (may use fallback)
        assert "fingerprints" in match
    
    def test_missing_artifact_field(self):
        """Test handling of matches with missing artifact field."""
        data_with_missing_artifact = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2023-12345",
                        "severity": "HIGH"
                    }
                    # Missing "artifact" field
                }
            ]
        }
        
        # Should handle gracefully
        result = fingerprint_findings(data_with_missing_artifact)
        
        assert len(result["matches"]) == 1
        match = result["matches"][0]
        # Fingerprints should still be added (may use fallback)
        assert "fingerprints" in match
    
    def test_unknown_severity_string(self):
        """Test handling of unknown severity strings."""
        data_with_unknown_severity = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2023-12345",
                        "severity": "UNKNOWN_SEVERITY_XYZ",
                        "description": "Test vulnerability"
                    },
                    "artifact": {
                        "name": "test-package",
                        "version": "1.0.0",
                        "type": "python",
                        "locations": [{"path": "requirements.txt"}]
                    }
                }
            ]
        }
        
        result = fingerprint_findings(data_with_unknown_severity)
        
        assert len(result["matches"]) == 1
        match = result["matches"][0]
        # Should still process and add fingerprints
        assert "fingerprints" in match
        # Unknown severity should be preserved
        assert match.get("vulnerability", {}).get("severity") == "UNKNOWN_SEVERITY_XYZ"
    
    def test_missing_locations(self):
        """Test handling of artifacts with missing locations."""
        data_with_missing_locations = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2023-12345",
                        "severity": "HIGH"
                    },
                    "artifact": {
                        "name": "test-package",
                        "version": "1.0.0",
                        "type": "python"
                        # Missing "locations" field
                    }
                }
            ]
        }
        
        result = fingerprint_findings(data_with_missing_locations)
        
        assert len(result["matches"]) == 1
        match = result["matches"][0]
        # Should still process
        assert "fingerprints" in match
    
    def test_empty_locations(self):
        """Test handling of artifacts with empty locations list."""
        data_with_empty_locations = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2023-12345",
                        "severity": "HIGH"
                    },
                    "artifact": {
                        "name": "test-package",
                        "version": "1.0.0",
                        "type": "python",
                        "locations": []  # Empty locations
                    }
                }
            ]
        }
        
        result = fingerprint_findings(data_with_empty_locations)
        
        assert len(result["matches"]) == 1
        match = result["matches"][0]
        # Should still process
        assert "fingerprints" in match


class TestGrypeParserRobustness:
    """Test robustness against schema drift and unexpected fields."""
    
    def test_unexpected_top_level_fields(self, grype_fixture):
        """Test that unexpected top-level fields are ignored."""
        data_with_extra = grype_fixture.copy()
        data_with_extra["unexpected_field"] = "should be ignored"
        data_with_extra["another_unexpected"] = {"nested": "data"}
        
        result = fingerprint_findings(data_with_extra)
        
        # Should still process normally
        assert "matches" in result
        assert len(result["matches"]) > 0
    
    def test_unexpected_match_fields(self, grype_fixture):
        """Test that unexpected fields in matches are preserved but don't break processing."""
        data_with_extra = grype_fixture.copy()
        if data_with_extra["matches"]:
            data_with_extra["matches"][0]["unexpected_field"] = "should be preserved"
            data_with_extra["matches"][0]["nested_unexpected"] = {"key": "value"}
        
        result = fingerprint_findings(data_with_extra)
        
        # Should still process normally
        assert len(result["matches"]) > 0
        
        # Unexpected fields should be preserved
        if result["matches"]:
            assert "unexpected_field" in result["matches"][0]
            assert "nested_unexpected" in result["matches"][0]
            # Fingerprints should still be added
            assert "fingerprints" in result["matches"][0]
    
    def test_schema_drift_in_vulnerability(self, grype_fixture):
        """Test handling of schema drift in vulnerability field."""
        data_with_drift = grype_fixture.copy()
        if data_with_drift["matches"]:
            data_with_drift["matches"][0]["vulnerability"]["new_field_v2"] = "new value"
            data_with_drift["matches"][0]["vulnerability"]["metadata_v3"] = {"new": "structure"}
        
        result = fingerprint_findings(data_with_drift)
        
        # Should process successfully
        assert len(result["matches"]) > 0
        match = result["matches"][0]
        assert "fingerprints" in match
        
        # New fields should be preserved
        assert "new_field_v2" in match.get("vulnerability", {})
        assert "metadata_v3" in match.get("vulnerability", {})
    
    def test_schema_drift_in_artifact(self, grype_fixture):
        """Test handling of schema drift in artifact field."""
        data_with_drift = grype_fixture.copy()
        if data_with_drift["matches"]:
            data_with_drift["matches"][0]["artifact"]["new_field_v2"] = "new value"
            data_with_drift["matches"][0]["artifact"]["metadata_v3"] = {"new": "structure"}
        
        result = fingerprint_findings(data_with_drift)
        
        # Should process successfully
        assert len(result["matches"]) > 0
        match = result["matches"][0]
        assert "fingerprints" in match
        
        # New fields should be preserved
        assert "new_field_v2" in match.get("artifact", {})
        assert "metadata_v3" in match.get("artifact", {})
    
    def test_null_values(self):
        """Test handling of null values in fields."""
        data_with_nulls = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2023-12345",
                        "severity": "HIGH",
                        "description": None,  # Null description
                        "fix": None  # Null fix
                    },
                    "artifact": {
                        "name": "test-package",
                        "version": "1.0.0",
                        "type": "python",
                        "purl": None  # Null purl
                    }
                }
            ]
        }
        
        result = fingerprint_findings(data_with_nulls)
        
        # Should handle nulls gracefully
        assert len(result["matches"]) == 1
        match = result["matches"][0]
        assert "fingerprints" in match
    
    def test_missing_fix_versions(self):
        """Test handling of missing fix versions."""
        data_without_fix = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2023-12345",
                        "severity": "HIGH",
                        "fix": {
                            "state": "not-fixed"
                            # Missing "versions" field
                        }
                    },
                    "artifact": {
                        "name": "test-package",
                        "version": "1.0.0",
                        "type": "python"
                    }
                }
            ]
        }
        
        result = fingerprint_findings(data_without_fix)
        
        # Should handle missing fix versions gracefully
        assert len(result["matches"]) == 1
        match = result["matches"][0]
        assert "fingerprints" in match

