"""Unit tests for Checkov (IaC) parser/normalizer."""

import json
import pytest
from pathlib import Path

from dsoinabox.reporting.checkov import fingerprint_findings


@pytest.fixture
def checkov_fixture(golden_dir):
    """Load Checkov fixture JSON."""
    fixture_path = golden_dir / "scanner_outputs" / "checkov.json"
    with open(fixture_path) as f:
        return json.load(f)


class TestCheckovParserNormalization:
    """Test Checkov parser normalization and fingerprinting."""
    
    def test_fingerprint_findings_adds_fingerprints(self, checkov_fixture, tmp_path):
        """Test that fingerprint_findings adds fingerprints to all results."""
        source_path = str(tmp_path)
        result = fingerprint_findings(checkov_fixture, source_path)
        
        assert "runs" in result
        assert len(result["runs"]) > 0
        
        runs = result["runs"]
        for run in runs:
            assert "results" in run
            for result_item in run["results"]:
                assert "fingerprints" in result_item
                assert isinstance(result_item["fingerprints"], dict)
                assert "rule" in result_item["fingerprints"]
                assert "exact" in result_item["fingerprints"]
                assert "ctx" in result_item["fingerprints"]
    
    def test_fingerprint_format(self, checkov_fixture, tmp_path):
        """Test that fingerprints follow the expected format."""
        source_path = str(tmp_path)
        result = fingerprint_findings(checkov_fixture, source_path)
        
        runs = result["runs"]
        for run in runs:
            for result_item in run["results"]:
                fps = result_item["fingerprints"]
                
                # RULE fingerprint format: ck:1:RULE:<rule_id>:<hmac>[:R:<repo_hint>]
                assert fps["rule"].startswith("ck:1:RULE:")
                
                # EXACT fingerprint format: ck:1:EXACT:<rule_id>:<path_sha>:<start_line>:<end_line>[:R:<repo_hint>]
                assert fps["exact"].startswith("ck:1:EXACT:")
                
                # CTX fingerprint format: ck:1:CTX:<rule_id>:<path_sha>:<snippet_hash>[:R:<repo_hint>]
                assert fps["ctx"].startswith("ck:1:CTX:")
    
    def test_normalized_schema_fields(self, checkov_fixture, tmp_path):
        """Test that results have all normalized schema fields."""
        source_path = str(tmp_path)
        result = fingerprint_findings(checkov_fixture, source_path)
        
        runs = result["runs"]
        for run in runs:
            for result_item in run["results"]:
                # Required fields from SARIF schema
                assert "ruleId" in result_item or "ruleIndex" in result_item
                assert "level" in result_item
                assert "message" in result_item
                assert "locations" in result_item
                
                # Fingerprints (added by normalizer)
                assert "fingerprints" in result_item
                assert isinstance(result_item["fingerprints"], dict)
    
    @pytest.mark.parametrize("field", [
        "ruleId",
        "level",
        "message",
        "locations",
    ])
    def test_required_fields_present(self, checkov_fixture, tmp_path, field):
        """Test that required fields are present in results."""
        source_path = str(tmp_path)
        result = fingerprint_findings(checkov_fixture, source_path)
        
        runs = result["runs"]
        for run in runs:
            for result_item in run["results"]:
                if field == "ruleId":
                    # ruleId might be missing if using ruleIndex
                    assert "ruleId" in result_item or "ruleIndex" in result_item
                else:
                    assert field in result_item
    
    def test_severity_extraction(self, checkov_fixture, tmp_path):
        """Test that severity is extracted correctly from SARIF level."""
        from dsoinabox.reporting.checkov import _extract_severity
        
        source_path = str(tmp_path)
        result = fingerprint_findings(checkov_fixture, source_path)
        
        runs = result["runs"]
        for run in runs:
            for result_item in run["results"]:
                level = result_item.get("level", "error").lower()
                severity = _extract_severity(result_item, result)
                
                # Severity should be one of: info, low, medium, high, critical
                valid_severities = {"info", "low", "medium", "high", "critical"}
                assert severity.lower() in valid_severities
    
    def test_file_path_extraction(self, checkov_fixture, tmp_path):
        """Test that file paths are extracted correctly."""
        source_path = str(tmp_path)
        result = fingerprint_findings(checkov_fixture, source_path)
        
        runs = result["runs"]
        for run in runs:
            for result_item in run["results"]:
                locations = result_item.get("locations", [])
                if locations:
                    physical_location = locations[0].get("physicalLocation", {})
                    artifact_location = physical_location.get("artifactLocation", {})
                    uri = artifact_location.get("uri", "")
                    # URI should be present (may be relative or absolute)
                    assert isinstance(uri, str)


class TestCheckovParserEdgeCases:
    """Test edge cases for Checkov parser."""
    
    def test_empty_results(self, tmp_path):
        """Test handling of empty results."""
        empty_data = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Checkov",
                            "version": "2.1.0"
                        }
                    },
                    "results": []
                }
            ]
        }
        
        source_path = str(tmp_path)
        result = fingerprint_findings(empty_data, source_path)
        
        assert "runs" in result
        assert len(result["runs"]) > 0
        assert len(result["runs"][0]["results"]) == 0
    
    def test_missing_locations(self, tmp_path):
        """Test handling of results with missing locations."""
        data_with_missing_locations = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Checkov",
                            "rules": []
                        }
                    },
                    "results": [
                        {
                            "ruleId": "CKV_AWS_21",
                            "level": "error",
                            "message": {"text": "Test finding"}
                            # Missing "locations" field
                        }
                    ]
                }
            ]
        }
        
        source_path = str(tmp_path)
        result = fingerprint_findings(data_with_missing_locations, source_path)
        
        assert len(result["runs"]) > 0
        assert len(result["runs"][0]["results"]) == 1
        result_item = result["runs"][0]["results"][0]
        # Fingerprints should still be added
        assert "fingerprints" in result_item
    
    def test_unknown_severity_level(self, tmp_path):
        """Test handling of unknown SARIF level values."""
        data_with_unknown_level = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Checkov",
                            "rules": []
                        }
                    },
                    "results": [
                        {
                            "ruleId": "CKV_AWS_21",
                            "level": "UNKNOWN_LEVEL_XYZ",
                            "message": {"text": "Test finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "main.tf"
                                        },
                                        "region": {
                                            "startLine": 5
                                        }
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        
        source_path = str(tmp_path)
        result = fingerprint_findings(data_with_unknown_level, source_path)
        
        assert len(result["runs"]) > 0
        assert len(result["runs"][0]["results"]) == 1
        result_item = result["runs"][0]["results"][0]
        # Should still process and add fingerprints
        assert "fingerprints" in result_item
        # Unknown level should be preserved
        assert result_item.get("level") == "UNKNOWN_LEVEL_XYZ"
    
    def test_missing_rule_id_uses_rule_index(self, tmp_path):
        """Test that ruleIndex is used when ruleId is missing."""
        data_with_rule_index = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Checkov",
                            "rules": [
                                {
                                    "id": "CKV_AWS_21",
                                    "shortDescription": {"text": "Test rule"}
                                }
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleIndex": 0,  # Use ruleIndex instead of ruleId
                            "level": "error",
                            "message": {"text": "Test finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "main.tf"
                                        },
                                        "region": {
                                            "startLine": 5
                                        }
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        
        source_path = str(tmp_path)
        result = fingerprint_findings(data_with_rule_index, source_path)
        
        assert len(result["runs"]) > 0
        assert len(result["runs"][0]["results"]) == 1
        result_item = result["runs"][0]["results"][0]
        # Fingerprints should be added using rule from ruleIndex
        assert "fingerprints" in result_item
    
    def test_missing_message_text(self, tmp_path):
        """Test handling of results with missing message text."""
        data_with_missing_message = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Checkov",
                            "rules": []
                        }
                    },
                    "results": [
                        {
                            "ruleId": "CKV_AWS_21",
                            "level": "error",
                            "message": {},  # Empty message dict
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "main.tf"
                                        },
                                        "region": {
                                            "startLine": 5
                                        }
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        
        source_path = str(tmp_path)
        result = fingerprint_findings(data_with_missing_message, source_path)
        
        assert len(result["runs"]) > 0
        assert len(result["runs"][0]["results"]) == 1
        result_item = result["runs"][0]["results"][0]
        # Should still process
        assert "fingerprints" in result_item


class TestCheckovParserRobustness:
    """Test robustness against schema drift and unexpected fields."""
    
    def test_unexpected_top_level_fields(self, checkov_fixture, tmp_path):
        """Test that unexpected top-level fields are ignored."""
        data_with_extra = checkov_fixture.copy()
        data_with_extra["unexpected_field"] = "should be ignored"
        data_with_extra["another_unexpected"] = {"nested": "data"}
        
        source_path = str(tmp_path)
        result = fingerprint_findings(data_with_extra, source_path)
        
        # Should still process normally
        assert "runs" in result
        assert len(result["runs"]) > 0
    
    def test_unexpected_result_fields(self, checkov_fixture, tmp_path):
        """Test that unexpected fields in results are preserved but don't break processing."""
        data_with_extra = checkov_fixture.copy()
        if data_with_extra["runs"] and data_with_extra["runs"][0]["results"]:
            data_with_extra["runs"][0]["results"][0]["unexpected_field"] = "should be preserved"
            data_with_extra["runs"][0]["results"][0]["nested_unexpected"] = {"key": "value"}
        
        source_path = str(tmp_path)
        result = fingerprint_findings(data_with_extra, source_path)
        
        # Should still process normally
        assert len(result["runs"]) > 0
        if result["runs"][0]["results"]:
            assert "unexpected_field" in result["runs"][0]["results"][0]
            assert "nested_unexpected" in result["runs"][0]["results"][0]
            # Fingerprints should still be added
            assert "fingerprints" in result["runs"][0]["results"][0]
    
    def test_schema_drift_in_message(self, tmp_path):
        """Test handling of schema drift in message field."""
        data_with_drift = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Checkov",
                            "rules": []
                        }
                    },
                    "results": [
                        {
                            "ruleId": "CKV_AWS_21",
                            "level": "error",
                            "message": {
                                "text": "Test finding",
                                # Unexpected fields in message
                                "new_field_v2": "new value",
                                "metadata_v3": {"new": "structure"}
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "main.tf"
                                        },
                                        "region": {
                                            "startLine": 5
                                        }
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        
        source_path = str(tmp_path)
        result = fingerprint_findings(data_with_drift, source_path)
        
        # Should process successfully
        assert len(result["runs"]) > 0
        if result["runs"][0]["results"]:
            result_item = result["runs"][0]["results"][0]
            assert "fingerprints" in result_item
            
            # New fields should be preserved
            assert "new_field_v2" in result_item.get("message", {})
            assert "metadata_v3" in result_item.get("message", {})
    
    def test_null_values(self, tmp_path):
        """Test handling of null values in fields."""
        data_with_nulls = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Checkov",
                            "rules": []
                        }
                    },
                    "results": [
                        {
                            "ruleId": "CKV_AWS_21",
                            "level": "error",
                            "message": None,  # Null message
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "main.tf"
                                        },
                                        "region": {
                                            "startLine": 5,
                                            "snippet": None  # Null snippet
                                        }
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        
        source_path = str(tmp_path)
        result = fingerprint_findings(data_with_nulls, source_path)
        
        # Should handle nulls gracefully
        assert len(result["runs"]) > 0
        if result["runs"][0]["results"]:
            result_item = result["runs"][0]["results"][0]
            assert "fingerprints" in result_item
    
    def test_missing_region_fields(self, tmp_path):
        """Test handling of missing region fields."""
        data_with_missing_region = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Checkov",
                            "rules": []
                        }
                    },
                    "results": [
                        {
                            "ruleId": "CKV_AWS_21",
                            "level": "error",
                            "message": {"text": "Test finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "main.tf"
                                        },
                                        "region": {
                                            # Missing startLine/endLine
                                        }
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        
        source_path = str(tmp_path)
        result = fingerprint_findings(data_with_missing_region, source_path)
        
        # Should handle missing region fields gracefully
        assert len(result["runs"]) > 0
        if result["runs"][0]["results"]:
            result_item = result["runs"][0]["results"][0]
            assert "fingerprints" in result_item

