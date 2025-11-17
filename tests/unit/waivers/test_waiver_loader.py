"""Unit tests for waiver loader edge cases and robustness."""

from __future__ import annotations

import pytest
import yaml
import tempfile
from pathlib import Path

from dsoinabox.waivers.loader import load_waiver_file, _load_schema_v1_0


class TestWaiverLoaderEdgeCases:
    """Test waiver loader handles edge cases gracefully."""
    
    def test_waiver_loader_missing_fingerprint_raises(self, tmp_path):
        """Test that waiver without fingerprint field raises ValueError."""
        waiver_file = tmp_path / "waivers.yaml"
        waiver_data = {
            "schema_version": "1.0",
            "finding_waivers": [
                {
                    "type": "false_positive",  # Missing fingerprint
                    "reason": "Test waiver"
                }
            ]
        }
        
        with open(waiver_file, 'w') as f:
            yaml.dump(waiver_data, f)
        
        with pytest.raises(ValueError, match="missing required 'fingerprint' field"):
            load_waiver_file(str(waiver_file))
    
    def test_waiver_loader_missing_type_raises(self, tmp_path):
        """Test that waiver without type field raises ValueError."""
        waiver_file = tmp_path / "waivers.yaml"
        waiver_data = {
            "schema_version": "1.0",
            "finding_waivers": [
                {
                    "fingerprint": "og:1:RULE:test:abc",
                    # Missing type
                }
            ]
        }
        
        with open(waiver_file, 'w') as f:
            yaml.dump(waiver_data, f)
        
        with pytest.raises(ValueError, match="missing required 'type' field"):
            load_waiver_file(str(waiver_file))
    
    def test_waiver_loader_invalid_type_raises(self, tmp_path):
        """Test that waiver with invalid type raises ValueError."""
        waiver_file = tmp_path / "waivers.yaml"
        waiver_data = {
            "schema_version": "1.0",
            "finding_waivers": [
                {
                    "fingerprint": "og:1:RULE:test:abc",
                    "type": "invalid_type",  # Invalid type
                }
            ]
        }
        
        with open(waiver_file, 'w') as f:
            yaml.dump(waiver_data, f)
        
        with pytest.raises(ValueError, match="Invalid finding_waiver type"):
            load_waiver_file(str(waiver_file))
    
    def test_waiver_loader_unsupported_version_raises(self, tmp_path):
        """Test that unsupported schema version raises ValueError."""
        waiver_file = tmp_path / "waivers.yaml"
        waiver_data = {
            "schema_version": "2.0",  # Unsupported version
            "finding_waivers": []
        }
        
        with open(waiver_file, 'w') as f:
            yaml.dump(waiver_data, f)
        
        with pytest.raises(ValueError, match="Unsupported waiver schema version: 2.0"):
            load_waiver_file(str(waiver_file))
    
    def test_waiver_loader_defaults_to_v1_0(self, tmp_path):
        """Test that missing schema_version defaults to 1.0."""
        waiver_file = tmp_path / "waivers.yaml"
        waiver_data = {
            # No schema_version
            "finding_waivers": [
                {
                    "fingerprint": "og:1:RULE:test:abc",
                    "type": "false_positive",
                }
            ]
        }
        
        with open(waiver_file, 'w') as f:
            yaml.dump(waiver_data, f)
        
        result = load_waiver_file(str(waiver_file))
        assert result["schema_version"] == "1.0"
        assert len(result["finding_waivers"]) == 1
    
    def test_waiver_loader_empty_file_returns_empty_waivers(self, tmp_path):
        """Test that empty waiver file returns empty structure."""
        waiver_file = tmp_path / "waivers.yaml"
        waiver_data = {
            "schema_version": "1.0",
            "finding_waivers": []
        }
        
        with open(waiver_file, 'w') as f:
            yaml.dump(waiver_data, f)
        
        result = load_waiver_file(str(waiver_file))
        assert result["schema_version"] == "1.0"
        assert result["finding_waivers"] == []
        assert result.get("meta", {}) == {}
        assert result.get("path_exclusions", []) == []
    
    def test_waiver_loader_missing_finding_waivers_key(self, tmp_path):
        """Test that missing finding_waivers key defaults to empty list."""
        waiver_file = tmp_path / "waivers.yaml"
        waiver_data = {
            "schema_version": "1.0",
            # No finding_waivers key
        }
        
        with open(waiver_file, 'w') as f:
            yaml.dump(waiver_data, f)
        
        result = load_waiver_file(str(waiver_file))
        assert result["finding_waivers"] == []
    
    def test_waiver_loader_invalid_finding_waiver_not_dict(self, tmp_path):
        """Test that finding_waiver that's not a dict raises ValueError."""
        waiver_file = tmp_path / "waivers.yaml"
        waiver_data = {
            "schema_version": "1.0",
            "finding_waivers": [
                "not a dict",  # Invalid: should be dict
            ]
        }
        
        with open(waiver_file, 'w') as f:
            yaml.dump(waiver_data, f)
        
        with pytest.raises(ValueError, match="Invalid finding_waiver: must be a dictionary"):
            load_waiver_file(str(waiver_file))
    
    def test_waiver_loader_nonexistent_file_raises(self):
        """Test that nonexistent waiver file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_waiver_file("/nonexistent/waivers.yaml")
    
    def test_waiver_loader_invalid_yaml_raises(self, tmp_path):
        """Test that invalid YAML raises appropriate error."""
        waiver_file = tmp_path / "waivers.yaml"
        waiver_file.write_text("invalid: yaml: [unclosed")
        
        with pytest.raises((yaml.YAMLError, ValueError)):
            load_waiver_file(str(waiver_file))
    
    def test_waiver_loader_not_dict_raises(self, tmp_path):
        """Test that YAML that's not a dict raises ValueError."""
        waiver_file = tmp_path / "waivers.yaml"
        waiver_file.write_text("- item1\n- item2\n")  # List, not dict
        
        with pytest.raises(ValueError, match="expected dict, got"):
            load_waiver_file(str(waiver_file))
    
    def test_waiver_loader_duplicate_fingerprints_allowed(self, tmp_path):
        """Test that duplicate fingerprints in waiver list are allowed."""
        waiver_file = tmp_path / "waivers.yaml"
        waiver_data = {
            "schema_version": "1.0",
            "finding_waivers": [
                {
                    "fingerprint": "og:1:RULE:test:abc",
                    "type": "false_positive",
                    "reason": "First waiver"
                },
                {
                    "fingerprint": "og:1:RULE:test:abc",  # Duplicate
                    "type": "risk_acceptance",
                    "reason": "Second waiver"
                }
            ]
        }
        
        with open(waiver_file, 'w') as f:
            yaml.dump(waiver_data, f)
        
        # Should load successfully (duplicates allowed)
        result = load_waiver_file(str(waiver_file))
        assert len(result["finding_waivers"]) == 2
        assert result["finding_waivers"][0]["fingerprint"] == "og:1:RULE:test:abc"
        assert result["finding_waivers"][1]["fingerprint"] == "og:1:RULE:test:abc"
    
    def test_waiver_loader_validates_all_waiver_types(self, tmp_path):
        """Test that all valid waiver types are accepted."""
        waiver_file = tmp_path / "waivers.yaml"
        waiver_data = {
            "schema_version": "1.0",
            "finding_waivers": [
                {
                    "fingerprint": "og:1:RULE:test1:abc",
                    "type": "false_positive",
                },
                {
                    "fingerprint": "og:1:RULE:test2:abc",
                    "type": "risk_acceptance",
                },
                {
                    "fingerprint": "og:1:RULE:test3:abc",
                    "type": "policy_waiver",
                }
            ]
        }
        
        with open(waiver_file, 'w') as f:
            yaml.dump(waiver_data, f)
        
        result = load_waiver_file(str(waiver_file))
        assert len(result["finding_waivers"]) == 3
        assert result["finding_waivers"][0]["type"] == "false_positive"
        assert result["finding_waivers"][1]["type"] == "risk_acceptance"
        assert result["finding_waivers"][2]["type"] == "policy_waiver"
    
    def test_waiver_loader_preserves_optional_fields(self, tmp_path):
        """Test that optional fields in waivers are preserved."""
        waiver_file = tmp_path / "waivers.yaml"
        waiver_data = {
            "schema_version": "1.0",
            "meta": {
                "owner": "Security Team",
                "ticket": "SEC-123"
            },
            "path_exclusions": [
                {
                    "pattern": "**/vendor/**",
                    "reason": "Vendored code"
                }
            ],
            "finding_waivers": [
                {
                    "fingerprint": "og:1:RULE:test:abc",
                    "type": "false_positive",
                    "reason": "Test reason",
                    "expires_at": "2026-01-01",
                    "created_by": "alice@example.com",
                    "meta_ticket": "SEC-456"
                }
            ]
        }
        
        with open(waiver_file, 'w') as f:
            yaml.dump(waiver_data, f)
        
        result = load_waiver_file(str(waiver_file))
        assert result["meta"]["owner"] == "Security Team"
        assert len(result["path_exclusions"]) == 1
        assert result["finding_waivers"][0]["reason"] == "Test reason"
        assert result["finding_waivers"][0]["expires_at"] == "2026-01-01"

