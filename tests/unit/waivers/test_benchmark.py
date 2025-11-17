"""Unit tests for benchmark functionality."""

from __future__ import annotations

import pytest
import yaml
import tempfile
from pathlib import Path

from dsoinabox.waivers.loader import load_waiver_file
from dsoinabox.waivers.matcher import check_waiver, apply_waivers_to_findings
from dsoinabox.waivers.benchmark import generate_benchmark_yaml, _extract_primary_fingerprint


class TestBenchmarkLoader:
    """Test benchmark section loading in waiver files."""
    
    def test_benchmark_section_loaded(self, tmp_path):
        """Test that benchmark section is loaded from waiver file."""
        waiver_file = tmp_path / "waivers.yaml"
        waiver_data = {
            "schema_version": "1.0",
            "finding_waivers": [
                {
                    "fingerprint": "og:1:RULE:test1:abc",
                    "type": "false_positive",
                }
            ],
            "benchmark": [
                {
                    "fingerprint": "og:1:RULE:test2:xyz",
                    "type": "risk_acceptance",  # Should be overridden
                }
            ]
        }
        
        with open(waiver_file, 'w') as f:
            yaml.dump(waiver_data, f)
        
        result = load_waiver_file(str(waiver_file))
        assert "benchmark" in result
        assert len(result["benchmark"]) == 1
        assert result["benchmark"][0]["fingerprint"] == "og:1:RULE:test2:xyz"
        # Type should be overridden to "benchmark"
        assert result["benchmark"][0]["type"] == "benchmark"
    
    def test_benchmark_type_override(self, tmp_path):
        """Test that benchmark entry type is always overridden to 'benchmark'."""
        waiver_file = tmp_path / "waivers.yaml"
        waiver_data = {
            "schema_version": "1.0",
            "benchmark": [
                {
                    "fingerprint": "og:1:RULE:test:abc",
                    "type": "false_positive",  # Should be overridden
                },
                {
                    "fingerprint": "og:1:RULE:test2:xyz",
                    "type": "risk_acceptance",  # Should be overridden
                },
                {
                    "fingerprint": "og:1:RULE:test3:def",
                    "type": "policy_waiver",  # Should be overridden
                }
            ]
        }
        
        with open(waiver_file, 'w') as f:
            yaml.dump(waiver_data, f)
        
        result = load_waiver_file(str(waiver_file))
        for entry in result["benchmark"]:
            assert entry["type"] == "benchmark"
    
    def test_benchmark_missing_fingerprint_raises(self, tmp_path):
        """Test that benchmark entry without fingerprint raises ValueError."""
        waiver_file = tmp_path / "waivers.yaml"
        waiver_data = {
            "schema_version": "1.0",
            "benchmark": [
                {
                    "type": "benchmark",  # Missing fingerprint
                }
            ]
        }
        
        with open(waiver_file, 'w') as f:
            yaml.dump(waiver_data, f)
        
        with pytest.raises(ValueError, match="missing required 'fingerprint' field"):
            load_waiver_file(str(waiver_file))
    
    def test_benchmark_empty_section(self, tmp_path):
        """Test that empty benchmark section is handled."""
        waiver_file = tmp_path / "waivers.yaml"
        waiver_data = {
            "schema_version": "1.0",
            "finding_waivers": [],
            "benchmark": []
        }
        
        with open(waiver_file, 'w') as f:
            yaml.dump(waiver_data, f)
        
        result = load_waiver_file(str(waiver_file))
        assert result["benchmark"] == []
    
    def test_benchmark_missing_section_defaults_to_empty(self, tmp_path):
        """Test that missing benchmark section defaults to empty list."""
        waiver_file = tmp_path / "waivers.yaml"
        waiver_data = {
            "schema_version": "1.0",
            "finding_waivers": []
        }
        
        with open(waiver_file, 'w') as f:
            yaml.dump(waiver_data, f)
        
        result = load_waiver_file(str(waiver_file))
        assert result["benchmark"] == []


class TestBenchmarkMatcher:
    """Test benchmark entries in waiver matching."""
    
    def test_benchmark_entry_matches_finding(self):
        """Test that benchmark entries match findings like regular waivers."""
        fingerprints = {
            'rule': 'og:1:RULE:test:abc',
        }
        
        waiver_data = {
            'finding_waivers': [],
            'benchmark': [
                {
                    'fingerprint': 'og:1:RULE:test:abc',
                    'type': 'benchmark'
                }
            ]
        }
        
        assert check_waiver(fingerprints, waiver_data) is True
    
    def test_benchmark_and_finding_waivers_both_checked(self):
        """Test that both finding_waivers and benchmark are checked."""
        fingerprints = {
            'rule': 'og:1:RULE:test:abc',
            'exact': 'og:1:EXACT:test2:xyz',
        }
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:RULE:test:abc',
                    'type': 'false_positive',
                }
            ],
            'benchmark': [
                {
                    'fingerprint': 'og:1:EXACT:test2:xyz',
                    'type': 'benchmark'
                }
            ]
        }
        
        # Both should match
        assert check_waiver(fingerprints, waiver_data) is True
    
    def test_benchmark_applies_to_findings(self):
        """Test that benchmark entries apply to findings like regular waivers."""
        findings = [
            {
                'check_id': 'test.rule.id',
                'fingerprints': {
                    'rule': 'og:1:RULE:test:abc',
                }
            }
        ]
        
        waiver_data = {
            'finding_waivers': [],
            'benchmark': [
                {
                    'fingerprint': 'og:1:RULE:test:abc',
                    'type': 'benchmark'
                }
            ]
        }
        
        result = apply_waivers_to_findings(
            findings,
            waiver_data,
            persist_waived_findings=True
        )
        
        assert len(result) == 1
        assert result[0]['waived'] is True
    
    def test_benchmark_filters_findings(self):
        """Test that benchmark entries filter findings when persist_waived_findings=False."""
        findings = [
            {
                'check_id': 'test.rule.id',
                'fingerprints': {
                    'rule': 'og:1:RULE:test:abc',
                }
            },
            {
                'check_id': 'other.rule.id',
                'fingerprints': {
                    'rule': 'og:1:RULE:other:xyz',
                }
            }
        ]
        
        waiver_data = {
            'finding_waivers': [],
            'benchmark': [
                {
                    'fingerprint': 'og:1:RULE:test:abc',
                    'type': 'benchmark'
                }
            ]
        }
        
        result = apply_waivers_to_findings(
            findings,
            waiver_data,
            persist_waived_findings=False
        )
        
        # Only non-waived finding should remain
        assert len(result) == 1
        assert result[0]['check_id'] == 'other.rule.id'
    
    def test_benchmark_loaded_from_file_works(self, tmp_path):
        """Test that benchmark entries loaded from file work correctly."""
        waiver_file = tmp_path / "waivers.yaml"
        waiver_data = {
            "schema_version": "1.0",
            "benchmark": [
                {
                    "fingerprint": "og:1:RULE:test:abc",
                    "type": "risk_acceptance",  # Will be overridden
                }
            ]
        }
        
        with open(waiver_file, 'w') as f:
            yaml.dump(waiver_data, f)
        
        # Load the waiver file
        loaded_data = load_waiver_file(str(waiver_file))
        
        # Verify type was overridden
        assert loaded_data['benchmark'][0]['type'] == 'benchmark'
        
        # Test that it matches findings
        fingerprints = {
            'rule': 'og:1:RULE:test:abc',
        }
        
        assert check_waiver(fingerprints, loaded_data) is True


class TestBenchmarkGeneration:
    """Test benchmark.yaml generation."""
    
    def test_extract_primary_fingerprint_trufflehog(self):
        """Test primary fingerprint extraction for Trufflehog."""
        finding = {
            'fingerprints': {
                'secret': 'th:1:SECRET:URI:abc123',
                'exact': 'th:1:EXACT:URI:def456',
                'ctx': 'th:1:CTX:URI:ghi789'
            }
        }
        
        fp = _extract_primary_fingerprint(finding, 'trufflehog')
        assert fp == 'th:1:SECRET:URI:abc123'
    
    def test_extract_primary_fingerprint_trufflehog_fallback(self):
        """Test Trufflehog fingerprint fallback when secret missing."""
        finding = {
            'fingerprints': {
                'exact': 'th:1:EXACT:URI:def456',
                'ctx': 'th:1:CTX:URI:ghi789'
            }
        }
        
        fp = _extract_primary_fingerprint(finding, 'trufflehog')
        assert fp == 'th:1:EXACT:URI:def456'
    
    def test_extract_primary_fingerprint_opengrep(self):
        """Test primary fingerprint extraction for Opengrep."""
        finding = {
            'fingerprints': {
                'rule': 'og:1:RULE:test:abc123',
                'exact': 'og:1:EXACT:test:def456',
                'ctx': 'og:1:CTX:test:ghi789'
            }
        }
        
        fp = _extract_primary_fingerprint(finding, 'opengrep')
        assert fp == 'og:1:RULE:test:abc123'
    
    def test_extract_primary_fingerprint_grype(self):
        """Test primary fingerprint extraction for Grype."""
        finding = {
            'fingerprints': {
                'pkg': 'gy:1:PKG:CVE-123:pkg123',
                'exact': 'gy:1:EXACT:CVE-123:def456',
                'ctx': 'gy:1:CTX:CVE-123:ghi789'
            }
        }
        
        fp = _extract_primary_fingerprint(finding, 'grype')
        assert fp == 'gy:1:PKG:CVE-123:pkg123'
    
    def test_extract_primary_fingerprint_checkov(self):
        """Test primary fingerprint extraction for Checkov."""
        finding = {
            'fingerprints': {
                'rule': 'ck:1:RULE:test:abc123',
                'exact': 'ck:1:EXACT:test:def456',
                'ctx': 'ck:1:CTX:test:ghi789'
            }
        }
        
        fp = _extract_primary_fingerprint(finding, 'checkov')
        assert fp == 'ck:1:RULE:test:abc123'
    
    def test_extract_primary_fingerprint_no_fingerprints(self):
        """Test that None is returned when no fingerprints exist."""
        finding = {}
        
        fp = _extract_primary_fingerprint(finding, 'opengrep')
        assert fp is None
    
    def test_extract_primary_fingerprint_empty_dict(self):
        """Test that None is returned when fingerprints is empty dict."""
        finding = {
            'fingerprints': {}
        }
        
        fp = _extract_primary_fingerprint(finding, 'opengrep')
        assert fp is None
    
    def test_generate_benchmark_yaml_trufflehog(self, tmp_path):
        """Test benchmark.yaml generation with Trufflehog findings."""
        trufflehog_data = [
            {
                'DetectorName': 'URI',
                'fingerprints': {
                    'secret': 'th:1:SECRET:URI:abc123',
                }
            }
        ]
        
        output_path = tmp_path / "benchmark.yaml"
        generate_benchmark_yaml(
            trufflehog_data=trufflehog_data,
            opengrep_data=None,
            grype_data=None,
            checkov_data=None,
            output_path=str(output_path)
        )
        
        assert output_path.exists()
        with open(output_path, 'r') as f:
            data = yaml.safe_load(f)
        
        assert data['schema_version'] == '1.0'
        assert len(data['benchmark']) == 1
        assert data['benchmark'][0]['fingerprint'] == 'th:1:SECRET:URI:abc123'
        assert data['benchmark'][0]['type'] == 'benchmark'
    
    def test_generate_benchmark_yaml_opengrep(self, tmp_path):
        """Test benchmark.yaml generation with Opengrep findings."""
        opengrep_data = {
            'results': [
                {
                    'check_id': 'test.rule.id',
                    'fingerprints': {
                        'rule': 'og:1:RULE:test:abc123',
                    }
                }
            ]
        }
        
        output_path = tmp_path / "benchmark.yaml"
        generate_benchmark_yaml(
            trufflehog_data=None,
            opengrep_data=opengrep_data,
            grype_data=None,
            checkov_data=None,
            output_path=str(output_path)
        )
        
        assert output_path.exists()
        with open(output_path, 'r') as f:
            data = yaml.safe_load(f)
        
        assert len(data['benchmark']) == 1
        assert data['benchmark'][0]['fingerprint'] == 'og:1:RULE:test:abc123'
    
    def test_generate_benchmark_yaml_grype(self, tmp_path):
        """Test benchmark.yaml generation with Grype findings."""
        grype_data = {
            'matches': [
                {
                    'vulnerability': {'id': 'CVE-123'},
                    'fingerprints': {
                        'pkg': 'gy:1:PKG:CVE-123:pkg123',
                    }
                }
            ]
        }
        
        output_path = tmp_path / "benchmark.yaml"
        generate_benchmark_yaml(
            trufflehog_data=None,
            opengrep_data=None,
            grype_data=grype_data,
            checkov_data=None,
            output_path=str(output_path)
        )
        
        assert output_path.exists()
        with open(output_path, 'r') as f:
            data = yaml.safe_load(f)
        
        assert len(data['benchmark']) == 1
        assert data['benchmark'][0]['fingerprint'] == 'gy:1:PKG:CVE-123:pkg123'
    
    def test_generate_benchmark_yaml_checkov(self, tmp_path):
        """Test benchmark.yaml generation with Checkov findings."""
        checkov_data = {
            'runs': [
                {
                    'results': [
                        {
                            'ruleId': 'CKV_TEST_1',
                            'fingerprints': {
                                'rule': 'ck:1:RULE:test:abc123',
                            }
                        }
                    ]
                }
            ]
        }
        
        output_path = tmp_path / "benchmark.yaml"
        generate_benchmark_yaml(
            trufflehog_data=None,
            opengrep_data=None,
            grype_data=None,
            checkov_data=checkov_data,
            output_path=str(output_path)
        )
        
        assert output_path.exists()
        with open(output_path, 'r') as f:
            data = yaml.safe_load(f)
        
        assert len(data['benchmark']) == 1
        assert data['benchmark'][0]['fingerprint'] == 'ck:1:RULE:test:abc123'
    
    def test_generate_benchmark_yaml_all_tools(self, tmp_path):
        """Test benchmark.yaml generation with findings from all tools."""
        trufflehog_data = [
            {
                'fingerprints': {'secret': 'th:1:SECRET:URI:abc123'}
            }
        ]
        opengrep_data = {
            'results': [
                {
                    'fingerprints': {'rule': 'og:1:RULE:test:abc123'}
                }
            ]
        }
        grype_data = {
            'matches': [
                {
                    'fingerprints': {'pkg': 'gy:1:PKG:CVE-123:pkg123'}
                }
            ]
        }
        checkov_data = {
            'runs': [
                {
                    'results': [
                        {
                            'fingerprints': {'rule': 'ck:1:RULE:test:abc123'}
                        }
                    ]
                }
            ]
        }
        
        output_path = tmp_path / "benchmark.yaml"
        generate_benchmark_yaml(
            trufflehog_data=trufflehog_data,
            opengrep_data=opengrep_data,
            grype_data=grype_data,
            checkov_data=checkov_data,
            output_path=str(output_path)
        )
        
        assert output_path.exists()
        with open(output_path, 'r') as f:
            data = yaml.safe_load(f)
        
        # Should have 4 entries (one from each tool)
        assert len(data['benchmark']) == 4
        fingerprints = {entry['fingerprint'] for entry in data['benchmark']}
        assert 'th:1:SECRET:URI:abc123' in fingerprints
        assert 'og:1:RULE:test:abc123' in fingerprints
        assert 'gy:1:PKG:CVE-123:pkg123' in fingerprints
        assert 'ck:1:RULE:test:abc123' in fingerprints
        
        # All should have type "benchmark"
        for entry in data['benchmark']:
            assert entry['type'] == 'benchmark'
    
    def test_generate_benchmark_yaml_no_findings(self, tmp_path):
        """Test benchmark.yaml generation with no findings."""
        output_path = tmp_path / "benchmark.yaml"
        generate_benchmark_yaml(
            trufflehog_data=None,
            opengrep_data=None,
            grype_data=None,
            checkov_data=None,
            output_path=str(output_path)
        )
        
        assert output_path.exists()
        with open(output_path, 'r') as f:
            data = yaml.safe_load(f)
        
        assert data['schema_version'] == '1.0'
        assert data['benchmark'] == []
    
    def test_generate_benchmark_yaml_findings_without_fingerprints(self, tmp_path):
        """Test that findings without fingerprints are skipped."""
        opengrep_data = {
            'results': [
                {
                    'check_id': 'test.rule.id',
                    # No fingerprints
                },
                {
                    'check_id': 'test2.rule.id',
                    'fingerprints': {
                        'rule': 'og:1:RULE:test2:abc123'
                    }
                }
            ]
        }
        
        output_path = tmp_path / "benchmark.yaml"
        generate_benchmark_yaml(
            trufflehog_data=None,
            opengrep_data=opengrep_data,
            grype_data=None,
            checkov_data=None,
            output_path=str(output_path)
        )
        
        assert output_path.exists()
        with open(output_path, 'r') as f:
            data = yaml.safe_load(f)
        
        # Only finding with fingerprints should be included
        assert len(data['benchmark']) == 1
        assert data['benchmark'][0]['fingerprint'] == 'og:1:RULE:test2:abc123'
    
    def test_generate_benchmark_yaml_trufflehog_single_finding(self, tmp_path):
        """Test benchmark.yaml generation with single Trufflehog finding (not a list)."""
        # Trufflehog can return a single finding dict instead of a list
        trufflehog_data = {
            'DetectorName': 'URI',
            'fingerprints': {
                'secret': 'th:1:SECRET:URI:abc123',
            }
        }
        
        output_path = tmp_path / "benchmark.yaml"
        generate_benchmark_yaml(
            trufflehog_data=trufflehog_data,
            opengrep_data=None,
            grype_data=None,
            checkov_data=None,
            output_path=str(output_path)
        )
        
        assert output_path.exists()
        with open(output_path, 'r') as f:
            data = yaml.safe_load(f)
        
        assert len(data['benchmark']) == 1
        assert data['benchmark'][0]['fingerprint'] == 'th:1:SECRET:URI:abc123'

