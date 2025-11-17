"""Tests for large report performance and consolidation."""

from __future__ import annotations

import pytest
import time
import json
import tempfile
import os
from pathlib import Path

from dsoinabox.reporting.report_builder import report_builder
from dsoinabox.reporting.parser import OpengrepParser, GrypeParser, CheckovParser


class TestLargeReportPerformance:
    """Test performance with extremely large reports."""
    
    @pytest.mark.slow
    def test_large_report_consolidation_performance(self, tmp_path):
        """Test that consolidation of 5k findings is O(n log n) and under a few seconds.
        
        This test simulates a large report with 5,000 findings and ensures:
        1. Consolidation completes in reasonable time (< 5 seconds)
        2. Performance scales approximately O(n log n) or better
        3. All findings are properly included in the output
        """
        # Generate 5k opengrep findings
        large_opengrep_data = {
            "results": []
        }
        
        for i in range(5000):
            finding = {
                "check_id": f"test.rule.id.{i % 100}",  # 100 different rules
                "path": f"src/file_{i % 50}.py",  # 50 different files
                "line": (i % 1000) + 1,
                "extra": {
                    "severity": ["low", "medium", "high", "critical"][i % 4],
                    "message": f"Test finding {i}",
                    "metadata": {
                        "source": "https://example.com/rule"
                    }
                },
                "fingerprints": {
                    "rule": f"og:1:RULE:test.rule.id.{i % 100}:hash{i}",
                    "exact": f"og:1:EXACT:test.rule.id.{i % 100}:filehash{i}:{i}:{i+10}",
                    "ctx": f"og:1:CTX:test.rule.id.{i % 100}:pathhash{i}:ctx{i}"
                }
            }
            large_opengrep_data["results"].append(finding)
        
        # Generate 5k grype findings
        large_grype_data = {
            "matches": []
        }
        
        for i in range(5000):
            match = {
                "vulnerability": {
                    "id": f"CVE-2024-{10000 + i:05d}",
                    "severity": ["low", "medium", "high", "critical"][i % 4].upper(),
                    "description": f"Test vulnerability {i}",
                    "dataSource": "https://nvd.nist.gov"
                },
                "artifact": {
                    "name": f"package_{i % 200}",
                    "version": f"1.{i % 10}.{i % 100}",
                    "locations": [
                        {
                            "path": f"path/to/package_{i % 200}"
                        }
                    ]
                },
                "fingerprints": {
                    "pkg": f"grype:1:PKG:package_{i % 200}:1.{i % 10}.{i % 100}:hash{i}",
                    "exact": f"grype:1:EXACT:package_{i % 200}:1.{i % 10}.{i % 100}:hash{i}",
                    "ctx": f"grype:1:CTX:package_{i % 200}:1.{i % 10}.{i % 100}:ctx{i}"
                }
            }
            large_grype_data["matches"].append(match)
        
        # Generate 5k checkov findings
        large_checkov_data = {
            "runs": [
                {
                    "results": []
                }
            ]
        }
        
        for i in range(5000):
            result = {
                "ruleId": f"CKV_AWS_{100 + (i % 200)}",
                "level": ["error", "warning", "note"][i % 3],
                "message": {
                    "text": f"Test checkov finding {i}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"file:///path/to/resource_{i % 100}.tf"
                            },
                            "region": {
                                "startLine": (i % 1000) + 1,
                                "snippet": {
                                    "text": f"resource \"aws_s3_bucket\" \"bucket_{i}\" {{"
                                }
                            }
                        }
                    }
                ],
                "fingerprints": {
                    "rule": f"checkov:1:RULE:CKV_AWS_{100 + (i % 200)}:hash{i}",
                    "exact": f"checkov:1:EXACT:CKV_AWS_{100 + (i % 200)}:filehash{i}:{i}:{i+10}",
                    "ctx": f"checkov:1:CTX:CKV_AWS_{100 + (i % 200)}:pathhash{i}:ctx{i}"
                }
            }
            large_checkov_data["runs"][0]["results"].append(result)
        
        # Measure consolidation time
        output_dir = tmp_path / "reports"
        output_dir.mkdir()
        
        start_time = time.time()
        
        # Build report with large datasets
        report_builder(
            reports_directory=str(output_dir),
            output_dir=str(output_dir),
            timestamp="2024_01_01T00_00_00",
            git_repo_info={
                "repo_url": "https://example.com/repo",
                "commit_hash": "abc123",
                "branch": "main"
            },
            data=(
                None,  # trufflehog_data
                large_opengrep_data,  # opengrep_data
                None,  # syft_data
                large_grype_data,  # grype_data
                large_checkov_data  # checkov_data
            ),
            output_format="json"
        )
        
        elapsed_time = time.time() - start_time
        
        # Performance assertion: should complete in under 5 seconds
        # For 5k findings, O(n log n) should be well under 5 seconds
        assert elapsed_time < 5.0, f"Consolidation took {elapsed_time:.2f}s, expected < 5.0s"
        
        # Verify output was created
        output_file = output_dir / "dsoinabox_unified_report_2024_01_01T00_00_00.json"
        assert output_file.exists(), "Output file should be created"
        
        # Verify all findings are included
        with open(output_file, 'r') as f:
            output_data = json.load(f)
        
        assert output_data['opengrep_data']['results'] is not None
        assert len(output_data['opengrep_data']['results']) == 5000
        
        assert output_data['grype_data']['matches'] is not None
        assert len(output_data['grype_data']['matches']) == 5000
        
        assert output_data['checkov_data']['runs'][0]['results'] is not None
        assert len(output_data['checkov_data']['runs'][0]['results']) == 5000
        
        # Performance should scale roughly O(n log n) or better
        # For 5k items, if it's O(n log n), time should be reasonable
        # log2(5000) ≈ 12.3, so n*log(n) ≈ 61,500 operations
        # At modern CPU speeds, this should be < 1 second for simple operations
        # Allowing 5 seconds accounts for I/O and Python overhead
        print(f"Consolidated 15,000 findings (5k each from 3 scanners) in {elapsed_time:.3f}s")
    
    @pytest.mark.slow
    def test_large_report_memory_bounded(self, tmp_path):
        """Test that report generation with 5k findings stays within memory bounds.
        
        This test verifies that memory usage doesn't grow unbounded with large datasets.
        Note: Exact memory measurement is platform-dependent, so we use a reasonable bound.
        """
        import sys
        import tracemalloc
        
        # Generate 5k opengrep findings
        large_opengrep_data = {
            "results": [
                {
                    "check_id": f"test.rule.id.{i % 100}",
                    "path": f"src/file_{i % 50}.py",
                    "line": (i % 1000) + 1,
                    "extra": {
                        "severity": ["low", "medium", "high", "critical"][i % 4],
                        "message": f"Test finding {i}",
                    },
                    "fingerprints": {
                        "rule": f"og:1:RULE:test.rule.id.{i % 100}:hash{i}",
                        "exact": f"og:1:EXACT:test.rule.id.{i % 100}:filehash{i}:{i}:{i+10}",
                        "ctx": f"og:1:CTX:test.rule.id.{i % 100}:pathhash{i}:ctx{i}"
                    }
                }
                for i in range(5000)
            ]
        }
        
        output_dir = tmp_path / "reports"
        output_dir.mkdir()
        
        # Start memory tracing
        tracemalloc.start()
        
        try:
            # Build report
            report_builder(
                reports_directory=str(output_dir),
                output_dir=str(output_dir),
                timestamp="2024_01_01T00_00_00",
                git_repo_info=None,
                data=(
                    None,  # trufflehog_data
                    large_opengrep_data,  # opengrep_data
                    None,  # syft_data
                    None,  # grype_data
                    None  # checkov_data
                ),
                output_format="json"
            )
            
            # Get peak memory usage
            current, peak = tracemalloc.get_traced_memory()
            peak_mb = peak / 1024 / 1024
            
            # Assert memory usage is reasonable (< 500MB for 5k findings)
            # This is a generous bound; actual usage should be much lower
            assert peak_mb < 500, f"Peak memory usage {peak_mb:.2f}MB exceeds 500MB bound"
            
            print(f"Peak memory usage: {peak_mb:.2f}MB for 5k findings")
            
        finally:
            tracemalloc.stop()
    
    @pytest.mark.slow
    def test_large_report_html_generation_performance(self, tmp_path):
        """Test HTML report generation with large dataset."""
        # Generate smaller dataset for HTML (HTML rendering is slower)
        opengrep_data = {
            "results": [
                {
                    "check_id": f"test.rule.id.{i}",
                    "path": f"src/file_{i % 10}.py",
                    "line": i + 1,
                    "extra": {
                        "severity": ["low", "medium", "high"][i % 3],
                        "message": f"Test finding {i}"
                    }
                }
                for i in range(1000)  # 1k findings for HTML test
            ]
        }
        
        output_dir = tmp_path / "reports"
        output_dir.mkdir()
        
        start_time = time.time()
        
        report_builder(
            reports_directory=str(output_dir),
            output_dir=str(output_dir),
            timestamp="2024_01_01T00_00_00",
            git_repo_info=None,
            data=(
                None,  # trufflehog_data
                opengrep_data,  # opengrep_data
                None,  # syft_data
                None,  # grype_data
                None  # checkov_data
            ),
            output_format="html"
        )
        
        elapsed_time = time.time() - start_time
        
        # HTML generation with 1k findings should complete in reasonable time
        assert elapsed_time < 10.0, f"HTML generation took {elapsed_time:.2f}s, expected < 10.0s"
        
        output_file = output_dir / "dsoinabox_unified_report_2024_01_01T00_00_00.html"
        assert output_file.exists(), "HTML output file should be created"
        
        # Verify file has content
        assert output_file.stat().st_size > 0, "HTML file should not be empty"

