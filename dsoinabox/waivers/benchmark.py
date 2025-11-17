"""Benchmark generation functionality."""

from __future__ import annotations

import yaml
import os
from typing import Dict, Any, List, Optional


def _extract_primary_fingerprint(finding: Dict[str, Any], tool_name: str) -> Optional[str]:
    """
    Extract the primary fingerprint from a finding based on tool type.
    
    Args:
        finding: Finding dictionary with fingerprints
        tool_name: Name of the tool (trufflehog, opengrep, grype, checkov)
        
    Returns:
        Primary fingerprint string, or None if not found
    """
    fingerprints = finding.get('fingerprints', {})
    if not isinstance(fingerprints, dict):
        return None
    
    # Choose primary fingerprint based on tool type
    if tool_name == 'trufflehog':
        # Prefer secret fingerprint, fallback to exact or ctx
        return fingerprints.get('secret') or fingerprints.get('exact') or fingerprints.get('ctx')
    elif tool_name == 'opengrep':
        # Prefer rule fingerprint, fallback to exact or ctx
        return fingerprints.get('rule') or fingerprints.get('exact') or fingerprints.get('ctx')
    elif tool_name == 'grype':
        # Prefer pkg fingerprint, fallback to exact or ctx
        return fingerprints.get('pkg') or fingerprints.get('exact') or fingerprints.get('ctx')
    elif tool_name == 'checkov':
        # Prefer rule fingerprint, fallback to exact or ctx
        return fingerprints.get('rule') or fingerprints.get('exact') or fingerprints.get('ctx')
    else:
        # Generic fallback: try common fingerprint keys
        for key in ['rule', 'secret', 'pkg', 'exact', 'ctx']:
            if key in fingerprints:
                return fingerprints[key]
    
    return None


def generate_benchmark_yaml(
    trufflehog_data: Optional[List[Dict[str, Any]]],
    opengrep_data: Optional[Dict[str, Any]],
    grype_data: Optional[Dict[str, Any]],
    checkov_data: Optional[Dict[str, Any]],
    output_path: str,
    schema_version: str = "1.0"
) -> None:
    """
    Generate benchmark.yaml file with all findings from all tools.
    
    Args:
        trufflehog_data: List of Trufflehog findings
        opengrep_data: Opengrep data dict with 'results' key
        grype_data: Grype data dict with 'matches' key
        checkov_data: Checkov data dict with 'runs' key containing results
        output_path: Path where benchmark.yaml should be written
        schema_version: Schema version for the benchmark file
    """
    benchmark_entries = []
    
    # Collect findings from Trufflehog
    if trufflehog_data:
        if isinstance(trufflehog_data, list):
            for finding in trufflehog_data:
                fingerprint = _extract_primary_fingerprint(finding, 'trufflehog')
                if fingerprint:
                    benchmark_entries.append({
                        'fingerprint': fingerprint,
                        'type': 'benchmark'
                    })
        else:
            # Single finding
            fingerprint = _extract_primary_fingerprint(trufflehog_data, 'trufflehog')
            if fingerprint:
                benchmark_entries.append({
                    'fingerprint': fingerprint,
                    'type': 'benchmark'
                })
    
    # Collect findings from Opengrep
    if opengrep_data and opengrep_data.get('results'):
        for finding in opengrep_data['results']:
            fingerprint = _extract_primary_fingerprint(finding, 'opengrep')
            if fingerprint:
                benchmark_entries.append({
                    'fingerprint': fingerprint,
                    'type': 'benchmark'
                })
    
    # Collect findings from Grype
    if grype_data and grype_data.get('matches'):
        for finding in grype_data['matches']:
            fingerprint = _extract_primary_fingerprint(finding, 'grype')
            if fingerprint:
                benchmark_entries.append({
                    'fingerprint': fingerprint,
                    'type': 'benchmark'
                })
    
    # Collect findings from Checkov
    if checkov_data:
        runs = checkov_data.get('runs', [])
        if runs:
            results = runs[0].get('results', [])
            for finding in results:
                fingerprint = _extract_primary_fingerprint(finding, 'checkov')
                if fingerprint:
                    benchmark_entries.append({
                        'fingerprint': fingerprint,
                        'type': 'benchmark'
                    })
    
    # Create benchmark YAML structure
    benchmark_data = {
        'schema_version': schema_version,
        'benchmark': benchmark_entries
    }
    
    # Write to file
    with open(output_path, 'w') as f:
        yaml.dump(benchmark_data, f, default_flow_style=False, sort_keys=False)

