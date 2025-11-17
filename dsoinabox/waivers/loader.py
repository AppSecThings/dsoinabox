"""version-aware waiver schema loader."""

from __future__ import annotations

import yaml
import os
from typing import Dict, Any, Optional
from pathlib import Path


def load_waiver_file(filepath: str) -> Dict[str, Any]:
    """load a waiver file using version-aware schema loader."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Waiver file not found: {filepath}")
    
    with open(filepath, 'r') as f:
        data = yaml.safe_load(f)
    
    if not isinstance(data, dict):
        raise ValueError(f"Invalid waiver file format: expected dict, got {type(data)}")
    
    schema_version = data.get('schema_version', '1.0')
    
    if schema_version == '1.0':
        return _load_schema_v1_0(data)
    else:
        raise ValueError(f"Unsupported waiver schema version: {schema_version}")


def _load_schema_v1_0(data: Dict[str, Any]) -> Dict[str, Any]:
    """load and validate schema version 1.0."""
    waiver_data = {
        'schema_version': data.get('schema_version', '1.0'),
        'meta': data.get('meta', {}),
        'path_exclusions': data.get('path_exclusions', []),
        'finding_waivers': data.get('finding_waivers', []),
        'benchmark': data.get('benchmark', [])
    }
    
    for waiver in waiver_data['finding_waivers']:
        if not isinstance(waiver, dict):
            raise ValueError("Invalid finding_waiver: must be a dictionary")
        if 'fingerprint' not in waiver:
            raise ValueError("Invalid finding_waiver: missing required 'fingerprint' field")
        if 'type' not in waiver:
            raise ValueError("Invalid finding_waiver: missing required 'type' field")
        if waiver['type'] not in ['false_positive', 'risk_acceptance', 'policy_waiver']:
            raise ValueError(f"Invalid finding_waiver type: {waiver['type']}. Must be one of: false_positive, risk_acceptance, policy_waiver")
    
    for benchmark_entry in waiver_data['benchmark']:
        if not isinstance(benchmark_entry, dict):
            raise ValueError("Invalid benchmark entry: must be a dictionary")
        if 'fingerprint' not in benchmark_entry:
            raise ValueError("Invalid benchmark entry: missing required 'fingerprint' field")
        benchmark_entry['type'] = 'benchmark'
    
    return waiver_data

