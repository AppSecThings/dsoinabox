"""waiver fingerprint matcher."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Union

from .models import WaiverSet

WaiverData = Union[WaiverSet, Dict[str, Any]]


def _build_waiver_fingerprints(waiver_data: WaiverData) -> Set[str]:
    """Build a set of all waiver fingerprints from finding and benchmark waivers."""
    if isinstance(waiver_data, WaiverSet):
        return {e.fingerprint for e in waiver_data.all_fingerprint_entries() if e.fingerprint}

    finding_waivers = waiver_data.get('finding_waivers', [])
    benchmark_waivers = waiver_data.get('benchmark', [])

    all_waivers = finding_waivers + benchmark_waivers
    return {w['fingerprint'] for w in all_waivers if 'fingerprint' in w}


def check_waiver(
    fingerprints: Dict[str, str],
    waiver_data: WaiverData,
    waiver_fingerprints: Optional[Set[str]] = None
) -> bool:
    """check if any fingerprint from a finding matches a waiver."""
    if not fingerprints:
        return False

    if waiver_fingerprints is None:
        waiver_fingerprints = _build_waiver_fingerprints(waiver_data)

    if not waiver_fingerprints:
        return False

    for fp_value in fingerprints.values():
        if fp_value and fp_value in waiver_fingerprints:
            return True

    return False


def apply_waivers_to_findings(
    findings: Union[List[Dict[str, Any]], Dict[str, Any]],
    waiver_data: Optional[WaiverData],
    findings_key: Optional[str] = None,
    persist_waived_findings: bool = False
) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
    """apply waiver checking to a list of findings."""
    if waiver_data is None:
        if findings_key and isinstance(findings, dict):
            for finding in findings.get(findings_key, []):
                finding['waived'] = False
        elif isinstance(findings, list):
            for finding in findings:
                finding['waived'] = False
        return findings
    
    if findings_key and isinstance(findings, dict):
        findings_list = findings.get(findings_key, [])
        findings_dict = findings
    elif isinstance(findings, list):
        findings_list = findings
        findings_dict = None
    else:
        for key in ['results', 'matches']:
            if key in findings:
                findings_list = findings[key]
                findings_dict = findings
                break
        else:
            return findings

    waiver_fingerprints = _build_waiver_fingerprints(waiver_data)
    
    if persist_waived_findings:
        for finding in findings_list:
            finding_fingerprints = finding.get('fingerprints', {})
            if isinstance(finding_fingerprints, dict):
                finding['waived'] = check_waiver(
                    finding_fingerprints, waiver_data, waiver_fingerprints
                )
            else:
                finding['waived'] = False
    else:
        filtered_findings = []
        for finding in findings_list:
            finding_fingerprints = finding.get('fingerprints', {})
            if isinstance(finding_fingerprints, dict):
                is_waived = check_waiver(
                    finding_fingerprints, waiver_data, waiver_fingerprints
                )
                if not is_waived:
                    filtered_findings.append(finding)
            else:
                filtered_findings.append(finding)
        
        if findings_dict is not None:
            if findings_key:
                findings_dict[findings_key] = filtered_findings
            else:
                for key in ['results', 'matches']:
                    if key in findings_dict:
                        findings_dict[key] = filtered_findings
                        break
        else:
            findings_list[:] = filtered_findings
    
    return findings
