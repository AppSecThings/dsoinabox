"""waiver fingerprint matcher."""

from __future__ import annotations

from typing import Dict, Any, List, Optional, Union


def check_waiver(fingerprints: Dict[str, str], waiver_data: Dict[str, Any]) -> bool:
    """check if any fingerprint from a finding matches a waiver."""
    if not fingerprints:
        return False
    
    finding_waivers = waiver_data.get('finding_waivers', [])
    benchmark_waivers = waiver_data.get('benchmark', [])
    
    all_waivers = finding_waivers + benchmark_waivers
    
    if not all_waivers:
        return False
    
    waiver_fingerprints = {w['fingerprint'] for w in all_waivers if 'fingerprint' in w}
    
    for fp_value in fingerprints.values():
        if fp_value and fp_value in waiver_fingerprints:
            return True
    
    return False


def apply_waivers_to_findings(
    findings: Union[List[Dict[str, Any]], Dict[str, Any]],
    waiver_data: Optional[Dict[str, Any]],
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
    
    if persist_waived_findings:
        for finding in findings_list:
            finding_fingerprints = finding.get('fingerprints', {})
            if isinstance(finding_fingerprints, dict):
                finding['waived'] = check_waiver(finding_fingerprints, waiver_data)
            else:
                finding['waived'] = False
    else:
        filtered_findings = []
        for finding in findings_list:
            finding_fingerprints = finding.get('fingerprints', {})
            if isinstance(finding_fingerprints, dict):
                is_waived = check_waiver(finding_fingerprints, waiver_data)
                if not is_waived:
                    filtered_findings.append(finding)
            else:
                filtered_findings.append(finding)
        
        if findings_dict is not None:
            if findings_key:
                findings[findings_key] = filtered_findings
            else:
                for key in ['results', 'matches']:
                    if key in findings:
                        findings[key] = filtered_findings
                        break
        else:
            findings[:] = filtered_findings
    
    return findings

