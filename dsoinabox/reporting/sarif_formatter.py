"""sarif 2.1.0 formatter for unified findings"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set
from collections import defaultdict


def _map_severity_to_sarif_level(severity: str) -> str:
    """map unified severity to sarif level
    
    returns sarif level: "error", "warning", "note", or "none"
    """
    severity_lower = (severity or "").lower()
    
    if severity_lower in ("critical", "high", "error"):
        return "error"
    elif severity_lower in ("medium", "warning"):
        return "warning"
    elif severity_lower in ("low", "info", "note"):
        return "note"
    else:
        return "warning"  #default


def _extract_rule_id_from_finding(finding: Dict[str, Any], tool_name: str) -> str:
    """extract rule id from a finding based on tool type"""
    if tool_name == "opengrep":
        return finding.get("check_id", "unknown")
    elif tool_name == "trufflehog":
        detector_name = finding.get("DetectorName", "")
        detector_type = finding.get("DetectorType", "")
        return f"{detector_name}_{detector_type}" if detector_name else f"detector_{detector_type}"
    elif tool_name == "grype":
        vuln = finding.get("vulnerability", {})
        return vuln.get("id", "unknown")
    elif tool_name == "checkov":
        return finding.get("ruleId", "unknown")
    else:
        return finding.get("rule_id") or finding.get("ruleId") or "unknown"


def _extract_message_from_finding(finding: Dict[str, Any], tool_name: str) -> str:
    """extract message text from a finding based on tool type"""
    if tool_name == "opengrep":
        extra = finding.get("extra", {})
        return extra.get("message", "")
    elif tool_name == "trufflehog":
        desc = finding.get("DetectorDescription", "")
        redacted = finding.get("Redacted", "")
        if desc:
            return f"{desc}. Redacted: {redacted}" if redacted else desc
        return redacted or "Secret detected"
    elif tool_name == "grype":
        vuln = finding.get("vulnerability", {})
        desc = vuln.get("description", "")
        vid = vuln.get("id", "")
        if desc:
            return f"{vid}: {desc}" if vid else desc
        return vid or "Vulnerability found"
    elif tool_name == "checkov":
        message = finding.get("message", {})
        if isinstance(message, dict):
            return message.get("text", "")
        return str(message) if message else ""
    else:
        return finding.get("message") or finding.get("summary") or ""


def _extract_file_path_from_finding(finding: Dict[str, Any], tool_name: str) -> str:
    """extract file path from a finding based on tool type"""
    if tool_name == "opengrep":
        return finding.get("path", "")
    elif tool_name == "trufflehog":
        source_metadata = finding.get("SourceMetadata", {})
        data = source_metadata.get("Data", {})
        git_data = data.get("Git", {})
        filesystem_data = data.get("Filesystem", {})
        file_path = git_data.get("file") or filesystem_data.get("file")
        return file_path or ""
    elif tool_name == "grype":
        artifact = finding.get("artifact", {})
        locations = artifact.get("locations", [])
        if locations:
            return locations[0].get("path", "")
        return ""
    elif tool_name == "checkov":
        locations = finding.get("locations", [])
        if locations:
            physical_location = locations[0].get("physicalLocation", {})
            artifact_location = physical_location.get("artifactLocation", {})
            return artifact_location.get("uri", "")
        return ""
    else:
        return finding.get("file") or finding.get("path") or finding.get("uri", "")


def _extract_line_info_from_finding(finding: Dict[str, Any], tool_name: str) -> tuple[int, int]:
    """extract start and end line numbers from a finding
    
    returns tuple of (start_line, end_line). returns (0, 0) if not available
    """
    if tool_name == "opengrep":
        start = finding.get("start", {})
        end = finding.get("end", {})
        start_line = start.get("line", 0) if start else 0
        end_line = end.get("line", start_line) if end else start_line
        return start_line, end_line
    elif tool_name == "trufflehog":
        source_metadata = finding.get("SourceMetadata", {})
        data = source_metadata.get("Data", {})
        git_data = data.get("Git", {})
        line = git_data.get("line") or 0
        approx_line = finding.get("approx_line") or line
        return approx_line, approx_line
    elif tool_name == "grype":
        #grype doesn't typically have line numbers
        return 0, 0
    elif tool_name == "checkov":
        locations = finding.get("locations", [])
        if locations:
            physical_location = locations[0].get("physicalLocation", {})
            region = physical_location.get("region", {})
            start_line = region.get("startLine", 0)
            end_line = region.get("endLine", start_line)
            return start_line, end_line
        return 0, 0
    else:
        start_line = finding.get("line", finding.get("start_line", 0))
        end_line = finding.get("end_line", start_line)
        return start_line, end_line


def _extract_severity_from_finding(finding: Dict[str, Any], tool_name: str) -> str:
    """extract severity from a finding based on tool type"""
    if tool_name == "opengrep":
        extra = finding.get("extra", {})
        severity = extra.get("severity", "")
        #map opengrep severities: Error=High, Warning=Medium, Info=Low
        severity_map = {
            "ERROR": "high",
            "WARNING": "medium",
            "INFO": "low",
            "LOW": "low",
            "MEDIUM": "medium",
            "HIGH": "high",
            "CRITICAL": "critical"
        }
        return severity_map.get(severity.upper(), "medium")
    elif tool_name == "trufflehog":
        #trufflehog findings are typically high severity (secrets)
        return "high"
    elif tool_name == "grype":
        vuln = finding.get("vulnerability", {})
        severity = vuln.get("severity", "")
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "NEGLIGIBLE": "low",
            "UNKNOWN": "medium"
        }
        return severity_map.get(severity.upper(), "medium")
    elif tool_name == "checkov":
        level = finding.get("level", "error")
        level_map = {
            "error": "high",
            "warning": "medium",
            "note": "low",
            "none": "info"
        }
        return level_map.get(level.lower(), "medium")
    else:
        return finding.get("severity", "medium")


def _extract_fingerprints_from_finding(finding: Dict[str, Any]) -> Dict[str, str]:
    """extract fingerprints from a finding"""
    fingerprints = finding.get("fingerprints", {})
    if isinstance(fingerprints, dict):
        return fingerprints
    return {}


def _is_waived(finding: Dict[str, Any]) -> bool:
    """check if a finding is waived"""
    #check for waiver metadata in various possible locations
    if finding.get("waived"):
        return True
    if finding.get("suppressions"):
        return True
    properties = finding.get("properties", {})
    if properties and properties.get("waived"):
        return True
    return False


def _create_sarif_rule(rule_id: str, tool_name: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """create a sarif rule definition from rule id and findings"""
    #try to extract rule description from first finding
    description = ""
    help_uri = ""
    
    if findings:
        first_finding = findings[0]
        if tool_name == "opengrep":
            extra = first_finding.get("extra", {})
            metadata = extra.get("metadata", {})
            description = extra.get("message", "")
            help_uri = metadata.get("source", "")
        elif tool_name == "trufflehog":
            description = first_finding.get("DetectorDescription", "")
        elif tool_name == "grype":
            vuln = first_finding.get("vulnerability", {})
            description = vuln.get("description", "")
            urls = vuln.get("urls", [])
            help_uri = urls[0] if urls else ""
        elif tool_name == "checkov":
            #checkov rules are already in sarif format, but create a simplified version
            message = first_finding.get("message", {})
            if isinstance(message, dict):
                description = message.get("text", "")
    
    rule = {
        "id": rule_id,
        "name": rule_id
    }
    
    if description:
        rule["shortDescription"] = {"text": description[:200]}  #limit length
        rule["fullDescription"] = {"text": description}
    
    if help_uri:
        rule["helpUri"] = help_uri
    
    return rule


def _create_sarif_result(
    finding: Dict[str, Any],
    tool_name: str,
    rule_id: str
) -> Dict[str, Any]:
    """create a sarif result from a finding"""
    message_text = _extract_message_from_finding(finding, tool_name)
    severity = _extract_severity_from_finding(finding, tool_name)
    level = _map_severity_to_sarif_level(severity)
    file_path = _extract_file_path_from_finding(finding, tool_name)
    start_line, end_line = _extract_line_info_from_finding(finding, tool_name)
    fingerprints = _extract_fingerprints_from_finding(finding)
    is_waived = _is_waived(finding)
    
    result = {
        "ruleId": rule_id,
        "level": level,
        "message": {
            "text": message_text or f"Finding from {tool_name}"
        }
    }
    
    #add location if file path is available
    if file_path:
        location = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": file_path
                }
            }
        }
        
        if start_line and start_line > 0:
            region = {"startLine": start_line}
            if end_line and end_line > start_line:
                region["endLine"] = end_line
            location["physicalLocation"]["region"] = region
        
        result["locations"] = [location]
    
    #add fingerprints if available
    if fingerprints:
        #sarif supports partialFingerprints
        partial_fingerprints = {}
        if "rule" in fingerprints:
            partial_fingerprints["rule"] = fingerprints["rule"]
        if "exact" in fingerprints:
            partial_fingerprints["exact"] = fingerprints["exact"]
        if "ctx" in fingerprints:
            partial_fingerprints["ctx"] = fingerprints["ctx"]
        
        if partial_fingerprints:
            result["partialFingerprints"] = partial_fingerprints
    
    #add suppression/waiver information
    if is_waived:
        result["suppressions"] = [{
            "kind": "external",
            "status": "accepted"
        }]
    
    #add properties for additional metadata
    properties = {}
    if fingerprints:
        properties["fingerprints"] = fingerprints
    if is_waived:
        properties["waived"] = True
    
    if properties:
        result["properties"] = properties
    
    return result


def _create_sarif_run(
    tool_name: str,
    findings: List[Dict[str, Any]],
    existing_rules: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """create a sarif run for a specific tool
    
    existing_rules: optional list of existing sarif rules (e.g., from checkov)
    """
    if not findings:
        return None
    
    #use existing rules if provided (e.g., from checkov sarif)
    if existing_rules:
        rules = existing_rules
    else:
        #group findings by rule id
        findings_by_rule: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for finding in findings:
            rule_id = _extract_rule_id_from_finding(finding, tool_name)
            findings_by_rule[rule_id].append(finding)
        
        #create rules from unique rule ids
        rules = []
        for rule_id, rule_findings in findings_by_rule.items():
            rule = _create_sarif_rule(rule_id, tool_name, rule_findings)
            rules.append(rule)
    
    #create results from all findings
    results = []
    for finding in findings:
        rule_id = _extract_rule_id_from_finding(finding, tool_name)
        result = _create_sarif_result(finding, tool_name, rule_id)
        results.append(result)
    
    #create tool driver
    tool_driver = {
        "name": tool_name,
        "version": "1.0.0"  #default version, could be extracted from metadata
    }
    
    if rules:
        tool_driver["rules"] = rules
    
    run = {
        "tool": {
            "driver": tool_driver
        },
        "results": results
    }
    
    return run


def convert_unified_json_to_sarif(unified_data: Dict[str, Any]) -> Dict[str, Any]:
    """convert unified json structure to sarif 2.1.0 format
    
    returns sarif 2.1.0 log structure
    """
    runs = []
    
    #process each tool type
    tool_mappings = {
        "trufflehog_data": "trufflehog",
        "opengrep_data": "opengrep",
        "grype_data": "grype",
        "checkov_data": "checkov"
    }
    
    for data_key, tool_name in tool_mappings.items():
        tool_data = unified_data.get(data_key)
        if not tool_data:
            continue
        
        findings = []
        existing_rules = None
        
        if tool_name == "trufflehog":
            #trufflehog data is a list
            if isinstance(tool_data, list):
                findings = tool_data
            else:
                findings = [tool_data]
        elif tool_name == "opengrep":
            #opengrep data has results key
            if isinstance(tool_data, dict):
                findings = tool_data.get("results", [])
        elif tool_name == "grype":
            #grype data has matches key
            if isinstance(tool_data, dict):
                findings = tool_data.get("matches", [])
        elif tool_name == "checkov":
            #checkov data is already sarif format, extract results and rules
            if isinstance(tool_data, dict):
                checkov_runs = tool_data.get("runs", [])
                if checkov_runs:
                    checkov_run = checkov_runs[0]
                    checkov_results = checkov_run.get("results", [])
                    findings = checkov_results
                    #extract existing rules from checkov sarif
                    tool_driver = checkov_run.get("tool", {}).get("driver", {})
                    existing_rules = tool_driver.get("rules", [])
        
        if findings:
            run = _create_sarif_run(tool_name, findings, existing_rules)
            if run:
                runs.append(run)
    
    #create sarif log
    sarif_log = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs
    }
    
    return sarif_log


def generate_sarif_report(
    unified_json_path: str,
    output_path: str
) -> None:
    """generate sarif report from unified json file"""
    with open(unified_json_path, "r") as f:
        unified_data = json.load(f)
    
    sarif_log = convert_unified_json_to_sarif(unified_data)
    
    with open(output_path, "w") as f:
        json.dump(sarif_log, f, indent=2)

