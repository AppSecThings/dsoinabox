import json
import os
import shutil
from typing import Any

from jinja2 import Environment, FileSystemLoader

from .. import __version__
from ..utils.deterministic import utcnow
from ..waivers.apply import active_findings, waived_findings
from .sarif_formatter import (
    _extract_file_path_from_finding,
    _extract_line_info_from_finding,
    _extract_rule_id_from_finding,
    _extract_severity_from_finding,
    convert_unified_json_to_sarif,
)


def _tool_findings(tool: str, data: Any) -> list[dict[str, Any]]:
    """The findings list inside a raw tool payload."""
    if not data:
        return []
    if tool == "trufflehog":
        return data if isinstance(data, list) else [data]
    if tool == "opengrep":
        return data.get("results", []) or []
    if tool == "grype":
        return data.get("matches", []) or []
    if tool == "checkov":
        runs = data.get("runs", []) or []
        return (runs[0].get("results", []) or []) if runs else []
    return []


def _with_findings(tool: str, data: Any, findings: list[dict[str, Any]]) -> Any:
    """Shallow copy of a raw tool payload with its findings list replaced."""
    if not data:
        return data
    if tool == "trufflehog":
        return findings
    if tool == "opengrep":
        return {**data, "results": findings}
    if tool == "grype":
        return {**data, "matches": findings}
    if tool == "checkov":
        runs = list(data.get("runs", []) or [])
        if runs:
            runs[0] = {**runs[0], "results": findings}
        return {**data, "runs": runs}
    return data


def _waiver_row(tool: str, finding: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    start, _end = _extract_line_info_from_finding(finding, tool)
    return {
        "tool": tool,
        "severity": _extract_severity_from_finding(finding, tool),
        "rule_id": _extract_rule_id_from_finding(finding, tool),
        "path": _extract_file_path_from_finding(finding, tool),
        "line": start or "",
        "waiver": record,
    }


def split_waived(tool_payloads: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (payloads with only active findings, waived rows, expired-waiver rows)."""
    active: dict[str, Any] = {}
    waived_rows: list[dict[str, Any]] = []
    expired_rows: list[dict[str, Any]] = []
    for tool, data in tool_payloads.items():
        findings = _tool_findings(tool, data)
        active[tool] = _with_findings(tool, data, active_findings(findings)) if findings else data
        for f in waived_findings(findings):
            waived_rows.append(_waiver_row(tool, f, f.get("waived_by") or {}))
        for f in active_findings(findings):
            for record in f.get("expired_waivers") or []:
                expired_rows.append(_waiver_row(tool, f, record))
    return active, waived_rows, expired_rows


def report_builder(
    reports_directory = "reports", 
    output_dir = "reports", 
    timestamp: str = None,
    template_file: str = "default_unified_report.html",
    git_repo_info: dict = None,
    data: tuple = None,
    output_format: str = "html",
    waiver_data: Any = None,
    waiver_summary: dict | None = None,
    scan_run: Any = None,
) -> str | None:
    # Generate timestamp if not provided
    if timestamp is None:
        timestamp = utcnow().strftime('%Y_%m_%dT%H_%M_%S')
    trufflehog_data, opengrep_data, syft_data, grype_data, checkov_data = data or (None, None, None, None, None)
    '''report builder supports report outputs in html, jenkins_html, json, and ndjson formats'''
    
    #templates and json need a plain dict; accept WaiverSet or legacy dict
    if waiver_data is not None and hasattr(waiver_data, "to_dict"):
        waiver_data = waiver_data.to_dict()

    #paths are made repo-relative by the normalizers (dsoinabox.normalize); nothing is rewritten here
    if output_format.lower() == "json":
        #ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        output_filename = f"dsoinabox_unified_report_{timestamp}.json"
        output_path = os.path.join(output_dir, output_filename)
        metadata: dict[str, Any] = {
            "dsoinabox_version": __version__,
            "scan_timestamp": timestamp,
            "git_repo_info": git_repo_info,
            "waivers": waiver_summary,
        }
        if scan_run is not None:
            metadata.update(scan_run.metadata_dict())
            metadata["dsoinabox_version"] = __version__
        output_data = {
            "metadata": metadata,
            "trufflehog_data": trufflehog_data,
            "opengrep_data": opengrep_data,
            "syft_data": syft_data,
            "grype_data": grype_data,
            "checkov_data": checkov_data,
            "git_repo_info": git_repo_info
        }
        if scan_run is not None:
            output_data["findings"] = [f.to_report_dict() for f in scan_run.findings]
        with open(output_path, "w") as out_file:
            json.dump(output_data, out_file, indent=4)
        return output_path
    
    if output_format.lower() == "ndjson":
        #ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        output_filename = f"dsoinabox_unified_report_{timestamp}.ndjson"
        output_path = os.path.join(output_dir, output_filename)
        
        #collect all findings from different scanners
        findings = []
        
        #add metadata as first line
        meta_line: dict[str, Any] = {
            "type": "metadata",
            "dsoinabox_version": __version__,
            "scan_timestamp": timestamp,
            "git_repo_info": git_repo_info,
            "waivers": waiver_summary,
        }
        if scan_run is not None:
            meta_line.update(scan_run.metadata_dict())
            meta_line["type"] = "metadata"
            meta_line["dsoinabox_version"] = __version__
        findings.append(meta_line)
        
        #add findings from each scanner
        if trufflehog_data:
            for finding in (trufflehog_data if isinstance(trufflehog_data, list) else [trufflehog_data]):
                findings.append({
                    "type": "trufflehog",
                    "finding": finding
                })
        
        if opengrep_data and opengrep_data.get("results"):
            for finding in opengrep_data["results"]:
                findings.append({
                    "type": "opengrep",
                    "finding": finding
                })
        
        if grype_data and grype_data.get("matches"):
            for finding in grype_data["matches"]:
                findings.append({
                    "type": "grype",
                    "finding": finding
                })
        
        if checkov_data:
            runs = checkov_data.get("runs", [])
            if runs:
                results = runs[0].get("results", [])
                for finding in results:
                    findings.append({
                        "type": "checkov",
                        "finding": finding
                    })
        
        #write ndjson (one json object per line)
        with open(output_path, "w") as out_file:
            for finding in findings:
                out_file.write(json.dumps(finding) + "\n")
        return output_path
    
    if output_format.lower() == "sarif":
        #ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        output_filename = f"dsoinabox_unified_report_{timestamp}.sarif"
        output_path = os.path.join(output_dir, output_filename)
        
        #build unified data structure
        unified_data = {
            "metadata": {
                "scan_timestamp": timestamp,
                "git_repo_info": git_repo_info
            },
            "trufflehog_data": trufflehog_data,
            "opengrep_data": opengrep_data,
            "syft_data": syft_data,
            "grype_data": grype_data,
            "checkov_data": checkov_data
        }
        
        #convert to sarif format
        sarif_log = convert_unified_json_to_sarif(unified_data)
        
        #write sarif file
        with open(output_path, "w") as out_file:
            json.dump(sarif_log, out_file, indent=2)
        return output_path
    
    #ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    if output_format == "jenkins_html":
        output_filename = f"dsoinabox_unified_report_{timestamp}_jenkins.html"
    else:
        output_filename = f"dsoinabox_unified_report_{timestamp}.html"
    #determine template directory based on output format
    templates_dir = os.path.join(os.path.dirname(__file__), "templates")
    if output_format == "jenkins_html":
        template_dir = os.path.join(templates_dir, "jenkins_html")
    else:
        template_dir = os.path.join(templates_dir, "html")
    
    #set up jinja environment and load template
    env = Environment(loader=FileSystemLoader(template_dir))
    #add tojson filter for json serialization in templates
    env.filters['tojson'] = lambda value: json.dumps(value)
    template = env.get_template(template_file)

    #waived findings leave the per-tool tables and get their own section
    active_payloads, waived_rows, expired_rows = split_waived({
        "trufflehog": trufflehog_data,
        "opengrep": opengrep_data,
        "grype": grype_data,
        "checkov": checkov_data,
    })

    #render template with data
    rendered = template.render(
        grype_data=active_payloads["grype"],
        syft_data=syft_data,
        trufflehog_data=active_payloads["trufflehog"],
        opengrep_data=active_payloads["opengrep"],
        checkov_data=active_payloads["checkov"],
        git_repo_info=git_repo_info,
        waiver_data=waiver_data,
        waiver_summary=waiver_summary,
        waived_findings=waived_rows,
        expired_waiver_findings=expired_rows,
        dsoinabox_version=__version__,
    )

    #write rendered output to file
    output_path = os.path.join(output_dir, output_filename)
    with open(output_path, "w") as out_file:
        out_file.write(rendered)
    
    #for jenkins html format, copy assets to output directory
    if output_format == "jenkins_html":
        assets_source = os.path.join(template_dir, "assets")
        assets_dest = os.path.join(output_dir, "assets")
        if os.path.exists(assets_source):
            if os.path.exists(assets_dest):
                shutil.rmtree(assets_dest)
            shutil.copytree(assets_source, assets_dest)
    return output_path
