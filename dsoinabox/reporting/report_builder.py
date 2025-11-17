import json
from jinja2 import Environment, FileSystemLoader
import os
import shutil
from typing import Any

from ..utils.deterministic import utcnow, normalize_path
from .sarif_formatter import convert_unified_json_to_sarif


def _normalize_paths_in_data(data: Any) -> Any:
    """
    recursively normalize absolute paths in data structures
    
    ensures paths in reports are deterministic across different machines and environments
    """
    if isinstance(data, dict):
        normalized = {}
        for key, value in data.items():
            #normalize common path fields
            if key in ("path", "file", "file_path", "uri", "location", "realPath", "repository_local_path", "base_path"):
                if isinstance(value, str):
                    normalized[key] = normalize_path(value)
                else:
                    normalized[key] = _normalize_paths_in_data(value)
            elif key in ("locations", "artifactLocation", "physicalLocation", "SourceMetadata", "Data", "Git", "Filesystem"):
                #handle nested location structures
                normalized[key] = _normalize_paths_in_data(value)
            else:
                normalized[key] = _normalize_paths_in_data(value)
        return normalized
    elif isinstance(data, list):
        return [_normalize_paths_in_data(item) for item in data]
    elif isinstance(data, str):
        #check if string looks like an absolute path
        if os.path.isabs(data) and ("/" in data or "\\" in data):
            return normalize_path(data)
        return data
    else:
        return data

def report_builder(
    reports_directory = "reports", 
    output_dir = "reports", 
    timestamp: str = None,
    template_file: str = "default_unified_report.html",
    git_repo_info: dict = None,
    data: tuple = None,
    output_format: str = "html",
    waiver_data: dict = None,
) -> None:
    # Generate timestamp if not provided
    if timestamp is None:
        timestamp = utcnow().strftime('%Y_%m_%dT%H_%M_%S')
    trufflehog_data, opengrep_data, syft_data, grype_data, checkov_data = data or (None, None, None, None, None)
    '''report builder supports report outputs in html, jenkins_html, json, and ndjson formats'''
    
    #normalize paths in all data structures for deterministic output
    trufflehog_data = _normalize_paths_in_data(trufflehog_data) if trufflehog_data else None
    opengrep_data = _normalize_paths_in_data(opengrep_data) if opengrep_data else None
    syft_data = _normalize_paths_in_data(syft_data) if syft_data else None
    grype_data = _normalize_paths_in_data(grype_data) if grype_data else None
    checkov_data = _normalize_paths_in_data(checkov_data) if checkov_data else None
    
    if output_format.lower() == "json":
        #ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        output_filename = f"dsoinabox_unified_report_{timestamp}.json"
        output_path = os.path.join(output_dir, output_filename)
        output_data = {
            "metadata": {
                "scan_timestamp": timestamp,
                "git_repo_info": git_repo_info
            },
            "trufflehog_data": trufflehog_data,
            "opengrep_data": opengrep_data,
            "syft_data": syft_data,
            "grype_data": grype_data,
            "checkov_data": checkov_data,
            "git_repo_info": git_repo_info
        }
        with open(output_path, "w") as out_file:
            json.dump(output_data, out_file, indent=4)
        return
    
    if output_format.lower() == "ndjson":
        #ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        output_filename = f"dsoinabox_unified_report_{timestamp}.ndjson"
        output_path = os.path.join(output_dir, output_filename)
        
        #collect all findings from different scanners
        findings = []
        
        #add metadata as first line
        findings.append({
            "type": "metadata",
            "scan_timestamp": timestamp,
            "git_repo_info": git_repo_info
        })
        
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
        return
    
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
        return
    
    #ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    output_filename=f"dsoinabox_unified_report_{timestamp}.html"
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

    #render template with data
    rendered = template.render(
        grype_data=grype_data,
        syft_data=syft_data,
        trufflehog_data=trufflehog_data,
        opengrep_data=opengrep_data,
        checkov_data=checkov_data,
        git_repo_info=git_repo_info,
        waiver_data=waiver_data
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

