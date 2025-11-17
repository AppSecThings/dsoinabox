import hashlib, hmac, re, json, os
from typing import Any, Dict, Tuple, Optional

def _b(s): 
    return s if isinstance(s, (bytes, bytearray)) else s.encode("utf-8")

def _hex8(b: bytes):  return hashlib.sha256(b).hexdigest()[:8]
def _hex12(b: bytes): return hashlib.sha256(b).hexdigest()[:12]
def _hex16(b: bytes): return hashlib.sha256(b).hexdigest()[:16]
def _hmac40(key: bytes, msg: bytes): return hmac.new(key, msg, hashlib.sha256).hexdigest()[:40]

def path_norm_sha(p: str) -> str:
    p2 = p.replace("\\", "/")
    p2 = re.sub(r"/+", "/", p2).lstrip("./")
    return _hex8(_b(p2))

#---------------- extractors ----------------

def _extract_rule_id(result: Dict[str, Any], sarif_data: Dict[str, Any]) -> str:
    """extract rule id from sarif result"""
    rule_id = result.get("ruleId", "")
    if not rule_id:
        rule_index = result.get("ruleIndex")
        if rule_index is not None:
            runs = sarif_data.get("runs", [])
            if runs:
                rules = runs[0].get("tool", {}).get("driver", {}).get("rules", [])
                if rule_index < len(rules):
                    rule = rules[rule_index]
                    rule_id = rule.get("id", "")
    return rule_id or "unknown"

def _extract_file_path(result: Dict[str, Any]) -> str:
    """extract file path from sarif result location"""
    locations = result.get("locations", [])
    if locations:
        physical_location = locations[0].get("physicalLocation", {})
        artifact_location = physical_location.get("artifactLocation", {})
        return artifact_location.get("uri", "")
    return ""

def _extract_line_info(result: Dict[str, Any]) -> Tuple[int, int]:
    """extract start and end line from sarif result"""
    locations = result.get("locations", [])
    if locations:
        physical_location = locations[0].get("physicalLocation", {})
        region = physical_location.get("region", {})
        start_line = region.get("startLine", 0)
        end_line = region.get("endLine", start_line)
        return start_line, end_line
    return 0, 0

def _extract_severity(result: Dict[str, Any], sarif_data: Dict[str, Any]) -> str:
    """extract severity from sarif result, mapping sarif levels to standard severities"""
    #sarif level: "error", "warning", "note", "none"
    sarif_level = result.get("level", "error").lower()
    
    #map sarif levels to standard severities
    #error -> high, warning -> medium, note -> low, none -> info
    level_map = {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "info"
    }
    
    severity = level_map.get(sarif_level, "medium")
    
    #also check rule properties for security-severity if available
    rule_index = result.get("ruleIndex")
    if rule_index is not None:
        runs = sarif_data.get("runs", [])
        if runs:
            rules = runs[0].get("tool", {}).get("driver", {}).get("rules", [])
            if rule_index < len(rules):
                rule = rules[rule_index]
                props = rule.get("properties", {})
                sec_severity = props.get("security-severity")
                if sec_severity:
                    #map numeric security-severity to severity levels
                    if sec_severity >= 9.0:
                        severity = "critical"
                    elif sec_severity >= 7.0:
                        severity = "high"
                    elif sec_severity >= 4.0:
                        severity = "medium"
                    else:
                        severity = "low"
    
    return severity

def _extract_message(result: Dict[str, Any]) -> str:
    """extract message text from sarif result"""
    message = result.get("message", {})
    if isinstance(message, dict):
        return message.get("text", "")
    return str(message) if message else ""

def _extract_snippet(result: Dict[str, Any]) -> str:
    """extract code snippet from sarif result"""
    locations = result.get("locations", [])
    if locations:
        physical_location = locations[0].get("physicalLocation", {})
        region = physical_location.get("region", {})
        snippet = region.get("snippet", {})
        if isinstance(snippet, dict):
            return snippet.get("text", "")
    return ""

#---------------- fingerprinting ----------------

def fingerprint_checkov_result(
    result: Dict[str, Any],
    sarif_data: Dict[str, Any],
    source_path: str,
    project_hmac_key: bytes,
    repo_hint: str = "",
) -> Tuple[str, str, str]:
    """
    build deterministic fingerprints for a checkov sarif result:
      - RULE   (rule-level, stable across file changes)
      - EXACT  (location-bound, specific to file and line)
      - CTX    (contextual, resilient to small changes)
    """
    rule_id = _extract_rule_id(result, sarif_data)
    file_path = _extract_file_path(result)
    start_line, end_line = _extract_line_info(result)
    message = _extract_message(result)
    snippet = _extract_snippet(result)
    
    #normalize file path relative to source
    if file_path:
        rel_path = file_path
        if source_path and file_path.startswith(source_path):
            rel_path = os.path.relpath(file_path, source_path)
        elif not os.path.isabs(file_path):
            rel_path = file_path
    else:
        rel_path = "unknown"
    
    #--- RULE fingerprint ---
    rule_coord = f"{rule_id}:{path_norm_sha(rel_path)}"
    rule_fp = f"ck:1:RULE:{rule_id}:{_hmac40(project_hmac_key, _b(rule_coord))}"
    
    #--- EXACT fingerprint ---
    file_sha = _hex12(_b(rel_path))  #simplified for now
    exact_fp = f"ck:1:EXACT:{rule_id}:{path_norm_sha(rel_path)}:{start_line}:{end_line}"
    
    #--- CTX fingerprint ---
    #use rule_id, normalized path, and snippet hash for context
    snippet_hash = _hex16(_b(snippet)) if snippet else "0000000000000000"
    ctx_fp = f"ck:1:CTX:{rule_id}:{path_norm_sha(rel_path)}:{snippet_hash}"
    
    if repo_hint:
        suf = ":" + _hex8(_b(repo_hint))
        rule_fp  += ":R" + suf
        exact_fp += ":R" + suf
        ctx_fp   += ":R" + suf
    
    return rule_fp, exact_fp, ctx_fp


def fingerprint_findings(
    sarif_data: Dict[str, Any],
    source_path: str,
    project_id: Optional[str] = None,
    repo_hint: str = "",
) -> Dict[str, Any]:
    """add fingerprints to each result in a checkov sarif report (mutates in-place)"""
    #backward compatibility: use DSOB_PROJECT_HMAC_KEY if set
    env_key = os.environ.get("DSOB_PROJECT_HMAC_KEY")
    if env_key:
        project_hmac_key = env_key.encode()
    elif project_id:
        from ..utils.project_id import derive_project_hmac_key
        project_hmac_key = derive_project_hmac_key(project_id)
        #use project_id as repo_hint if not explicitly provided
        if not repo_hint:
            repo_hint = project_id
    else:
        #fallback to default (should not happen in normal flow)
        project_hmac_key = b"<32-bytes-from-kms>"
    
    runs = sarif_data.get("runs", [])
    for run in runs:
        results = run.get("results", [])
        for result in results:
            rule_fp, exact_fp, ctx_fp = fingerprint_checkov_result(
                result, sarif_data, source_path, project_hmac_key, repo_hint
            )
            result.setdefault("fingerprints", {})
            result["fingerprints"].update({
                "rule": rule_fp,
                "exact": exact_fp,
                "ctx": ctx_fp
            })
    
    return sarif_data

