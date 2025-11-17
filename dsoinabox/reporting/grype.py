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

def _source_hint(report: Dict[str, Any]) -> str:
    src = report.get("source") or {}
    target = src.get("target") or {}
    
    #if target is already a string, return it
    if isinstance(target, str):
        return target
    
    #if target is not a dict, can't extract anything from it
    if not isinstance(target, dict):
        return ""
    
    t = src.get("type") or ""
    if t == "directory":
        return target.get("userInput") or ""
    return (
        (target.get("repoDigests") or [None])[0]
        if isinstance(target.get("repoDigests"), list)
        else target.get("repoDigests")
    ) or target.get("repoDigest") or target.get("imageID") or target.get("userInput") or ""

def _package_coordinate(artifact: Dict[str, Any], match: Dict[str, Any], report: Dict[str, Any]) -> str:
    t = (artifact.get("type") or "").lower()
    n = (artifact.get("name") or "").lower()
    v = (artifact.get("version") or "")
    purl = (artifact.get("purl") or "").lower()
    vuln = match.get("vulnerability") or {}
    ns = (vuln.get("namespace") or "").lower()

    if not ns:
        d = report.get("distro") or {}
        ns = f"{d.get('name','').lower()}:{d.get('version','')}" if d else ""

    coord = f"{t}:{n}@{v}"
    if purl: coord += f"|{purl}"
    if ns:   coord += f"|{ns}"
    return coord

def _artifact_locations_hash(artifact: Dict[str, Any]) -> str:
    locs = artifact.get("locations") or []
    paths = sorted({path_norm_sha(l.get("path","")) for l in locs if l.get("path")})
    return _hex8(_b(",".join(paths))) if paths else "00000000"

def _package_version_hash(artifact: Dict[str, Any]) -> str:
    return _hex8(_b(artifact.get("version") or ""))

def _pkg8(artifact: Dict[str, Any]) -> str:
    return _hex8(_b(f"{artifact.get('type','').lower()}:{artifact.get('name','').lower()}"))

def _context_hash(match: Dict[str, Any], artifact: Dict[str, Any]) -> str:
    vuln = match.get("vulnerability") or {}
    ns = vuln.get("namespace","").lower()
    sev = vuln.get("severity","").upper()
    fix = vuln.get("fix") or {}
    vers = ",".join(sorted(fix.get("versions") or []))
    matcher = None
    for md in match.get("matchDetails") or []:
        fb = md.get("foundBy")
        if fb: matcher = fb; break
    purl = artifact.get("purl") or f"{artifact.get('type','').lower()}:{artifact.get('name','').lower()}"
    tup = "|".join([ns, sev, vers, str(matcher or ""), purl])
    return _hex16(_b(tup))

#---------------- fingerprinting ----------------

def fingerprint_grype_match(
    match: Dict[str, Any],
    report: Dict[str, Any],
    project_hmac_key: bytes,
    repo_hint: str = "",
) -> Tuple[str, str, str]:
    """
    build deterministic fingerprints for a grype match record:
      - PKG   (package-level, stable across environments)
      - EXACT (location-bound)
      - CTX   (contextual, resilient to small changes)
    """
    vuln = match.get("vulnerability") or {}
    artifact = match.get("artifact") or {}
    vid = (vuln.get("id") or "").strip()

    #--- PKG fingerprint ---
    coord = _package_coordinate(artifact, match, report)
    pkg_fp = f"gy:1:PKG:{vid}:{_hmac40(project_hmac_key, _b(coord))}"

    #--- EXACT fingerprint ---
    src_hint = _source_hint(report)
    src8  = _hex8(_b(src_hint)) if src_hint else "00000000"
    locs8 = _artifact_locations_hash(artifact)
    pver8 = _package_version_hash(artifact)
    exact_fp = f"gy:1:EXACT:{vid}:{src8}:{locs8}:{pver8}"

    #--- CTX fingerprint ---
    pkg8 = _pkg8(artifact)
    ctx16 = _context_hash(match, artifact)
    ctx_fp = f"gy:1:CTX:{vid}:{pkg8}:{ctx16}"

    if repo_hint:
        suf = ":" + _hex8(_b(repo_hint))
        pkg_fp   += ":R" + suf
        exact_fp += ":R" + suf
        ctx_fp   += ":R" + suf

    return pkg_fp, exact_fp, ctx_fp


def fingerprint_findings(
    report: Dict[str, Any],
    project_id: Optional[str] = None,
    repo_hint: str = "",
) -> Dict[str, Any]:
    """add fingerprints to each match in a grype report (mutates in-place)"""
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
    
    for m in report.get("matches", []):
        pkg, exact, ctx = fingerprint_grype_match(m, report, project_hmac_key, repo_hint)
        m.setdefault("fingerprints", {})
        m["fingerprints"].update({
            "pkg": pkg,
            "exact": exact,
            "ctx": ctx
        })
    return report
