import hmac, hashlib, base64, re, json
from typing import Tuple, Optional
import os
import subprocess
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

from ..utils.runner import run_cmd

#---------------- shared helpers ----------------

def _b(s): 
    return s if isinstance(s, (bytes, bytearray)) else s.encode("utf-8")

def _git(repo_root, *args, check=True):
    cmd = ["git", "-C", repo_root] + list(args)
    try:
        returncode, stdout, stderr = run_cmd(cmd, text=False, check=check)
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)
    except subprocess.CalledProcessError:
        #re-raise to maintain compatibility with existing exception handling
        raise

def _rev_parse_head(repo_root):
    try:
        return _git(repo_root, "rev-parse", "HEAD").stdout.decode().strip()
    except subprocess.CalledProcessError:
        return None

def file_sha(file_bytes: bytes) -> str:
    norm = file_bytes.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(norm).hexdigest()[:12]

def path_norm_sha(path_rel: str) -> str:
    p = path_rel.replace("\\", "/")
    p = re.sub(r"/+", "/", p).lstrip("./")
    return hashlib.sha256(_b(p)).hexdigest()[:8]

def context_hash(file_bytes: bytes, start: int, end: int) -> str:
    lo = max(0, start - 120)
    hi = min(len(file_bytes), end + 120)
    ctx = bytearray(file_bytes[lo:hi])
    red_lo, red_hi = start - lo, end - lo
    ctx[red_lo:red_hi] = b"<MATCH>"
    ctx = re.sub(rb"\s+", b" ", bytes(ctx))
    return hashlib.sha256(ctx).hexdigest()[:16]

def _first_nonempty(*vals):
    for v in vals:
        if v:
            return v
    return None

#---------------- opengrep-specific helpers ----------------

def read_bytes_for_path(repo_root: str, rel_path: str, commit: Optional[str] = None) -> bytes:
    """
    read file content from working tree (if commit is None or HEAD matches)
    or from a specific commit if provided
    """
    rel_posix = str(PurePosixPath(rel_path))
    head = _rev_parse_head(repo_root)
    disk_path = os.path.join(repo_root, rel_path)

    if (not commit) or (head and head.startswith(commit)):
        with open(disk_path, "rb") as f:
            return f.read()

    try:
        cp = _git(repo_root, "show", f"{commit}:{rel_posix}")
        return cp.stdout
    except subprocess.CalledProcessError as e:
        raise FileNotFoundError(f"git show {commit}:{rel_posix} failed: {e.stderr.decode(errors='replace')}")

def _split_lines_bytes_keepends(b: bytes):
    #bytes.splitlines(keepends=True) handles \n, \r\n, \r
    return b.splitlines(keepends=True)

def _byte_offset_from_line_col(file_bytes: bytes, line: int, col: int) -> int:
    """
    convert 1-based (line, col) to byte offset. tolerate utf-8 by re-encoding the slice
    """
    if line < 1 or col < 1:
        raise ValueError("line/col must be 1-based and >= 1")
    lines = _split_lines_bytes_keepends(file_bytes)
    if line > len(lines):
        #clamp to eof to be defensive
        return len(file_bytes)
    #start of target line
    start = sum(len(l) for l in lines[:line-1])
    line_bytes = lines[line-1]
    #convert "col characters" to bytes; col is 1-based char index
    try:
        #decode safely, then re-encode prefix
        txt = line_bytes.decode("utf-8", errors="ignore")
        prefix = txt[:max(0, col-1)].encode("utf-8", errors="ignore")
        return start + len(prefix)
    except Exception:
        #fallback to byte-wise for ascii-ish content
        return start + min(len(line_bytes), col-1)

def _extract_rule_id(f: dict) -> str:
    #try common shapes (semgrep-like/opengrep-ish)
    return _first_nonempty(
        f.get("rule_id"),
        f.get("check_id"),
        (f.get("rule") or {}).get("id"),
        (f.get("extra") or {}).get("id"),
        "unknown_rule"
    )

def _extract_repo_commit_hint(f: dict) -> Optional[str]:
    #if pipeline enriches findings with commit/repo info, pick it up
    sm = (f.get("source") or {})  #e.g. {"git": {"commit": "..."}}
    git = (sm.get("git") or {}) if isinstance(sm, dict) else {}
    return _first_nonempty(git.get("commit"), None)

def _extract_path(f: dict) -> str:
    return _first_nonempty(
        f.get("path"),
        (f.get("location") or {}).get("path"),
        (f.get("extra") or {}).get("path"),
        f.get("file"),
        ""
    ) or ""

def _extract_span_lc(f: dict):
    """
    return (start_line, start_col, end_line, end_col) if present (1-based), else None
    """
    def _lc(d, key):
        o = (f.get(d) or {}) if isinstance(f.get(d), dict) else {}
        p = o.get(key) or {}
        return (p.get("line"), p.get("col"))

    #common shapes
    start = (f.get("start") or {}) if isinstance(f.get("start"), dict) else None
    end   = (f.get("end") or {})   if isinstance(f.get("end"), dict)   else None
    if start and end and "line" in start and "col" in start and "line" in end and "col" in end:
        return (int(start["line"]), int(start["col"]), int(end["line"]), int(end["col"]))

    loc = f.get("location") or {}
    if "start" in loc and "end" in loc and isinstance(loc["start"], dict) and isinstance(loc["end"], dict):
        s, e = loc["start"], loc["end"]
        if {"line","col"} <= set(s) and {"line","col"} <= set(e):
            return (int(s["line"]), int(s["col"]), int(e["line"]), int(e["col"]))

    extra = f.get("extra") or {}
    if "start" in extra and "end" in extra and isinstance(extra["start"], dict) and isinstance(extra["end"], dict):
        s, e = extra["start"], extra["end"]
        if {"line","col"} <= set(s) and {"line","col"} <= set(e):
            return (int(s["line"]), int(s["col"]), int(e["line"]), int(e["col"]))

    return None

def _extract_snippet(f: dict) -> Optional[str]:
    """
    try to pull matched snippet if present (semgrep puts it in extra.lines)
    """
    extra = f.get("extra") or {}
    lines = extra.get("lines")  #raw matched lines (string)
    if isinstance(lines, str) and lines.strip():
        return lines
    #sometimes engines attach 'match' field
    return _first_nonempty(f.get("match"), None)

def _collect_primary_metavars(f: dict) -> dict:
    """
    grab small set of metavars and their 'abstract_content' if present
    order-insensitive
    """
    meta = ((f.get("extra") or {}).get("metavars") or {}) if isinstance(f.get("extra"), dict) else {}
    out = {}
    for k, v in sorted(meta.items()):
        if isinstance(v, dict):
            ac = _first_nonempty(v.get("abstract_content"), v.get("str"), v.get("value"))
            if isinstance(ac, str) and ac:
                out[k] = ac.strip()
    return out

def _normalize_structural(snippet: Optional[str], metavars: dict) -> bytes:
    """
    normalize code-ish content for hmac:
      - collapse whitespace
      - strip obvious comments (single-line //, #) lightly (best-effort)
      - include small, sorted set of meta vars (names + normalized values)
    """
    buf = ""
    if snippet:
        s = snippet
        #rudimentary comment stripping (best-effort, language-agnostic)
        s = re.sub(r"(?m)//.*$", "", s)          #c/js style
        s = re.sub(r"(?m)#.*$", "", s)           #python/shell
        s = re.sub(r"/\*[\s\S]*?\*/", "", s)     #block comments
        s = re.sub(r"(?m)^\s*\*\s*", "", s)      #javadoc leading '*'
        s = re.sub(r"\s+", " ", s).strip()
        buf += s
    if metavars:
        parts = []
        for k, v in sorted(metavars.items()):
            vv = re.sub(r"\s+", " ", v).strip()
            parts.append(f"{k}={vv}")
        if parts:
            buf += " | MV:" + ";".join(parts)
    return _b(buf)

def hmac_structural(project_key: bytes, normalized: bytes) -> str:
    return hmac.new(project_key, normalized, hashlib.sha256).hexdigest()[:40]

#---------------- fingerprint builder for opengrep ----------------

def fingerprint_opengrep(
    finding: dict,
    repo_root: str,
    project_key: bytes,
    repo_hint: str = "",
) -> Tuple[str, str, str]:
    """
    produce (RULE, EXACT, CTX) fingerprints for an opengrep finding
    """
    rule_id = _extract_rule_id(finding)
    rel_path = _extract_path(finding) or finding.get("file") or ""
    if not rel_path:
        raise KeyError("OpenGrep finding missing path")

    commit_hint = _extract_repo_commit_hint(finding)
    file_bytes = read_bytes_for_path(repo_root, rel_path, commit=commit_hint)

    #compute byte span
    start_b = end_b = None
    lc = _extract_span_lc(finding)
    if lc:
        sl, sc, el, ec = lc
        start_b = _byte_offset_from_line_col(file_bytes, sl, sc)
        end_b   = _byte_offset_from_line_col(file_bytes, el, ec)
        if end_b < start_b:
            start_b, end_b = end_b, start_b  #defensive
    else:
        #fallback: try to locate snippet bytes
        snippet = _extract_snippet(finding)
        if snippet:
            #search robustly (eol-agnostic)
            fb_norm = file_bytes.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            sn_norm = snippet.replace("\r\n", "\n").replace("\r", "\n")
            i = fb_norm.find(_b(sn_norm))
            if i != -1:
                start_b, end_b = i, i + len(_b(sn_norm))
    if start_b is None or end_b is None:
        #if we can't anchor, bind to path-only context
        start_b, end_b = 0, 0

    #structural hmac input: snippet + metavars
    snippet = _extract_snippet(finding)
    metavars = _collect_primary_metavars(finding)
    norm_struct = _normalize_structural(snippet, metavars)

    #--------- build three tiers ---------
    rule_fp  = f"og:1:RULE:{rule_id}:{hmac_structural(project_key, norm_struct)}"
    exact_fp = f"og:1:EXACT:{rule_id}:{file_sha(file_bytes)}:{start_b}:{end_b}"
    ctx_fp   = f"og:1:CTX:{rule_id}:{path_norm_sha(rel_path)}:{context_hash(file_bytes, start_b, end_b)}"

    if repo_hint:
        suffix = hashlib.sha256(_b(repo_hint)).hexdigest()[:8]
        rule_fp  += f":R:{suffix}"
        exact_fp += f":R:{suffix}"
        ctx_fp   += f":R:{suffix}"

    return rule_fp, exact_fp, ctx_fp

#---------------- batch driver ----------------

def fingerprint_findings(findings: list[dict], source_path: str, project_id: Optional[str] = None) -> list[dict]:
    """
    given a list of opengrep findings, append:
      finding["fingerprints"] = {"rule": ..., "exact": ..., "ctx": ...}
    """
    #backward compatibility: use DSOB_PROJECT_HMAC_KEY if set
    env_key = os.environ.get("DSOB_PROJECT_HMAC_KEY")
    if env_key:
        project_key = env_key.encode()
    elif project_id:
        from ..utils.project_id import derive_project_hmac_key
        project_key = derive_project_hmac_key(project_id)
    else:
        #fallback to default (should not happen in normal flow)
        project_key = b"<32-bytes-from-kms>"
    
    #use project_id as repo_hint if not explicitly provided
    repo_hint = project_id if project_id else "psf/requests"

    for f in findings['results']:
        try:
            rule_fp, exact_fp, ctx_fp = fingerprint_opengrep(
                finding=f,
                repo_root=source_path,
                project_key=project_key,
                repo_hint=repo_hint,
            )
            f["fingerprints"] = {
                "rule": rule_fp,
                "exact": exact_fp,
                "ctx": ctx_fp,
            }
        except (FileNotFoundError, KeyError) as e:
            #file not found or missing required metadata - mark as unlocatable
            rule_id = _extract_rule_id(f)
            rel_path = _extract_path(f) or f.get("file") or "unknown"
            #generate minimal rule fingerprint for waivers/deduplication
            snippet = _extract_snippet(f)
            metavars = _collect_primary_metavars(f)
            norm_struct = _normalize_structural(snippet, metavars)
            rule_fp = f"og:1:RULE:{rule_id}:{hmac_structural(project_key, norm_struct)}"
            if repo_hint:
                suffix = hashlib.sha256(_b(repo_hint)).hexdigest()[:8]
                rule_fp += f":R:{suffix}"
            f["fingerprints"] = {
                "rule": rule_fp,
                "exact": f"og:1:EXACT:{rule_id}:<unlocatable>",
                "ctx": f"og:1:CTX:{rule_id}:{path_norm_sha(rel_path)}:<unlocatable>",
            }
    return findings
