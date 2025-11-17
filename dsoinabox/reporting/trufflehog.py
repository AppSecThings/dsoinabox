import hmac, hashlib, base64, re, html, urllib.parse, unicodedata
from typing import Tuple, Optional
import os
import subprocess
from pathlib import Path, PurePosixPath
from collections import defaultdict
from types import SimpleNamespace

from ..utils.runner import run_cmd

def _b(s): return s if isinstance(s, (bytes, bytearray)) else s.encode("utf-8")

def _git(repo_root, *args, check=True):
    cmd = ["git", "-C", repo_root] + list(args)
    try:
        returncode, stdout, stderr = run_cmd(cmd, text=False, check=check)
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)
    except subprocess.CalledProcessError:
        #re-raise to maintain compatibility with existing exception handling
        raise

#cache for git HEAD per repo_root
_head_cache: dict[str, Optional[str]] = {}

def _rev_parse_head(repo_root: str, cache: dict[str, Optional[str]] = None) -> Optional[str]:
    """get git HEAD commit, with caching"""
    if cache is None:
        cache = _head_cache
    
    if repo_root not in cache:
        try:
            cache[repo_root] = _git(repo_root, "rev-parse", "HEAD").stdout.decode().strip()
        except subprocess.CalledProcessError:
            cache[repo_root] = None
    return cache[repo_root]

ENTITY_MAP = {
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;"
}

def candidate_variants(detector: str, c: str) -> list[str]:
    #raw
    vs = [c]

    #html entity decode/encode
    unesc = html.unescape(c)
    if unesc != c: vs.append(unesc)

    esc = c
    for ch, ent in ENTITY_MAP.items():
        esc = esc.replace(ch, ent)
    if esc != c: vs.append(esc)

    #url decode/encode (useful for uri-ish findings)
    url_dec = urllib.parse.unquote(c)
    if url_dec != c: vs.append(url_dec)
    url_enc = urllib.parse.quote(c, safe="/:@?&=+,$-_.!~*'()#")
    if url_enc != c: vs.append(url_enc)

    #collapse whitespace (detectors sometimes normalize)
    sq = " ".join(c.split())
    if sq != c: vs.append(sq)

    #de-hyphen/underscore for key-ish tokens (mirrors your normalize_secret)
    if detector.lower() not in {"jwt", "json web token"}:
        de_sep = re.sub(r"[-_\s]", "", c)
        if de_sep != c: vs.append(de_sep)

    #dedup while preserving order
    seen, out = set(), []
    for v in vs:
        if v not in seen:
            out.append(v); seen.add(v)
    return out

def decode_text_views(file_bytes: bytes) -> list[tuple[str, str]]:
    """
    returns labeled textual 'views' of the blob for tolerant matching
    byte offsets are only reliable for the 'raw' view
    """
    views = []
    #try common encodings quickly
    for enc, label in [("utf-8", "utf8"), ("utf-16-le", "utf16le"), ("utf-16-be", "utf16be")]:
        try:
            txt = file_bytes.decode(enc)
            views.append((label, txt))
        except Exception:
            pass
    #fallback 'latin1' (never fails)
    if not views:
        views.append(("latin1", file_bytes.decode("latin1", errors="replace")))

    #for each view, add normalized + entity-decoded
    expanded = []
    for label, txt in views:
        base = txt
        expanded.append((label, base))
        expanded.append((label + "+nfkc", unicodedata.normalize("NFKC", base)))
        expanded.append((label + "+unescape", html.unescape(base)))
        expanded.append((label + "+nfkc+unescape", html.unescape(unicodedata.normalize("NFKC", base))))
    return expanded

def scheme_mismatch(detector: str, file_bytes: bytes) -> bool:
    d = (detector or "").lower()
    if d in {"sqlserver", "mssql"}:
        try_views = []
        #quick, cheap text views
        for enc in ("utf-8", "utf-16-le", "utf-16-be", "latin1"):
            try:
                try_views.append(file_bytes.decode(enc))
            except Exception:
                pass
        hay = "\n".join(try_views[:2]) if try_views else ""
        return not re.search(r"(?:sqlserver|mssql)://", hay, re.I)
    return False

def locate_span(detector: str, candidate: str, file_bytes: bytes, approx_line: int | None):
    """
    returns (start, end, status) where status in:
      - FOUND_EXACT
      - FOUND_AFTER_DECODE  (found only after entity/url/normalization)
      - SCHEME_MISMATCH     (detector implies scheme that is not present)
      - UNLOCATABLE
    """
    #1) fast/strict path: your robust finder
    try:
        s, e = find_span_in_file(file_bytes, candidate, approx_line=approx_line)
        return s, e, "FOUND_EXACT"
    except ValueError:
        pass

    #2) try entity-decoded text and map back to raw
    #(best-effort, still return FOUND_AFTER_DECODE even if can't map)
    text = None
    for enc in ("utf-8", "utf-16-le", "utf-16-be", "latin1"):
        try:
            text = file_bytes.decode(enc)
            break
        except Exception:
            continue
    if text is None:
        text = file_bytes.decode("latin1", errors="replace")

    variants = {candidate, html.unescape(candidate), urllib.parse.unquote(candidate)}
    decoded = html.unescape(text)
    hit = None
    which = None
    for v in variants:
        idx = decoded.find(v)
        if idx != -1:
            hit = (idx, idx + len(v))
            which = v
            break

    if hit:
        #try mapping back by re-escaping common entities
        raw_guess = html.escape(decoded[hit[0]:hit[1]], quote=True)
        rb = raw_guess.encode("utf-8")
        j = file_bytes.find(rb)
        if j != -1:
            return j, j + len(rb), "FOUND_AFTER_DECODE"
        #couldn't map back to bytes, but did find it logically
        return -1, -1, "FOUND_AFTER_DECODE"

    #3) heuristic: scheme mismatch for scheme-specific detectors
    if scheme_mismatch(detector, file_bytes):
        return -1, -1, "SCHEME_MISMATCH"

    #4) give up
    return -1, -1, "UNLOCATABLE"

# def should_fail_build(f):
#     status = f.get("location_status")
#     verified = f.get("Verified", False)
#     det = (f.get("DetectorName") or "").lower()

#     if status in {"FOUND_EXACT", "FOUND_AFTER_DECODE"}:
#         return True
#     if status in {"SCHEME_MISMATCH", "UNLOCATABLE"}:
#         # You can tune this per detector. For SQLServer, likely False.
#         if det in {"sqlserver", "mssql"}:
#             return False
#         # For others, you might still fail if Verified is True.
#         return bool(verified)
#     return False



def _make_file_cache_key(path_rel: str, mode: str, commit: Optional[str] = None, mtime: Optional[float] = None) -> str:
    """create a cache key for file bytes"""
    if mode == "git" and commit:
        return f"git:{commit}:{path_rel}"
    elif mode == "filesystem" and mtime is not None:
        return f"fs:{path_rel}:{mtime}"
    else:
        #fallback: use path only (less safe but better than nothing)
        return f"{mode}:{path_rel}"

def read_file_bytes_from_git_finding(
    repo_root: str, 
    git_meta: dict, 
    cache: Optional[dict[str, bytes]] = None,
    cached_head: Optional[str] = None
) -> bytes:
    """
    read exact blob from commit/path recorded in trufflehog's git metadata
    falls back to on-disk read iff HEAD matches that commit and path exists
    uses cache if provided
    """
    commit = git_meta["commit"]
    path_rel = git_meta["file"]
    git_path = str(PurePosixPath(path_rel))  #ensure posix for `git show`
    
    #check cache first
    cache_key = _make_file_cache_key(path_rel, "git", commit=commit)
    if cache is not None and cache_key in cache:
        return cache[cache_key]
    
    #print(f"Reading file bytes from git finding: {commit}:{git_path}")

    head = cached_head if cached_head is not None else _rev_parse_head(repo_root)
    disk_path = os.path.join(repo_root, path_rel)

    if head and head.startswith(commit) and os.path.exists(disk_path):
        with open(disk_path, "rb") as f:
            file_bytes = f.read()
            if cache is not None:
                cache[cache_key] = file_bytes
            return file_bytes

    #read directly from commit
    try:
        cp = _git(repo_root, "show", f"{commit}:{git_path}")
        file_bytes = cp.stdout  #raw bytes
        if cache is not None:
            cache[cache_key] = file_bytes
        return file_bytes
    except subprocess.CalledProcessError as e:
        #helpful diagnostics: list paths in that commit
        try:
            tree = _git(repo_root, "ls-tree", "-r", commit).stdout.decode(errors="replace")
        except subprocess.CalledProcessError:
            tree = ""
        msg = (
            f"Failed to load blob via git show {commit}:{git_path}\n"
            f"git stderr: {e.stderr.decode(errors='replace')}\n"
        )
        if tree:
            msg += "Paths in that commit include e.g.:\n" + "\n".join(tree.splitlines()[:10])
        raise FileNotFoundError(msg)

def _first_nonempty(*vals):
    for v in vals:
        if v:
            return v
    return None

def read_file_bytes_generic(
    repo_root: str, 
    finding: dict,
    cache: Optional[dict[str, bytes]] = None,
    cached_head: Optional[str] = None
):
    """
    supports both git and filesystem findings
    returns (file_bytes, approx_line, path_used, mode) where mode is 'git' or 'filesystem'
    uses cache if provided
    """
    sm = finding.get("SourceMetadata", {}) or {}
    data = sm.get("Data", {}) or {}

    git_meta = data.get("Git")
    #some detectors place line info outside git block; try a few spots
    approx_line = _first_nonempty(
        (git_meta or {}).get("line"),
        data.get("line"),
        (data.get("Filesystem") or {}).get("line"),
        finding.get("line"),
    )

    if isinstance(git_meta, dict) and "file" in git_meta and "commit" in git_meta:
        file_bytes = read_file_bytes_from_git_finding(repo_root, git_meta, cache=cache, cached_head=cached_head)
        return file_bytes, approx_line, git_meta.get("file"), "git"

    #filesystem modes can show up as:
    #- Data["file"]
    #- Data["Filesystem"]["file"]
    #- occasionally top-level "file" (defensive)
    fs_meta = data.get("Filesystem") or {}
    fs_path = _first_nonempty(
        data.get("file"),
        fs_meta.get("file"),
        finding.get("file"),
    )
    if not fs_path:
        raise KeyError("No usable path found in finding for filesystem mode (checked Data.file, Data.Filesystem.file).")

    #if fs_path is absolute, use it; otherwise join to repo_root (if provided)
    p = Path(fs_path)
    disk_path = p if p.is_absolute() else Path(repo_root) / fs_path

    #check cache for filesystem files (using mtime for cache key)
    mtime = None
    if cache is not None:
        try:
            mtime = os.path.getmtime(disk_path)
            cache_key = _make_file_cache_key(str(disk_path), "filesystem", mtime=mtime)
            if cache_key in cache:
                return cache[cache_key], approx_line, str(disk_path), "filesystem"
        except OSError:
            pass  #file might not exist, fall through to error handling

    try:
        with open(disk_path, "rb") as f:
            file_bytes = f.read()
            #cache filesystem files
            if cache is not None:
                try:
                    if mtime is None:
                        mtime = os.path.getmtime(disk_path)
                    cache_key = _make_file_cache_key(str(disk_path), "filesystem", mtime=mtime)
                    cache[cache_key] = file_bytes
                except OSError:
                    pass  #can't get mtime, skip caching
            return file_bytes, approx_line, str(disk_path), "filesystem"
    except FileNotFoundError as e:
        raise FileNotFoundError(f"Filesystem path not found: {disk_path}") from e

def normalize_secret(detector: str, candidate: str, cache: Optional[dict[tuple[str, str], bytes]] = None) -> bytes:
    """normalize secret candidate, with optional caching by (detector, candidate) tuple"""
    cache_key = (detector, candidate)
    if cache is not None and cache_key in cache:
        return cache[cache_key]
    
    s = candidate.strip()

    #remove common separators for key-like tokens
    if detector.lower() not in {"jwt", "json web token"}:
        s = re.sub(r"[-_\s]", "", s)

    #try base64 decode if plausible (length, charset, padding)
    b64ish = re.fullmatch(r"[A-Za-z0-9+/=]{16,}", s) is not None and len(s) % 4 == 0
    if b64ish:
        try:
            dec = base64.b64decode(s, validate=True)
            if 8 <= len(dec) <= 4096:
                result = dec  #prefer decoded bytes
                if cache is not None:
                    cache[cache_key] = result
                return result
        except Exception:
            pass

    #hex normalization (case-insensitive)
    if re.fullmatch(r"[0-9A-Fa-f]{16,}", s):
        s = s.lower()

    result = _b(s)
    if cache is not None:
        cache[cache_key] = result
    return result

def hmac_secret(project_key: bytes, normalized_secret: bytes) -> str:
    return hmac.new(project_key, normalized_secret, hashlib.sha256).hexdigest()[:40]

def file_sha(file_bytes: bytes, cache: Optional[dict[bytes, str]] = None) -> str:
    """
    compute sha256 hash of normalized file bytes (crlf -> lf)
    uses cache if provided (keyed by file_bytes)
    """
    #check cache first (using file_bytes as key)
    if cache is not None and file_bytes in cache:
        return cache[file_bytes]
    
    #normalize newlines to lf for stability
    norm = file_bytes.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    sha = hashlib.sha256(norm).hexdigest()[:12]
    
    #cache the result
    if cache is not None:
        cache[file_bytes] = sha
    
    return sha

def context_hash(file_bytes: bytes, start: int, end: int) -> str:
    """
    generate context hash for a file region, redacting the secret span
    
    handles edge cases where start/end might be negative or invalid
    """
    #ensure start and end are valid
    start = max(0, start)
    end = max(start, min(end, len(file_bytes)))
    
    #extract context window (120 bytes before and after)
    lo = max(0, start - 120)
    hi = min(len(file_bytes), end + 120)
    
    if lo >= hi:
        #edge case: no valid context window
        ctx = b"<NO_CONTEXT>"
    else:
        ctx = bytearray(file_bytes[lo:hi])
        #redact secret region (only if it's within context window)
        red_lo = max(0, start - lo)
        red_hi = min(len(ctx), end - lo)
        if red_lo < red_hi:
            ctx[red_lo:red_hi] = b"<SECRET>"
    
    #normalize whitespace
    ctx = re.sub(rb"\s+", b" ", bytes(ctx))
    return hashlib.sha256(ctx).hexdigest()[:16]

def path_norm_sha(path_rel: str, cache: Optional[dict[str, str]] = None) -> str:
    """compute normalized path sha, with optional caching by path string"""
    if cache is not None and path_rel in cache:
        return cache[path_rel]
    
    p = path_rel.replace("\\", "/")
    p = re.sub(r"/+", "/", p).lstrip("./")
    result = hashlib.sha256(_b(p)).hexdigest()[:8]
    if cache is not None:
        cache[path_rel] = result
    return result

def fingerprint_trufflehog(
    detector: str,
    candidate: str,
    file_bytes: bytes,
    start: int,
    end: int,
    project_key: bytes,
    path_rel: str,
    repo_hint: str = "",
    file_sha_cache: Optional[dict[bytes, str]] = None,
    normalize_secret_cache: Optional[dict[tuple[str, str], bytes]] = None,
    path_norm_sha_cache: Optional[dict[str, str]] = None,
    repo_hint_suffix: Optional[str] = None,
) -> Tuple[str, str, str]:
    ns = normalize_secret(detector, candidate, cache=normalize_secret_cache)
    secret = f"th:1:SECRET:{detector}:{hmac_secret(project_key, ns)}"
    exact  = f"th:1:EXACT:{detector}:{file_sha(file_bytes, cache=file_sha_cache)}:{start}:{end}"
    ctx    = f"th:1:CTX:{detector}:{path_norm_sha(path_rel, cache=path_norm_sha_cache)}:{context_hash(file_bytes, start, end)}"
    if repo_hint:
        suffix = repo_hint_suffix if repo_hint_suffix is not None else ":" + hashlib.sha256(_b(repo_hint)).hexdigest()[:8]
        secret += ":R" + suffix
        exact  += ":R" + suffix
        ctx    += ":R" + suffix
    return secret, exact, ctx


def find_span_in_file(file_bytes: bytes, target: str, approx_line: int | None = None):
    """
    return (start, end) byte offsets for first occurrence of `target`
    handles both single and multi-line `target`, tolerant to line-ending variations (\n, \r\n, \r)
    if `approx_line` is provided, search that line first, then fall back to whole-file search
    """
    for tv in candidate_variants("", target):
        tb = _b(tv)
        i = file_bytes.find(tb)
        if i != -1:
            return i, i + len(tb)

    #print(f"Finding span in file: {file_bytes}")
    #normalize target's line endings to canonical form; file bytes remain unchanged
    target_norm = target.replace("\r\n", "\n").replace("\r", "\n")

    #prepare variants to tolerate trailing/leading newline mismatches
    target_variants: list[str] = [target_norm]
    trimmed = target_norm.strip("\n")
    if trimmed and trimmed != target_norm:
        target_variants.append(trimmed)
    rtrim = target_norm.rstrip("\n")
    if rtrim and rtrim not in target_variants:
        target_variants.append(rtrim)
    ltrim = target_norm.lstrip("\n")
    if ltrim and ltrim not in target_variants:
        target_variants.append(ltrim)

    def build_eol_pattern_bytes(s: str) -> bytes:
        #build eol-agnostic regex for target: each newline in target can match crlf/cr/lf in file
        ends_with_nl = s.endswith("\n")
        parts = [re.escape(p) for p in s.split("\n") if p != ""]
        if parts:
            pattern_text = "(?:\\r\\n|\\r|\\n)".join(parts)
        else:
            pattern_text = ""
        #make the final eol optional if original ended with a newline
        if ends_with_nl:
            if pattern_text:
                pattern_text = pattern_text + "(?:\\r\\n|\\r|\\n)?"
            else:
                pattern_text = "(?:\\r\\n|\\r|\\n)"
        return pattern_text.encode("utf-8")

    #1) try hinted line first for precision
    if approx_line and approx_line >= 1:
        lines = file_bytes.splitlines(keepends=True)
        if approx_line <= len(lines):
            #compute byte offset to start of that line
            line_start = sum(len(l) for l in lines[:approx_line-1])
            line_bytes = lines[approx_line-1]

            for tv in target_variants:
                target_b = _b(tv)
                #direct bytes find (works when line endings already match)
                i = line_bytes.find(target_b)
                if i != -1:
                    start = line_start + i
                    return start, start + len(target_b)

                #eol-agnostic regex match within the line
                m = re.search(build_eol_pattern_bytes(tv), line_bytes)
                if m:
                    return line_start + m.start(), line_start + m.end()

    #build file variants to handle cr/lf differences robustly
    file_variants: list[bytes] = [file_bytes]
    file_norm = file_bytes.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    if file_norm != file_bytes:
        file_variants.append(file_norm)

    #2) whole-file direct search across variants
    for fb in file_variants:
        for tv in target_variants:
            target_b = _b(tv)
            i = fb.find(target_b)
            if i != -1:
                return i, i + len(target_b)

    #3) whole-file eol-agnostic regex search across variants
    for fb in file_variants:
        for tv in target_variants:
            m = re.search(build_eol_pattern_bytes(tv), fb)
            if m:
                return m.start(), m.end()

    #4) last resort: whitespace-tolerant using tokenization (avoids fragile parentheses)
    #split on any whitespace in normalized target and join tokens with \s+
    m = None
    for fb in file_variants:
        for tv in target_variants:
            tokens = [re.escape(t) for t in re.split(r"\s+", tv) if t]
            if not tokens:
                continue
            pattern_bytes = b"\\s+".join(t.encode("utf-8") for t in tokens)
            m = re.search(pattern_bytes, fb)
            if m:
                return m.start(), m.end()

    #5) pem-aware fallback: if target looks like pem block, capture begin..end span
    if "-----BEGIN " in target_norm:
        first_line = next((ln for ln in target_norm.split("\n") if ln.strip()), "")
        end_marker = None
        pem_type = None
        if first_line.startswith("-----BEGIN ") and first_line.endswith("-----"):
            pem_type = first_line[len("-----BEGIN "):-len("-----")]
        if pem_type:
            #build pattern: -----BEGIN <TYPE>----- ... -----END <TYPE>-----
            t_esc = re.escape(pem_type)
            pem_pat = (fr"-----BEGIN\s+{t_esc}-----[\s\S]*?-----END\s+{t_esc}-----").encode("utf-8")
            for fb in file_variants:
                m = re.search(pem_pat, fb)
                if m:
                    return m.start(), m.end()

    #6) generic pem block fallback: match any pem block when candidate likely references one
    if "-----BEGIN " in target_norm or "PRIVATE KEY" in target_norm or "CERTIFICATE" in target_norm:
        generic_pem_pat = rb"-----BEGIN [^\r\n-]+-----[\s\S]*?-----END [^\r\n-]+-----"
        for fb in file_variants:
            for m in re.finditer(generic_pem_pat, fb):
                #prefer the first block that contains any non-empty token from target
                tokens = [t for t in re.split(r"\s+", target_norm) if t]
                if not tokens:
                    return m.start(), m.end()
                block = fb[m.start():m.end()]
                if any(_b(t) in block for t in tokens[:5] + tokens[-5:]):
                    return m.start(), m.end()
    
    if m:
        return m.start(), m.end()
    
    #if not found, try tolerant match against decoded text views
    #if we match in decoded view, attempt to map back by trying entity-encoded variant on raw bytes
    for label, txt in decode_text_views(file_bytes):
        for tv in candidate_variants("", target):
            #whitespace/linebreak tolerant text regex
            pat = re.compile(r"\s*".join(map(re.escape, tv.split())), re.DOTALL)
            m = pat.search(txt)
            if not m:
                continue
            #try to map back to raw bytes by testing a few re-encodings of the matched substring
            snippet = txt[m.start():m.end()]
            #try as-is
            for back in [snippet, html.escape(snippet, quote=True), urllib.parse.quote(snippet, safe="/:@?&=+,$-_.!~*'()#")]:
                bb = _b(back)
                j = file_bytes.find(bb)
                if j != -1:
                    return j, j + len(bb)

    raise ValueError("Could not locate target bytes in file content")

# def fingerprint_findings(findings: list[dict], source_path: str) -> list[dict]:
#     """
#     Generate deterministic, privacy-safe fingerprints for a Trufflehog finding.

#     Each fingerprint tier captures a different balance of stability and specificity:

#     - SECRET: Hash-based identifier derived from the normalized secret value
#       (via HMAC-SHA256 with a project-scoped key). Stable across file moves
#       and commits, and safe to store publicly since the raw secret is never exposed.
#       This is the preferred fingerprint type for waivers and deduplication.

#     - EXACT: Location-bound identifier derived from the detector name,
#       normalized file content hash, and byte span of the finding.
#       This binds tightly to a specific file revision and match location,
#       ensuring precise scoping but breaking if the file changes.

#     - CTX: Contextual identifier derived from the detector name,
#       normalized relative file path, and a hash of the redacted
#       surrounding context window. This fingerprint remains valid
#       through small edits or whitespace changes but loses specificity
#       if the finding moves significantly.

#     Returns a tuple of (SECRET, EXACT, CTX) fingerprints as strings.
#     These findings are appended to the finding as "fingerprints" key.
#     eg: 
#     {
#         "fingerprints": {
#             "secret": "th:1:SECRET:URI:1f2a...c9d",
#             "exact": "th:1:EXACT:URI:sha256:1f2a...c9d:1:10",
#             "ctx": "th:1:CTX:URI:path_norm_sha:context_hash"
#         }
#     }
#     """
#     for finding in findings:
#         detector = finding["DetectorName"]                       # e.g., "URI"
#         candidate = finding.get("RawV2") or finding.get("Raw")
#         repo_root = source_path                                  # "/scan_target"

#         file_bytes, approx_line, path_used, mode = read_file_bytes_generic(repo_root, finding)

#         # Compute byte-span of the secret in this file
#         start, end = find_span_in_file(file_bytes, candidate, approx_line=approx_line)

#         # HMAC key for the SECRET fingerprint (store/rotate via KMS in real deployments)
#         project_key = b"<32-bytes-from-kms>"  # e.g., os.environ["DSOB_PROJECT_HMAC_KEY"].encode()

#         # Optional: repo hint to reduce cross-repo collisions in broad waivers
#         repo_hint = "psf/requests"  # or whatever stable repo identifier you use

#         # --------- Generate fingerprints ---------
#         secret_fp, exact_fp, context_fp = fingerprint_trufflehog(
#             detector=detector,
#             candidate=candidate,
#             file_bytes=file_bytes,
#             start=start,
#             end=end,
#             project_key=project_key,
#             path_rel=path_used,
#             repo_hint=repo_hint,
#         )

#         finding["fingerprints"] = {
#             "secret": secret_fp,
#             "exact": exact_fp,
#             "ctx": context_fp
#         }
#     return findings


def fingerprint_findings(findings: list[dict], source_path: str, project_id: Optional[str] = None) -> list[dict]:
    """
    annotate findings with deterministic fingerprints and location_status
    
    optimized with caching:
    - file bytes cache (by path+commit for git, path+mtime for filesystem)
    - file sha cache (by file_bytes)
    - git HEAD cache (per repo_root)

    emits:
      - fingerprints.secret   (always)
      - fingerprints.exact    (when byte span available)
      - fingerprints.ctx      (when byte span available)
      - fingerprints.ctx_soft (when no span; path+filehash+approx_line)
      - location_status: FOUND_EXACT | FOUND_AFTER_DECODE | SCHEME_MISMATCH | UNLOCATABLE
      - approx_line (passthrough for debugging)
    """
    repo_root = source_path
    
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

    #initialize caches
    file_cache: dict[str, bytes] = {}  #cache file_bytes by cache key
    file_sha_cache: dict[bytes, str] = {}  #cache file_sha by file_bytes
    head_cache: dict[str, Optional[str]] = {}  #cache git HEAD per repo_root
    normalize_secret_cache: dict[tuple[str, str], bytes] = {}  #cache normalize_secret by (detector, candidate)
    path_norm_sha_cache: dict[str, str] = {}  #cache path_norm_sha by path
    
    #get git HEAD once (cached)
    cached_head = _rev_parse_head(repo_root, cache=head_cache)
    #compute repo_hint suffix once
    repo_hint_suffix = ":" + hashlib.sha256(_b(repo_hint)).hexdigest()[:8] if repo_hint else None

    for finding in findings:
        detector  = finding.get("DetectorName") or "Unknown"
        #RawV2 can be a dict (with "redacted" key) or a string; prefer non-empty string RawV2, fallback to Raw
        rawv2 = finding.get("RawV2")
        if isinstance(rawv2, str) and rawv2:
            #RawV2 is a non-empty string, use it
            candidate = rawv2
        else:
            #RawV2 is not a string, is empty, or is a dict - fallback to Raw
            candidate = finding.get("Raw") or ""
        if not candidate:
            #nothing to fingerprint; keep going
            finding.setdefault("fingerprints", {})
            finding["location_status"] = "UNLOCATABLE"
            continue

        #read file bytes (with caching)
        try:
            file_bytes, approx_line, path_used, mode = read_file_bytes_generic(
                repo_root, 
                finding, 
                cache=file_cache,
                cached_head=cached_head
            )
        except (FileNotFoundError, KeyError) as e:
            #file not found or missing required metadata - mark as UNLOCATABLE
            #still generate secret fingerprint for waivers/deduplication
            ns = normalize_secret(detector, candidate, cache=normalize_secret_cache)
            secret_fp = f"th:1:SECRET:{detector}:{hmac_secret(project_key, ns)}"
            if repo_hint:
                suffix = repo_hint_suffix if repo_hint_suffix is not None else ":" + hashlib.sha256(_b(repo_hint)).hexdigest()[:8]
                secret_fp += ":R" + suffix
            finding.setdefault("fingerprints", {})
            finding["fingerprints"]["secret"] = secret_fp
            finding["location_status"] = "UNLOCATABLE"
            finding["approx_line"] = None
            continue

        #locate span (robust + decoded fallback + scheme coherence)
        start, end, status = locate_span(detector, candidate, file_bytes, approx_line)

        #always generate at least secret fingerprint for waivers/deduplication
        ns = normalize_secret(detector, candidate, cache=normalize_secret_cache)
        secret_fp = f"th:1:SECRET:{detector}:{hmac_secret(project_key, ns)}"
        if repo_hint:
            suffix = repo_hint_suffix if repo_hint_suffix is not None else ":" + hashlib.sha256(_b(repo_hint)).hexdigest()[:8]
            secret_fp += ":R" + suffix

        fps = {"secret": secret_fp}
        
        #only generate exact and ctx fingerprints if we successfully located span
        if start >= 0 and end >= 0:
            try:
                #build fingerprints (with file_sha caching)
                #fingerprint_trufflehog returns (secret, exact, ctx), but we already have secret
                #so extract just exact and ctx, but still need to call it for exact/ctx generation
                _, exact_fp, context_fp = fingerprint_trufflehog(
                    detector=detector,
                    candidate=candidate,
                    file_bytes=file_bytes,
                    start=start,
                    end=end,
                    project_key=project_key,
                    path_rel=path_used,
                    repo_hint=repo_hint,
                    file_sha_cache=file_sha_cache,
                    normalize_secret_cache=normalize_secret_cache,
                    path_norm_sha_cache=path_norm_sha_cache,
                    repo_hint_suffix=repo_hint_suffix,
                )
                fps["exact"] = exact_fp
                fps["ctx"] = context_fp
            except Exception:
                #if fingerprint generation fails, fall back to ctx_soft
                fps["ctx_soft"] = f"th:1:CTXSOFT:{detector}:{path_norm_sha(path_used, cache=path_norm_sha_cache)}:{file_sha(file_bytes, cache=file_sha_cache)}:{approx_line or 0}"
        else:
            #span not located - use soft context fingerprint
            fps["ctx_soft"] = f"th:1:CTXSOFT:{detector}:{path_norm_sha(path_used, cache=path_norm_sha_cache)}:{file_sha(file_bytes, cache=file_sha_cache)}:{approx_line or 0}"

        finding["fingerprints"] = fps
        finding["location_status"] = status
        finding["approx_line"] = approx_line
    

    return findings
