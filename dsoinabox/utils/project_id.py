"""Project ID derivation and HMAC key generation utilities.

This module provides functions to derive a deterministic project identifier
from git repository information or explicit overrides, and to generate
consistent HMAC keys from project IDs.
"""

from __future__ import annotations

import os
import re
import hmac
import hashlib
from typing import Optional
from urllib.parse import urlparse

from .runner import run_cmd


def is_git(path: str) -> bool:
    # check if the specified directory is a git repository.
    return os.path.isdir(os.path.join(path, ".git"))


def normalize_git_remote(url: str) -> str:
    """
    Normalize git remote URL to consistent format.
    
    Rules:
    - Strip credentials (user@, tokens, etc.)
    - Lowercase hostname
    - Strip .git suffix
    - Normalize SSH and HTTPS to same format
    - Handle custom ports
    
    Examples:
    - git@github.com:user/repo.git → github.com/user/repo
    - https://github.com/user/repo.git → github.com/user/repo
    - git@gitlab.com:group/project.git → gitlab.com/group/project
    - https://token@github.com/user/repo.git → github.com/user/repo
    - git@gitlab.com:2222:group/project.git → gitlab.com/group/project
    """
    if not url:
        return ""
    
    # Remove .git suffix if present
    url = url.rstrip('/')
    if url.endswith('.git'):
        url = url[:-4]
    
    # Check if URL already looks normalized (no protocol, no git@)
    if not url.startswith(('http://', 'https://', 'git@')):
        # Already normalized format: hostname/path
        # Just ensure hostname is lowercase and remove any trailing slashes
        parts = url.split('/', 1)
        hostname = parts[0].lower()
        path = parts[1] if len(parts) > 1 else ""
        return f"{hostname}/{path}".rstrip('/')
    
    # Handle SSH format: git@host:path or git@host:port:path
    if url.startswith('git@'):
        # Remove git@ prefix
        url = url[4:]
        
        # Handle custom port: git@host:port:path
        # Split by ':' - if there are 3 parts and middle is numeric, it's a port
        parts = url.split(':')
        if len(parts) == 3:
            try:
                int(parts[1])  # Check if middle part is a port number
                # It's a port, skip it
                url = f"{parts[0]}/{parts[2]}"
            except ValueError:
                # Not a port, treat as normal SSH format
                url = url.replace(':', '/', 1)
        elif len(parts) == 2:
            # Normal SSH format: host:path
            url = url.replace(':', '/', 1)
        
        # Add https:// prefix for parsing (we'll strip it later)
        url = f"https://{url}"
    
    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception:
        # If parsing fails, try to extract hostname and path manually
        # Remove protocol if present
        url_no_proto = re.sub(r'^[a-z+]+://', '', url, flags=re.IGNORECASE)
        # Remove credentials if present (user@ or user:pass@)
        url_no_proto = re.sub(r'^[^@]+@', '', url_no_proto)
        # Split by first /
        parts = url_no_proto.split('/', 1)
        hostname = parts[0].lower()
        path = parts[1] if len(parts) > 1 else ""
        # Remove port if present
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        return f"{hostname}/{path}".rstrip('/')
    
    # Extract hostname (lowercase, no port, no credentials)
    hostname = parsed.hostname or ""
    if not hostname:
        # If no hostname, try to extract from path (for malformed URLs)
        # This handles cases where urlparse didn't work as expected
        url_no_proto = re.sub(r'^[a-z+]+://', '', url, flags=re.IGNORECASE)
        url_no_proto = re.sub(r'^[^@]+@', '', url_no_proto)
        parts = url_no_proto.split('/', 1)
        hostname = parts[0].lower()
        path = parts[1] if len(parts) > 1 else ""
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        return f"{hostname}/{path}".rstrip('/')
    
    hostname = hostname.lower()
    
    # Extract path (remove leading slash)
    path = parsed.path.lstrip('/')
    
    # Reconstruct as: hostname/path
    normalized = f"{hostname}/{path}".rstrip('/')
    
    return normalized


def get_initial_commit_hash(repo_path: str) -> Optional[str]:
    """
    Get the initial commit hash of a git repository.
    
    Uses: git rev-list --max-parents=0 HEAD
    
    Returns None if not a git repo or command fails.
    """
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        return None
    
    try:
        returncode, stdout, stderr = run_cmd(
            ["git", "rev-list", "--max-parents=0", "HEAD"],
            cwd=repo_path,
            text=True,
            check=False
        )
        if returncode == 0 and stdout.strip():
            return stdout.strip()
    except Exception:
        pass
    
    return None


def derive_project_id(source_path: str, project_id_override: Optional[str] = None) -> str:
    """
    Derive project identifier using priority:
    1. project_id_override (if provided)
    2. Git remote.origin.url (normalized)
    3. Git initial commit hash
    4. Raise ValueError if none available (non-git, no override)
    
    Returns deterministic project identifier string.
    """
    if project_id_override:
        return project_id_override
    
    # Check if it's a git repository
    if not os.path.isdir(os.path.join(source_path, ".git")):
        raise ValueError(
            f"Unable to determine project ID: source path '{source_path}' is not a git repository. "
            "Please provide --project-id argument for non-git directories."
        )
    
    # Try to get remote.origin.url
    try:
        returncode, stdout, stderr = run_cmd(
            ["git", "config", "--get", "remote.origin.url"],
            cwd=source_path,
            text=True,
            check=False
        )
        if returncode == 0 and stdout.strip():
            remote_url = stdout.strip()
            normalized = normalize_git_remote(remote_url)
            if normalized:
                return normalized
    except Exception:
        pass
    
    # Fallback to initial commit hash
    initial_commit = get_initial_commit_hash(source_path)
    if initial_commit:
        return initial_commit
    
    raise ValueError(
        f"Unable to determine project ID: git repository at '{source_path}' has no remote "
        "and no commits. Please provide --project-id argument."
    )


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """
    HKDF Extract step: PRK = HMAC-SHA256(salt, IKM)
    
    Args:
        salt: Salt value (can be empty bytes)
        ikm: Input keying material
        
    Returns:
        Pseudo-random key (PRK)
    """
    if not salt:
        salt = b'\x00' * 32  # Default salt of zeros if empty
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF Expand step: OKM = T(1) || T(2) || ... || T(N)
    where T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
    
    Args:
        prk: Pseudo-random key from extract step
        info: Context/application-specific information
        length: Desired output length in bytes
        
    Returns:
        Output keying material (OKM)
    """
    n = (length + 31) // 32  # Number of hash blocks needed (SHA256 = 32 bytes)
    okm = b''
    t = b''
    
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    
    return okm[:length]


def derive_project_hmac_key(project_id: str) -> bytes:
    """
    Derive 32-byte HMAC key from project_id using HKDF.
    
    Uses:
    - Hash: SHA-256
    - Salt/Context: b"dsoinabox-project-key-v1"
    - Output length: 32 bytes
    
    This ensures consistent key generation from the same project_id.
    
    Implementation uses HKDF (HMAC-based Key Derivation Function) as specified
    in RFC 5869, implemented using HMAC-SHA256.
    """
    salt = b"dsoinabox-project-key-v1"
    ikm = project_id.encode('utf-8')
    info = b""  # No additional context info needed
    
    # HKDF = Extract + Expand
    prk = _hkdf_extract(salt, ikm)
    okm = _hkdf_expand(prk, info, 32)
    
    return okm

