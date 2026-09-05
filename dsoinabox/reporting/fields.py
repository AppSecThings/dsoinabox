"""Tool-agnostic accessors over raw scanner records.

These are the seams the waiver engine and reports use until the normalized
Finding model (W3.1) replaces raw dicts. Keep them free of report concerns.
"""

from __future__ import annotations

import os
from typing import Any

TOOL_CATEGORY: dict[str, str] = {
    "trufflehog": "secret",
    "opengrep": "sast",
    "syft": "sbom",
    "grype": "sca",
    "checkov": "iac",
}


def tool_category(tool: str) -> str:
    return TOOL_CATEGORY.get(tool.lower(), tool.lower())


def relativize_path(path: str | None, source_path: str | None) -> str:
    """Return a repo-root-relative POSIX path.

    Absolute paths under ``source_path`` are made relative to it. Other
    absolute paths are returned unchanged (still POSIX). ``file://`` prefixes
    and leading ``./`` are stripped.
    """
    if not path:
        return ""
    text = str(path)
    if text.startswith("file://"):
        text = text[len("file://"):]
    text = text.replace("\\", "/")
    if source_path and os.path.isabs(text):
        candidates = []
        for root in {os.path.abspath(source_path), os.path.realpath(source_path)}:
            candidates.append(root.replace("\\", "/").rstrip("/") + "/")
        for root in candidates:
            if text.startswith(root):
                text = text[len(root):]
                break
        else:
            try:
                real = os.path.realpath(text).replace("\\", "/")
                for root in candidates:
                    if real.startswith(root):
                        text = real[len(root):]
                        break
            except OSError:
                pass
    while text.startswith("./"):
        text = text[2:]
    return text


def finding_paths(finding: dict[str, Any], tool: str, source_path: str | None = None) -> list[str]:
    """All file paths a finding points at, repo-relative. Grype may return several."""
    tool = tool.lower()
    raw: list[str] = []
    if tool == "opengrep":
        raw = [finding.get("path") or (finding.get("location") or {}).get("path") or (finding.get("extra") or {}).get("path") or ""]
    elif tool == "trufflehog":
        data = ((finding.get("SourceMetadata") or {}).get("Data") or {})
        git = data.get("Git") or {}
        fs = data.get("Filesystem") or {}
        raw = [git.get("file") or fs.get("file") or fs.get("file_path") or fs.get("path") or data.get("file") or ""]
    elif tool == "grype":
        for loc in (finding.get("artifact") or {}).get("locations") or []:
            if isinstance(loc, dict) and loc.get("path"):
                raw.append(loc["path"])
    elif tool == "checkov":
        for loc in finding.get("locations") or []:
            uri = ((loc.get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")
            if uri:
                raw.append(uri)
    else:
        raw = [finding.get("path") or finding.get("file") or finding.get("uri") or ""]
    return [relativize_path(p, source_path) for p in raw if p]


def finding_fingerprints(finding: dict[str, Any]) -> dict[str, str]:
    fps = finding.get("fingerprints")
    if not isinstance(fps, dict):
        return {}
    return {k: v for k, v in fps.items() if isinstance(v, str) and v}
