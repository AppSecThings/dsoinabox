from __future__ import annotations

from typing import Any

from ..model import Finding
from ..reporting.fields import finding_fingerprints, finding_paths, relativize_path


def relativize_raw_paths(raw: dict[str, Any], tool: str, source_path: str | None) -> None:
    """Rewrite the raw record's path fields to repo-relative POSIX form, in place.

    Scanners given an absolute source directory (``/scan_target`` in Docker)
    report absolute paths. Reports must show repo-relative paths, and SARIF
    consumers need them to map alerts onto files.
    """
    if not isinstance(raw, dict):
        return
    if tool == "opengrep":
        if raw.get("path"):
            raw["path"] = relativize_path(raw["path"], source_path)
    elif tool == "trufflehog":
        data = ((raw.get("SourceMetadata") or {}).get("Data") or {})
        for block in ("Git", "Filesystem"):
            meta = data.get(block)
            if isinstance(meta, dict):
                for key in ("file", "file_path", "path"):
                    if meta.get(key):
                        meta[key] = relativize_path(meta[key], source_path)
        if data.get("file"):
            data["file"] = relativize_path(data["file"], source_path)
    elif tool == "grype":
        for loc in (raw.get("artifact") or {}).get("locations") or []:
            if isinstance(loc, dict) and loc.get("path"):
                loc["path"] = relativize_path(loc["path"], source_path)
    elif tool == "checkov":
        for loc in raw.get("locations") or []:
            art = ((loc.get("physicalLocation") or {}).get("artifactLocation") or {})
            if art.get("uri"):
                art["uri"] = relativize_path(art["uri"], source_path)


def attach_common(finding: Finding, raw: dict[str, Any], tool: str, source_path: str | None) -> Finding:
    """Fill fields every normalizer shares: paths, fingerprints, waiver annotations."""
    relativize_raw_paths(raw, tool, source_path)
    paths = finding_paths(raw, tool, source_path)
    finding.paths = paths
    if not finding.path and paths:
        finding.path = paths[0]
    fps = finding_fingerprints(raw)
    finding.fingerprints = {k: v for k, v in fps.items() if k != "legacy"}
    legacy = raw.get("fingerprints", {}).get("legacy") if isinstance(raw.get("fingerprints"), dict) else None
    if isinstance(legacy, list):
        finding.legacy_fingerprints = [str(x) for x in legacy]
    finding.waived = bool(raw.get("waived"))
    finding.waived_by = raw.get("waived_by") if isinstance(raw.get("waived_by"), dict) else None
    exp = raw.get("expired_waivers")
    finding.expired_waivers = list(exp) if isinstance(exp, list) else []
    finding.raw = raw
    return finding


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
