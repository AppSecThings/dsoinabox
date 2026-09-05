from __future__ import annotations

from typing import Any

from ..model import Finding
from ..reporting.fields import finding_fingerprints, finding_paths


def attach_common(finding: Finding, raw: dict[str, Any], tool: str, source_path: str | None) -> Finding:
    """Fill fields every normalizer shares: paths, fingerprints, waiver annotations."""
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
