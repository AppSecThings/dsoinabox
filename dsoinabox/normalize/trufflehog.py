from __future__ import annotations

from typing import Any

from ..model import Finding, normalize_severity
from ._common import _int, attach_common


def normalize(raw: Any, source_path: str | None = None) -> list[Finding]:
    records = raw if isinstance(raw, list) else ([raw] if isinstance(raw, dict) else [])
    out: list[Finding] = []
    for r in records:
        if not isinstance(r, dict):
            continue
        data = ((r.get("SourceMetadata") or {}).get("Data") or {})
        git = data.get("Git") or {}
        fs = data.get("Filesystem") or {}
        line = r.get("approx_line") or git.get("line") or fs.get("line") or r.get("line") or 0
        detector = str(r.get("DetectorName") or "Unknown")
        desc = str(r.get("DetectorDescription") or "")
        redacted = str(r.get("Redacted") or "")
        message = desc or "Secret detected"
        if redacted:
            message = f"{message}. Redacted: {redacted}"
        verified = r.get("Verified")
        f = Finding(
            tool="trufflehog",
            category="secret",
            rule_id=detector,
            title=f"{detector} secret",
            message=message,
            severity=normalize_severity("trufflehog", None),
            original_severity="",
            start_line=_int(line),
            end_line=_int(line),
            location_status=str(r.get("location_status") or ""),
            verified=bool(verified) if verified is not None else None,
        )
        out.append(attach_common(f, r, "trufflehog", source_path))
    return out
