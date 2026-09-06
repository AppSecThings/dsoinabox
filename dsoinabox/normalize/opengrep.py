from __future__ import annotations

from typing import Any

from ..model import Finding, normalize_severity
from ._common import _int, attach_common


def normalize(raw: Any, source_path: str | None = None) -> list[Finding]:
    results = (raw or {}).get("results") or [] if isinstance(raw, dict) else []
    out: list[Finding] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        refs: list[str] = []
        if meta.get("source"):
            refs.append(str(meta["source"]))
        for ref in meta.get("references") or []:
            if isinstance(ref, str):
                refs.append(ref)
        f = Finding(
            tool="opengrep",
            category="sast",
            rule_id=str(r.get("check_id") or r.get("rule_id") or "unknown_rule"),
            title=str(r.get("check_id") or ""),
            message=str(extra.get("message") or ""),
            severity=normalize_severity("opengrep", extra.get("severity")),
            original_severity=str(extra.get("severity") or ""),
            start_line=_int((r.get("start") or {}).get("line")),
            end_line=_int((r.get("end") or {}).get("line")),
            snippet=str(extra.get("lines") or ""),
            references=refs,
        )
        if not f.end_line:
            f.end_line = f.start_line
        out.append(attach_common(f, r, "opengrep", source_path))
    return out
