from __future__ import annotations

from typing import Any

from ..model import Finding, Package, normalize_severity
from ._common import attach_common


def normalize(raw: Any, source_path: str | None = None) -> list[Finding]:
    matches = (raw or {}).get("matches") or [] if isinstance(raw, dict) else []
    out: list[Finding] = []
    for m in matches:
        if not isinstance(m, dict):
            continue
        vuln = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        fix = vuln.get("fix") or {}
        vid = str(vuln.get("id") or "unknown")
        pkg = Package(
            name=str(art.get("name") or ""),
            version=str(art.get("version") or ""),
            type=str(art.get("type") or ""),
            purl=str(art.get("purl") or ""),
            namespace=str(vuln.get("namespace") or ""),
            fix_versions=[str(v) for v in (fix.get("versions") or [])],
        )
        desc = str(vuln.get("description") or "")
        refs = [str(u) for u in (vuln.get("urls") or []) if u]
        if vuln.get("dataSource"):
            refs.insert(0, str(vuln["dataSource"]))
        f = Finding(
            tool="grype",
            category="sca",
            rule_id=vid,
            title=f"{vid} in {pkg.name}@{pkg.version}".strip(),
            message=f"{vid}: {desc}" if desc else vid,
            severity=normalize_severity("grype", vuln.get("severity")),
            original_severity=str(vuln.get("severity") or ""),
            package=pkg,
            references=refs,
        )
        out.append(attach_common(f, m, "grype", source_path))
    return out
