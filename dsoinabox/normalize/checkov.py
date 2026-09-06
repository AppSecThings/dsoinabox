from __future__ import annotations

from typing import Any

from ..model import Finding, normalize_severity, severity_from_security_score
from ._common import _int, attach_common


def _rules(raw: dict[str, Any]) -> list[dict[str, Any]]:
    runs = raw.get("runs") or []
    if not runs:
        return []
    return ((runs[0].get("tool") or {}).get("driver") or {}).get("rules") or []


def normalize(raw: Any, source_path: str | None = None) -> list[Finding]:
    if not isinstance(raw, dict):
        return []
    runs = raw.get("runs") or []
    results = (runs[0].get("results") or []) if runs else []
    rules = _rules(raw)
    out: list[Finding] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        rule_id = str(r.get("ruleId") or "")
        rule: dict[str, Any] = {}
        idx = r.get("ruleIndex")
        if isinstance(idx, int) and 0 <= idx < len(rules):
            rule = rules[idx] or {}
            rule_id = rule_id or str(rule.get("id") or "")
        rule_id = rule_id or "unknown"
        message = r.get("message") or {}
        text = message.get("text", "") if isinstance(message, dict) else str(message or "")
        severity = normalize_severity("checkov", r.get("level", "error"))
        score = (rule.get("properties") or {}).get("security-severity")
        scored = severity_from_security_score(score)
        if scored is not None:
            severity = scored
        loc = (r.get("locations") or [{}])[0] if r.get("locations") else {}
        phys = loc.get("physicalLocation") or {}
        region = phys.get("region") or {}
        snippet = region.get("snippet") or {}
        refs: list[str] = []
        if rule.get("helpUri"):
            refs.append(str(rule["helpUri"]))
        f = Finding(
            tool="checkov",
            category="iac",
            rule_id=rule_id,
            title=str((rule.get("shortDescription") or {}).get("text") or rule.get("name") or rule_id),
            message=text,
            severity=severity,
            original_severity=str(r.get("level") or ""),
            start_line=_int(region.get("startLine")),
            end_line=_int(region.get("endLine"), _int(region.get("startLine"))),
            snippet=str(snippet.get("text") or "") if isinstance(snippet, dict) else "",
            references=refs,
        )
        out.append(attach_common(f, r, "checkov", source_path))
    return out
