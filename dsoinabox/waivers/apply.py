"""Apply a WaiverSet to scanner findings.

Every documented waiver mechanism is enforced here:

- ``finding_waivers`` match by exact fingerprint (any tier) and optional ``tools`` scope
- ``benchmark`` entries match by fingerprint and are reported as type ``benchmark``
- ``path_exclusions`` match repo-relative paths with gitignore-style globs and optional ``tools`` scope
- ``expires_at`` on any of the above; an expired entry no longer suppresses,
  and the finding is annotated so reports can show the expired waiver
- ``--waiver_grace_days`` extends every expiry by N days and flags the match as expiring

Waived findings are never deleted. They get ``waived: True`` and a
``waived_by`` record so reports, SARIF suppressions and the summary can show
them. Findings matched only by expired entries get ``expired_waivers``.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

import pathspec

from ..reporting.fields import finding_fingerprints, finding_paths, tool_category
from ..utils.deterministic import utcnow
from .models import BenchmarkEntry, FindingWaiver, PathExclusion, WaiverSet

MatchKind = Literal["finding_waiver", "benchmark", "path_exclusion"]


def entry_applies_to_tool(tools: list[str] | None, tool: str) -> bool:
    if not tools:
        return True
    tool = tool.lower()
    category = tool_category(tool)
    for scope in tools:
        s = scope.lower()
        if s == "all" or s == tool or s == category or (s == "secrets" and category == "secret"):
            return True
    return False


@dataclass
class WaiverMatch:
    kind: MatchKind
    ref: str
    key: str
    type: str
    reason: str | None
    expires_at: datetime | None
    expired: bool
    expiring: bool
    ticket: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind, "ref": self.ref, "type": self.type}
        out["fingerprint" if self.kind != "path_exclusion" else "pattern"] = self.key
        if self.reason:
            out["reason"] = self.reason
        if self.ticket:
            out["ticket"] = self.ticket
        if self.expires_at is not None:
            out["expires_at"] = self.expires_at.date().isoformat() if self.expires_at.time() == datetime.min.time() else self.expires_at.isoformat().replace("+00:00", "Z")
        if self.expired:
            out["expired"] = True
        if self.expiring:
            out["expiring"] = True
        return out


@dataclass
class WaiverUsage:
    """Accumulates what the waiver file did across every tool in a run."""

    total_findings: int = 0
    waived: int = 0
    waived_by_type: Counter[str] = field(default_factory=Counter)
    waived_by_kind: Counter[str] = field(default_factory=Counter)
    expired_matches: int = 0
    expiring_matches: int = 0
    matched_refs: Counter[str] = field(default_factory=Counter)
    expired_refs: Counter[str] = field(default_factory=Counter)

    def merge(self, other: WaiverUsage) -> WaiverUsage:
        self.total_findings += other.total_findings
        self.waived += other.waived
        self.waived_by_type.update(other.waived_by_type)
        self.waived_by_kind.update(other.waived_by_kind)
        self.expired_matches += other.expired_matches
        self.expiring_matches += other.expiring_matches
        self.matched_refs.update(other.matched_refs)
        self.expired_refs.update(other.expired_refs)
        return self

    def unused_refs(self, ws: WaiverSet) -> list[str]:
        refs = [f"finding_waivers[{i}]" for i in range(len(ws.finding_waivers))]
        refs += [f"benchmark[{i}]" for i in range(len(ws.benchmark))]
        refs += [f"path_exclusions[{i}]" for i in range(len(ws.path_exclusions))]
        return [r for r in refs if r not in self.matched_refs and r not in self.expired_refs]

    def summary_dict(self, ws: WaiverSet | None) -> dict[str, Any]:
        out: dict[str, Any] = {
            "waived": self.waived,
            "waived_by_type": dict(self.waived_by_type),
            "waived_by_kind": dict(self.waived_by_kind),
            "expired_matches": self.expired_matches,
            "expiring_matches": self.expiring_matches,
        }
        if ws is not None:
            unused = self.unused_refs(ws)
            out["unused"] = unused
            out["unused_count"] = len(unused)
            out["schema_version"] = ws.schema_version
            out["deprecated_schema"] = ws.deprecated
            out["file"] = ws.source_path
            out["entries"] = {
                "finding_waivers": len(ws.finding_waivers),
                "benchmark": len(ws.benchmark),
                "path_exclusions": len(ws.path_exclusions),
            }
        return out


class WaiverEngine:
    """Pre-indexes a WaiverSet so per-finding evaluation is a dict lookup plus glob checks."""

    def __init__(self, ws: WaiverSet, *, now: datetime | None = None, grace_days: int = 0):
        self.ws = ws
        self.now = now or utcnow()
        self.grace = timedelta(days=max(0, grace_days))
        self._by_fp: dict[str, list[tuple[str, FindingWaiver | BenchmarkEntry, MatchKind]]] = {}
        for i, fw in enumerate(ws.finding_waivers):
            self._by_fp.setdefault(fw.fingerprint, []).append((f"finding_waivers[{i}]", fw, "finding_waiver"))
        for i, be in enumerate(ws.benchmark):
            self._by_fp.setdefault(be.fingerprint, []).append((f"benchmark[{i}]", be, "benchmark"))
        self._paths: list[tuple[str, PathExclusion, pathspec.GitIgnoreSpec]] = []
        for i, pe in enumerate(ws.path_exclusions):
            spec = pathspec.GitIgnoreSpec.from_lines([pe.pattern])
            self._paths.append((f"path_exclusions[{i}]", pe, spec))

    # -- expiry -------------------------------------------------------------
    def _expiry_state(self, expires_at: datetime | None) -> tuple[bool, bool]:
        """Return (expired, expiring). Grace extends the deadline; inside grace it is 'expiring'."""
        if expires_at is None:
            return False, False
        if expires_at <= self.now:
            if self.now < expires_at + self.grace:
                return False, True
            return True, False
        return False, False

    def _match(self, kind: MatchKind, ref: str, key: str, type_: str, reason: str | None, expires_at: datetime | None, ticket: str | None) -> WaiverMatch:
        if kind == "benchmark" and self.ws.benchmark_expires_at is not None:
            # a benchmark-wide expiry applies when the entry has none or expires later
            if expires_at is None or self.ws.benchmark_expires_at < expires_at:
                expires_at = self.ws.benchmark_expires_at
        expired, expiring = self._expiry_state(expires_at)
        return WaiverMatch(kind, ref, key, type_, reason, expires_at, expired, expiring, ticket)

    # -- evaluation --------------------------------------------------------
    def matches_for(self, tool: str, fingerprints: dict[str, str], paths: list[str]) -> list[WaiverMatch]:
        out: list[WaiverMatch] = []
        seen_refs: set[str] = set()
        for fp in fingerprints.values():
            for ref, entry, kind in self._by_fp.get(fp, []):
                if ref in seen_refs:
                    continue
                tools = getattr(entry, "tools", None)
                if not entry_applies_to_tool(tools, tool):
                    continue
                seen_refs.add(ref)
                type_ = entry.type.value if hasattr(entry.type, "value") else str(entry.type)
                out.append(self._match(kind, ref, fp, type_, entry.reason, entry.expires_at, entry.ticket))
        if paths:
            for ref, pe, spec in self._paths:
                if not entry_applies_to_tool(pe.tools, tool):
                    continue
                if all(spec.match_file(p) for p in paths):
                    out.append(self._match("path_exclusion", ref, pe.pattern, "path_exclusion", pe.reason, pe.expires_at, None))
        return out

    def decide(self, matches: list[WaiverMatch]) -> tuple[WaiverMatch | None, list[WaiverMatch]]:
        """Pick the active match that waives the finding (first by kind priority) and the expired ones."""
        priority = {"finding_waiver": 0, "benchmark": 1, "path_exclusion": 2}
        active = sorted((m for m in matches if not m.expired), key=lambda m: priority[m.kind])
        expired = [m for m in matches if m.expired]
        return (active[0] if active else None), expired


def apply_waivers(
    tool: str,
    findings: list[dict[str, Any]],
    engine: WaiverEngine | None,
    *,
    source_path: str | None = None,
) -> WaiverUsage:
    """Annotate findings in place. Returns usage stats for this tool."""
    usage = WaiverUsage(total_findings=len(findings))
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        finding["waived"] = False
        finding.pop("waived_by", None)
        finding.pop("expired_waivers", None)
        if engine is None:
            continue
        fps = finding_fingerprints(finding)
        paths = finding_paths(finding, tool, source_path)
        matches = engine.matches_for(tool, fps, paths)
        if not matches:
            continue
        winner, expired = engine.decide(matches)
        if expired:
            finding["expired_waivers"] = [m.to_dict() for m in expired]
            usage.expired_matches += len(expired)
            for m in expired:
                usage.expired_refs[m.ref] += 1
        if winner is not None:
            finding["waived"] = True
            finding["waived_by"] = winner.to_dict()
            usage.waived += 1
            usage.waived_by_type[winner.type] += 1
            usage.waived_by_kind[winner.kind] += 1
            usage.matched_refs[winner.ref] += 1
            if winner.expiring:
                usage.expiring_matches += 1
            # other active matches also count as "used"
            for m in matches:
                if not m.expired and m.ref != winner.ref:
                    usage.matched_refs[m.ref] += 1
    return usage


def active_findings(findings: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Findings that still count: not waived."""
    if not findings:
        return []
    return [f for f in findings if not (isinstance(f, dict) and f.get("waived"))]


def waived_findings(findings: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if not findings:
        return []
    return [f for f in findings if isinstance(f, dict) and f.get("waived")]
