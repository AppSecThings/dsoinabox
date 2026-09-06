"""Health checks for a loaded WaiverSet: expiry, duplicates, deprecation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ..utils.deterministic import utcnow
from .models import BenchmarkEntry, FindingWaiver, WaiverSet


@dataclass
class ValidationReport:
    path: str | None
    schema_version: str
    deprecated: bool
    finding_waivers: int
    path_exclusions: int
    benchmark_entries: int
    warnings: list[str] = field(default_factory=list)
    expired: list[str] = field(default_factory=list)
    expiring_soon: list[str] = field(default_factory=list)
    duplicates: list[str] = field(default_factory=list)

    @property
    def problems(self) -> list[str]:
        out: list[str] = []
        out.extend(f"warning: {w}" for w in self.warnings)
        out.extend(f"expired: {e}" for e in self.expired)
        out.extend(f"duplicate: {d}" for d in self.duplicates)
        return out

    @property
    def ok(self) -> bool:
        return not self.problems

    def lines(self) -> list[str]:
        head = f"{self.path or '<data>'}: schema {self.schema_version}"
        if self.deprecated:
            head += " (deprecated)"
        out = [
            head,
            f"  finding_waivers={self.finding_waivers} path_exclusions={self.path_exclusions} benchmark={self.benchmark_entries}",
        ]
        for w in self.warnings:
            out.append(f"  warning: {w}")
        for e in self.expired:
            out.append(f"  expired: {e}")
        for e in self.expiring_soon:
            out.append(f"  expiring soon: {e}")
        for d in self.duplicates:
            out.append(f"  duplicate: {d}")
        if self.ok and not self.expiring_soon:
            out.append("  ok")
        return out


def _describe(entry: FindingWaiver | BenchmarkEntry, where: str) -> str:
    when = entry.expires_at.date().isoformat() if entry.expires_at else "never"
    return f"{where} {entry.fingerprint} (expires {when})"


def validate_waiver_set(ws: WaiverSet, *, now: datetime | None = None, soon_days: int = 30) -> ValidationReport:
    now = now or utcnow()
    soon = now + timedelta(days=soon_days)
    report = ValidationReport(
        path=ws.source_path,
        schema_version=ws.schema_version,
        deprecated=ws.deprecated,
        finding_waivers=len(ws.finding_waivers),
        path_exclusions=len(ws.path_exclusions),
        benchmark_entries=len(ws.benchmark),
        warnings=list(ws.warnings),
    )

    seen: dict[str, str] = {}
    for i, fw in enumerate(ws.finding_waivers):
        where = f"finding_waivers[{i}]"
        if fw.expires_at is not None:
            if fw.expires_at <= now:
                report.expired.append(_describe(fw, where))
            elif fw.expires_at <= soon:
                report.expiring_soon.append(_describe(fw, where))
        if fw.fingerprint in seen:
            report.duplicates.append(f"{where} repeats {seen[fw.fingerprint]}: {fw.fingerprint}")
        else:
            seen[fw.fingerprint] = where

    for i, pe in enumerate(ws.path_exclusions):
        where = f"path_exclusions[{i}]"
        if pe.expires_at is not None and pe.expires_at <= now:
            report.expired.append(f"{where} {pe.pattern} (expires {pe.expires_at.date().isoformat()})")

    bench_expired_all = ws.benchmark_expires_at is not None and ws.benchmark_expires_at <= now
    for i, be in enumerate(ws.benchmark):
        where = f"benchmark[{i}]"
        if bench_expired_all or (be.expires_at is not None and be.expires_at <= now):
            report.expired.append(_describe(be, where) if be.expires_at else f"{where} {be.fingerprint} (benchmark_expires_at passed)")
        if be.fingerprint in seen:
            report.duplicates.append(f"{where} repeats {seen[be.fingerprint]}: {be.fingerprint}")
        else:
            seen[be.fingerprint] = where

    return report
