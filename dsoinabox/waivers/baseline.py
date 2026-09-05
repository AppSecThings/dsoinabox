"""Baseline (benchmark) comparison: classify findings as new or known.

A baseline is a benchmark file (``schema_version`` plus a ``benchmark`` list of
fingerprints), as written by ``--benchmark`` or ``dsoinabox baseline update``.
Classification matches any fingerprint tier, current or legacy. Baselines
never suppress anything by themselves; ``--fail_on new`` decides whether
known findings can still fail the gate.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..model import Finding
from .loader import load_waiver_file
from .models import WaiverSet


def baseline_fingerprints(ws: WaiverSet) -> set[str]:
    return {e.fingerprint for e in ws.benchmark if e.fingerprint} | {w.fingerprint for w in ws.finding_waivers if w.fingerprint}


def classify(findings: Iterable[Finding], known: set[str]) -> dict[str, int]:
    counts = {"new": 0, "known": 0}
    for f in findings:
        values = list(f.fingerprints.values()) + list(f.legacy_fingerprints)
        f.baseline_status = "known" if any(v in known for v in values) else "new"
        counts[f.baseline_status] += 1
        if isinstance(f.raw, dict):
            f.raw["baseline_status"] = f.baseline_status
    return counts


def apply_baseline(findings: list[Finding], path: str) -> dict[str, Any]:
    ws = load_waiver_file(path)
    known = baseline_fingerprints(ws)
    counts = classify(findings, known)
    return {
        "file": path,
        "schema_version": ws.schema_version,
        "entries": len(known),
        "new": counts["new"],
        "known": counts["known"],
        "warnings": list(ws.warnings),
    }
