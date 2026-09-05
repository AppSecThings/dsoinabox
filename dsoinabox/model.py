"""Normalized data model shared by gating, waivers, console output and every report.

``Finding`` is the one representation of a scanner result. Each scanner has a
normalizer in ``dsoinabox.normalize`` that maps its raw record onto it. The raw
record stays attached as ``Finding.raw`` so tool-specific templates and
consumers keep full fidelity while everything else uses the normalized fields.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"
    unknown = "unknown"


# highest first; ``unknown`` sorts below ``info`` so it never trips a gate by accident
SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.critical,
    Severity.high,
    Severity.medium,
    Severity.low,
    Severity.info,
    Severity.unknown,
)
SEVERITY_RANK: dict[Severity, int] = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Only these can be used as thresholds; ``none`` disables the gate/filter.
THRESHOLD_CHOICES: tuple[str, ...] = ("none", "info", "low", "medium", "high", "critical")


def parse_threshold(value: str | None) -> Severity | None:
    """``none``/``None`` -> None. Legacy Semgrep names are accepted: warning=medium, error=high."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in ("", "none"):
        return None
    legacy = {"warning": "medium", "error": "high"}
    text = legacy.get(text, text)
    try:
        return Severity(text)
    except ValueError as exc:
        raise ValueError(
            f"Invalid severity threshold '{value}'. Expected one of: {', '.join(THRESHOLD_CHOICES)}"
        ) from exc


def severity_at_or_above(severity: Severity, threshold: Severity) -> bool:
    """True when ``severity`` is as severe as ``threshold`` or more. ``unknown`` never qualifies."""
    if severity is Severity.unknown:
        return False
    return SEVERITY_RANK[severity] <= SEVERITY_RANK[threshold]


# ---------------------------------------------------------------------------
# per-tool severity normalization tables
# ---------------------------------------------------------------------------

_OPENGREP = {
    "CRITICAL": Severity.critical,
    "HIGH": Severity.high,
    "ERROR": Severity.high,      # legacy rule severity
    "MEDIUM": Severity.medium,
    "WARNING": Severity.medium,  # legacy rule severity
    "LOW": Severity.low,
    "INFO": Severity.low,        # legacy: Info rules are low severity
    "INVENTORY": Severity.info,
    "EXPERIMENT": Severity.info,
}
_GRYPE = {
    "CRITICAL": Severity.critical,
    "HIGH": Severity.high,
    "MEDIUM": Severity.medium,
    "LOW": Severity.low,
    "NEGLIGIBLE": Severity.info,
    "UNKNOWN": Severity.unknown,
}
_SARIF_LEVEL = {
    "error": Severity.high,
    "warning": Severity.medium,
    "note": Severity.low,
    "none": Severity.info,
}


def normalize_severity(tool: str, raw: Any) -> Severity:
    """Map a tool's own severity string onto the unified scale."""
    tool = tool.lower()
    text = ("" if raw is None else str(raw)).strip()
    if tool == "trufflehog":
        return Severity.high  # a secret is a secret
    if tool == "opengrep":
        return _OPENGREP.get(text.upper(), Severity.unknown)
    if tool == "grype":
        return _GRYPE.get(text.upper(), Severity.unknown)
    if tool == "checkov":
        return _SARIF_LEVEL.get(text.lower(), Severity.unknown)
    try:
        return Severity(text.lower())
    except ValueError:
        return Severity.unknown


def severity_from_security_score(score: float | int | str | None) -> Severity | None:
    """SARIF ``security-severity`` (CVSS-like 0-10) to a Severity, or None when absent."""
    if score is None or score == "":
        return None
    try:
        value = float(score)
    except (TypeError, ValueError):
        return None
    if value >= 9.0:
        return Severity.critical
    if value >= 7.0:
        return Severity.high
    if value >= 4.0:
        return Severity.medium
    if value > 0:
        return Severity.low
    return Severity.info


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------

Category = Literal["sast", "secret", "sca", "iac", "sbom"]


class Package(BaseModel):
    name: str = ""
    version: str = ""
    type: str = ""
    purl: str = ""
    namespace: str = ""
    fix_versions: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    tool: str
    category: Category
    rule_id: str
    title: str = ""
    message: str = ""
    severity: Severity = Severity.unknown
    original_severity: str = ""
    path: str = ""
    """Repo-root-relative POSIX path (empty when the tool has none)."""
    paths: list[str] = Field(default_factory=list)
    """All paths (SCA findings may point at several manifests)."""
    start_line: int = 0
    end_line: int = 0
    snippet: str = ""
    fingerprints: dict[str, str] = Field(default_factory=dict)
    legacy_fingerprints: list[str] = Field(default_factory=list)
    waived: bool = False
    waived_by: dict[str, Any] | None = None
    expired_waivers: list[dict[str, Any]] = Field(default_factory=list)
    location_status: str = ""
    verified: bool | None = None
    package: Package | None = None
    references: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)

    @property
    def primary_fingerprint(self) -> str:
        for key in ("secret", "rule", "pkg", "ctx", "exact", "ctx_soft"):
            if self.fingerprints.get(key):
                return self.fingerprints[key]
        return next(iter(self.fingerprints.values()), "")

    @property
    def location(self) -> str:
        if not self.path:
            return ""
        return f"{self.path}:{self.start_line}" if self.start_line else self.path

    def to_report_dict(self) -> dict[str, Any]:
        """JSON shape for the normalized findings list (raw record included)."""
        data = self.model_dump(mode="json")
        data["raw"] = self.raw
        return data


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

ScanStatus = Literal["ok", "failed", "skipped"]


class ScanResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    tool: str
    category: Category
    status: ScanStatus = "ok"
    findings: list[Finding] = Field(default_factory=list)
    duration_s: float = 0.0
    tool_version: str = ""
    error: str = ""
    raw: Any = Field(default=None, exclude=True)
    """Tool payload with findings annotated in place (what legacy templates consume)."""
    raw_output_path: str = ""

    @property
    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if not f.waived]

    @property
    def waived_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.waived]

    def summary_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "category": self.category,
            "status": self.status,
            "tool_version": self.tool_version,
            "duration_s": round(self.duration_s, 3),
            "findings": len(self.findings),
            "active": len(self.active_findings),
            "waived": len(self.waived_findings),
            "error": self.error or None,
        }


class PolicyResult(BaseModel):
    failure_threshold: Severity | None = None
    fail_on_secrets: bool = False
    report_threshold: Severity | None = None
    threshold_exceeded: bool = False
    secrets_found: int = 0
    secrets_failed: bool = False
    failing_by_tool: dict[str, int] = Field(default_factory=dict)
    scanner_failures: list[str] = Field(default_factory=list)
    exit_code: int = 0

    @property
    def passed(self) -> bool:
        return self.exit_code == 0

    def summary_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class ScanOptions(BaseModel):
    """Everything ``run_scan`` needs. Built by the CLI from config, env and flags."""

    source: str
    report_directory: str
    """Final timestamped directory reports are written to."""
    timestamp: str
    project_id: str | None = None
    tools: list[str] = Field(default_factory=lambda: ["all"])
    failure_threshold: Severity | None = None
    report_threshold: Severity | None = None
    fail_on_secrets: bool = False
    waiver_file: str | None = ".dsoinabox_waivers.yaml"
    waiver_file_is_default: bool = True
    waiver_grace_days: int = 0
    outputs: list[str] = Field(default_factory=lambda: ["html"])
    keep_tool_output: bool = False
    benchmark: bool = False
    report_name: str | None = None
    """Base file name for reports; default is dsoinabox_unified_report_<timestamp>."""
    base_report_directory: str | None = None
    """Parent of the timestamped directory; a `latest` pointer is maintained there."""
    tool_args: dict[str, Any] = Field(default_factory=dict)
    scan_timeout: int | None = 1800
    tool_timeouts: dict[str, int] = Field(default_factory=dict)
    fail_fast: bool = False
    max_workers: int = 5


class ScanRun(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    started_at: datetime
    finished_at: datetime | None = None
    dsoinabox_version: str
    timestamp: str
    project_id: str
    source: str
    report_directory: str
    git_info: dict[str, Any] | None = None
    results: list[ScanResult] = Field(default_factory=list)
    waiver_summary: dict[str, Any] | None = None
    policy: PolicyResult = Field(default_factory=PolicyResult)
    report_paths: list[str] = Field(default_factory=list)
    latest_directory: str | None = None
    hidden_by_report_threshold: int = 0
    fingerprint_aliases: dict[str, str] = Field(default_factory=dict)
    """legacy fingerprint -> current fingerprint, for `waivers migrate --from-report`."""

    def result_for(self, tool: str) -> ScanResult | None:
        for r in self.results:
            if r.tool == tool:
                return r
        return None

    def raw_for(self, tool: str) -> Any:
        r = self.result_for(tool)
        return r.raw if r is not None else None

    @property
    def findings(self) -> list[Finding]:
        return [f for r in self.results for f in r.findings]

    @property
    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if not f.waived]

    def severity_counts(self, *, active_only: bool = True) -> dict[str, int]:
        counts = {s.value: 0 for s in SEVERITY_ORDER}
        for f in self.active_findings if active_only else self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def duration_s(self) -> float:
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    def tool_versions(self) -> dict[str, str]:
        return {r.tool: r.tool_version for r in self.results if r.tool_version}

    def metadata_dict(self) -> dict[str, Any]:
        return {
            "dsoinabox_version": self.dsoinabox_version,
            "scan_timestamp": self.timestamp,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_s": round(self.duration_s, 3),
            "project_id": self.project_id,
            "source": self.source,
            "git_repo_info": self.git_info,
            "tool_versions": self.tool_versions(),
            "scanners": [r.summary_dict() for r in self.results],
            "severity_counts": self.severity_counts(),
            "hidden_by_report_threshold": self.hidden_by_report_threshold,
            "fingerprint_aliases": self.fingerprint_aliases,
            "policy": self.policy.summary_dict(),
            "waivers": self.waiver_summary,
        }
