"""Pydantic models for every supported waiver schema version, plus the
version-independent ``WaiverSet`` the rest of dsoinabox consumes.

Rules for adding a schema version:

1. Add a new ``WaiverFileV<major>_<minor>`` model here. Never edit an existing
   version's model except to fix a bug that made it reject valid files.
2. Register it in ``SCHEMA_MODELS`` and update ``schema.py`` constants.
3. Add a ``to_waiver_set`` branch and a migration in ``migrate.py``.
4. Add fixtures under ``tests/fixtures/waivers/v<version>/`` and regenerate
   the JSON Schema files with ``python -m dsoinabox.waivers.jsonschema --write``.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .schema import CURRENT_SCHEMA_VERSION

# Tool names and categories accepted in ``tools`` lists.
TOOL_NAMES: tuple[str, ...] = ("trufflehog", "opengrep", "syft", "grype", "checkov")
TOOL_CATEGORIES: tuple[str, ...] = ("sast", "sbom", "sca", "secret", "secrets", "iac")
TOOL_SCOPE_ALL = "all"


class WaiverType(str, Enum):
    false_positive = "false_positive"
    risk_acceptance = "risk_acceptance"
    policy_waiver = "policy_waiver"
    benchmark = "benchmark"


FINDING_WAIVER_TYPES: tuple[str, ...] = ("false_positive", "risk_acceptance", "policy_waiver")


# ---------------------------------------------------------------------------
# date handling
# ---------------------------------------------------------------------------

def parse_datetime(value: Any) -> datetime | None:
    """Accept ISO 8601 strings, ``YYYY-MM-DD`` strings, and the ``date`` /
    ``datetime`` objects PyYAML produces for unquoted values. Naive values are
    treated as UTC. Returns an aware UTC datetime or ``None``."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, date):
        dt = datetime(value.year, value.month, value.day)
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith("Z") or text.endswith("z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError(
                f"Invalid date {value!r}: expected ISO 8601 (2026-01-31T00:00:00Z) or YYYY-MM-DD"
            ) from exc
    else:
        raise ValueError(f"Invalid date {value!r}: expected a string")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_datetime(dt: datetime | None) -> str | None:
    """Serialize as ``YYYY-MM-DD`` when the time is midnight UTC, else full ISO 8601 with ``Z``."""
    if dt is None:
        return None
    dt = dt.astimezone(timezone.utc)
    if dt.hour == 0 and dt.minute == 0 and dt.second == 0 and dt.microsecond == 0:
        return dt.date().isoformat()
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_tools(value: Any) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        raise ValueError("tools must be a list of tool names or categories")
    out: list[str] = []
    for item in value:
        name = str(item).strip().lower()
        if not name:
            continue
        if name not in TOOL_NAMES and name not in TOOL_CATEGORIES and name != TOOL_SCOPE_ALL:
            raise ValueError(
                f"unknown tool '{item}' in tools; expected one of {', '.join(TOOL_NAMES + TOOL_CATEGORIES + (TOOL_SCOPE_ALL,))}"
            )
        out.append("secret" if name == "secrets" else name)
    return out or None


# ---------------------------------------------------------------------------
# entry models (shared shapes)
# ---------------------------------------------------------------------------

class _ExtraAllowed(BaseModel):
    """Base that keeps unknown keys so the loader can warn about them."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    def unknown_keys(self) -> list[str]:
        return sorted((self.model_extra or {}).keys())


class _DatedEntry(_ExtraAllowed):
    reason: str | None = None
    expires_at: datetime | None = None
    created_by: str | None = None
    created_at: datetime | None = None

    @field_validator("expires_at", "created_at", mode="before")
    @classmethod
    def _parse_dates(cls, v: Any) -> datetime | None:
        return parse_datetime(v)


class PathExclusion(_DatedEntry):
    """Repo-root-relative gitignore-style pattern applied at output time."""

    pattern: str = Field(min_length=1)
    tools: list[str] | None = None

    @field_validator("tools", mode="before")
    @classmethod
    def _tools(cls, v: Any) -> list[str] | None:
        return _normalize_tools(v)


class BenchmarkEntry(_DatedEntry):
    """Baseline entry. ``type`` is always ``benchmark`` regardless of input."""

    fingerprint: str = Field(min_length=1)
    type: str = Field(
        default="benchmark",
        description="Always 'benchmark'. Any other value is accepted and overridden on load.",
    )
    ticket: str | None = None

    @field_validator("type", mode="before")
    @classmethod
    def _force_benchmark(cls, v: Any) -> str:
        # 1.0 loader semantics: any declared type is overridden to "benchmark"
        return "benchmark"


class FindingWaiverV1_0(_DatedEntry):
    fingerprint: str = Field(min_length=1)
    type: WaiverType
    ticket: str | None = None
    meta_ticket: str | None = None  # 1.0 example used this spelling on one entry

    @field_validator("type", mode="before")
    @classmethod
    def _type_allowed(cls, v: Any) -> Any:
        if isinstance(v, WaiverType):
            v = v.value
        if v not in FINDING_WAIVER_TYPES:
            raise ValueError(
                f"Invalid finding_waiver type: {v}. Must be one of: {', '.join(FINDING_WAIVER_TYPES)}"
            )
        return v


class FindingWaiverV1_1(_DatedEntry):
    fingerprint: str = Field(min_length=1)
    type: WaiverType
    ticket: str | None = None
    tools: list[str] | None = None

    @field_validator("type", mode="before")
    @classmethod
    def _type_allowed(cls, v: Any) -> Any:
        if isinstance(v, WaiverType):
            v = v.value
        if v not in FINDING_WAIVER_TYPES:
            raise ValueError(
                f"Invalid finding_waiver type: {v}. Must be one of: {', '.join(FINDING_WAIVER_TYPES)}"
            )
        return v

    @field_validator("tools", mode="before")
    @classmethod
    def _tools(cls, v: Any) -> list[str] | None:
        return _normalize_tools(v)


# ---------------------------------------------------------------------------
# file models, one per schema version
# ---------------------------------------------------------------------------

class WaiverFileV1_0(_ExtraAllowed):
    """Schema 1.0: the original waiver file format (dsoinabox 0.1.x)."""

    schema_version: Literal["1.0"] = "1.0"
    meta: dict[str, Any] = Field(default_factory=dict)
    path_exclusions: list[PathExclusion] = Field(default_factory=list)
    finding_waivers: list[FindingWaiverV1_0] = Field(default_factory=list)
    benchmark: list[BenchmarkEntry] = Field(default_factory=list)


class WaiverFileV1_1(_ExtraAllowed):
    """Schema 1.1 (dsoinabox 1.0.0).

    Changes from 1.0, all additive or normalizing:
    - ``finding_waivers[].ticket`` is the only ticket field (``meta_ticket`` migrates to it)
    - ``finding_waivers[].tools`` scopes a waiver to tools or categories
    - top-level ``benchmark_expires_at`` expires every benchmark entry at once
    - ``meta.schema_url`` may point at the published JSON Schema
    """

    schema_version: Literal["1.1"] = "1.1"
    meta: dict[str, Any] = Field(default_factory=dict)
    path_exclusions: list[PathExclusion] = Field(default_factory=list)
    finding_waivers: list[FindingWaiverV1_1] = Field(default_factory=list)
    benchmark: list[BenchmarkEntry] = Field(default_factory=list)
    benchmark_expires_at: datetime | None = None

    @field_validator("benchmark_expires_at", mode="before")
    @classmethod
    def _parse_bench_expiry(cls, v: Any) -> datetime | None:
        return parse_datetime(v)


SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "1.0": WaiverFileV1_0,
    "1.1": WaiverFileV1_1,
}


# ---------------------------------------------------------------------------
# version-independent internal representation
# ---------------------------------------------------------------------------

FindingWaiver = FindingWaiverV1_1
"""Canonical finding waiver shape used inside dsoinabox (always the newest schema's)."""


class WaiverSet(BaseModel):
    """What the rest of dsoinabox consumes. Independent of file schema version."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    schema_version: str
    """Version the file declared (or was assumed to have)."""
    source_path: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)
    path_exclusions: list[PathExclusion] = Field(default_factory=list)
    finding_waivers: list[FindingWaiver] = Field(default_factory=list)
    benchmark: list[BenchmarkEntry] = Field(default_factory=list)
    benchmark_expires_at: datetime | None = None
    warnings: list[str] = Field(default_factory=list)

    @property
    def deprecated(self) -> bool:
        from .schema import is_deprecated

        return is_deprecated(self.schema_version)

    @property
    def is_current(self) -> bool:
        return self.schema_version == CURRENT_SCHEMA_VERSION

    def all_fingerprint_entries(self) -> list[FindingWaiver | BenchmarkEntry]:
        return [*self.finding_waivers, *self.benchmark]

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe dict shaped like the *current* schema version.

        Used for the HTML report's embedded waiver data and for tests. Dates
        are strings in the documented formats; ``None`` values are dropped.
        """

        def clean(d: dict[str, Any]) -> dict[str, Any]:
            out: dict[str, Any] = {}
            for k, v in d.items():
                if v is None:
                    continue
                if isinstance(v, datetime):
                    out[k] = format_datetime(v)
                elif isinstance(v, Enum):
                    out[k] = v.value
                else:
                    out[k] = v
            return out

        data: dict[str, Any] = {
            "schema_version": CURRENT_SCHEMA_VERSION,
            "meta": dict(self.meta),
            "path_exclusions": [clean(p.model_dump(exclude_none=True)) for p in self.path_exclusions],
            "finding_waivers": [clean(w.model_dump(exclude_none=True)) for w in self.finding_waivers],
            "benchmark": [clean(b.model_dump(exclude_none=True)) for b in self.benchmark],
        }
        if self.benchmark_expires_at is not None:
            data["benchmark_expires_at"] = format_datetime(self.benchmark_expires_at)
        return data


def to_waiver_set(model: BaseModel, *, version: str, source_path: str | None = None) -> WaiverSet:
    """Convert a validated per-version file model into the canonical ``WaiverSet``."""
    warnings: list[str] = []

    def note_unknown(entry: _ExtraAllowed, where: str) -> None:
        for key in entry.unknown_keys():
            warnings.append(f"unknown key '{key}' in {where} is ignored")

    if isinstance(model, WaiverFileV1_0):
        finding_waivers: list[FindingWaiver] = []
        for i, fw in enumerate(model.finding_waivers):
            ticket = fw.ticket or fw.meta_ticket
            if fw.meta_ticket and not fw.ticket:
                warnings.append(
                    f"finding_waivers[{i}] uses 'meta_ticket'; schema 1.1 calls this 'ticket' (migrate fixes this)"
                )
            note_unknown(fw, f"finding_waivers[{i}]")
            finding_waivers.append(
                FindingWaiverV1_1(
                    fingerprint=fw.fingerprint,
                    type=fw.type,
                    reason=fw.reason,
                    expires_at=fw.expires_at,
                    created_by=fw.created_by,
                    created_at=fw.created_at,
                    ticket=ticket,
                    tools=None,
                )
            )
        for i, p in enumerate(model.path_exclusions):
            note_unknown(p, f"path_exclusions[{i}]")
        for i, b in enumerate(model.benchmark):
            note_unknown(b, f"benchmark[{i}]")
        note_unknown(model, "top level")
        return WaiverSet(
            schema_version=version,
            source_path=source_path,
            meta=dict(model.meta),
            path_exclusions=list(model.path_exclusions),
            finding_waivers=finding_waivers,
            benchmark=list(model.benchmark),
            benchmark_expires_at=None,
            warnings=warnings,
        )

    if isinstance(model, WaiverFileV1_1):
        for i, fw11 in enumerate(model.finding_waivers):
            note_unknown(fw11, f"finding_waivers[{i}]")
        for i, p in enumerate(model.path_exclusions):
            note_unknown(p, f"path_exclusions[{i}]")
        for i, b in enumerate(model.benchmark):
            note_unknown(b, f"benchmark[{i}]")
        note_unknown(model, "top level")
        return WaiverSet(
            schema_version=version,
            source_path=source_path,
            meta=dict(model.meta),
            path_exclusions=list(model.path_exclusions),
            finding_waivers=list(model.finding_waivers),
            benchmark=list(model.benchmark),
            benchmark_expires_at=model.benchmark_expires_at,
            warnings=warnings,
        )

    raise TypeError(f"no WaiverSet conversion for {type(model).__name__}")


# ---------------------------------------------------------------------------
# error formatting
# ---------------------------------------------------------------------------

def format_validation_error(exc: ValidationError) -> str:
    """Turn a pydantic error into the single-line messages users (and tests) expect."""
    messages: list[str] = []
    for err in exc.errors():
        loc = list(err.get("loc", ()))
        etype = err.get("type", "")
        msg = err.get("msg", "")
        section = str(loc[0]) if loc else "file"
        entry = section.rstrip("s") if section in ("finding_waivers", "path_exclusions") else section
        if section == "benchmark":
            entry = "benchmark entry"
        field = str(loc[-1]) if len(loc) >= 3 else None

        if etype in ("model_type", "dict_type", "model_attributes_type") and len(loc) == 2:
            messages.append(f"Invalid {entry}: must be a dictionary")
        elif etype == "missing" and field:
            messages.append(f"Invalid {entry}: missing required '{field}' field")
        elif etype == "string_too_short" and field:
            messages.append(f"Invalid {entry}: '{field}' must not be empty")
        elif etype == "value_error":
            # our own validators already produce a full sentence
            text = msg.replace("Value error, ", "", 1)
            messages.append(text)
        elif etype in ("list_type",) and len(loc) == 1:
            messages.append(f"Invalid {section}: must be a list")
        else:
            where = ".".join(str(p) for p in loc) or "file"
            messages.append(f"Invalid waiver file at {where}: {msg}")
    # de-duplicate while preserving order
    unique: list[str] = []
    for m in messages:
        if m not in unique:
            unique.append(m)
    return "; ".join(unique)
