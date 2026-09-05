"""Rewrite waiver and benchmark files to a newer schema version.

Uses ruamel.yaml in round-trip mode so comments, key order and quoting in the
user's file survive. Migrations are pure functions on the round-trip tree and
are chained one MINOR/MAJOR step at a time.
"""

from __future__ import annotations

import difflib
import io
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.scalarstring import DoubleQuotedScalarString

from .loader import load_waiver_data
from .schema import (
    CURRENT_SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    UnsupportedSchemaVersionError,
    normalize_version,
    parse_version,
)


def _yaml() -> YAML:
    y = YAML(typ="rt")
    y.preserve_quotes = True
    y.width = 4096
    y.indent(mapping=2, sequence=4, offset=2)
    return y


def load_round_trip(path: Path) -> CommentedMap:
    data = _yaml().load(path.read_text(encoding="utf-8"))
    if data is None:
        data = CommentedMap()
    if not isinstance(data, CommentedMap):
        raise ValueError(f"Invalid waiver file format: expected mapping at top level in {path}")
    return data


def dump_round_trip(data: CommentedMap) -> str:
    buf = io.StringIO()
    _yaml().dump(data, buf)
    return buf.getvalue()


def _plain(data: Any) -> Any:
    """Convert a ruamel tree into plain Python containers for validation."""
    if isinstance(data, CommentedMap):
        return {str(k): _plain(v) for k, v in data.items()}
    if isinstance(data, CommentedSeq):
        return [_plain(v) for v in data]
    return data


# ---------------------------------------------------------------------------
# migration steps
# ---------------------------------------------------------------------------

def _set_version(data: CommentedMap, version: str) -> None:
    quoted = DoubleQuotedScalarString(version)
    if "schema_version" in data:
        data["schema_version"] = quoted
    else:
        data.insert(0, "schema_version", quoted)


def migrate_1_0_to_1_1(data: CommentedMap) -> list[str]:
    """1.0 -> 1.1: canonicalize ``meta_ticket`` to ``ticket``."""
    notes: list[str] = []
    _set_version(data, "1.1")
    for i, entry in enumerate(data.get("finding_waivers") or []):
        if not isinstance(entry, CommentedMap) or "meta_ticket" not in entry:
            continue
        if "ticket" in entry:
            del entry["meta_ticket"]
            notes.append(f"finding_waivers[{i}]: dropped meta_ticket (ticket already set)")
        else:
            keys = list(entry.keys())
            pos = keys.index("meta_ticket")
            value = entry.pop("meta_ticket")
            entry.insert(pos, "ticket", value)
            notes.append(f"finding_waivers[{i}]: renamed meta_ticket to ticket")
    return notes


MIGRATIONS: dict[tuple[str, str], Callable[[CommentedMap], list[str]]] = {
    ("1.0", "1.1"): migrate_1_0_to_1_1,
}


def migration_path(from_version: str, to_version: str) -> list[tuple[str, str]]:
    """Ordered list of (from, to) steps between two supported versions."""
    versions = list(SUPPORTED_SCHEMA_VERSIONS)
    if from_version not in versions or to_version not in versions:
        raise UnsupportedSchemaVersionError(
            f"Cannot migrate from {from_version} to {to_version}; supported versions: {', '.join(versions)}"
        )
    start, end = versions.index(from_version), versions.index(to_version)
    if start > end:
        raise ValueError(f"Cannot migrate backwards from {from_version} to {to_version}")
    steps = [(versions[i], versions[i + 1]) for i in range(start, end)]
    for step in steps:
        if step not in MIGRATIONS:
            raise UnsupportedSchemaVersionError(f"No migration registered for {step[0]} -> {step[1]}")
    return steps


@dataclass
class MigrateResult:
    path: Path
    from_version: str
    to_version: str
    changed: bool
    original_text: str
    migrated_text: str
    notes: list[str] = field(default_factory=list)
    output_path: Path | None = None
    backup_path: Path | None = None

    @property
    def diff(self) -> str:
        return "".join(
            difflib.unified_diff(
                self.original_text.splitlines(keepends=True),
                self.migrated_text.splitlines(keepends=True),
                fromfile=f"{self.path} (schema {self.from_version})",
                tofile=f"{self.path} (schema {self.to_version})",
            )
        )


def load_fingerprint_aliases(report_path: str | Path) -> dict[str, str]:
    """Read ``fingerprint_aliases`` from a dsoinabox JSON report (metadata or top level)."""
    import json

    with Path(report_path).open(encoding="utf-8") as fh:
        report = json.load(fh)
    if not isinstance(report, dict):
        raise ValueError(f"{report_path}: not a dsoinabox JSON report")
    aliases = (report.get("metadata") or {}).get("fingerprint_aliases") or report.get("fingerprint_aliases") or {}
    if not isinstance(aliases, dict):
        raise ValueError(f"{report_path}: fingerprint_aliases is not a mapping")
    return {str(k): str(v) for k, v in aliases.items()}


def rewrite_fingerprints(data: CommentedMap, aliases: dict[str, str]) -> list[str]:
    """Replace legacy fingerprints with their current equivalents, in place."""
    notes: list[str] = []
    if not aliases:
        return notes
    for section in ("finding_waivers", "benchmark"):
        for i, entry in enumerate(data.get(section) or []):
            if not isinstance(entry, CommentedMap):
                continue
            current = entry.get("fingerprint")
            if isinstance(current, str) and current in aliases and aliases[current] != current:
                entry["fingerprint"] = DoubleQuotedScalarString(aliases[current])
                notes.append(f"{section}[{i}]: fingerprint {current} -> {aliases[current]}")
    return notes


def migrate_data(
    data: CommentedMap, *, to_version: str | None = None, aliases: dict[str, str] | None = None
) -> tuple[str, str, list[str]]:
    """Migrate a round-trip tree in place. Returns (from_version, to_version, notes)."""
    raw_version = data.get("schema_version")
    from_version = normalize_version(raw_version) if raw_version is not None else "1.0"
    target = normalize_version(to_version) if to_version else CURRENT_SCHEMA_VERSION
    notes: list[str] = []
    if raw_version is None:
        notes.append("schema_version was missing; treated as 1.0")
    for step in migration_path(from_version, target):
        notes.extend(MIGRATIONS[step](data))
    if from_version == target and (raw_version is None or not isinstance(raw_version, str)):
        # nothing to migrate, but normalize the version scalar to a quoted string
        _set_version(data, target)
        notes.append("normalized schema_version to a quoted string")
    if aliases:
        notes.extend(rewrite_fingerprints(data, aliases))
    # validate the result with the regular loader before anyone writes it
    load_waiver_data(_plain(data))
    return from_version, target, notes


def migrate_file(
    path: str | Path,
    *,
    to_version: str | None = None,
    in_place: bool = False,
    output: str | Path | None = None,
    dry_run: bool = False,
    aliases: dict[str, str] | None = None,
) -> MigrateResult:
    """Migrate a file. Writes only when ``in_place`` or ``output`` is given and not ``dry_run``."""
    src = Path(path)
    if not src.exists():
        raise FileNotFoundError(f"Waiver file not found: {src}")
    original_text = src.read_text(encoding="utf-8")
    data = load_round_trip(src)
    from_version, target, notes = migrate_data(data, to_version=to_version, aliases=aliases)
    migrated_text = dump_round_trip(data)
    result = MigrateResult(
        path=src,
        from_version=from_version,
        to_version=target,
        changed=migrated_text != original_text,
        original_text=original_text,
        migrated_text=migrated_text,
        notes=notes,
    )
    _write_result(result, in_place=in_place, output=output, dry_run=dry_run)
    return result


# ---------------------------------------------------------------------------
# prune / add (share the round-trip writer so comments survive)
# ---------------------------------------------------------------------------


def prune_data(
    data: CommentedMap,
    *,
    now: Any,
    unused_refs: set[str] | None = None,
) -> list[str]:
    """Remove expired entries (and optionally entries named in ``unused_refs``). Returns notes."""
    from .models import parse_datetime

    notes: list[str] = []
    bench_expiry = parse_datetime(data.get("benchmark_expires_at")) if data.get("benchmark_expires_at") is not None else None
    for section in ("finding_waivers", "benchmark", "path_exclusions"):
        entries = data.get(section)
        if not isinstance(entries, CommentedSeq):
            continue
        keep_indexes: list[int] = []
        for i, entry in enumerate(entries):
            ref = f"{section}[{i}]"
            if not isinstance(entry, CommentedMap):
                keep_indexes.append(i)
                continue
            expires = parse_datetime(entry.get("expires_at")) if entry.get("expires_at") is not None else None
            if section == "benchmark" and bench_expiry is not None and (expires is None or bench_expiry < expires):
                expires = bench_expiry
            key = entry.get("fingerprint") or entry.get("pattern") or "?"
            if expires is not None and expires <= now:
                notes.append(f"{ref}: removed expired entry {key} (expired {expires.date().isoformat()})")
                continue
            if unused_refs and ref in unused_refs:
                notes.append(f"{ref}: removed unused entry {key}")
                continue
            keep_indexes.append(i)
        for i in reversed([i for i in range(len(entries)) if i not in keep_indexes]):
            del entries[i]
    return notes


def prune_file(
    path: str | Path,
    *,
    now: Any,
    unused_refs: set[str] | None = None,
    in_place: bool = False,
    output: str | Path | None = None,
    dry_run: bool = False,
) -> MigrateResult:
    src = Path(path)
    if not src.exists():
        raise FileNotFoundError(f"Waiver file not found: {src}")
    original_text = src.read_text(encoding="utf-8")
    data = load_round_trip(src)
    raw_version = data.get("schema_version")
    version = normalize_version(raw_version) if raw_version is not None else "1.0"
    notes = prune_data(data, now=now, unused_refs=unused_refs)
    load_waiver_data(_plain(data))
    text = dump_round_trip(data)
    result = MigrateResult(path=src, from_version=version, to_version=version, changed=text != original_text,
                           original_text=original_text, migrated_text=text, notes=notes)
    _write_result(result, in_place=in_place, output=output, dry_run=dry_run)
    return result


def add_entry(
    path: str | Path,
    *,
    fingerprints: list[str],
    type_: str,
    reason: str | None = None,
    expires_at: str | None = None,
    ticket: str | None = None,
    created_by: str | None = None,
    created_at: str | None = None,
    tools: list[str] | None = None,
    in_place: bool = True,
    output: str | Path | None = None,
    dry_run: bool = False,
) -> MigrateResult:
    """Append finding waivers (or benchmark entries when type_ == 'benchmark') to a file, creating it if needed."""
    src = Path(path)
    if src.exists():
        original_text = src.read_text(encoding="utf-8")
        data = load_round_trip(src)
    else:
        original_text = ""
        data = CommentedMap()
        _set_version(data, CURRENT_SCHEMA_VERSION)
    raw_version = data.get("schema_version")
    version = normalize_version(raw_version) if raw_version is not None else "1.0"
    section = "benchmark" if type_ == "benchmark" else "finding_waivers"
    entries = data.get(section)
    if entries is None:
        entries = CommentedSeq()
        data[section] = entries
    existing = {e.get("fingerprint") for e in entries if isinstance(e, CommentedMap)}
    notes: list[str] = []
    for fp in fingerprints:
        if fp in existing:
            notes.append(f"{section}: {fp} already present, skipped")
            continue
        entry = CommentedMap()
        entry["fingerprint"] = DoubleQuotedScalarString(fp)
        entry["type"] = type_
        if reason:
            entry["reason"] = reason
        if expires_at:
            entry["expires_at"] = DoubleQuotedScalarString(expires_at)
        if created_by:
            entry["created_by"] = created_by
        if created_at:
            entry["created_at"] = DoubleQuotedScalarString(created_at)
        if ticket:
            entry["ticket"] = ticket
        if tools and section == "finding_waivers":
            entry["tools"] = list(tools)
        entries.append(entry)
        existing.add(fp)
        notes.append(f"{section}: added {fp}")
    load_waiver_data(_plain(data))
    text = dump_round_trip(data)
    result = MigrateResult(path=src, from_version=version, to_version=version, changed=text != original_text,
                           original_text=original_text, migrated_text=text, notes=notes)
    _write_result(result, in_place=in_place, output=output, dry_run=dry_run)
    return result


def update_baseline_file(
    path: str | Path,
    *,
    fingerprints: list[str],
    seen_fingerprints: set[str] | None = None,
    prune: bool = False,
    expires_at: str | None = None,
    created_at: str | None = None,
    dry_run: bool = False,
) -> MigrateResult:
    """Add fingerprints to the ``benchmark`` section; optionally prune entries not seen in the run."""
    src = Path(path)
    if src.exists():
        original_text = src.read_text(encoding="utf-8")
        data = load_round_trip(src)
    else:
        original_text = ""
        data = CommentedMap()
        _set_version(data, CURRENT_SCHEMA_VERSION)
        meta = CommentedMap()
        meta["created_at"] = DoubleQuotedScalarString(created_at or "")
        meta["notes"] = "Baseline generated by `dsoinabox baseline update`"
        data["meta"] = meta
    raw_version = data.get("schema_version")
    version = normalize_version(raw_version) if raw_version is not None else "1.0"
    notes: list[str] = []
    if expires_at:
        data["benchmark_expires_at"] = DoubleQuotedScalarString(expires_at)
        notes.append(f"benchmark_expires_at set to {expires_at}")
        if version < "1.1":
            _set_version(data, "1.1")
            version = "1.1"
            notes.append("schema upgraded to 1.1 (benchmark_expires_at needs it)")
    entries = data.get("benchmark")
    if entries is None:
        entries = CommentedSeq()
        data["benchmark"] = entries
    existing = {e.get("fingerprint"): i for i, e in enumerate(entries) if isinstance(e, CommentedMap)}
    if prune and seen_fingerprints is not None:
        for i in sorted([i for fp, i in existing.items() if fp not in seen_fingerprints], reverse=True):
            notes.append(f"benchmark[{i}]: removed {entries[i].get('fingerprint')} (not present in report)")
            del entries[i]
        existing = {e.get("fingerprint"): i for i, e in enumerate(entries) if isinstance(e, CommentedMap)}
    added = 0
    for fp in fingerprints:
        if fp in existing:
            continue
        entry = CommentedMap()
        entry["fingerprint"] = DoubleQuotedScalarString(fp)
        entry["type"] = "benchmark"
        if created_at:
            entry["created_at"] = DoubleQuotedScalarString(created_at)
        entries.append(entry)
        existing[fp] = len(entries) - 1
        added += 1
    if added:
        notes.append(f"added {added} benchmark entr{'y' if added == 1 else 'ies'}")
    load_waiver_data(_plain(data))
    text = dump_round_trip(data)
    result = MigrateResult(path=src, from_version=version, to_version=version, changed=text != original_text,
                           original_text=original_text, migrated_text=text, notes=notes)
    _write_result(result, in_place=True, output=None, dry_run=dry_run)
    return result


def _write_result(result: MigrateResult, *, in_place: bool, output: str | Path | None, dry_run: bool) -> None:
    if dry_run or not result.changed:
        return
    if output is not None:
        out = Path(output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(result.migrated_text, encoding="utf-8")
        result.output_path = out
    elif in_place:
        if result.path.exists():
            backup = result.path.with_name(result.path.name + ".bak")
            shutil.copy2(result.path, backup)
            result.backup_path = backup
        result.path.parent.mkdir(parents=True, exist_ok=True)
        result.path.write_text(result.migrated_text, encoding="utf-8")
        result.output_path = result.path


def parse_version_arg(value: str) -> str:
    version = normalize_version(value)
    parse_version(version)
    return version
