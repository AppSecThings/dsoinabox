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


def migrate_data(data: CommentedMap, *, to_version: str | None = None) -> tuple[str, str, list[str]]:
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
) -> MigrateResult:
    """Migrate a file. Writes only when ``in_place`` or ``output`` is given and not ``dry_run``."""
    src = Path(path)
    if not src.exists():
        raise FileNotFoundError(f"Waiver file not found: {src}")
    original_text = src.read_text(encoding="utf-8")
    data = load_round_trip(src)
    from_version, target, notes = migrate_data(data, to_version=to_version)
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
    if dry_run or not result.changed:
        return result
    if output is not None:
        out = Path(output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(migrated_text, encoding="utf-8")
        result.output_path = out
    elif in_place:
        backup = src.with_name(src.name + ".bak")
        shutil.copy2(src, backup)
        src.write_text(migrated_text, encoding="utf-8")
        result.output_path = src
        result.backup_path = backup
    return result


def parse_version_arg(value: str) -> str:
    version = normalize_version(value)
    parse_version(version)
    return version
