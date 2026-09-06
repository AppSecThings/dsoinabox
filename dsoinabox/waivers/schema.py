"""Waiver file schema version policy.

Version scheme: ``MAJOR.MINOR`` strings.

- A MINOR bump adds optional fields or relaxes validation. Every loader for
  the same MAJOR can read every MINOR of that MAJOR.
- A MAJOR bump changes meaning or removes fields and requires a migration
  step (``dsoinabox waivers migrate``).
- A missing ``schema_version`` is treated as the oldest version (``1.0``),
  never as "latest", because reinterpreting an old file under new rules
  silently changes what it waives. A warning tells the user to add the field.
- Versions listed in ``DEPRECATED_SCHEMA_VERSIONS`` still load and apply
  fully, with a one-line warning pointing at the migrate command.
- Unknown future versions fail with an error naming the newest supported
  version so the user knows to upgrade dsoinabox rather than edit the file.

The same policy applies to benchmark files, which share this module.
"""

from __future__ import annotations

from typing import Any

CURRENT_SCHEMA_VERSION = "1.1"
SUPPORTED_SCHEMA_VERSIONS: tuple[str, ...] = ("1.0", "1.1")
DEPRECATED_SCHEMA_VERSIONS: frozenset[str] = frozenset({"1.0"})
DEFAULT_SCHEMA_VERSION_WHEN_MISSING = "1.0"

MIGRATE_HINT = "run `dsoinabox waivers migrate <file>` to upgrade it to schema " + CURRENT_SCHEMA_VERSION


class SchemaVersionError(ValueError):
    """Raised when a schema_version value is malformed."""


class UnsupportedSchemaVersionError(SchemaVersionError):
    """Raised when a schema_version is well-formed but not supported by this build."""


def normalize_version(value: Any) -> str:
    """Return the canonical ``MAJOR.MINOR`` string for a schema_version value.

    YAML parses an unquoted ``1.0`` as a float, and ``1`` as an int, so both
    are accepted here. ``1.10`` cannot be distinguished from ``1.1`` once it
    has become a float, which is why the documented form is a quoted string.
    """
    if value is None:
        raise SchemaVersionError("schema_version is missing")
    if isinstance(value, bool):
        raise SchemaVersionError(f"Invalid schema_version: {value!r}")
    if isinstance(value, int):
        return f"{value}.0"
    if isinstance(value, float):
        major = int(value)
        minor_str = repr(value).split(".", 1)[1] if "." in repr(value) else "0"
        return f"{major}.{int(minor_str)}"
    if isinstance(value, str):
        text = value.strip()
        parts = text.split(".")
        if len(parts) == 1 and parts[0].isdigit():
            return f"{int(parts[0])}.0"
        if len(parts) == 2 and all(p.isdigit() for p in parts):
            return f"{int(parts[0])}.{int(parts[1])}"
        raise SchemaVersionError(f"Invalid schema_version: {value!r} (expected MAJOR.MINOR, e.g. \"1.1\")")
    raise SchemaVersionError(f"Invalid schema_version: {value!r}")


def parse_version(value: Any) -> tuple[int, int]:
    """Return ``(major, minor)`` for a schema_version value."""
    major, minor = normalize_version(value).split(".")
    return int(major), int(minor)


def is_supported(version: str) -> bool:
    return version in SUPPORTED_SCHEMA_VERSIONS


def is_deprecated(version: str) -> bool:
    return version in DEPRECATED_SCHEMA_VERSIONS


def resolve_version(value: Any) -> tuple[str, list[str]]:
    """Resolve a raw schema_version value into a supported version.

    Returns ``(version, warnings)``. Raises ``UnsupportedSchemaVersionError``
    for well-formed versions this build cannot read.
    """
    warnings: list[str] = []
    if value is None:
        version = DEFAULT_SCHEMA_VERSION_WHEN_MISSING
        warnings.append(
            f"schema_version is missing; assuming \"{version}\". Add `schema_version: \"{CURRENT_SCHEMA_VERSION}\"` "
            "to the top of the file to make this explicit."
        )
    else:
        if not isinstance(value, str):
            warnings.append(
                f"schema_version should be a quoted string (got {value!r}); "
                f"write it as schema_version: \"{normalize_version(value)}\""
            )
        version = normalize_version(value)

    if not is_supported(version):
        major, _ = parse_version(version)
        newest_major, _ = parse_version(CURRENT_SCHEMA_VERSION)
        if major > newest_major or version > CURRENT_SCHEMA_VERSION:
            raise UnsupportedSchemaVersionError(
                f"Unsupported waiver schema version: {version}. This build supports up to "
                f"{CURRENT_SCHEMA_VERSION}; upgrade dsoinabox to read this file."
            )
        raise UnsupportedSchemaVersionError(
            f"Unsupported waiver schema version: {version}. Supported versions: "
            f"{', '.join(SUPPORTED_SCHEMA_VERSIONS)}."
        )

    if is_deprecated(version):
        warnings.append(f"waiver schema {version} is deprecated; {MIGRATE_HINT}")
    return version, warnings
