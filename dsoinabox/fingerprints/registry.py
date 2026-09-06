"""Fingerprint version policy and project key resolution.

Format: ``<tool>:<fp_version>:<TIER>:<data...>[:R:<repo8>]``

Policy (also in docs/waivers/compatibility.md):

- A fingerprint version, once released, is frozen forever. Waiver files in
  the wild contain those exact strings. ``tests/unit/fingerprints/golden_v1.json``
  enforces this for version 1.
- Any change to an algorithm ships as a new version number. For at least one
  major release the scanner emits the current version in ``fingerprints`` and
  the previous one under ``fingerprints.legacy`` so existing waivers keep
  matching. The matcher always accepts legacy values; a match through one is
  reported so the user can migrate (``dsoinabox waivers migrate --from-report``).
- ``EMIT_LEGACY_VERSIONS`` lists the versions still emitted per tool. When a
  version drops off that list, files must be migrated with a report that still
  contained both versions.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

TOOL_PREFIX: dict[str, str] = {
    "trufflehog": "th",
    "opengrep": "og",
    "grype": "gy",
    "checkov": "ck",
}
PREFIX_TOOL: dict[str, str] = {v: k for k, v in TOOL_PREFIX.items()}

CURRENT_FP_VERSION: dict[str, int] = {"trufflehog": 1, "opengrep": 1, "grype": 1, "checkov": 1}
EMIT_LEGACY_VERSIONS: dict[str, tuple[int, ...]] = {"trufflehog": (), "opengrep": (), "grype": (), "checkov": ()}
SUPPORTED_FP_VERSIONS: dict[str, tuple[int, ...]] = {"trufflehog": (1,), "opengrep": (1,), "grype": (1,), "checkov": (1,)}

ENV_KEY_OVERRIDE = "DSOB_PROJECT_HMAC_KEY"
_env_key_warned = False


def parse_fingerprint(value: str) -> tuple[str, int, str] | None:
    """Return ``(tool, version, tier)`` for a fingerprint string, or None when malformed."""
    parts = value.split(":")
    if len(parts) < 4 or parts[0] not in PREFIX_TOOL:
        return None
    try:
        version = int(parts[1])
    except ValueError:
        return None
    return PREFIX_TOOL[parts[0]], version, parts[2]


def fingerprint_version_status(value: str) -> str:
    """``current``, ``legacy``, ``unsupported`` or ``unknown`` for a waiver fingerprint."""
    parsed = parse_fingerprint(value)
    if parsed is None:
        return "unknown"
    tool, version, _tier = parsed
    if version == CURRENT_FP_VERSION.get(tool):
        return "current"
    if version in SUPPORTED_FP_VERSIONS.get(tool, ()):
        return "legacy"
    return "unsupported"


def resolve_project_key(project_id: str | None) -> bytes:
    """Derive the per-project HMAC key used by every fingerprint tier.

    ``DSOB_PROJECT_HMAC_KEY`` overrides the derived key. Setting it changes every
    fingerprint, so a loud warning is logged once per process.
    """
    global _env_key_warned
    env_key = os.environ.get(ENV_KEY_OVERRIDE)
    if env_key:
        if not _env_key_warned:
            logger.warning(
                f"{ENV_KEY_OVERRIDE} is set: fingerprints are derived from this key instead of the project id. "
                "Existing waiver files only match if they were generated with the same key."
            )
            _env_key_warned = True
        return env_key.encode()
    if not project_id:
        raise ValueError("A project id is required to derive fingerprints (pass --project_id for non-git sources).")
    from ..utils.project_id import derive_project_hmac_key

    return derive_project_hmac_key(project_id)


def repo_hint_for(project_id: str | None) -> str:
    return project_id or ""


FINGERPRINTERS: dict[str, Callable[..., Any]] = {}


def register_fingerprinter(tool: str, fn: Callable[..., Any]) -> None:
    FINGERPRINTERS[tool] = fn
