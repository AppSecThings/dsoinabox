"""Per-tool normalizers: raw scanner record -> ``Finding``."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..model import Finding
from . import checkov, grype, opengrep, trufflehog

NORMALIZERS: dict[str, Callable[[Any, str | None], list[Finding]]] = {
    "trufflehog": trufflehog.normalize,
    "opengrep": opengrep.normalize,
    "grype": grype.normalize,
    "checkov": checkov.normalize,
}


def normalize(tool: str, raw: Any, source_path: str | None = None) -> list[Finding]:
    fn = NORMALIZERS.get(tool.lower())
    if fn is None:
        return []
    return fn(raw, source_path)


__all__ = ["NORMALIZERS", "normalize"]
