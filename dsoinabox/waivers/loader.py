"""Version-aware waiver file loader.

Every supported schema version loads into the same ``WaiverSet``. Deprecated
versions load with a warning. See ``schema.py`` for the policy.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import yaml
from pydantic import ValidationError

from .models import SCHEMA_MODELS, WaiverSet, format_validation_error, to_waiver_set
from .schema import resolve_version

logger = logging.getLogger("dsoinabox.waivers")


def load_waiver_data(data: Any, *, source_path: str | None = None) -> WaiverSet:
    """Validate already-parsed YAML/JSON data and return a ``WaiverSet``."""
    if not isinstance(data, dict):
        raise ValueError(f"Invalid waiver file format: expected dict, got {type(data)}")

    version, warnings = resolve_version(data.get("schema_version"))
    model_cls = SCHEMA_MODELS[version]

    payload = dict(data)
    payload["schema_version"] = version
    try:
        model = model_cls.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(format_validation_error(exc)) from None

    waiver_set = to_waiver_set(model, version=version, source_path=source_path)
    waiver_set.warnings = [*warnings, *waiver_set.warnings]
    for message in waiver_set.warnings:
        logger.warning("%s%s", f"{source_path}: " if source_path else "", message)
    return waiver_set


def load_waiver_file(filepath: str) -> WaiverSet:
    """Load a waiver (or benchmark) file at any supported schema version."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Waiver file not found: {filepath}")

    with open(filepath, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if data is None:
        data = {}
    return load_waiver_data(data, source_path=filepath)
