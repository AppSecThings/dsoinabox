"""runtime configuration helpers for config/env/cli merging."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_FILE = ".dsoinabox.yaml"
CONFIG_ENV_VAR = "DSOINABOX_CONFIG"

TOOL_NAMES = ("trufflehog", "opengrep", "syft", "grype", "checkov")
TOOL_ARG_KEYS = tuple(f"{tool}_args" for tool in TOOL_NAMES)

MERGEABLE_KEYS = (
    "source",
    "report_directory",
    "project_id",
    "tools",
    "failure_threshold",
    "fail_on_secrets",
    "show_findings",
    "waiver_file",
    "output",
    "tool_output",
    "benchmark",
    *TOOL_ARG_KEYS,
)

ENV_KEY_MAP = {
    "source": "DSOINABOX_SOURCE",
    "report_directory": "DSOINABOX_REPORT_DIRECTORY",
    "project_id": "DSOINABOX_PROJECT_ID",
    "tools": "DSOINABOX_TOOLS",
    "failure_threshold": "DSOINABOX_FAILURE_THRESHOLD",
    "fail_on_secrets": "DSOINABOX_FAIL_ON_SECRETS",
    "show_findings": "DSOINABOX_SHOW_FINDINGS",
    "waiver_file": "DSOINABOX_WAIVER_FILE",
    "output": "DSOINABOX_OUTPUT",
    "tool_output": "DSOINABOX_TOOL_OUTPUT",
    "benchmark": "DSOINABOX_BENCHMARK",
    "trufflehog_args": "DSOINABOX_TRUFFLEHOG_ARGS",
    "opengrep_args": "DSOINABOX_OPENGREP_ARGS",
    "syft_args": "DSOINABOX_SYFT_ARGS",
    "grype_args": "DSOINABOX_GRYPE_ARGS",
    "checkov_args": "DSOINABOX_CHECKOV_ARGS",
    "config_file": CONFIG_ENV_VAR,
}

BOOL_KEYS = {"fail_on_secrets", "show_findings", "tool_output", "benchmark"}
STRING_LIST_KEYS = {"tools", "output"}
NESTED_TOOL_ARG_KEYS = ("tool_args", "extra_tool_args")

DEFAULT_CONFIG_TEMPLATE = """# Repository-level defaults for dsoinabox.
# Precedence: .dsoinabox.yaml -> DSOINABOX_* env vars -> CLI flags.

tools: all
failure_threshold: none
fail_on_secrets: false
waiver_file: .dsoinabox_waivers.yaml
output: html
show_findings: true
tool_output: false
benchmark: false

# Optional per-tool extra args (uncomment and customize):
# trufflehog_args: "--filter-unverified"
# opengrep_args: "--severity high"
# syft_args: "--scope all-layers"
# grype_args: "--scope all-layers"
# checkov_args: "--framework terraform"
"""


def str_to_bool(v: bool | str | None) -> bool:
    """convert common bool string values."""
    if isinstance(v, bool):
        return v
    if v is None:
        return True
    if isinstance(v, str):
        lowered = v.lower()
        if lowered in ("yes", "true", "t", "y", "1"):
            return True
        if lowered in ("no", "false", "f", "n", "0"):
            return False
    raise ValueError("Boolean value expected.")


def resolve_config_path(*, source: str, explicit_path: str | None) -> Path:
    """resolve config path, relative to source when not absolute."""
    if explicit_path:
        path = Path(explicit_path)
        if path.is_absolute():
            return path
        return Path(source) / path
    return Path(source) / DEFAULT_CONFIG_FILE


def read_env_overrides() -> dict[str, Any]:
    """read supported DSOINABOX_* environment variables."""
    overrides: dict[str, Any] = {}
    for key, env_var in ENV_KEY_MAP.items():
        raw_value = os.getenv(env_var)
        if raw_value is None:
            continue
        if key in BOOL_KEYS:
            overrides[key] = str_to_bool(raw_value)
        else:
            overrides[key] = raw_value
    return overrides


def _normalize_value(key: str, value: Any) -> Any:
    """normalize a supported config value to runtime shape."""
    if key in BOOL_KEYS:
        return str_to_bool(value)

    if key in STRING_LIST_KEYS and isinstance(value, list):
        return ",".join(str(item).strip() for item in value if str(item).strip())

    if key == "waiver_file" and value is None:
        return None

    if value is None:
        return None

    if key in TOOL_ARG_KEYS and isinstance(value, (list, tuple)):
        return [str(v) for v in value]

    return str(value)


def load_config_file(filepath: Path) -> dict[str, Any]:
    """load and normalize .dsoinabox.yaml contents."""
    with open(filepath, "r", encoding="utf-8") as f:
        loaded = yaml.safe_load(f)

    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ValueError(f"Invalid config format in {filepath}: expected mapping at top level.")

    config_values: dict[str, Any] = {}
    for key in MERGEABLE_KEYS:
        if key in loaded:
            config_values[key] = _normalize_value(key, loaded[key])

    for nested_key in NESTED_TOOL_ARG_KEYS:
        nested = loaded.get(nested_key)
        if nested is None:
            continue
        if not isinstance(nested, dict):
            raise ValueError(f"Invalid config key '{nested_key}' in {filepath}: expected mapping.")
        for tool_name, tool_args in nested.items():
            normalized_tool = str(tool_name).strip().lower()
            if normalized_tool not in TOOL_NAMES:
                raise ValueError(
                    f"Invalid tool name '{tool_name}' in '{nested_key}' in {filepath}. "
                    f"Supported values: {', '.join(TOOL_NAMES)}."
                )
            config_key = f"{normalized_tool}_args"
            config_values.setdefault(config_key, _normalize_value(config_key, tool_args))

    return config_values


def write_default_config(filepath: Path, *, overwrite: bool = False) -> bool:
    """write starter config file. returns True if created/written."""
    if filepath.exists() and not overwrite:
        return False
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(DEFAULT_CONFIG_TEMPLATE)
    return True
