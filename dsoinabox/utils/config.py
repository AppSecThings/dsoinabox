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
    "report_threshold",
    "fail_on_secrets",
    "show_findings",
    "scan_timeout",
    "fail_fast",
    "waiver_file",
    "waiver_grace_days",
    "output",
    "report_name",
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
    "report_threshold": "DSOINABOX_REPORT_THRESHOLD",
    "scan_timeout": "DSOINABOX_SCAN_TIMEOUT",
    "fail_fast": "DSOINABOX_FAIL_FAST",
    "fail_on_secrets": "DSOINABOX_FAIL_ON_SECRETS",
    "show_findings": "DSOINABOX_SHOW_FINDINGS",
    "waiver_file": "DSOINABOX_WAIVER_FILE",
    "waiver_grace_days": "DSOINABOX_WAIVER_GRACE_DAYS",
    "output": "DSOINABOX_OUTPUT",
    "report_name": "DSOINABOX_REPORT_NAME",
    "tool_output": "DSOINABOX_TOOL_OUTPUT",
    "benchmark": "DSOINABOX_BENCHMARK",
    "trufflehog_args": "DSOINABOX_TRUFFLEHOG_ARGS",
    "opengrep_args": "DSOINABOX_OPENGREP_ARGS",
    "syft_args": "DSOINABOX_SYFT_ARGS",
    "grype_args": "DSOINABOX_GRYPE_ARGS",
    "checkov_args": "DSOINABOX_CHECKOV_ARGS",
    "config_file": CONFIG_ENV_VAR,
}

BOOL_KEYS = {"fail_on_secrets", "tool_output", "benchmark", "fail_fast"}
INT_KEYS = {"waiver_grace_days", "scan_timeout"}
SHOW_FINDINGS_CHOICES = ("false", "true", "full")
STRING_LIST_KEYS = {"tools", "output"}
NESTED_TOOL_ARG_KEYS = ("tool_args", "extra_tool_args")

DEFAULT_CONFIG_TEMPLATE = """# Repository-level defaults for dsoinabox.
# Precedence: .dsoinabox.yaml -> DSOINABOX_* env vars -> CLI flags.

tools: all
failure_threshold: none     # exit 1 when unwaived findings at/above this severity exist
# report_threshold: none    # hide findings below this severity from reports (gate is unaffected)
fail_on_secrets: false
waiver_file: .dsoinabox_waivers.yaml
# waiver_grace_days: 0      # keep expired waivers active for N extra days (flagged as expiring)
# report_name: dsoinabox_unified_report   # base file name; <report_directory>/latest/ always points at the newest run
output: html
show_findings: false        # false | true (compact table) | full (details)
tool_output: false
benchmark: false
# scan_timeout: 1800        # seconds per scanner; a timeout is a scanner failure (exit 2)
# fail_fast: false          # stop remaining scanners after the first failure

# Optional per-tool extra args (uncomment and customize):
# trufflehog_args: "--filter-unverified"
# opengrep_args: "--severity high"
# syft_args: "--scope all-layers"
# grype_args: "--scope all-layers"
# checkov_args: "--framework terraform"
"""


def normalize_show_findings(value: bool | str | None) -> str:
    """--show_findings accepts false/true/full (plus the usual yes/no/1/0 spellings)."""
    if value is None:
        return "true"
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value).strip().lower()
    if text == "full":
        return "full"
    return "true" if str_to_bool(text) else "false"


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
        elif key == "show_findings":
            overrides[key] = normalize_show_findings(raw_value)
        elif key in INT_KEYS:
            overrides[key] = int(raw_value)
        else:
            overrides[key] = raw_value
    return overrides


def _normalize_value(key: str, value: Any) -> Any:
    """normalize a supported config value to runtime shape."""
    if key in BOOL_KEYS:
        return str_to_bool(value)

    if key == "show_findings":
        return normalize_show_findings(value)

    if key in INT_KEYS:
        return int(value)

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
