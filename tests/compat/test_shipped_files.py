"""Compatibility matrix (W9.2): every waiver/benchmark file this repository ships or documents must load,
validate against its JSON Schema, and migrate cleanly to the current schema."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from dsoinabox.waivers import jsonschema as schema_files
from dsoinabox.waivers.loader import load_waiver_file
from dsoinabox.waivers.migrate import migrate_file
from dsoinabox.waivers.schema import CURRENT_SCHEMA_VERSION, SUPPORTED_SCHEMA_VERSIONS

ROOT = Path(__file__).resolve().parents[2]
SHIPPED = [
    ROOT / "dsoinabox" / "waivers" / "waiver_schema_1.0_example.yaml",
    ROOT / "dsoinabox" / "waivers" / "waiver_schema_1.1_example.yaml",
    ROOT / ".dsoinabox_waivers.yaml",
    *sorted((ROOT / "tests" / "fixtures" / "waivers").glob("v*/*.yaml")),
]
INVALID_BY_DESIGN = {"invalid_type.yaml", "invalid_date.yaml", "future_version.yaml", "bad_tool_scope.yaml"}
VALID = [p for p in SHIPPED if p.name not in INVALID_BY_DESIGN]


@pytest.mark.parametrize("path", VALID, ids=lambda p: str(p.relative_to(ROOT)))
def test_shipped_file_loads(path):
    ws = load_waiver_file(str(path))
    assert ws.schema_version in SUPPORTED_SCHEMA_VERSIONS


@pytest.mark.parametrize("path", VALID, ids=lambda p: str(p.relative_to(ROOT)))
def test_shipped_file_matches_its_json_schema(path):
    jsonschema = pytest.importorskip("jsonschema")
    data = yaml.safe_load(path.read_text()) or {}
    version = str(data.get("schema_version") or "1.0")
    data = json.loads(json.dumps(data, default=str))
    data["schema_version"] = version
    jsonschema.validate(data, schema_files.load_checked_in(version))


@pytest.mark.parametrize("path", VALID, ids=lambda p: str(p.relative_to(ROOT)))
def test_shipped_file_migrates_to_current(path, tmp_path):
    dst = tmp_path / path.name
    shutil.copy(path, dst)
    result = migrate_file(dst, in_place=True)
    ws = load_waiver_file(str(dst))
    assert ws.schema_version == CURRENT_SCHEMA_VERSION
    assert not any("deprecated" in w for w in ws.warnings)
    assert result.to_version == CURRENT_SCHEMA_VERSION


def test_examples_exist_for_every_supported_version():
    for version in SUPPORTED_SCHEMA_VERSIONS:
        assert (ROOT / "dsoinabox" / "waivers" / f"waiver_schema_{version}_example.yaml").exists(), version
        assert (ROOT / "dsoinabox" / "waivers" / "schema_files" / f"waivers-{version}.schema.json").exists(), version


def test_current_example_is_warning_free():
    ws = load_waiver_file(str(ROOT / "dsoinabox" / "waivers" / f"waiver_schema_{CURRENT_SCHEMA_VERSION}_example.yaml"))
    assert ws.warnings == []
