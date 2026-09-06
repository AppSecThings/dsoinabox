"""Generate JSON Schema documents for every waiver schema version.

The generated files live in ``dsoinabox/waivers/schema_files/`` and ship with
the package so editors can validate waiver files. A test asserts the checked-in
files match what the models generate; regenerate with::

    python -m dsoinabox.waivers.jsonschema --write
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .models import SCHEMA_MODELS

SCHEMA_DIR = Path(__file__).with_name("schema_files")
SCHEMA_ID_BASE = "https://github.com/AppSecThings/dsoinabox/schema"


def schema_filename(version: str) -> str:
    return f"waivers-{version}.schema.json"


def generate_schema(version: str) -> dict[str, Any]:
    model = SCHEMA_MODELS[version]
    schema = model.model_json_schema(mode="validation")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = f"{SCHEMA_ID_BASE}/{schema_filename(version)}"
    schema["title"] = f"dsoinabox waiver file (schema {version})"
    return schema


def generate_all() -> dict[str, dict[str, Any]]:
    return {version: generate_schema(version) for version in SCHEMA_MODELS}


def write_all(target_dir: Path = SCHEMA_DIR) -> list[Path]:
    target_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for version, schema in generate_all().items():
        path = target_dir / schema_filename(version)
        path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(path)
    return written


def load_checked_in(version: str) -> dict[str, Any]:
    return json.loads((SCHEMA_DIR / schema_filename(version)).read_text(encoding="utf-8"))


if __name__ == "__main__":  # pragma: no cover
    if "--write" not in sys.argv:
        print(__doc__)
        sys.exit(2)
    for p in write_all():
        print(f"wrote {p}")
