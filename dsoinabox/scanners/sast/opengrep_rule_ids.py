"""Bare rule ids for findings from local OpenGrep rules.

OpenGrep prefixes the id of every rule loaded from a local file or directory
with that file's location: the rule ``agent-sdk-mcp-auto-approve`` in
``/home/me/rules/python/permissions/x.yaml`` reports as
``home.me.rules.python.permissions.agent-sdk-mcp-auto-approve``. The prefix
depends on where the rules live and on OpenGrep's working directory, so the
same finding reads differently on another machine, in Docker or under
``--git_tracked_only``.

dsoinabox reads the ``id`` of every rule in the configured local sources and
replaces a ``check_id`` that ends in ``.<id>`` with the bare id. The original
stays on the result as ``original_check_id`` (version 1 fingerprints hash it).
Ids defined in more than one rule file are left alone, since stripping would
merge different rules. Registry rules (``auto``) carry no path prefix and are
not touched.
"""

from __future__ import annotations

import json
import logging
import os
from collections import Counter
from typing import Any

import yaml

logger = logging.getLogger(__name__)

ORIGINAL_KEY = "original_check_id"
RULE_FILE_SUFFIXES = (".yaml", ".yml", ".json")
_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def _rule_ids_in_file(path: str) -> list[str]:
    """Ids of the rules in one config file; [] for anything that is not a rules file."""
    try:
        with open(path, "rb") as fd:
            if path.endswith(".json"):
                data = json.load(fd)
            else:
                data = yaml.load(fd, Loader=_LOADER)  # noqa: S506 - safe loader
    except Exception:  # test targets and fixtures live next to rules; not every file parses
        return []
    rules = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(rules, list):
        return []
    return [r["id"] for r in rules if isinstance(r, dict) and isinstance(r.get("id"), str) and r["id"]]


def _rule_files(source: str) -> list[str]:
    if os.path.isfile(source):
        return [source]
    files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(source):  # OpenGrep loads hidden folders too
        dirnames.sort()
        files.extend(os.path.join(dirpath, f) for f in sorted(filenames) if f.endswith(RULE_FILE_SUFFIXES))
    return files


def local_rule_ids(rule_sources: list[str]) -> tuple[set[str], set[str]]:
    """``(unique ids, ids defined in more than one rule file)`` across the local sources."""
    files_per_id: Counter[str] = Counter()
    for source in rule_sources:
        if source.lower() == "auto" or not os.path.exists(source):
            continue
        for path in _rule_files(source):
            for rule_id in set(_rule_ids_in_file(path)):
                files_per_id[rule_id] += 1
    duplicated = {i for i, n in files_per_id.items() if n > 1}
    return set(files_per_id) - duplicated, duplicated


def bare_rule_id(check_id: str, rule_ids: set[str]) -> str | None:
    """The longest known id that ``check_id`` ends with after a dot (or equals); None when there is none."""
    if check_id in rule_ids:
        return check_id
    start = check_id.find(".")
    while start != -1:
        candidate = check_id[start + 1:]
        if candidate in rule_ids:
            return candidate
        start = check_id.find(".", start + 1)
    return None


def strip_rule_id_prefixes(raw: Any, rule_sources: list[str]) -> Any:
    """Replace path-prefixed ``check_id`` values in an OpenGrep payload with the bare rule id (in place)."""
    results = raw.get("results") if isinstance(raw, dict) else None
    if not results or not any(s.lower() != "auto" for s in rule_sources):
        return raw
    rule_ids, duplicated = local_rule_ids(rule_sources)
    skipped: set[str] = set()
    for result in results:
        check_id = result.get("check_id") if isinstance(result, dict) else None
        if not isinstance(check_id, str):
            continue
        bare = bare_rule_id(check_id, rule_ids)
        if bare is None:
            dup = bare_rule_id(check_id, duplicated)
            if dup is not None:
                skipped.add(dup)
            continue
        if bare != check_id:
            result.setdefault(ORIGINAL_KEY, check_id)
            result["check_id"] = bare
    if skipped:
        logger.warning(
            "OpenGrep rule ids defined in more than one rule file keep their path prefix: "
            + ", ".join(sorted(skipped))
        )
    return raw
