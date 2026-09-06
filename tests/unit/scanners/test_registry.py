"""Scanner registry (W3.3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from dsoinabox.normalize import NORMALIZERS
from dsoinabox.scanners.registry import REGISTRY, TOOL_ORDER, all_selectors, select_tools

TEMPLATES = Path(__file__).resolve().parents[3] / "dsoinabox" / "reporting" / "templates"
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "scanner_outputs"


def test_every_spec_is_complete():
    for spec in REGISTRY.values():
        assert spec.name and spec.category and spec.executable and spec.module
        assert (TEMPLATES / "html" / f"default_{spec.name}.html").exists(), spec.name
        assert (TEMPLATES / "jenkins_html" / f"default_{spec.name}.html").exists(), spec.name
        assert (FIXTURES / f"{spec.name}.json").exists(), spec.name
        if spec.category != "sbom":
            assert spec.fingerprint is not None and spec.normalize is not None
            assert spec.name in NORMALIZERS
        for dep in spec.depends_on:
            assert dep in REGISTRY


def test_order_is_stable():
    assert TOOL_ORDER == ("trufflehog", "opengrep", "syft", "grype", "checkov")


@pytest.mark.parametrize(
    "selection, expected",
    [
        ("all", list(TOOL_ORDER)),
        ("sast", ["opengrep"]),
        ("SAST,SECRET", ["trufflehog", "opengrep"]),
        ("secrets", ["trufflehog"]),
        (["grype", "syft"], ["syft", "grype"]),
        ("iac,sca,sbom", ["syft", "grype", "checkov"]),
        ("trufflehog, all", list(TOOL_ORDER)),
    ],
)
def test_select_tools(selection, expected):
    assert [s.name for s in select_tools(selection)] == expected


def test_unknown_selector_is_an_error():
    with pytest.raises(ValueError, match="Unknown tool selector"):
        select_tools("bandit")


def test_all_selectors_contains_names_categories_and_aliases():
    sel = all_selectors()
    assert {"all", "trufflehog", "secret", "secrets", "sast", "sbom", "sca", "iac"} <= sel
