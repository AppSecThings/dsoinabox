"""Keep report snapshots independent of the package version."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _pin_report_version(monkeypatch):
    import dsoinabox.reporting.report_builder as rb

    monkeypatch.setattr(rb, "__version__", "0.0.0-test")
