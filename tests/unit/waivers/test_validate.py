"""Tests for waiver health checks (validate)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from dsoinabox.waivers.loader import load_waiver_data, load_waiver_file
from dsoinabox.waivers.validate import validate_waiver_set

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "waivers"
NOW = datetime(2026, 9, 5, tzinfo=timezone.utc)


def test_full_fixture_reports_expired_and_deprecated():
    ws = load_waiver_file(str(FIXTURES / "v1.0" / "full.yaml"))
    report = validate_waiver_set(ws, now=NOW)
    assert report.deprecated
    assert report.finding_waivers == 3 and report.path_exclusions == 2 and report.benchmark_entries == 1
    assert any("gy:1:PKG:CVE-2024-12345" in e for e in report.expired)
    assert not report.ok
    text = "\n".join(report.lines())
    assert "(deprecated)" in text and "expired:" in text


def test_current_minimal_is_ok():
    ws = load_waiver_file(str(FIXTURES / "v1.1" / "minimal.yaml"))
    report = validate_waiver_set(ws, now=NOW)
    assert report.ok
    assert report.lines()[-1].strip() == "ok"


def test_duplicates_across_sections():
    ws = load_waiver_data({
        "schema_version": "1.1",
        "finding_waivers": [
            {"fingerprint": "og:1:RULE:a:b", "type": "false_positive"},
            {"fingerprint": "og:1:RULE:a:b", "type": "risk_acceptance"},
        ],
        "benchmark": [{"fingerprint": "og:1:RULE:a:b"}],
    })
    report = validate_waiver_set(ws, now=NOW)
    assert len(report.duplicates) == 2


def test_expiring_soon_window():
    ws = load_waiver_data({
        "schema_version": "1.1",
        "finding_waivers": [{"fingerprint": "og:1:RULE:a:b", "type": "false_positive", "expires_at": "2026-09-20"}],
    })
    report = validate_waiver_set(ws, now=NOW, soon_days=30)
    assert report.expiring_soon and not report.expired and report.ok


def test_benchmark_expires_at_expires_every_entry():
    ws = load_waiver_data({
        "schema_version": "1.1",
        "benchmark_expires_at": "2026-01-01",
        "benchmark": [{"fingerprint": "a:1:X:y"}, {"fingerprint": "a:1:X:z"}],
    })
    report = validate_waiver_set(ws, now=NOW)
    assert len(report.expired) == 2


def test_expired_path_exclusion():
    ws = load_waiver_data({
        "schema_version": "1.1",
        "path_exclusions": [{"pattern": "x/**", "expires_at": "2020-01-01"}],
    })
    assert validate_waiver_set(ws, now=NOW).expired
