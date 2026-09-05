"""End-to-end waiver behaviour through the CLI (W2.1, W2.2, W2.4, W2.5)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from dsoinabox.cli import main


def _run(tmp_project: Path, source_dir: Path, *extra: str) -> tuple[int, dict]:
    reports = tmp_project / "reports"
    code = main([
        "--source", str(source_dir),
        "--output", "json,html,sarif",
        "--report_directory", str(reports),
        "--show_findings", "False",
        "--project_id", "test-project",
        "-t", "opengrep,grype",
        *extra,
    ])
    json_files = list(reports.glob("*/dsoinabox_unified_report_*.json"))
    data = json.loads(json_files[-1].read_text()) if json_files else {}
    return code, data


def _high_opengrep_fp(data: dict) -> str:
    for r in data["opengrep_data"]["results"]:
        if r["extra"]["severity"].upper() == "HIGH":
            return r["fingerprints"]["rule"]
    raise AssertionError("fixture has no HIGH opengrep finding")


@pytest.fixture
def source_dir(tmp_project):
    src = tmp_project / "source"
    src.mkdir()
    (src / "src").mkdir()
    for name in ("file.py", "file2.py", "file3.py"):
        (src / "src" / name).write_text("x = 1\n" * 20)
    return src


@pytest.mark.integration
def test_waived_findings_are_kept_flagged_and_do_not_gate(tmp_project, source_dir, fake_runner):
    code, first = _run(tmp_project, source_dir, "--failure_threshold", "high", "-t", "opengrep")
    assert code == 1
    fp = _high_opengrep_fp(first)
    total_before = len(first["opengrep_data"]["results"])

    (source_dir / ".dsoinabox_waivers.yaml").write_text(yaml.safe_dump({
        "schema_version": "1.1",
        "finding_waivers": [{"fingerprint": fp, "type": "risk_acceptance", "reason": "accepted", "ticket": "SEC-9"}],
    }))
    code, second = _run(tmp_project, source_dir, "--failure_threshold", "high", "-t", "opengrep")
    assert code == 0, "waived high finding must not fail the gate"

    results = second["opengrep_data"]["results"]
    assert len(results) == total_before, "waived findings stay in the report data"
    waived = [r for r in results if r.get("waived")]
    assert len(waived) == 1
    assert waived[0]["waived_by"]["type"] == "risk_acceptance" and waived[0]["waived_by"]["ticket"] == "SEC-9"

    meta = second["metadata"]["waivers"]
    assert meta["waived"] == 1 and meta["waived_by_type"] == {"risk_acceptance": 1}
    assert meta["unused_count"] == 0 and meta["schema_version"] == "1.1"
    assert second["metadata"]["dsoinabox_version"]

    reports = tmp_project / "reports"
    html = sorted(reports.glob("*/dsoinabox_unified_report_*.html"))[-1].read_text()
    assert "Waived findings (1)" in html and "risk acceptance" in html
    sarif = json.loads(sorted(reports.glob("*/dsoinabox_unified_report_*.sarif"))[-1].read_text())
    suppressed = [r for run in sarif["runs"] for r in run["results"] if r.get("suppressions")]
    assert len(suppressed) == 1


@pytest.mark.integration
def test_expired_waiver_no_longer_suppresses(tmp_project, source_dir, fake_runner):
    code, first = _run(tmp_project, source_dir, "-t", "opengrep")
    fp = _high_opengrep_fp(first)
    (source_dir / ".dsoinabox_waivers.yaml").write_text(yaml.safe_dump({
        "schema_version": "1.1",
        "finding_waivers": [{"fingerprint": fp, "type": "false_positive", "expires_at": "2020-01-01"}],
    }))
    code, data = _run(tmp_project, source_dir, "--failure_threshold", "high", "-t", "opengrep")
    assert code == 1
    hit = [r for r in data["opengrep_data"]["results"] if r.get("expired_waivers")]
    assert len(hit) == 1 and hit[0]["waived"] is False
    assert data["metadata"]["waivers"]["expired_matches"] == 1
    html = sorted((tmp_project / "reports").glob("*/dsoinabox_unified_report_*.html"))[-1].read_text()
    assert "Expired waivers (1)" in html

    # grace period keeps it active
    code, data = _run(tmp_project, source_dir, "--failure_threshold", "high", "-t", "opengrep",
                      "--waiver_grace_days", "100000")
    assert code == 0
    assert data["metadata"]["waivers"]["expiring_matches"] == 1


@pytest.mark.integration
def test_path_exclusion_waives_everything_under_pattern(tmp_project, source_dir, fake_runner):
    (source_dir / ".dsoinabox_waivers.yaml").write_text(yaml.safe_dump({
        "schema_version": "1.1",
        "path_exclusions": [{"pattern": "src/**", "reason": "fixture paths", "tools": ["sast"]}],
    }))
    code, data = _run(tmp_project, source_dir, "--failure_threshold", "low", "-t", "opengrep")
    assert code == 0
    results = data["opengrep_data"]["results"]
    assert results and all(r["waived"] for r in results)
    assert all(r["waived_by"]["kind"] == "path_exclusion" for r in results)
    assert data["metadata"]["waivers"]["waived_by_kind"] == {"path_exclusion": len(results)}


@pytest.mark.integration
def test_unused_waivers_are_counted(tmp_project, source_dir, fake_runner, caplog):
    (source_dir / ".dsoinabox_waivers.yaml").write_text(yaml.safe_dump({
        "schema_version": "1.1",
        "finding_waivers": [{"fingerprint": "og:1:RULE:does.not.exist:0000", "type": "false_positive"}],
    }))
    code, data = _run(tmp_project, source_dir, "-t", "opengrep")
    assert code == 0
    assert data["metadata"]["waivers"]["unused"] == ["finding_waivers[0]"]
    assert any("1 unused entry" in m for m in caplog.messages)


@pytest.mark.integration
def test_deprecated_schema_warns_but_applies(tmp_project, source_dir, fake_runner, caplog):
    code, first = _run(tmp_project, source_dir, "-t", "opengrep")
    fp = _high_opengrep_fp(first)
    (source_dir / ".dsoinabox_waivers.yaml").write_text(yaml.safe_dump({
        "schema_version": "1.0",
        "finding_waivers": [{"fingerprint": fp, "type": "false_positive", "meta_ticket": "SEC-1"}],
    }))
    code, data = _run(tmp_project, source_dir, "--failure_threshold", "high", "-t", "opengrep")
    assert code == 0
    assert any("deprecated" in m and "waivers migrate" in m for m in caplog.messages)
    assert data["metadata"]["waivers"]["deprecated_schema"] is True
    waived = [r for r in data["opengrep_data"]["results"] if r.get("waived")]
    assert waived[0]["waived_by"]["ticket"] == "SEC-1"
