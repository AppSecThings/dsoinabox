"""--baseline / --fail_on new end to end (W7.1, W7.2)."""

from __future__ import annotations

import json

import pytest
import yaml

from dsoinabox.cli import main


def _run(tmp_project, src, *extra):
    reports = tmp_project / "reports"
    code = main(["--source", str(src), "-t", "opengrep", "-o", "json,sarif,html", "--report_directory", str(reports),
                 "--project_id", "p", "--show_findings", "False", *extra])
    latest = reports / "latest"
    data = json.loads(next(latest.glob("*.json")).read_text())
    return code, data, latest


@pytest.fixture
def src(tmp_project):
    s = tmp_project / "source"
    s.mkdir()
    (s / "src").mkdir()
    for name in ("file.py", "file2.py", "file3.py"):
        (s / "src" / name).write_text("x = 1\n" * 20)
    return s


@pytest.mark.integration
def test_baseline_classifies_and_fail_on_new_gates_regressions_only(tmp_project, src, fake_runner):
    code, first, _ = _run(tmp_project, src, "--failure_threshold", "low")
    assert code == 1
    fps = [f["fingerprints"]["rule"] for f in first["findings"]]
    assert len(fps) >= 2

    # baseline everything but the first finding
    (src / "benchmark.yaml").write_text(yaml.safe_dump({"schema_version": "1.1", "benchmark": [{"fingerprint": fp} for fp in fps[1:]]}))

    code, data, latest = _run(tmp_project, src, "--failure_threshold", "low", "--baseline", "benchmark.yaml")
    assert code == 1, "fail_on=all still fails on known findings"
    statuses = [f["baseline_status"] for f in data["findings"]]
    assert statuses.count("new") == 1 and statuses.count("known") == len(fps) - 1
    assert data["metadata"]["baseline"]["new"] == 1 and data["metadata"]["baseline"]["known"] == len(fps) - 1
    sarif = json.loads(next(latest.glob("*.sarif")).read_text())
    assert {r["properties"]["baseline_status"] for run in sarif["runs"] for r in run["results"]} == {"new", "known"}

    code, data, _ = _run(tmp_project, src, "--failure_threshold", "low", "--baseline", "benchmark.yaml", "--fail_on", "new")
    assert code == 1, "one new finding remains"
    assert data["metadata"]["policy"]["failing_by_tool"] == {"opengrep": 1}

    (src / "benchmark.yaml").write_text(yaml.safe_dump({"schema_version": "1.1", "benchmark": [{"fingerprint": fp} for fp in fps]}))
    code, data, _ = _run(tmp_project, src, "--failure_threshold", "low", "--baseline", "benchmark.yaml", "--fail_on", "new")
    assert code == 0 and data["metadata"]["baseline"]["new"] == 0


@pytest.mark.integration
def test_missing_baseline_is_usage_error(tmp_project, src, fake_runner):
    code = main(["--source", str(src), "-t", "opengrep", "-o", "json", "--report_directory", str(tmp_project / "r"),
                 "--project_id", "p", "--baseline", "nope.yaml"])
    assert code == 3


@pytest.mark.integration
def test_baseline_update_roundtrip_through_cli(tmp_project, src, fake_runner):
    code, data, latest = _run(tmp_project, src)
    report = next(latest.glob("*.json"))
    out = src / "benchmark.yaml"
    assert main(["baseline", "update", "--from", str(report), "--file", str(out)]) == 0
    code, data, _ = _run(tmp_project, src, "--failure_threshold", "low", "--baseline", "benchmark.yaml", "--fail_on", "new")
    assert code == 0 and data["metadata"]["baseline"]["new"] == 0
