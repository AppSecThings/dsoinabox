"""Reports must show repo-relative paths, never the <ROOT> placeholder (W6.4)."""

from __future__ import annotations

import json

import pytest

from dsoinabox.cli import main


@pytest.mark.integration
def test_absolute_scanner_paths_become_repo_relative(tmp_project, fake_runner, monkeypatch):
    source_dir = tmp_project / "scan_target"
    source_dir.mkdir()
    (source_dir / "src").mkdir()
    (source_dir / "src" / "app.py").write_text("import os\nos.system('x')\n")

    import dsoinabox.scanners.iac.checkov
    import dsoinabox.scanners.sast.opengrep
    import dsoinabox.scanners.sca.grype

    abs_app = str(source_dir / "src" / "app.py")
    monkeypatch.setattr(dsoinabox.scanners.sast.opengrep, "run_scan", lambda *a, **k: {"results": [
        {"check_id": "r.sys", "path": abs_app, "start": {"line": 2, "col": 1}, "end": {"line": 2, "col": 13},
         "extra": {"severity": "HIGH", "message": "m", "lines": "os.system('x')"}},
    ]})
    monkeypatch.setattr(dsoinabox.scanners.sca.grype, "run_scan", lambda *a, **k: {"matches": [
        {"vulnerability": {"id": "CVE-1", "severity": "High"}, "artifact": {"name": "p", "version": "1", "type": "python",
         "locations": [{"path": str(source_dir / "requirements.txt")}]}}]})
    monkeypatch.setattr(dsoinabox.scanners.iac.checkov, "run_scan", lambda *a, **k: {"runs": [{"tool": {"driver": {"rules": []}}, "results": [
        {"ruleId": "CKV_1", "level": "error", "message": {"text": "t"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"file://{source_dir}/infra/s3.tf"}, "region": {"startLine": 1}}}]}]}]})

    reports = tmp_project / "reports"
    code = main(["--source", str(source_dir), "-t", "opengrep,grype,checkov", "-o", "html,sarif,json",
                 "--report_directory", str(reports), "--project_id", "p", "--show_findings", "False"])
    assert code == 0

    html = next(reports.rglob("*.html")).read_text()
    sarif = next(reports.rglob("*.sarif")).read_text()
    data = json.loads(next(reports.rglob("*.json")).read_text())

    findings_only = {k: v for k, v in data.items() if k != "metadata"}
    for text in (html, sarif, json.dumps(findings_only)):
        assert "<ROOT>" not in text
        assert str(source_dir) not in text, "absolute source directory must not leak into finding paths"
    assert data["metadata"]["source"] == str(source_dir)

    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for run in json.loads(sarif)["runs"] for r in run["results"] if r.get("locations")}
    assert uris == {"src/app.py", "requirements.txt", "infra/s3.tf"}
    assert {f["path"] for f in data["findings"]} == {"src/app.py", "requirements.txt", "infra/s3.tf"}
    assert data["opengrep_data"]["results"][0]["path"] == "src/app.py"
