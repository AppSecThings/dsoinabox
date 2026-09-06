"""Report naming, latest pointer, SBOM export and flag aliases (W5.2, W6.5, W6.6)."""

from __future__ import annotations

import json
import os

import pytest

from dsoinabox.cli import build_parser, main, parse_cli_overrides


def _src(tmp_project):
    src = tmp_project / "source"
    src.mkdir()
    (src / "test.py").write_text("print('hello')\n")
    return src


class TestKebabAliases:
    @pytest.mark.parametrize(
        "snake, kebab",
        [
            (["--failure_threshold", "high"], ["--failure-threshold", "high"]),
            (["--report_threshold", "low"], ["--report-threshold", "low"]),
            (["--fail_on_secrets"], ["--fail-on-secrets"]),
            (["--show_findings", "full"], ["--show-findings", "full"]),
            (["--waiver_file", "w.yaml"], ["--waiver-file", "w.yaml"]),
            (["--project_id", "p"], ["--project-id", "p"]),
            (["--tool_output"], ["--tool-output"]),
            (["--scan_timeout", "5"], ["--scan-timeout", "5"]),
            (["--opengrep_args=--severity high"], ["--opengrep-args=--severity high"]),
        ],
    )
    def test_kebab_and_snake_parse_identically(self, snake, kebab):
        assert parse_cli_overrides(snake) == parse_cli_overrides(kebab)

    def test_aliases_are_hidden_from_help(self):
        text = build_parser().format_help()
        assert "--failure_threshold" in text and "--failure-threshold" not in text

    def test_defaults_survive_when_alias_unused(self):
        args = build_parser().parse_args([])
        assert args.failure_threshold == "none" and args.show_findings == "false"


@pytest.mark.integration
def test_report_name_and_latest_pointer(tmp_project, fake_runner):
    src = _src(tmp_project)
    reports = tmp_project / "reports"
    code = main(["--source", str(src), "-t", "opengrep", "-o", "json,sarif,html", "--report_name", "dsoinabox",
                 "--report_directory", str(reports), "--project_id", "p", "--show_findings", "False"])
    assert code == 0
    run_dirs = [d for d in reports.iterdir() if d.name.startswith("dsoinabox_20")]
    assert len(run_dirs) == 1
    assert {p.name for p in run_dirs[0].iterdir()} >= {"dsoinabox.json", "dsoinabox.sarif", "dsoinabox.html"}
    latest = reports / "latest"
    assert latest.exists() and (latest / "dsoinabox.sarif").exists()
    assert os.path.realpath(latest) == os.path.realpath(run_dirs[0])

    # a second run moves the pointer
    code = main(["--source", str(src), "-t", "opengrep", "-o", "json", "--report_name", "dsoinabox",
                 "--report_directory", str(reports), "--project_id", "p", "--show_findings", "False", "--report_threshold", "critical"])
    assert code == 0
    newest = sorted(d for d in reports.iterdir() if d.name.startswith("dsoinabox_20"))[-1]
    assert os.path.realpath(reports / "latest") == os.path.realpath(newest)


@pytest.mark.integration
def test_default_report_names_unchanged(tmp_project, fake_runner):
    src = _src(tmp_project)
    reports = tmp_project / "reports"
    assert main(["--source", str(src), "-t", "opengrep", "-o", "json", "--report_directory", str(reports),
                 "--project_id", "p", "--show_findings", "False"]) == 0
    assert list(reports.rglob("dsoinabox_unified_report_*.json"))


@pytest.mark.integration
def test_sbom_outputs_are_written_via_syft_convert(tmp_project, fake_runner, monkeypatch):
    src = _src(tmp_project)
    reports = tmp_project / "reports"
    seen: list[list[str]] = []
    real = fake_runner

    def tracking(cmd, **kw):
        seen.append(list(cmd))
        if cmd[:2] == ["syft", "convert"]:
            out_spec = cmd[cmd.index("-o") + 1]
            _fmt, path = out_spec.split("=", 1)
            with open(path, "w") as fh:
                json.dump({"bomFormat": "CycloneDX" if "cyclonedx" in _fmt else "SPDX", "from": cmd[2]}, fh)
            return (0, "", "") if kw.get("text", True) else (0, b"", b"")
        return real(cmd, **kw)

    import dsoinabox.scanners.base
    monkeypatch.setattr(dsoinabox.scanners.base, "run_cmd", tracking)

    code = main(["--source", str(src), "-t", "syft", "-o", "json,cyclonedx,spdx", "--report_directory", str(reports),
                 "--project_id", "p", "--show_findings", "False"])
    assert code == 0
    run_dir = next(d for d in reports.iterdir() if d.name.startswith("dsoinabox_20"))
    cdx = json.loads((run_dir / "sbom.cdx.json").read_text())
    spdx = json.loads((run_dir / "sbom.spdx.json").read_text())
    assert cdx["bomFormat"] == "CycloneDX" and spdx["bomFormat"] == "SPDX"
    assert cdx["from"].endswith("tools_output/syft.json")
    converts = [c for c in seen if c[:2] == ["syft", "convert"]]
    assert {c[c.index("-o") + 1].split("=")[0] for c in converts} == {"cyclonedx-json", "spdx-json"}
    # tools_output is cleaned up afterwards by default
    assert not (run_dir / "tools_output").exists()
    meta = json.loads((run_dir / next(p.name for p in run_dir.iterdir() if p.suffix == ".json" and p.name.startswith("dsoinabox_unified"))).read_text())
    assert meta["metadata"]["scanners"][0]["status"] == "ok"


@pytest.mark.integration
def test_sbom_output_without_syft_is_skipped_with_warning(tmp_project, fake_runner, caplog):
    src = _src(tmp_project)
    reports = tmp_project / "reports"
    code = main(["--source", str(src), "-t", "opengrep", "-o", "json,cyclonedx", "--report_directory", str(reports),
                 "--project_id", "p", "--show_findings", "False"])
    assert code == 0
    assert any("syft did not run" in m for m in caplog.messages)
    assert not list(reports.rglob("sbom.cdx.json"))


def test_invalid_output_format_is_usage_error(tmp_project, fake_runner):
    src = _src(tmp_project)
    assert main(["--source", str(src), "-o", "pdf", "--report_directory", str(tmp_project / "r"), "--project_id", "p"]) == 3


def test_docker_mount_copy_keeps_latest_pointer(tmp_project):
    from datetime import datetime, timezone

    from dsoinabox.cli import copy_reports_to_mount
    from dsoinabox.model import ScanRun

    run_dir = tmp_project / "app_reports" / "dsoinabox_2026_09_06T00_00_00"
    run_dir.mkdir(parents=True)
    (run_dir / "dsoinabox.sarif").write_text("{}")
    mount = tmp_project / "mount"
    mount.mkdir()
    run = ScanRun(started_at=datetime(2026, 9, 6, tzinfo=timezone.utc), dsoinabox_version="t", timestamp="2026_09_06T00_00_00",
                  project_id="p", source="/s", report_directory=str(run_dir), report_paths=[str(run_dir / "dsoinabox.sarif")])
    copied = copy_reports_to_mount(run, str(mount))
    assert (mount / "dsoinabox_2026_09_06T00_00_00" / "dsoinabox.sarif").exists()
    assert (mount / "latest" / "dsoinabox.sarif").exists()
    assert os.path.realpath(mount / "latest") == os.path.realpath(copied)
    assert run.report_paths == [str(mount / "dsoinabox_2026_09_06T00_00_00" / "dsoinabox.sarif")]
    assert run.latest_directory == str(mount / "latest")
