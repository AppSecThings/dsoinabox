"""Baseline classification and `baseline update` (W7)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
import yaml

from dsoinabox.cli import main
from dsoinabox.model import Finding, ScanOptions, ScanResult, ScanRun, Severity
from dsoinabox.policy import EXIT_OK, EXIT_POLICY, evaluate
from dsoinabox.utils.deterministic import set_utcnow_override
from dsoinabox.waivers.baseline import apply_baseline, classify

NOW = datetime(2026, 9, 5, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _frozen():
    set_utcnow_override(lambda: NOW)
    yield
    set_utcnow_override(None)


def _f(fp, legacy=None, waived=False):
    return Finding(tool="opengrep", category="sast", rule_id="r", severity=Severity.high, fingerprints={"rule": fp},
                   legacy_fingerprints=legacy or [], waived=waived, raw={})


def test_classify_matches_any_tier_including_legacy():
    a, b, c = _f("og:1:RULE:a"), _f("og:2:RULE:b", legacy=["og:1:RULE:b-old"]), _f("og:1:RULE:c")
    counts = classify([a, b, c], {"og:1:RULE:a", "og:1:RULE:b-old"})
    assert counts == {"new": 1, "known": 2}
    assert (a.baseline_status, b.baseline_status, c.baseline_status) == ("known", "known", "new")
    assert a.raw["baseline_status"] == "known"


def test_apply_baseline_reads_benchmark_file(tmp_path):
    p = tmp_path / "benchmark.yaml"
    p.write_text('schema_version: "1.1"\nbenchmark:\n  - fingerprint: "og:1:RULE:a"\n')
    findings = [_f("og:1:RULE:a"), _f("og:1:RULE:z")]
    summary = apply_baseline(findings, str(p))
    assert summary["new"] == 1 and summary["known"] == 1 and summary["entries"] == 1 and summary["schema_version"] == "1.1"


def test_policy_fail_on_new_ignores_known():
    known, new = _f("og:1:RULE:a"), _f("og:1:RULE:z")
    known.baseline_status, new.baseline_status = "known", "new"
    run = ScanRun(started_at=NOW, dsoinabox_version="t", timestamp="t", project_id="p", source="/s", report_directory="/r",
                  results=[ScanResult(tool="opengrep", category="sast", findings=[known])])
    opts = ScanOptions(source="/s", report_directory="/r", timestamp="t", failure_threshold=Severity.high, baseline="b.yaml", fail_on="new")
    assert evaluate(run, opts).exit_code == EXIT_OK
    run.results[0].findings.append(new)
    p = evaluate(run, opts)
    assert p.exit_code == EXIT_POLICY and p.fail_on == "new" and p.failing_by_tool == {"opengrep": 1}
    # without a baseline, fail_on=new is ignored and everything counts
    opts2 = opts.model_copy(update={"baseline": None})
    assert evaluate(run, opts2).failing_by_tool == {"opengrep": 2}


class TestBaselineUpdate:
    def _report(self, tmp_path, findings):
        p = tmp_path / "report.json"
        p.write_text(json.dumps({"metadata": {}, "findings": findings}))
        return p

    def test_creates_baseline_from_report(self, tmp_path, capsys):
        report = self._report(tmp_path, [
            {"fingerprints": {"rule": "og:1:RULE:a", "exact": "og:1:EXACT:a"}, "waived": False},
            {"fingerprints": {"pkg": "gy:1:PKG:b"}, "waived": False},
            {"fingerprints": {"rule": "og:1:RULE:waived"}, "waived": True},
        ])
        out = tmp_path / "benchmark.yaml"
        assert main(["baseline", "update", "--from", str(report), "--file", str(out), "--expires", "2027-01-01"]) == 0
        data = yaml.safe_load(out.read_text())
        assert data["schema_version"] == "1.1" and data["benchmark_expires_at"] == "2027-01-01"
        assert [b["fingerprint"] for b in data["benchmark"]] == ["og:1:RULE:a", "gy:1:PKG:b"]
        assert all(b["type"] == "benchmark" and b["created_at"] == "2026-09-05" for b in data["benchmark"])
        assert "added 2 benchmark entries" in capsys.readouterr().out

    def test_update_keeps_existing_unless_prune(self, tmp_path):
        out = tmp_path / "benchmark.yaml"
        out.write_text('schema_version: "1.1"\nbenchmark:\n  - fingerprint: "og:1:RULE:old"  # keep\n    type: benchmark\n')
        report = self._report(tmp_path, [{"fingerprints": {"rule": "og:1:RULE:new"}, "waived": False}])
        assert main(["baseline", "update", "--from", str(report), "--file", str(out)]) == 0
        text = out.read_text()
        assert "og:1:RULE:old" in text and "og:1:RULE:new" in text and "# keep" in text
        assert main(["baseline", "update", "--from", str(report), "--file", str(out), "--prune"]) == 0
        data = yaml.safe_load(out.read_text())
        assert [b["fingerprint"] for b in data["benchmark"]] == ["og:1:RULE:new"]

    def test_include_waived(self, tmp_path):
        report = self._report(tmp_path, [{"fingerprints": {"rule": "og:1:RULE:w"}, "waived": True}])
        out = tmp_path / "b.yaml"
        assert main(["baseline", "update", "--from", str(report), "--file", str(out), "--include-waived"]) == 0
        assert yaml.safe_load(out.read_text())["benchmark"][0]["fingerprint"] == "og:1:RULE:w"

    def test_report_without_findings_list_is_usage_error(self, tmp_path):
        p = tmp_path / "old.json"
        p.write_text(json.dumps({"opengrep_data": {"results": []}}))
        assert main(["baseline", "update", "--from", str(p), "--file", str(tmp_path / "b.yaml")]) == 3

    def test_dry_run(self, tmp_path, capsys):
        report = self._report(tmp_path, [{"fingerprints": {"rule": "og:1:RULE:a"}, "waived": False}])
        out = tmp_path / "b.yaml"
        assert main(["baseline", "update", "--from", str(report), "--file", str(out), "--dry-run"]) == 0
        assert not out.exists() and "og:1:RULE:a" in capsys.readouterr().out
