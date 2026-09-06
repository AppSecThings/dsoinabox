"""`dsoinabox waivers prune` and `waivers add` (W2.6, W2.7)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
import yaml

from dsoinabox.cli import main
from dsoinabox.utils.deterministic import set_utcnow_override
from dsoinabox.waivers.loader import load_waiver_file

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _frozen_now():
    set_utcnow_override(lambda: NOW)
    yield
    set_utcnow_override(None)


@pytest.fixture
def waiver_file(tmp_path):
    p = tmp_path / ".dsoinabox_waivers.yaml"
    p.write_text(
        'schema_version: "1.1"\n'
        'meta:\n  owner: "sec"  # owner comment\n'
        'finding_waivers:\n'
        '  - fingerprint: "og:1:RULE:live:a"\n    type: false_positive\n    expires_at: "2099-01-01"\n'
        '  - fingerprint: "og:1:RULE:dead:b"\n    type: risk_acceptance\n    expires_at: "2020-01-01"  # long gone\n'
        '  - fingerprint: "og:1:RULE:forever:c"\n    type: policy_waiver\n'
        'path_exclusions:\n'
        '  - pattern: "old/**"\n    expires_at: "2021-06-01"\n'
        '  - pattern: "vendor/**"\n'
        'benchmark_expires_at: "2022-01-01"\n'
        'benchmark:\n'
        '  - fingerprint: "gy:1:PKG:x:y"\n'
    )
    return p


class TestPrune:
    def test_removes_expired_entries_everywhere(self, waiver_file, capsys):
        assert main(["waivers", "prune", "--in-place", str(waiver_file)]) == 0
        out = capsys.readouterr().out
        assert "removed expired entry og:1:RULE:dead:b" in out
        assert "removed expired entry old/**" in out
        assert "removed expired entry gy:1:PKG:x:y" in out  # via benchmark_expires_at
        data = yaml.safe_load(waiver_file.read_text())
        assert [w["fingerprint"] for w in data["finding_waivers"]] == ["og:1:RULE:live:a", "og:1:RULE:forever:c"]
        assert [p["pattern"] for p in data["path_exclusions"]] == ["vendor/**"]
        assert data["benchmark"] == []
        assert "# owner comment" in waiver_file.read_text()
        assert waiver_file.with_name(waiver_file.name + ".bak").exists()

    def test_dry_run_prints_diff_only(self, waiver_file, capsys):
        before = waiver_file.read_text()
        assert main(["waivers", "prune", "--dry-run", str(waiver_file)]) == 0
        assert '-  - fingerprint: "og:1:RULE:dead:b"' in capsys.readouterr().out
        assert waiver_file.read_text() == before

    def test_prune_with_report_removes_unused(self, waiver_file, tmp_path, capsys):
        report = tmp_path / "report.json"
        report.write_text(json.dumps({"metadata": {"waivers": {"unused": ["finding_waivers[2]", "path_exclusions[1]"]}}}))
        assert main(["waivers", "prune", "--in-place", "--report", str(report), str(waiver_file)]) == 0
        out = capsys.readouterr().out
        assert "removed unused entry og:1:RULE:forever:c" in out and "removed unused entry vendor/**" in out
        data = yaml.safe_load(waiver_file.read_text())
        assert [w["fingerprint"] for w in data["finding_waivers"]] == ["og:1:RULE:live:a"]
        assert data["path_exclusions"] == []

    def test_nothing_to_prune(self, tmp_path, capsys):
        p = tmp_path / "w.yaml"
        p.write_text('schema_version: "1.1"\nfinding_waivers:\n  - fingerprint: "a:1:X:y"\n    type: false_positive\n')
        assert main(["waivers", "prune", "--in-place", str(p)]) == 0
        assert "nothing to prune" in capsys.readouterr().out

    def test_missing_file(self):
        assert main(["waivers", "prune", "/nope.yaml"]) == 3


class TestAdd:
    def test_add_creates_file_and_entry(self, tmp_path, capsys, monkeypatch):
        import dsoinabox.commands.waivers as cmd

        monkeypatch.setattr(cmd, "_git_user_email", lambda: "alice@example.com")
        target = tmp_path / "new.yaml"
        code = main(["waivers", "add", "--file", str(target), "--fingerprint", "og:1:RULE:r:abc",
                     "--type", "false_positive", "--reason", "test data", "--expires", "90d", "--ticket", "SEC-1",
                     "--tools", "sast"])
        assert code == 0
        ws = load_waiver_file(str(target))
        assert ws.schema_version == "1.1" and ws.warnings == []
        fw = ws.finding_waivers[0]
        assert fw.fingerprint == "og:1:RULE:r:abc" and fw.type == "false_positive" and fw.reason == "test data"
        assert fw.expires_at.date().isoformat() == "2026-12-04" and fw.ticket == "SEC-1" and fw.tools == ["sast"]
        assert fw.created_by == "alice@example.com" and fw.created_at.date().isoformat() == "2026-09-05"
        assert "added og:1:RULE:r:abc" in capsys.readouterr().out

    def test_add_appends_and_skips_duplicates(self, waiver_file, capsys):
        code = main(["waivers", "add", "--file", str(waiver_file), "-p", "og:1:RULE:live:a", "-p", "og:1:RULE:new:z",
                     "-t", "risk_acceptance", "--expires", "2027-01-31"])
        assert code == 0
        out = capsys.readouterr().out
        assert "already present, skipped" in out and "added og:1:RULE:new:z" in out
        data = yaml.safe_load(waiver_file.read_text())
        assert data["finding_waivers"][-1]["fingerprint"] == "og:1:RULE:new:z"
        assert data["finding_waivers"][-1]["expires_at"] == "2027-01-31"
        assert "# owner comment" in waiver_file.read_text()

    def test_add_benchmark_entry(self, waiver_file):
        assert main(["waivers", "add", "--file", str(waiver_file), "-p", "gy:1:PKG:new:1", "-t", "benchmark"]) == 0
        data = yaml.safe_load(waiver_file.read_text())
        assert [b["fingerprint"] for b in data["benchmark"]] == ["gy:1:PKG:x:y", "gy:1:PKG:new:1"]

    def test_add_dry_run(self, waiver_file, capsys):
        before = waiver_file.read_text()
        assert main(["waivers", "add", "--file", str(waiver_file), "-p", "og:1:RULE:q:1", "-t", "policy_waiver", "--dry-run"]) == 0
        assert 'og:1:RULE:q:1' in capsys.readouterr().out and waiver_file.read_text() == before

    def test_add_rejects_bad_date(self, waiver_file):
        assert main(["waivers", "add", "--file", str(waiver_file), "-p", "x:1:Y:z", "-t", "false_positive", "--expires", "soon"]) == 1
