"""Secret verification, Grype DB mode, fail_on_secrets modes and per-tool timeouts (W8.6, W8.7, W5.3)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

import dsoinabox.scanners.base as base
from dsoinabox.model import Finding, ScanOptions, ScanResult, ScanRun, Severity
from dsoinabox.policy import EXIT_OK, EXIT_POLICY, evaluate
from dsoinabox.scanners.sca import grype
from dsoinabox.scanners.secrets import trufflehog
from dsoinabox.utils.config import _normalize_value, parse_fail_on_secrets, read_env_overrides


@pytest.fixture
def capture(monkeypatch):
    calls: list[dict] = []

    def fake(cmd, *, cwd=None, env=None, timeout=None, text=True, check=False):
        calls.append({"cmd": list(cmd), "env": env, "timeout": timeout})
        if cmd[0] == "trufflehog":
            return (0, "", "")
        if cmd[:2] == ["grype", "db"]:
            return (0, '{"built": "2026-09-01T00:00:00Z", "schemaVersion": "6"}', "")
        return (0, '{"matches": []}', "")

    monkeypatch.setattr(base, "run_cmd", fake)
    return calls


class TestTruffleHogVerify:
    def test_default_disables_verification(self, capture, tmp_path):
        trufflehog.run_scan(str(tmp_path), None, str(tmp_path), git_repo=False)
        cmd = capture[0]["cmd"]
        assert cmd[:3] == ["trufflehog", "filesystem", str(tmp_path)] and "--no-verification" in cmd

    def test_verify_removes_flag(self, capture, tmp_path):
        trufflehog.run_scan(str(tmp_path), None, str(tmp_path), git_repo=True, verify=True, timeout=42)
        cmd = capture[0]["cmd"]
        assert cmd[:2] == ["trufflehog", "git"] and "--no-verification" not in cmd and "--no-update" in cmd
        assert capture[0]["timeout"] == 42


class TestGrypeDb:
    def test_auto_mode_has_no_env(self, capture, tmp_path):
        grype.run_scan(str(tmp_path), None, str(tmp_path))
        assert capture[0]["env"] is None

    def test_offline_mode_sets_env(self, capture, tmp_path):
        grype.run_scan(str(tmp_path), None, str(tmp_path), db_mode="offline")
        assert capture[0]["env"] == {"GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_DB_VALIDATE_AGE": "false"}

    def test_offline_missing_db_has_clear_message(self, monkeypatch, tmp_path):
        monkeypatch.setattr(base, "run_cmd", lambda cmd, **kw: (1, "", "1 error occurred: vulnerability database not found"))
        with pytest.raises(base.ScannerError, match="no vulnerability database is cached"):
            grype.run_scan(str(tmp_path), None, str(tmp_path), db_mode="offline")

    def test_db_status(self, capture):
        assert grype.db_status() == "built 2026-09-01T00:00:00Z (schema 6)"


class TestFailOnSecretsModes:
    @pytest.mark.parametrize("raw, expected", [(None, (False, "any")), (False, (False, "any")), (True, (True, "any")), ("true", (True, "any")),
                                               ("false", (False, "any")), ("any", (True, "any")), ("verified", (True, "verified")), ("VERIFIED", (True, "verified"))])
    def test_parse(self, raw, expected):
        assert parse_fail_on_secrets(raw) == expected

    def test_config_value_normalization(self):
        assert _normalize_value("fail_on_secrets", "verified") == "verified"
        assert _normalize_value("fail_on_secrets", True) == "any"
        assert _normalize_value("fail_on_secrets", "no") is False

    def _run(self, *verified_flags):
        findings = [Finding(tool="trufflehog", category="secret", rule_id="AWS", severity=Severity.high, verified=v) for v in verified_flags]
        return ScanRun(started_at=datetime(2026, 1, 1, tzinfo=timezone.utc), dsoinabox_version="t", timestamp="t", project_id="p",
                       source="/s", report_directory="/r", results=[ScanResult(tool="trufflehog", category="secret", findings=findings)])

    def test_verified_mode_ignores_unverified(self):
        opts = ScanOptions(source="/s", report_directory="/r", timestamp="t", fail_on_secrets=True, fail_on_secrets_mode="verified")
        assert evaluate(self._run(False, None), opts).exit_code == EXIT_OK
        p = evaluate(self._run(False, True), opts)
        assert p.exit_code == EXIT_POLICY and p.secrets_found == 2 and p.secrets_verified == 1

    def test_any_mode_fails_on_unverified(self):
        opts = ScanOptions(source="/s", report_directory="/r", timestamp="t", fail_on_secrets=True)
        assert evaluate(self._run(False), opts).exit_code == EXIT_POLICY


class TestConfigKeys:
    def test_tool_timeouts_mapping(self):
        assert _normalize_value("tool_timeouts", {"TruffleHog": "600", "grype": 900}) == {"trufflehog": 600, "grype": 900}
        with pytest.raises(ValueError):
            _normalize_value("tool_timeouts", "600")

    def test_env_overrides(self, monkeypatch):
        monkeypatch.setenv("DSOINABOX_TOOL_TIMEOUTS", "trufflehog=600, grype=900")
        monkeypatch.setenv("DSOINABOX_FAIL_ON_SECRETS", "verified")
        monkeypatch.setenv("DSOINABOX_GRYPE_DB", "offline")
        monkeypatch.setenv("DSOINABOX_VERIFY_SECRETS", "true")
        env = read_env_overrides()
        assert env["tool_timeouts"] == {"trufflehog": 600, "grype": 900}
        assert env["fail_on_secrets"] == "verified" and env["grype_db"] == "offline" and env["verify_secrets"] is True


def test_cli_wires_options(monkeypatch, tmp_path):
    import dsoinabox.cli as cli
    import dsoinabox.run as run_mod

    captured = {}

    def fake_run(options):
        captured["options"] = options
        raise run_mod.UsageError("stop here")

    monkeypatch.setattr(cli, "run_scan", fake_run)
    (tmp_path / ".dsoinabox.yaml").write_text("tool_timeouts:\n  grype: 120\n")
    code = cli.main(["--source", str(tmp_path), "--fail_on_secrets", "verified", "--grype_db", "offline",
                     "--report_directory", str(tmp_path / "r"), "--project_id", "p"])
    assert code == 3
    o = captured["options"]
    assert o.fail_on_secrets and o.fail_on_secrets_mode == "verified" and o.verify_secrets is True
    assert o.grype_db == "offline" and o.tool_timeouts == {"grype": 120}
