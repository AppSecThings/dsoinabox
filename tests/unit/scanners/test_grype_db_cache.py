"""Persistent Grype DB cache: --db_cache and --always_update."""

from __future__ import annotations

import os

import pytest

import dsoinabox.scanners.base as base
import dsoinabox.utils.environment as environment
from dsoinabox.model import ScanOptions
from dsoinabox.run import UsageError, run_scan
from dsoinabox.scanners.sca import grype
from dsoinabox.utils.config import load_config_file, read_env_overrides

OFFLINE_ENV = {"GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_DB_VALIDATE_AGE": "false"}


@pytest.fixture(autouse=True)
def no_user_grype_cache(monkeypatch):
    monkeypatch.delenv("GRYPE_DB_CACHE_DIR", raising=False)


@pytest.fixture
def capture(monkeypatch):
    calls: list[dict] = []

    def fake(cmd, *, cwd=None, env=None, timeout=None, text=True, check=False):
        calls.append({"cmd": list(cmd), "env": env})
        if cmd[:2] == ["grype", "db"]:
            return (0, '{"built": "2026-09-01T00:00:00Z", "schemaVersion": "6"}', "")
        return (0, '{"matches": []}', "")

    monkeypatch.setattr(base, "run_cmd", fake)
    return calls


class TestGrypeEnv:
    def test_unset_options_pass_no_env(self, capture, tmp_path):
        grype.run_scan(str(tmp_path), None, str(tmp_path))
        grype.db_status()
        assert [c["env"] for c in capture] == [None, None]

    def test_db_cache_sets_dir_and_24h_frequency(self, capture, tmp_path):
        cache = tmp_path / "cache"
        grype.run_scan(str(tmp_path), None, str(tmp_path), db_cache=str(cache))
        assert capture[0]["env"] == {
            "GRYPE_DB_CACHE_DIR": str(cache / "grype"),
            "GRYPE_DB_MAX_UPDATE_CHECK_FREQUENCY": "24h",
        }
        assert (cache / "grype").is_dir()

    def test_always_update_checks_every_run(self, capture, tmp_path):
        cache = tmp_path / "cache"
        grype.run_scan(str(tmp_path), None, str(tmp_path), db_cache=str(cache), always_update=True)
        grype.run_scan(str(tmp_path), None, str(tmp_path), always_update=True)
        assert capture[0]["env"] == {
            "GRYPE_DB_CACHE_DIR": str(cache / "grype"),
            "GRYPE_DB_MAX_UPDATE_CHECK_FREQUENCY": "0s",
        }
        assert capture[1]["env"] == {"GRYPE_DB_MAX_UPDATE_CHECK_FREQUENCY": "0s"}

    def test_offline_with_cache_keeps_offline_env(self, capture, tmp_path):
        cache = tmp_path / "cache"
        grype.run_scan(str(tmp_path), None, str(tmp_path), db_mode="offline", db_cache=str(cache))
        assert capture[0]["env"] == {**OFFLINE_ENV, "GRYPE_DB_CACHE_DIR": str(cache / "grype"),
                                     "GRYPE_DB_MAX_UPDATE_CHECK_FREQUENCY": "24h"}
        # offline never writes, so a missing or read-only cache is left alone
        assert not cache.exists()

    def test_user_grype_cache_dir_wins(self, capture, monkeypatch, tmp_path, caplog):
        monkeypatch.setenv("GRYPE_DB_CACHE_DIR", "/mnt/grypedb")
        cache = tmp_path / "cache"
        with caplog.at_level("INFO"):
            grype.run_scan(str(tmp_path), None, str(tmp_path), db_cache=str(cache), always_update=True)
        grype.db_status(db_cache=str(cache))
        assert capture[0]["env"] == {"GRYPE_DB_MAX_UPDATE_CHECK_FREQUENCY": "0s"}
        assert capture[1]["env"] == {"GRYPE_DB_MAX_UPDATE_CHECK_FREQUENCY": "24h"}
        assert "GRYPE_DB_CACHE_DIR=/mnt/grypedb is set" in caplog.text
        assert not cache.exists()

    def test_user_grype_cache_dir_named_offline(self, monkeypatch, tmp_path):
        monkeypatch.setenv("GRYPE_DB_CACHE_DIR", "/mnt/grypedb")
        monkeypatch.setattr(base, "run_cmd", lambda cmd, **kw: (1, "", "failed to load vulnerability db: database does not exist"))
        with pytest.raises(base.ScannerError, match="Cache in use: /mnt/grypedb"):
            grype.run_scan(str(tmp_path), None, str(tmp_path), db_mode="offline", db_cache=str(tmp_path / "c"))

    def test_db_status_uses_cache(self, capture, tmp_path):
        assert grype.db_status(db_cache=str(tmp_path)) == "built 2026-09-01T00:00:00Z (schema 6)"
        assert capture[0]["cmd"][:3] == ["grype", "db", "status"]
        assert capture[0]["env"]["GRYPE_DB_CACHE_DIR"] == os.path.join(str(tmp_path), "grype")


class TestGrypeErrors:
    def test_offline_missing_db_names_cache(self, monkeypatch, tmp_path):
        monkeypatch.setattr(base, "run_cmd", lambda cmd, **kw: (1, "", "failed to load vulnerability db: database does not exist"))
        with pytest.raises(base.ScannerError, match="no vulnerability database is cached") as exc:
            grype.run_scan(str(tmp_path), None, str(tmp_path), db_mode="offline", db_cache=str(tmp_path / "c"))
        assert f"Cache in use: {tmp_path / 'c' / 'grype'}" in str(exc.value)

    def test_offline_missing_db_without_cache_says_how_to_set_one(self, monkeypatch, tmp_path):
        monkeypatch.setattr(base, "run_cmd", lambda cmd, **kw: (1, "", "vulnerability database not found"))
        with pytest.raises(base.ScannerError, match="--db_cache PATH") as exc:
            grype.run_scan(str(tmp_path), None, str(tmp_path), db_mode="offline")
        assert "/var/cache/dsoinabox" in str(exc.value)

    def test_unwritable_cache_fails_before_grype_runs(self, capture, tmp_path):
        blocker = tmp_path / "cache"
        blocker.write_text("not a directory")
        with pytest.raises(base.ScannerError, match="named Docker volume.*uid 1001"):
            grype.run_scan(str(tmp_path), None, str(tmp_path), db_cache=str(blocker))
        assert capture == []

    def test_read_only_cache_dir_is_reported(self, capture, monkeypatch, tmp_path):
        monkeypatch.setattr(grype.os, "access", lambda path, mode: False)
        with pytest.raises(base.ScannerError, match="is not writable"):
            grype.run_scan(str(tmp_path), None, str(tmp_path), db_cache=str(tmp_path / "c"))
        assert capture == []

    def test_permission_denied_on_cache_is_explained(self, monkeypatch, tmp_path):
        db = tmp_path / "c" / "grype" / "6" / "vulnerability.db"
        monkeypatch.setattr(base, "run_cmd", lambda cmd, **kw: (1, "", f"open {db}: permission denied"))
        with pytest.raises(base.ScannerError, match="uid 1001.*permission denied"):
            grype.run_scan(str(tmp_path), None, str(tmp_path), db_cache=str(tmp_path / "c"))

    def test_permission_denied_elsewhere_is_generic(self, monkeypatch, tmp_path):
        monkeypatch.setattr(base, "run_cmd", lambda cmd, **kw: (1, "", "open /scan_target/secret: permission denied"))
        with pytest.raises(base.ScannerError) as exc:
            grype.run_scan(str(tmp_path), None, str(tmp_path), db_cache=str(tmp_path / "c"))
        assert "not writable" not in str(exc.value) and "/scan_target/secret: permission denied" in str(exc.value)


class TestOptionSources:
    def test_env_overrides(self, monkeypatch):
        monkeypatch.setenv("DSOINABOX_DB_CACHE", "/var/cache/dsoinabox")
        monkeypatch.setenv("DSOINABOX_ALWAYS_UPDATE", "true")
        env = read_env_overrides()
        assert env["db_cache"] == "/var/cache/dsoinabox" and env["always_update"] is True

    def test_config_file_keys(self, tmp_path):
        path = tmp_path / ".dsoinabox.yaml"
        path.write_text("db_cache: .cache/db\nalways_update: yes\n")
        assert load_config_file(path) == {"db_cache": ".cache/db", "always_update": True}

    @pytest.mark.parametrize("flags", [["--db_cache", "c", "--always_update"], ["--db-cache", "c", "--always-update"]])
    def test_cli_snake_and_kebab(self, monkeypatch, tmp_path, flags):
        options = self._options(monkeypatch, tmp_path, flags)
        assert options.db_cache == str(tmp_path / "c") and options.always_update is True

    def test_cli_defaults_unset(self, monkeypatch, tmp_path):
        monkeypatch.delenv("DSOINABOX_DB_CACHE", raising=False)
        monkeypatch.delenv("DSOINABOX_ALWAYS_UPDATE", raising=False)
        options = self._options(monkeypatch, tmp_path, [])
        assert options.db_cache is None and options.always_update is False

    def test_cli_reads_env_and_config(self, monkeypatch, tmp_path):
        (tmp_path / ".dsoinabox.yaml").write_text("always_update: true\n")
        monkeypatch.setenv("DSOINABOX_DB_CACHE", str(tmp_path / "env-cache"))
        options = self._options(monkeypatch, tmp_path, [])
        assert options.db_cache == str(tmp_path / "env-cache") and options.always_update is True

    def _options(self, monkeypatch, tmp_path, flags) -> ScanOptions:
        import dsoinabox.cli as cli

        captured = {}

        def fake_run(options):
            captured["options"] = options
            raise UsageError("stop here")

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(cli, "run_scan", fake_run)
        code = cli.main(["--source", str(tmp_path), "--report_directory", str(tmp_path / "r"), "--project_id", "p", *flags])
        assert code == 3
        return captured["options"]


class TestRunWiring:
    @pytest.fixture
    def fake_grype(self, monkeypatch):
        calls: dict[str, list] = {"scan": [], "status": []}

        def fake_scan(source, extra_args, out_dir, **kwargs):
            calls["scan"].append(kwargs)
            return {"matches": []}

        def fake_status(**kwargs):
            calls["status"].append(kwargs)
            return "built 2026-09-01"

        monkeypatch.setattr(environment, "check_tool_available", lambda tool: True)
        monkeypatch.setattr("dsoinabox.scanners.sca.grype.run_scan", fake_scan)
        monkeypatch.setattr("dsoinabox.scanners.sca.grype.db_status", fake_status)
        return calls

    def _options(self, tmp_path, **kw) -> ScanOptions:
        return ScanOptions(source=str(tmp_path), report_directory=str(tmp_path / "r"), timestamp="t", project_id="p",
                           tools=["grype"], outputs=["json"], **kw)

    def test_cache_reaches_scan_and_db_status(self, fake_grype, tmp_path):
        run = run_scan(self._options(tmp_path, db_cache="/cache", always_update=True))
        assert run.result_for("grype").status == "ok"
        assert fake_grype["scan"][0]["db_cache"] == "/cache" and fake_grype["scan"][0]["always_update"] is True
        assert fake_grype["status"] == [{"db_cache": "/cache", "always_update": True}]

    def test_always_update_with_offline_is_usage_error(self, fake_grype, tmp_path):
        with pytest.raises(UsageError, match="--always_update cannot be combined with --grype_db offline"):
            run_scan(self._options(tmp_path, grype_db="offline", always_update=True))
        assert fake_grype["scan"] == []

    def test_cli_exit_code_3(self, fake_grype, tmp_path, caplog):
        import dsoinabox.cli as cli

        code = cli.main(["--source", str(tmp_path), "--report_directory", str(tmp_path / "r"), "--project_id", "p",
                         "-t", "grype", "--grype_db", "offline", "--always_update"])
        assert code == 3 and fake_grype["scan"] == []
        assert "--always_update cannot be combined" in caplog.text
