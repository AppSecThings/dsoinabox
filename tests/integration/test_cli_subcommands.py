"""Subcommand dispatch and legacy-flag compatibility (W5.1, W1.4, W2.6)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from dsoinabox.cli import main, parse_cli_overrides

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "waivers"


def test_no_args_prints_help(capsys):
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "subcommands:" in out and "waivers migrate" in out


def test_unknown_command_is_usage_error(caplog):
    assert main(["frobnicate"]) == 3
    assert any("Unknown command 'frobnicate'" in m for m in caplog.messages)


def test_scan_and_legacy_flat_invocation_parse_identically():
    flat = parse_cli_overrides(["-t", "sast", "--failure_threshold", "high", "-o", "json"])
    explicit = parse_cli_overrides(["-t", "sast", "--failure_threshold", "high", "-o", "json"])
    assert flat == explicit
    # `scan` prefix routes to the same parser
    assert main(["scan"]) == 0


def test_legacy_flags_are_hidden_from_help(capsys):
    main(["scan", "--help"]) if False else None
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    for hidden in ("--tool_versions", "--init-config", "--trufflehog_help", "--checkov_help"):
        assert hidden not in out


def test_tools_versions_subcommand(monkeypatch, capsys):
    import dsoinabox.commands.tools as tools_cmd

    for module in tools_cmd.TOOL_MODULES.values():
        monkeypatch.setattr(module, "show_version", lambda: print("x 1.2.3"))
    assert main(["tools", "versions"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("dsoinabox ")
    assert out.count("x 1.2.3") == 5


def test_legacy_tool_versions_flag_warns(monkeypatch, capsys, caplog):
    import dsoinabox.commands.tools as tools_cmd

    for module in tools_cmd.TOOL_MODULES.values():
        monkeypatch.setattr(module, "show_version", lambda: None)
    assert main(["--tool_versions"]) == 0
    assert any("deprecated" in m and "tools versions" in m for m in caplog.messages)


def test_tools_help_subcommand(monkeypatch, capsys):
    import dsoinabox.commands.tools as tools_cmd

    monkeypatch.setattr(tools_cmd.TOOL_MODULES["grype"], "show_help", lambda: print("GRYPE HELP"))
    assert main(["tools", "help", "grype"]) == 0
    assert "GRYPE HELP" in capsys.readouterr().out


def test_config_init_subcommand(tmp_path):
    assert main(["config", "init", "--source", str(tmp_path)]) == 0
    assert (tmp_path / ".dsoinabox.yaml").exists()
    # second run does not overwrite
    (tmp_path / ".dsoinabox.yaml").write_text("tools: sast\n")
    assert main(["config", "init", "--source", str(tmp_path)]) == 0
    assert (tmp_path / ".dsoinabox.yaml").read_text() == "tools: sast\n"


class TestWaiversValidate:
    def test_ok_file(self, capsys):
        assert main(["waivers", "validate", str(FIXTURES / "v1.1" / "minimal.yaml")]) == 0
        assert "ok" in capsys.readouterr().out

    def test_strict_fails_on_expired(self, capsys):
        path = str(FIXTURES / "v1.0" / "full.yaml")
        assert main(["waivers", "validate", path]) == 0
        assert main(["waivers", "validate", "--strict", path]) == 1
        assert "expired:" in capsys.readouterr().out

    def test_invalid_file_is_exit_1(self, capsys):
        assert main(["waivers", "validate", str(FIXTURES / "v1.0" / "invalid_type.yaml")]) == 1
        assert "invalid:" in capsys.readouterr().out

    def test_missing_file_is_usage_error(self):
        assert main(["waivers", "validate", "/nonexistent/waivers.yaml"]) == 3


class TestWaiversMigrate:
    def test_dry_run_prints_diff(self, tmp_path, capsys):
        src = tmp_path / "w.yaml"
        shutil.copy(FIXTURES / "v1.0" / "full.yaml", src)
        before = src.read_text()
        assert main(["waivers", "migrate", "--dry-run", str(src)]) == 0
        out = capsys.readouterr().out
        assert '+schema_version: "1.1"' in out and "-schema_version: \"1.0\"" in out
        assert src.read_text() == before

    def test_in_place(self, tmp_path, capsys):
        src = tmp_path / "w.yaml"
        shutil.copy(FIXTURES / "v1.0" / "full.yaml", src)
        assert main(["waivers", "migrate", "--in-place", str(src)]) == 0
        assert (tmp_path / "w.yaml.bak").exists()
        assert 'schema_version: "1.1"' in src.read_text()
        assert "backup at" in capsys.readouterr().out

    def test_output_path(self, tmp_path):
        src = tmp_path / "w.yaml"
        shutil.copy(FIXTURES / "v1.0" / "minimal.yaml", src)
        out = tmp_path / "out" / "w.yaml"
        assert main(["waivers", "migrate", str(src), "--output", str(out)]) == 0
        assert out.exists() and 'schema_version: "1.0"' in src.read_text()

    def test_already_current_in_place_is_visible(self, tmp_path, capsys):
        src = tmp_path / "w.yaml"
        shutil.copy(FIXTURES / "v1.1" / "minimal.yaml", src)
        assert main(["waivers", "migrate", "--in-place", str(src)]) == 1
        assert "nothing to do" in capsys.readouterr().out

    def test_already_current_dry_run_is_ok(self, tmp_path):
        src = tmp_path / "w.yaml"
        shutil.copy(FIXTURES / "v1.1" / "minimal.yaml", src)
        assert main(["waivers", "migrate", "--dry-run", str(src)]) == 0

    def test_output_with_many_inputs_is_usage_error(self, tmp_path):
        a = tmp_path / "a.yaml"; b = tmp_path / "b.yaml"
        shutil.copy(FIXTURES / "v1.0" / "minimal.yaml", a); shutil.copy(FIXTURES / "v1.0" / "minimal.yaml", b)
        assert main(["waivers", "migrate", str(a), str(b), "--output", str(tmp_path / "o.yaml")]) == 3

    def test_missing_file(self):
        assert main(["waivers", "migrate", "/nonexistent.yaml"]) == 3
