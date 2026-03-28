"""integration tests for repo config and precedence merging."""

from __future__ import annotations

import json
import os

import pytest
import yaml

from dsoinabox.cli import main


def _load_unified_json_report(report_root):
    json_files = list(report_root.rglob("dsoinabox_unified_report_*.json"))
    assert json_files, "expected at least one unified json report"
    with open(json_files[0], "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.integration
def test_repo_config_applies_defaults(tmp_project, fake_runner):
    source_dir = tmp_project / "source"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("print('ok')\n")
    (source_dir / ".dsoinabox.yaml").write_text(
        yaml.safe_dump(
            {
                "tools": ["syft"],
                "output": ["json"],
                "show_findings": False,
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "--source",
            str(source_dir),
            "--report_directory",
            str(tmp_project / "reports"),
            "--project_id",
            "test-project",
        ]
    )
    assert exit_code == 0

    report = _load_unified_json_report(tmp_project / "reports")
    assert report.get("syft_data") is not None
    assert report.get("opengrep_data") is None
    assert report.get("trufflehog_data") is None


@pytest.mark.integration
def test_env_overrides_repo_config(tmp_project, fake_runner, monkeypatch):
    source_dir = tmp_project / "source"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("print('ok')\n")
    (source_dir / ".dsoinabox.yaml").write_text(
        yaml.safe_dump(
            {
                "tools": ["syft"],
                "output": ["json"],
                "show_findings": False,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("DSOINABOX_TOOLS", "opengrep")

    exit_code = main(
        [
            "--source",
            str(source_dir),
            "--report_directory",
            str(tmp_project / "reports"),
            "--project_id",
            "test-project",
        ]
    )
    assert exit_code == 0

    report = _load_unified_json_report(tmp_project / "reports")
    assert report.get("opengrep_data") is not None
    assert report.get("syft_data") is None


@pytest.mark.integration
def test_cli_overrides_env_and_repo_config(tmp_project, fake_runner, monkeypatch):
    source_dir = tmp_project / "source"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("print('ok')\n")
    (source_dir / ".dsoinabox.yaml").write_text(
        yaml.safe_dump(
            {
                "tools": ["syft"],
                "output": ["json"],
                "show_findings": False,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("DSOINABOX_TOOLS", "opengrep")

    exit_code = main(
        [
            "--source",
            str(source_dir),
            "--report_directory",
            str(tmp_project / "reports"),
            "--tools",
            "syft",
            "--project_id",
            "test-project",
        ]
    )
    assert exit_code == 0

    report = _load_unified_json_report(tmp_project / "reports")
    assert report.get("syft_data") is not None
    assert report.get("opengrep_data") is None


@pytest.mark.integration
def test_repo_config_nested_tool_args_are_applied(tmp_project, monkeypatch):
    source_dir = tmp_project / "source"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("print('ok')\n")
    (source_dir / ".dsoinabox.yaml").write_text(
        yaml.safe_dump(
            {
                "tools": ["opengrep"],
                "output": ["json"],
                "show_findings": False,
                "tool_args": {
                    "opengrep": "--severity high",
                },
            }
        ),
        encoding="utf-8",
    )

    seen_commands: list[list[str]] = []

    def _runner(cmd, *, cwd=None, env=None, timeout=None, text=True, check=False):
        seen_commands.append(list(cmd))
        if not cmd:
            return (1, "", "") if text else (1, b"", b"")
        if cmd[0] == "git":
            return (0, "", "") if text else (0, b"", b"")
        if cmd[0] == "opengrep":
            output_file_arg = next((arg for arg in cmd if arg.startswith("--json-output=")), None)
            if output_file_arg:
                out_file = output_file_arg.split("=", 1)[1]
                os.makedirs(os.path.dirname(out_file), exist_ok=True)
                with open(out_file, "w", encoding="utf-8") as f:
                    json.dump({"results": []}, f)
            return (0, "", "") if text else (0, b"", b"")
        return (0, "{}", "") if text else (0, b"{}", b"")

    import dsoinabox.utils.runner
    import dsoinabox.scanners.base
    import dsoinabox.utils.git
    import dsoinabox.utils.project_id
    import dsoinabox.reporting.trufflehog
    import dsoinabox.reporting.opengrep
    import dsoinabox.utils.environment
    import dsoinabox.cli

    monkeypatch.setattr(dsoinabox.utils.runner, "run_cmd", _runner)
    monkeypatch.setattr(dsoinabox.scanners.base, "run_cmd", _runner)
    monkeypatch.setattr(dsoinabox.utils.git, "run_cmd", _runner)
    monkeypatch.setattr(
        dsoinabox.utils.project_id,
        "run_git_cmd",
        lambda args, *, repo_path=None, cwd=None, text=True, check=False: _runner(
            ["git"] + list(args), cwd=cwd, text=text, check=check
        ),
    )
    monkeypatch.setattr(
        dsoinabox.reporting.trufflehog,
        "run_git_cmd",
        lambda args, *, repo_path=None, cwd=None, text=True, check=False: _runner(
            ["git"] + list(args), cwd=cwd, text=text, check=check
        ),
    )
    monkeypatch.setattr(
        dsoinabox.reporting.opengrep,
        "run_git_cmd",
        lambda args, *, repo_path=None, cwd=None, text=True, check=False: _runner(
            ["git"] + list(args), cwd=cwd, text=text, check=check
        ),
    )
    monkeypatch.setattr(dsoinabox.utils.environment, "check_tool_available", lambda tool_name: True)
    monkeypatch.setattr(dsoinabox.cli, "check_tool_available", lambda tool_name: True)

    exit_code = main(
        [
            "--source",
            str(source_dir),
            "--report_directory",
            str(tmp_project / "reports"),
            "--project_id",
            "test-project",
        ]
    )
    assert exit_code == 0
    opengrep_commands = [cmd for cmd in seen_commands if cmd and cmd[0] == "opengrep"]
    assert opengrep_commands, "expected opengrep command to be executed"
    assert "--severity" in opengrep_commands[0]
    assert "high" in opengrep_commands[0]


@pytest.mark.integration
def test_init_config_writes_default_file(tmp_project):
    source_dir = tmp_project / "source"
    source_dir.mkdir()

    config_path = source_dir / ".dsoinabox.yaml"
    assert not config_path.exists()

    exit_code = main(["--source", str(source_dir), "--init-config"])
    assert exit_code == 0
    assert config_path.exists()

    config_text = config_path.read_text(encoding="utf-8")
    assert "tools: all" in config_text
    assert "failure_threshold: none" in config_text
    assert "waiver_file: .dsoinabox_waivers.yaml" in config_text
