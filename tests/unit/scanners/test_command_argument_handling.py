from __future__ import annotations

import json
from pathlib import Path

import pytest

import dsoinabox.scanners.base as base_module
from dsoinabox.scanners.base import BaseScanner
from dsoinabox.scanners.iac.checkov import CheckovScanner
from dsoinabox.scanners.sast.opengrep import OpengrepScanner
from dsoinabox.scanners.sbom.syft import SyftScanner
from dsoinabox.scanners.sca.grype import GrypeScanner
from dsoinabox.scanners.secrets.trufflehog import TrufflehogScanner


@pytest.fixture
def run_cmd_recorder(monkeypatch):
    calls: list[list[str]] = []

    def _fake_run_cmd(cmd, *, cwd=None, env=None, timeout=None, text=True, check=False):
        calls.append(list(cmd))
        tool = cmd[0]

        if tool == "opengrep":
            output = json.dumps({"results": []})
            return (0, output if text else output.encode("utf-8"), "" if text else b"")

        if tool == "syft":
            return (0, json.dumps({"artifacts": []}), "")

        if tool == "grype":
            return (0, json.dumps({"matches": []}), "")

        if tool == "trufflehog":
            return (0, "[]\n", "")

        if tool == "checkov":
            if "--output-file-path" in cmd:
                out_dir = Path(cmd[cmd.index("--output-file-path") + 1])
                out_dir.mkdir(parents=True, exist_ok=True)
                sarif_file = out_dir / "results_sarif.sarif"
                sarif_file.write_text(json.dumps({"version": "2.1.0", "runs": []}))
            return (0, "", "")

        return (0, "", "")

    monkeypatch.setattr(base_module, "run_cmd", _fake_run_cmd)
    return calls


def test_base_run_command_parses_quoted_string_args(run_cmd_recorder):
    scanner = BaseScanner("dummy")
    scanner._run_command('--flag "value with spaces" "/tmp/source path"')

    assert run_cmd_recorder[-1] == [
        "dummy",
        "--flag",
        "value with spaces",
        "/tmp/source path",
    ]


def test_base_run_command_preserves_list_args(run_cmd_recorder):
    scanner = BaseScanner("dummy")
    scanner._run_command(["--path", "/tmp/source path", "--label", "release candidate"])

    assert run_cmd_recorder[-1] == [
        "dummy",
        "--path",
        "/tmp/source path",
        "--label",
        "release candidate",
    ]


@pytest.mark.parametrize("input_args", [None, "", []])
def test_base_run_command_handles_empty_or_none_args(run_cmd_recorder, input_args):
    scanner = BaseScanner("dummy")
    scanner._run_command(input_args)

    assert run_cmd_recorder[-1] == ["dummy"]


def test_opengrep_command_tokenization_with_quoted_extra_args(tmp_path, run_cmd_recorder):
    source = str(tmp_path / "src with spaces")
    report_dir = str(tmp_path / "reports with spaces")
    OpengrepScanner().run_scan(
        source_path=source,
        extra_tool_args='--severity "high critical" --flag',
        report_directory=report_dir,
    )

    assert run_cmd_recorder[-1] == [
        "opengrep",
        "scan",
        "--json",
        "--config",
        "auto",
        source,
        "--severity",
        "high critical",
        "--flag",
    ]


def test_opengrep_captures_utf8_json_stdout_as_bytes(tmp_path, monkeypatch):
    captured_env = None
    captured_text = None

    def _fake_run_cmd(cmd, *, cwd=None, env=None, timeout=None, text=True, check=False):
        nonlocal captured_env, captured_text
        captured_env = env
        captured_text = text
        return (0, b'{"results": []}', b"")

    monkeypatch.setattr(base_module, "run_cmd", _fake_run_cmd)

    OpengrepScanner().run_scan(
        source_path=str(tmp_path / "source"),
        report_directory=str(tmp_path / "reports"),
    )

    assert captured_env == {"PYTHONIOENCODING": "utf-8"}
    assert captured_text is False


def test_syft_command_tokenization_handles_none_extra_args(tmp_path, run_cmd_recorder):
    source = str(tmp_path / "src with spaces")
    SyftScanner().run_scan(source_path=source, extra_tool_args=None, report_directory=str(tmp_path))

    assert run_cmd_recorder[-1] == [
        "syft",
        "scan",
        f"dir:{source}",
        "-o",
        "json",
        "-q",
    ]


def test_grype_command_tokenization_with_quoted_extra_args(tmp_path, run_cmd_recorder):
    source = str(tmp_path / "src with spaces")
    GrypeScanner().run_scan(
        source_path=source,
        extra_tool_args='--scope "all layers"',
        report_directory=str(tmp_path),
    )

    assert run_cmd_recorder[-1] == [
        "grype",
        f"dir:{source}",
        "-o",
        "json",
        "--scope",
        "all layers",
    ]


def test_trufflehog_command_tokenization_with_quoted_extra_args(tmp_path, run_cmd_recorder):
    source = str(tmp_path / "repo with spaces")
    TrufflehogScanner().run_scan(
        source_path=source,
        extra_tool_args='--filter-unverified --rules "allow list"',
        report_directory=str(tmp_path),
        git_repo=False,
    )

    assert run_cmd_recorder[-1] == [
        "trufflehog",
        "filesystem",
        source,
        "--no-verification",
        "--no-update",
        "-j",
        "--filter-unverified",
        "--rules",
        "allow list",
    ]


def test_checkov_command_tokenization_source_path_with_spaces_regression(tmp_path, run_cmd_recorder):
    source = str(tmp_path / "infra source with spaces")
    report_dir = str(tmp_path / "report dir with spaces")
    CheckovScanner().run_scan(
        source_path=source,
        extra_tool_args='--framework "terraform kubernetes"',
        report_directory=report_dir,
    )

    expected_output_dir = str((Path(report_dir) / "checkov").resolve())
    assert run_cmd_recorder[-1] == [
        "checkov",
        "--soft-fail",
        "--quiet",
        "-d",
        source,
        "--output",
        "sarif",
        "--output-file-path",
        expected_output_dir,
        "--framework",
        "terraform kubernetes",
    ]
