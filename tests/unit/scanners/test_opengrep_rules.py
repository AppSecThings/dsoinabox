from __future__ import annotations

import json

import pytest
import yaml

import dsoinabox.cli as cli
import dsoinabox.run as run_module
import dsoinabox.scanners.base as base_module
from dsoinabox.model import ScanOptions, ScanResult
from dsoinabox.run import UsageError, _resolve_opengrep_rules
from dsoinabox.scanners.registry import REGISTRY
from dsoinabox.scanners.sast.opengrep import OpengrepScanner
from dsoinabox.utils.config import (
    DEFAULT_CONFIG_TEMPLATE,
    _normalize_value,
    load_config_file,
    read_env_overrides,
)
from dsoinabox.waivers.apply import WaiverUsage


def _capture_opengrep(monkeypatch, *, returncode=0, stderr=b""):
    calls: list[list[str]] = []

    def fake_run_cmd(cmd, **kwargs):
        calls.append(list(cmd))
        stdout = json.dumps({"results": []}).encode("utf-8")
        return returncode, stdout, stderr

    monkeypatch.setattr(base_module, "run_cmd", fake_run_cmd)
    return calls


def test_default_command_tokens_and_order_are_unchanged(tmp_path, monkeypatch):
    calls = _capture_opengrep(monkeypatch)
    source = str(tmp_path / "source")

    OpengrepScanner().run_scan(source, report_directory=str(tmp_path / "reports"))

    assert calls == [["opengrep", "scan", "--json", "--config", "auto", source]]


def test_one_and_multiple_local_configs_keep_the_existing_config_position(tmp_path, monkeypatch):
    calls = _capture_opengrep(monkeypatch)
    scanner = OpengrepScanner()
    source = str(tmp_path / "source")

    scanner.run_scan(source, report_directory=str(tmp_path / "one"), opengrep_rules=["/rules/one.yml"])
    scanner.run_scan(
        source,
        report_directory=str(tmp_path / "many"),
        opengrep_rules=["/rules/one.yml", "/rules/two"],
    )

    assert calls == [
        ["opengrep", "scan", "--json", "--config", "/rules/one.yml", source],
        [
            "opengrep",
            "scan",
            "--json",
            "--config",
            "/rules/one.yml",
            "--config",
            "/rules/two",
            source,
        ],
    ]


@pytest.mark.parametrize(
    "stderr",
    [
        b"HTTPSConnectionPool(host='semgrep.dev'): Max retries exceeded",
        b"ConnectionError: Temporary failure in name resolution",
        b"NewConnectionError: Name or service not known",
    ],
)
def test_auto_network_failures_have_offline_guidance(tmp_path, monkeypatch, stderr):
    _capture_opengrep(monkeypatch, returncode=2, stderr=stderr)

    with pytest.raises(base_module.ScannerError) as caught:
        OpengrepScanner().run_scan(str(tmp_path), report_directory=str(tmp_path / "reports"))

    message = str(caught.value)
    assert message.startswith(
        "OpenGrep could not download rules from semgrep.dev (--config auto needs outbound network access). "
        "Set --opengrep_rules / DSOINABOX_OPENGREP_RULES / opengrep_rules to a local rules directory or file "
        "to run offline. Original error: "
    )
    assert stderr.decode() in message


def test_auto_network_error_prefers_relevant_original_line(tmp_path, monkeypatch):
    _capture_opengrep(
        monkeypatch,
        returncode=2,
        stderr=b"generic preface\nrequest to semgrep.dev failed\nHTTPSConnectionPool later",
    )

    with pytest.raises(base_module.ScannerError, match=r"Original error: request to semgrep\.dev failed$"):
        OpengrepScanner().run_scan(str(tmp_path), report_directory=str(tmp_path / "reports"))


@pytest.mark.parametrize("rules", [None, ["/local/rules"]])
def test_non_network_or_non_auto_failures_retain_original_error(tmp_path, monkeypatch, rules):
    _capture_opengrep(monkeypatch, returncode=2, stderr=b"ordinary rule parse failure")

    with pytest.raises(base_module.ScannerError) as caught:
        OpengrepScanner().run_scan(
            str(tmp_path), report_directory=str(tmp_path / "reports"), opengrep_rules=rules
        )

    assert str(caught.value) == "OpenGrep scan failed: ordinary rule parse failure"


def test_local_mode_does_not_remap_network_shaped_failures(tmp_path, monkeypatch):
    _capture_opengrep(monkeypatch, returncode=2, stderr=b"HTTPSConnectionPool: local invocation failed")

    with pytest.raises(base_module.ScannerError) as caught:
        OpengrepScanner().run_scan(
            str(tmp_path),
            report_directory=str(tmp_path / "reports"),
            opengrep_rules=["/local/rules"],
        )

    assert str(caught.value) == "OpenGrep scan failed: HTTPSConnectionPool: local invocation failed"


class TestConfiguration:
    def test_yaml_string_and_list_normalize(self, tmp_path):
        config = tmp_path / ".dsoinabox.yaml"
        config.write_text(yaml.safe_dump({"opengrep_rules": ["rules/one.yml", "rules/two"]}))
        assert load_config_file(config)["opengrep_rules"] == ["rules/one.yml", "rules/two"]
        assert _normalize_value("opengrep_rules", "one.yml,two.yml") == ["one.yml", "two.yml"]

    def test_env_is_comma_separated(self, monkeypatch):
        monkeypatch.setenv("DSOINABOX_OPENGREP_RULES", "rules/one.yml, rules/two")
        assert read_env_overrides()["opengrep_rules"] == ["rules/one.yml", "rules/two"]

    def test_config_env_cli_precedence_and_kebab_alias(self, tmp_path, monkeypatch):
        (tmp_path / ".dsoinabox.yaml").write_text("opengrep_rules: [config-one, config-two]\n")
        captured: list[ScanOptions] = []

        def stop_after_options(options):
            captured.append(options)
            raise UsageError("captured")

        monkeypatch.setattr(cli, "run_scan", stop_after_options)
        common = ["--source", str(tmp_path), "--report_directory", str(tmp_path / "reports")]

        assert cli.main(common) == 3
        monkeypatch.setenv("DSOINABOX_OPENGREP_RULES", "env-one,env-two")
        assert cli.main(common) == 3
        assert cli.main([*common, "--opengrep-rules", "cli-one,cli-two"]) == 3

        assert [options.opengrep_rules for options in captured] == [
            ["config-one", "config-two"],
            ["env-one", "env-two"],
            ["cli-one", "cli-two"],
        ]

    def test_default_template_documents_local_rules(self):
        assert "# opengrep_rules: ./rules   # local rules dir/file; default auto fetches from semgrep.dev" in DEFAULT_CONFIG_TEMPLATE


class TestValidationAndMetadata:
    def _options(self, tmp_path, rules, *, tools=None):
        source = tmp_path / "source"
        source.mkdir(exist_ok=True)
        return ScanOptions(
            source=str(source),
            report_directory=str(tmp_path / "reports"),
            timestamp="t",
            project_id="p",
            tools=tools or ["opengrep"],
            outputs=[],
            waiver_file=None,
            opengrep_rules=rules,
        )

    def test_relative_paths_resolve_against_source(self, tmp_path):
        options = self._options(tmp_path, ["rules/one.yml", "rules/two"])
        first = tmp_path / "source" / "rules" / "one.yml"
        second = tmp_path / "source" / "rules" / "two"
        first.parent.mkdir()
        first.write_text("rules: []\n")
        second.mkdir()

        resolved = _resolve_opengrep_rules(options, [REGISTRY["opengrep"]])

        assert resolved == [str(first.resolve()), str(second.resolve())]

    def test_auto_cannot_be_mixed_with_paths(self, tmp_path):
        options = self._options(tmp_path, ["auto", "rules"])
        with pytest.raises(UsageError, match="cannot combine 'auto'"):
            _resolve_opengrep_rules(options, [REGISTRY["opengrep"]])

    def test_missing_path_fails_before_version_or_scan_execution(self, tmp_path, monkeypatch):
        options = self._options(tmp_path, ["missing-rules"])
        execution_started = False

        def mark_execution(*args, **kwargs):
            nonlocal execution_started
            execution_started = True
            return {}

        monkeypatch.setattr(run_module, "_tool_versions", mark_execution)
        monkeypatch.setattr(run_module, "_schedule", mark_execution)

        with pytest.raises(UsageError, match="opengrep_rules path does not exist"):
            run_module.run_scan(options)
        assert execution_started is False

    def test_missing_path_is_ignored_when_opengrep_is_not_selected(self, tmp_path):
        options = self._options(tmp_path, ["missing-rules"], tools=["syft"])
        assert _resolve_opengrep_rules(options, [REGISTRY["syft"]]) == ["missing-rules"]

    @pytest.mark.parametrize(
        ("rules", "expected_version"),
        [
            (["auto"], "1.2.3"),
            (["AUTO"], "1.2.3"),
            (["rules/local.yml"], "1.2.3 (rules rules/local.yml)"),
        ],
    )
    def test_metadata_suffix_is_non_auto_only_and_includes_failures(
        self, tmp_path, monkeypatch, rules, expected_version
    ):
        options = self._options(tmp_path, rules)
        if rules[0].lower() != "auto":
            path = tmp_path / "source" / rules[0]
            path.parent.mkdir(parents=True)
            path.write_text("rules: []\n")
        captured_rules = []

        monkeypatch.setattr(run_module, "is_git", lambda source: False)
        monkeypatch.setattr(run_module, "set_git_safe_directory", lambda source: None)
        monkeypatch.setattr(run_module.environment, "check_tool_available", lambda executable: True)
        monkeypatch.setattr(run_module, "_tool_versions", lambda specs: {"opengrep": "1.2.3"})

        def fake_schedule(specs, ctx_for, engine, **kwargs):
            captured_rules.extend(ctx_for(specs[0]).opengrep_rules)
            return [ScanResult(tool="opengrep", category="sast", status="failed", error="boom")], WaiverUsage()

        monkeypatch.setattr(run_module, "_schedule", fake_schedule)

        run = run_module.run_scan(options)

        assert run.results[0].tool_version == expected_version
        assert captured_rules == (["auto"] if rules[0].lower() == "auto" else [str(path.resolve())])
