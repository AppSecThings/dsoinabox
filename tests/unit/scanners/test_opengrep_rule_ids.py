"""Bare rule ids for local OpenGrep rules, and fingerprints that no longer depend on where rules live."""

from __future__ import annotations

import json
import logging
import subprocess

import pytest

import dsoinabox.scanners.registry as registry
from dsoinabox.fingerprints.opengrep import fingerprint_findings
from dsoinabox.scanners.sast import opengrep as opengrep_wrapper
from dsoinabox.scanners.sast.opengrep_rule_ids import (
    ORIGINAL_KEY,
    bare_rule_id,
    local_rule_ids,
    strip_rule_id_prefixes,
)


def _rule_file(path, *ids):
    path.parent.mkdir(parents=True, exist_ok=True)
    rules = "".join(  # each rule matches only a call to a function named after it
        f"- id: {i}\n  languages: [python]\n  severity: ERROR\n  message: m\n  pattern: {i.replace('-', '_')}(...)\n"
        for i in ids
    )
    path.write_text("rules:\n" + rules)


@pytest.fixture
def rules_dir(tmp_path):
    root = tmp_path / "My Rules" / "rules"
    _rule_file(root / "python" / "permissions" / "auto-approve.yaml", "agent-sdk-mcp-auto-approve")
    _rule_file(root / "python" / "exec" / "evals.yml", "py-eval", "py-exec")
    # neighbours that are not rule files: test targets and fixtures
    (root / "python" / "exec" / "evals.test.yaml").write_text("a: 1\n---\nb: 2\n")
    (root / "python" / "exec" / "target.json").write_text(json.dumps({"rules": "not a list"}))
    (root / "python" / "exec" / "target.py").write_text("py_eval(x)\n")
    _rule_file(root / ".hidden" / "hidden.yaml", "hidden-rule")  # OpenGrep loads hidden folders too
    return root


def _payload(*check_ids):
    return {"results": [{"check_id": c, "path": "app.py", "extra": {"lines": "eval(x)"}} for c in check_ids]}


class TestLocalRuleIds:
    def test_directory_ids_skip_non_rule_files(self, rules_dir):
        ids, duplicated = local_rule_ids([str(rules_dir)])
        assert ids == {"agent-sdk-mcp-auto-approve", "py-eval", "py-exec", "hidden-rule"}
        assert duplicated == set()

    def test_single_file_and_multiple_sources(self, rules_dir, tmp_path):
        bundle = tmp_path / "bundle.yaml"
        _rule_file(bundle, "bundled")
        ids, _ = local_rule_ids([str(bundle), str(rules_dir / "python" / "exec")])
        assert ids == {"bundled", "py-eval", "py-exec"}

    def test_id_defined_in_two_files_is_duplicated(self, rules_dir, tmp_path):
        _rule_file(rules_dir / "go" / "evals.yaml", "py-eval")
        ids, duplicated = local_rule_ids([str(rules_dir)])
        assert "py-eval" not in ids
        assert duplicated == {"py-eval"}

    def test_auto_and_missing_sources_contribute_nothing(self, tmp_path):
        assert local_rule_ids(["auto", str(tmp_path / "missing")]) == (set(), set())


class TestBareRuleId:
    @pytest.mark.parametrize(
        "check_id, expected",
        [
            ("Users.me.MyRules.rules.python.permissions.agent-sdk-mcp-auto-approve", "agent-sdk-mcp-auto-approve"),
            ("agent-sdk-mcp-auto-approve", "agent-sdk-mcp-auto-approve"),
            ("a.b.c.x.y", "x.y"),  # longest known id wins
            ("a.b.c.y", "y"),
            ("a.b.c.unknown", None),
            ("xy", None),  # a suffix must start after a dot
        ],
    )
    def test_suffix_match(self, check_id, expected):
        assert bare_rule_id(check_id, {"agent-sdk-mcp-auto-approve", "x.y", "y"}) == expected


class TestStripPrefixes:
    def test_prefixed_ids_become_bare_and_keep_the_original(self, rules_dir):
        prefixed = "tmp.MyRules.rules.python.permissions.agent-sdk-mcp-auto-approve"
        raw = strip_rule_id_prefixes(_payload(prefixed, "py-eval", "elsewhere.unknown-rule"), [str(rules_dir)])
        first, bare, unknown = raw["results"]
        assert first["check_id"] == "agent-sdk-mcp-auto-approve"
        assert first[ORIGINAL_KEY] == prefixed
        assert bare == {"check_id": "py-eval", "path": "app.py", "extra": {"lines": "eval(x)"}}
        assert unknown["check_id"] == "elsewhere.unknown-rule" and ORIGINAL_KEY not in unknown

    def test_auto_rules_are_untouched(self):
        raw = _payload("python.lang.security.audit.eval-detected")
        assert strip_rule_id_prefixes(raw, ["auto"]) == _payload("python.lang.security.audit.eval-detected")

    def test_duplicated_ids_keep_their_prefix_with_a_warning(self, rules_dir, caplog):
        _rule_file(rules_dir / "go" / "evals.yaml", "py-eval")
        raw = _payload("x.rules.python.exec.py-eval", "x.rules.python.exec.py-exec")
        with caplog.at_level(logging.WARNING):
            strip_rule_id_prefixes(raw, [str(rules_dir)])
        assert [r["check_id"] for r in raw["results"]] == ["x.rules.python.exec.py-eval", "py-exec"]
        assert "more than one rule file keep their path prefix: py-eval" in caplog.text

    def test_payload_without_results(self, rules_dir):
        assert strip_rule_id_prefixes({"errors": []}, [str(rules_dir)]) == {"errors": []}


class TestFingerprintsIgnoreRuleLocation:
    @pytest.fixture
    def source(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text("import os\n\ndef f(x):\n    return eval(x)\n")
        return src

    def _fingerprints(self, source, rules_dir, check_id):
        raw = {"results": [{
            "check_id": check_id, "path": "app.py",
            "start": {"line": 4, "col": 12}, "end": {"line": 4, "col": 19},
            "extra": {"lines": "    return eval(x)"},
        }]}
        strip_rule_id_prefixes(raw, [str(rules_dir)])
        fingerprint_findings(raw, str(source), project_id="github.com/example/repo")
        return raw["results"][0]["fingerprints"]

    def test_same_finding_from_two_rule_locations_has_one_current_fingerprint(self, source, rules_dir):
        laptop = self._fingerprints(source, rules_dir, "Users.me.MyRules.rules.python.exec.py-eval")
        docker = self._fingerprints(source, rules_dir, "rules.python.exec.py-eval")
        for tier in ("rule", "exact", "ctx"):
            assert laptop[tier] == docker[tier]
            assert laptop[tier].startswith(f"og:2:{tier.upper()}:py-eval:")
        # version 1 hashed the prefixed id, so it still differs, exactly as 1.2.x produced it
        assert laptop["legacy"] != docker["legacy"]
        assert laptop["legacy"][0].startswith("og:1:RULE:Users.me.MyRules.rules.python.exec.py-eval:")

    def test_legacy_v1_equals_what_the_unstripped_finding_produced(self, source, rules_dir):
        prefixed = "Users.me.MyRules.rules.python.exec.py-eval"
        stripped = self._fingerprints(source, rules_dir, prefixed)
        unstripped = self._fingerprints(source, source, prefixed)  # no rule ids found: nothing stripped
        assert stripped["legacy"] == unstripped["legacy"]


def test_registry_strips_prefixes_from_local_rule_results(rules_dir, tmp_path, monkeypatch):
    prefixed = "tmp.MyRules.rules.python.exec.py-exec"
    monkeypatch.setattr(opengrep_wrapper, "run_scan", lambda *a, **k: _payload(prefixed))
    ctx = registry.RunContext(
        source=str(tmp_path), tools_output_dir=str(tmp_path / "out"), project_id="p", is_git_repo=False,
        opengrep_rules=[str(rules_dir)],
    )
    raw = registry.REGISTRY["opengrep"].run(ctx)
    assert raw["results"][0]["check_id"] == "py-exec"
    assert raw["results"][0][ORIGINAL_KEY] == prefixed


@pytest.mark.skipif(subprocess.run(["which", "opengrep"], capture_output=True).returncode != 0,
                    reason="opengrep not installed")
def test_real_opengrep_prefix_is_stripped(rules_dir, tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("py_eval(user_input)\nhidden_rule(1)\n")
    raw = opengrep_wrapper.run_scan(str(target), report_directory=str(tmp_path / "out"),
                                    opengrep_rules=[str(rules_dir)], timeout=300)
    assert raw["results"], "fixture rule should match"
    assert all(r["check_id"] not in ("py-eval", "hidden-rule") for r in raw["results"])  # prefixed by opengrep
    strip_rule_id_prefixes(raw, [str(rules_dir)])
    assert sorted(r["check_id"] for r in raw["results"]) == ["hidden-rule", "py-eval"]
