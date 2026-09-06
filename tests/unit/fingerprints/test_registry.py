"""Fingerprint version registry, key resolution, legacy matching and alias migration (W1.5)."""

from __future__ import annotations

import json
import logging

import pytest

from dsoinabox.fingerprints.registry import (
    CURRENT_FP_VERSION,
    ENV_KEY_OVERRIDE,
    SUPPORTED_FP_VERSIONS,
    fingerprint_version_status,
    parse_fingerprint,
    resolve_project_key,
)
from dsoinabox.model import Finding
from dsoinabox.run import fingerprint_aliases
from dsoinabox.utils.project_id import derive_project_hmac_key
from dsoinabox.waivers.apply import WaiverEngine, apply_waivers_to_model
from dsoinabox.waivers.loader import load_waiver_data
from dsoinabox.waivers.migrate import load_fingerprint_aliases, migrate_file


class TestRegistry:
    def test_every_tool_has_current_and_supported(self):
        for tool, current in CURRENT_FP_VERSION.items():
            assert current in SUPPORTED_FP_VERSIONS[tool]

    @pytest.mark.parametrize(
        "value, expected",
        [
            ("og:1:RULE:x:abc", ("opengrep", 1, "RULE")),
            ("th:1:SECRET:AWS:abc:R:1234", ("trufflehog", 1, "SECRET")),
            ("gy:1:PKG:CVE-1:abc", ("grype", 1, "PKG")),
            ("ck:1:EXACT:CKV_1:a:1:2", ("checkov", 1, "EXACT")),
            ("th:1:CTXSOFT:AWS:a:b:0", ("trufflehog", 1, "CTXSOFT")),
            ("xx:1:RULE:x:abc", None),
            ("og:one:RULE:x:abc", None),
            ("og:1:RULE", None),
            ("not a fingerprint", None),
        ],
    )
    def test_parse(self, value, expected):
        assert parse_fingerprint(value) == expected

    @pytest.mark.parametrize(
        "value, status",
        [("og:1:RULE:x:abc", "current"), ("og:9:RULE:x:abc", "unsupported"), ("garbage", "unknown")],
    )
    def test_version_status(self, value, status):
        assert fingerprint_version_status(value) == status

    def test_legacy_status_when_registry_declares_it(self, monkeypatch):
        monkeypatch.setitem(SUPPORTED_FP_VERSIONS, "opengrep", (1, 2))
        monkeypatch.setitem(CURRENT_FP_VERSION, "opengrep", 2)
        assert fingerprint_version_status("og:1:RULE:x:abc") == "legacy"
        assert fingerprint_version_status("og:2:RULE:x:abc") == "current"


class TestProjectKey:
    def test_derived_from_project_id(self, monkeypatch):
        monkeypatch.delenv(ENV_KEY_OVERRIDE, raising=False)
        assert resolve_project_key("github.com/a/b") == derive_project_hmac_key("github.com/a/b")

    def test_missing_project_id_raises(self, monkeypatch):
        monkeypatch.delenv(ENV_KEY_OVERRIDE, raising=False)
        with pytest.raises(ValueError, match="project id is required"):
            resolve_project_key(None)

    def test_env_override_wins_and_warns_once(self, monkeypatch, caplog):
        import dsoinabox.fingerprints.registry as reg

        monkeypatch.setenv(ENV_KEY_OVERRIDE, "override-key")
        monkeypatch.setattr(reg, "_env_key_warned", False)
        with caplog.at_level(logging.WARNING, logger="dsoinabox.fingerprints.registry"):
            assert resolve_project_key("anything") == b"override-key"
            assert resolve_project_key(None) == b"override-key"
        assert sum(ENV_KEY_OVERRIDE in m for m in caplog.messages) == 1

    def test_no_placeholder_keys_remain(self):
        import pathlib

        src = "".join(p.read_text() for p in pathlib.Path("dsoinabox/fingerprints").glob("*.py"))
        assert "32-bytes-from-kms" not in src.replace("#", "")  # commented example text aside
        assert 'repo_hint = "psf/requests"' not in src


class TestLegacyMatching:
    def _finding(self):
        return Finding(tool="opengrep", category="sast", rule_id="r", path="a.py",
                       fingerprints={"rule": "og:2:RULE:r:new"}, legacy_fingerprints=["og:1:RULE:r:old"],
                       raw={"fingerprints": {"rule": "og:2:RULE:r:new", "legacy": ["og:1:RULE:r:old"]}})

    def test_waiver_written_against_legacy_fingerprint_still_matches(self):
        ws = load_waiver_data({"schema_version": "1.1", "finding_waivers": [{"fingerprint": "og:1:RULE:r:old", "type": "false_positive"}]})
        f = self._finding()
        usage = apply_waivers_to_model("opengrep", [f], WaiverEngine(ws))
        assert f.waived and f.waived_by["fingerprint"] == "og:1:RULE:r:old"
        assert f.raw["waived"] is True and usage.waived == 1

    def test_aliases_map_legacy_to_current_same_tier(self):
        f = self._finding()
        f.fingerprints["ctx"] = "og:2:CTX:r:c2"
        f.legacy_fingerprints.append("og:1:CTX:r:c1")
        assert fingerprint_aliases([f]) == {"og:1:RULE:r:old": "og:2:RULE:r:new", "og:1:CTX:r:c1": "og:2:CTX:r:c2"}

    def test_no_legacy_means_no_aliases(self):
        f = self._finding()
        f.legacy_fingerprints = []
        assert fingerprint_aliases([f]) == {}


class TestMigrateFromReport:
    def test_rewrites_legacy_fingerprints_and_keeps_comments(self, tmp_path):
        report = tmp_path / "report.json"
        report.write_text(json.dumps({"metadata": {"fingerprint_aliases": {"og:1:RULE:r:old": "og:2:RULE:r:new"}}}))
        waivers = tmp_path / "w.yaml"
        waivers.write_text(
            'schema_version: "1.1"\n'
            'finding_waivers:\n'
            '  - fingerprint: "og:1:RULE:r:old"  # keep me\n'
            '    type: false_positive\n'
            '  - fingerprint: "og:1:RULE:other:x"\n'
            '    type: false_positive\n'
            'benchmark:\n'
            '  - fingerprint: "og:1:RULE:r:old"\n'
        )
        aliases = load_fingerprint_aliases(report)
        result = migrate_file(waivers, in_place=True, aliases=aliases)
        assert result.changed
        text = waivers.read_text()
        assert text.count('"og:2:RULE:r:new"') == 2 and "# keep me" in text and '"og:1:RULE:other:x"' in text
        assert any("finding_waivers[0]: fingerprint og:1:RULE:r:old -> og:2:RULE:r:new" in n for n in result.notes)

    def test_bad_report(self, tmp_path):
        p = tmp_path / "r.json"
        p.write_text("[]")
        with pytest.raises(ValueError, match="not a dsoinabox JSON report"):
            load_fingerprint_aliases(p)

    def test_cli_from_report(self, tmp_path, capsys):
        from dsoinabox.cli import main

        report = tmp_path / "report.json"
        report.write_text(json.dumps({"fingerprint_aliases": {"og:1:RULE:r:old": "og:2:RULE:r:new"}}))
        waivers = tmp_path / "w.yaml"
        waivers.write_text('schema_version: "1.1"\nfinding_waivers:\n  - fingerprint: "og:1:RULE:r:old"\n    type: false_positive\n')
        assert main(["waivers", "migrate", "--in-place", "--from-report", str(report), str(waivers)]) == 0
        out = capsys.readouterr().out
        assert "1 fingerprint alias(es) loaded" in out and "og:2:RULE:r:new" in waivers.read_text()

    def test_validate_reports_fingerprint_version_problems(self, tmp_path, capsys):
        from dsoinabox.cli import main

        waivers = tmp_path / "w.yaml"
        waivers.write_text('schema_version: "1.1"\nfinding_waivers:\n  - fingerprint: "og:9:RULE:r:x"\n    type: false_positive\n  - fingerprint: "nonsense"\n    type: false_positive\n')
        assert main(["waivers", "validate", "--strict", str(waivers)]) == 1
        out = capsys.readouterr().out
        assert "unsupported fingerprint version" in out and "not in <tool>:<version>:<TIER>" in out
