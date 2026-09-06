"""Normalized Finding model and per-tool normalizers (W3.1)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from dsoinabox.model import (
    SEVERITY_ORDER,
    Severity,
    normalize_severity,
    parse_threshold,
    severity_at_or_above,
    severity_from_security_score,
)
from dsoinabox.normalize import normalize

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "scanner_outputs"


def load(name: str):
    return json.loads((FIXTURES / f"{name}.json").read_text())


class TestSeverity:
    @pytest.mark.parametrize(
        "tool, raw, expected",
        [
            ("opengrep", "ERROR", Severity.high),
            ("opengrep", "WARNING", Severity.medium),
            ("opengrep", "INFO", Severity.low),
            ("opengrep", "critical", Severity.critical),
            ("opengrep", "bogus", Severity.unknown),
            ("grype", "Negligible", Severity.info),
            ("grype", "Unknown", Severity.unknown),
            ("grype", "High", Severity.high),
            ("checkov", "error", Severity.high),
            ("checkov", "warning", Severity.medium),
            ("checkov", "note", Severity.low),
            ("checkov", "none", Severity.info),
            ("trufflehog", None, Severity.high),
            ("other", "medium", Severity.medium),
        ],
    )
    def test_normalize_severity(self, tool, raw, expected):
        assert normalize_severity(tool, raw) is expected

    @pytest.mark.parametrize("score, expected", [(9.5, Severity.critical), (7.0, Severity.high), (5, Severity.medium), ("2.5", Severity.low), (0, Severity.info), (None, None), ("x", None)])
    def test_security_score(self, score, expected):
        assert severity_from_security_score(score) is expected

    @pytest.mark.parametrize("value, expected", [("none", None), (None, None), ("", None), ("HIGH", Severity.high), ("warning", Severity.medium), ("error", Severity.high)])
    def test_parse_threshold(self, value, expected):
        assert parse_threshold(value) is expected

    def test_parse_threshold_rejects_garbage(self):
        with pytest.raises(ValueError, match="Invalid severity threshold"):
            parse_threshold("urgent")

    def test_at_or_above(self):
        assert severity_at_or_above(Severity.critical, Severity.high)
        assert severity_at_or_above(Severity.high, Severity.high)
        assert not severity_at_or_above(Severity.medium, Severity.high)
        assert not severity_at_or_above(Severity.unknown, Severity.info)
        assert severity_at_or_above(Severity.info, Severity.info)

    @given(st.sampled_from(list(SEVERITY_ORDER)), st.sampled_from([s for s in SEVERITY_ORDER if s is not Severity.unknown]))
    def test_at_or_above_is_consistent_with_order(self, sev, thr):
        expected = sev is not Severity.unknown and SEVERITY_ORDER.index(sev) <= SEVERITY_ORDER.index(thr)
        assert severity_at_or_above(sev, thr) is expected


class TestNormalizers:
    def test_opengrep(self):
        findings = normalize("opengrep", load("opengrep"), "/scan_target")
        assert findings and all(f.tool == "opengrep" and f.category == "sast" for f in findings)
        first = findings[0]
        assert first.rule_id == "test.rule.high" and first.severity is Severity.high
        assert first.path == "src/file.py" and first.start_line == 10 and first.end_line == 10
        assert first.raw is load("opengrep")["results"][0] or first.raw["check_id"] == "test.rule.high"

    def test_opengrep_legacy_severity_and_absolute_path(self):
        raw = {"results": [{"check_id": "r", "path": "/scan_target/a/b.py", "extra": {"severity": "WARNING", "lines": "x()"}, "start": {"line": 3, "col": 1}}]}
        f = normalize("opengrep", raw, "/scan_target")[0]
        assert f.severity is Severity.medium and f.original_severity == "WARNING"
        assert f.path == "a/b.py" and f.end_line == 3 and f.snippet == "x()"

    def test_trufflehog(self):
        findings = normalize("trufflehog", load("trufflehog"), "/scan_target")
        f = findings[0]
        assert f.category == "secret" and f.severity is Severity.high
        assert f.rule_id == "AWS" and f.path == "config/secrets.yaml" and f.start_line == 5
        assert "Redacted" in f.message

    def test_grype(self):
        findings = normalize("grype", load("grype"), "/scan_target")
        f = findings[0]
        assert f.category == "sca" and f.rule_id == "CVE-2024-1234" and f.severity is Severity.high
        assert f.package is not None and f.package.name == "test-package" and f.package.version == "1.0.0"

    def test_checkov(self):
        findings = normalize("checkov", load("checkov"), "/scan_target")
        f = findings[0]
        assert f.category == "iac" and f.rule_id == "CKV_AWS_123" and f.path == "main.tf" and f.start_line == 10
        assert f.severity is Severity.high

    def test_checkov_security_severity_overrides_level(self):
        raw = {"runs": [{"tool": {"driver": {"rules": [{"id": "CKV_1", "properties": {"security-severity": 9.1}, "helpUri": "https://x"}]}},
                         "results": [{"ruleIndex": 0, "level": "note", "message": {"text": "m"}}]}]}
        f = normalize("checkov", raw, None)[0]
        assert f.severity is Severity.critical and f.rule_id == "CKV_1" and f.references == ["https://x"]

    def test_waiver_annotations_are_read_from_raw(self):
        raw = {"results": [{"check_id": "r", "path": "a.py", "extra": {}, "fingerprints": {"rule": "og:1:RULE:r:x", "legacy": ["og:0:RULE:r:y"]},
                            "waived": True, "waived_by": {"kind": "finding_waiver"}, "expired_waivers": [{"ref": "x"}]}]}
        f = normalize("opengrep", raw, None)[0]
        assert f.waived and f.waived_by == {"kind": "finding_waiver"} and f.expired_waivers == [{"ref": "x"}]
        assert f.fingerprints == {"rule": "og:1:RULE:r:x"} and f.legacy_fingerprints == ["og:0:RULE:r:y"]
        assert f.primary_fingerprint == "og:1:RULE:r:x"

    @pytest.mark.parametrize("tool", ["opengrep", "grype", "checkov", "trufflehog"])
    @pytest.mark.parametrize("raw", [None, {}, [], {"results": None}, {"matches": [None, 1]}, {"runs": []}])
    def test_garbage_in_is_empty_or_skipped(self, tool, raw):
        out = normalize(tool, raw, None)
        assert isinstance(out, list)

    def test_unknown_tool(self):
        assert normalize("bandit", {"results": [1]}, None) == []

    def test_report_dict_includes_raw(self):
        f = normalize("opengrep", load("opengrep"), None)[0]
        d = f.to_report_dict()
        assert d["severity"] == "high" and d["raw"]["check_id"] == "test.rule.high"
