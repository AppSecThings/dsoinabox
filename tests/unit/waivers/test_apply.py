"""Waiver engine tests: path exclusions, expiry, tool scope, type semantics, usage (W2.1 to W2.5)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from dsoinabox.reporting.fields import finding_paths, relativize_path
from dsoinabox.waivers.apply import (
    WaiverEngine,
    WaiverUsage,
    active_findings,
    apply_waivers,
    entry_applies_to_tool,
    waived_findings,
)
from dsoinabox.waivers.loader import load_waiver_data

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)


def ws(**sections):
    data = {"schema_version": "1.1", **sections}
    return load_waiver_data(data)


def og(fp: str, path: str = "src/app.py") -> dict:
    return {"check_id": "r", "path": path, "fingerprints": {"rule": fp, "exact": fp + ":e", "ctx": fp + ":c"}}


def engine(waiver_set, grace_days=0):
    return WaiverEngine(waiver_set, now=NOW, grace_days=grace_days)


# ---------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------

class TestPaths:
    @pytest.mark.parametrize(
        "raw, source, expected",
        [
            ("src/a.py", "/scan_target", "src/a.py"),
            ("./src/a.py", "/scan_target", "src/a.py"),
            ("/scan_target/src/a.py", "/scan_target", "src/a.py"),
            ("/scan_target/src/a.py", "/scan_target/", "src/a.py"),
            ("file:///scan_target/infra/s3.tf", "/scan_target", "infra/s3.tf"),
            ("src\\win\\a.py", "/scan_target", "src/win/a.py"),
            ("/elsewhere/a.py", "/scan_target", "/elsewhere/a.py"),
            ("", "/scan_target", ""),
            (None, "/scan_target", ""),
        ],
    )
    def test_relativize(self, raw, source, expected):
        assert relativize_path(raw, source) == expected

    def test_finding_paths_per_tool(self):
        assert finding_paths({"path": "/s/x.py"}, "opengrep", "/s") == ["x.py"]
        th = {"SourceMetadata": {"Data": {"Git": {"file": "cfg/a.yaml"}}}}
        assert finding_paths(th, "trufflehog", "/s") == ["cfg/a.yaml"]
        gy = {"artifact": {"locations": [{"path": "/s/requirements.txt"}, {"path": "vendor/req.txt"}]}}
        assert finding_paths(gy, "grype", "/s") == ["requirements.txt", "vendor/req.txt"]
        ck = {"locations": [{"physicalLocation": {"artifactLocation": {"uri": "/s/infra/s3.tf"}}}]}
        assert finding_paths(ck, "checkov", "/s") == ["infra/s3.tf"]


# ---------------------------------------------------------------------------
# tool scope
# ---------------------------------------------------------------------------

class TestToolScope:
    @pytest.mark.parametrize(
        "tools, tool, expected",
        [
            (None, "opengrep", True),
            (["all"], "grype", True),
            (["sast"], "opengrep", True),
            (["sast"], "grype", False),
            (["secret"], "trufflehog", True),
            (["secrets"], "trufflehog", True),
            (["iac", "sca"], "checkov", True),
            (["trufflehog"], "opengrep", False),
        ],
    )
    def test_entry_applies_to_tool(self, tools, tool, expected):
        assert entry_applies_to_tool(tools, tool) is expected


# ---------------------------------------------------------------------------
# finding waivers
# ---------------------------------------------------------------------------

class TestFindingWaivers:
    def test_exact_match_any_tier_marks_waived_and_keeps_finding(self):
        w = ws(finding_waivers=[{"fingerprint": "og:1:RULE:a:1:c", "type": "false_positive", "reason": "known", "ticket": "SEC-1"}])
        findings = [og("og:1:RULE:a:1"), og("og:1:RULE:b:2")]
        usage = apply_waivers("opengrep", findings, engine(w), source_path="/s")
        assert [f["waived"] for f in findings] == [True, False]
        assert findings[0]["waived_by"] == {
            "kind": "finding_waiver", "ref": "finding_waivers[0]", "type": "false_positive",
            "fingerprint": "og:1:RULE:a:1:c", "reason": "known", "ticket": "SEC-1",
        }
        assert usage.waived == 1 and usage.waived_by_type["false_positive"] == 1
        assert len(active_findings(findings)) == 1 and len(waived_findings(findings)) == 1

    def test_type_is_carried_through(self):
        w = ws(finding_waivers=[
            {"fingerprint": "A", "type": "risk_acceptance"},
            {"fingerprint": "B", "type": "policy_waiver"},
        ])
        findings = [og("A"), og("B")]
        usage = apply_waivers("opengrep", findings, engine(w))
        assert usage.waived_by_type == {"risk_acceptance": 1, "policy_waiver": 1}

    def test_tool_scope_on_finding_waiver(self):
        w = ws(finding_waivers=[{"fingerprint": "A", "type": "false_positive", "tools": ["sca"]}])
        findings = [og("A")]
        apply_waivers("opengrep", findings, engine(w))
        assert findings[0]["waived"] is False
        apply_waivers("grype", findings, engine(w))
        assert findings[0]["waived"] is True

    def test_benchmark_entry_waives_with_type_benchmark(self):
        w = ws(benchmark=[{"fingerprint": "A"}])
        findings = [og("A")]
        usage = apply_waivers("opengrep", findings, engine(w))
        assert findings[0]["waived_by"]["type"] == "benchmark" and findings[0]["waived_by"]["kind"] == "benchmark"
        assert usage.waived_by_kind == {"benchmark": 1}

    def test_finding_waiver_wins_over_benchmark_and_path(self):
        w = ws(
            finding_waivers=[{"fingerprint": "A", "type": "risk_acceptance"}],
            benchmark=[{"fingerprint": "A"}],
            path_exclusions=[{"pattern": "src/**"}],
        )
        findings = [og("A")]
        usage = apply_waivers("opengrep", findings, engine(w))
        assert findings[0]["waived_by"]["kind"] == "finding_waiver"
        # every active match counts as used
        assert set(usage.matched_refs) == {"finding_waivers[0]", "benchmark[0]", "path_exclusions[0]"}

    def test_no_engine_resets_flags(self):
        findings = [{"fingerprints": {"rule": "A"}, "waived": True, "waived_by": {"x": 1}}]
        apply_waivers("opengrep", findings, None)
        assert findings[0]["waived"] is False and "waived_by" not in findings[0]


# ---------------------------------------------------------------------------
# expiry
# ---------------------------------------------------------------------------

class TestExpiry:
    def test_expired_waiver_does_not_suppress_and_is_annotated(self):
        w = ws(finding_waivers=[{"fingerprint": "A", "type": "false_positive", "expires_at": "2026-01-01", "reason": "old"}])
        findings = [og("A")]
        usage = apply_waivers("opengrep", findings, engine(w))
        assert findings[0]["waived"] is False
        assert findings[0]["expired_waivers"][0]["expired"] is True
        assert findings[0]["expired_waivers"][0]["expires_at"] == "2026-01-01"
        assert usage.expired_matches == 1 and usage.waived == 0
        # an expired entry is not "unused": it matched something
        assert usage.unused_refs(w) == []

    def test_future_expiry_still_waives(self):
        w = ws(finding_waivers=[{"fingerprint": "A", "type": "false_positive", "expires_at": "2027-01-01"}])
        findings = [og("A")]
        apply_waivers("opengrep", findings, engine(w))
        assert findings[0]["waived"] is True and "expiring" not in findings[0]["waived_by"]

    def test_grace_days_keeps_expired_waiver_active_but_flagged(self):
        w = ws(finding_waivers=[{"fingerprint": "A", "type": "false_positive", "expires_at": "2026-09-01"}])
        findings = [og("A")]
        usage = apply_waivers("opengrep", findings, engine(w, grace_days=7))
        assert findings[0]["waived"] is True and findings[0]["waived_by"]["expiring"] is True
        assert usage.expiring_matches == 1

    def test_grace_window_ends(self):
        w = ws(finding_waivers=[{"fingerprint": "A", "type": "false_positive", "expires_at": "2026-08-01"}])
        findings = [og("A")]
        apply_waivers("opengrep", findings, engine(w, grace_days=7))
        assert findings[0]["waived"] is False

    def test_expiry_boundary_is_exclusive(self):
        w = ws(finding_waivers=[{"fingerprint": "A", "type": "false_positive", "expires_at": "2026-09-05T12:00:00Z"}])
        findings = [og("A")]
        apply_waivers("opengrep", findings, engine(w))
        assert findings[0]["waived"] is False

    def test_expired_entry_falls_back_to_other_active_match(self):
        w = ws(
            finding_waivers=[{"fingerprint": "A", "type": "false_positive", "expires_at": "2020-01-01"}],
            benchmark=[{"fingerprint": "A"}],
        )
        findings = [og("A")]
        apply_waivers("opengrep", findings, engine(w))
        assert findings[0]["waived"] is True and findings[0]["waived_by"]["kind"] == "benchmark"
        assert findings[0]["expired_waivers"][0]["ref"] == "finding_waivers[0]"

    def test_benchmark_expires_at_applies_to_all_entries(self):
        w = ws(benchmark_expires_at="2026-01-01", benchmark=[{"fingerprint": "A"}, {"fingerprint": "B", "expires_at": "2099-01-01"}])
        findings = [og("A"), og("B")]
        apply_waivers("opengrep", findings, engine(w))
        assert [f["waived"] for f in findings] == [False, False]

    def test_expired_path_exclusion(self):
        w = ws(path_exclusions=[{"pattern": "src/**", "expires_at": "2020-01-01"}])
        findings = [og("A")]
        apply_waivers("opengrep", findings, engine(w), source_path="/s")
        assert findings[0]["waived"] is False and findings[0]["expired_waivers"][0]["pattern"] == "src/**"


# ---------------------------------------------------------------------------
# path exclusions
# ---------------------------------------------------------------------------

class TestPathExclusions:
    @pytest.mark.parametrize(
        "pattern, path, excluded",
        [
            ("third_party/**", "third_party/lib/x.js", True),
            ("third_party/**", "src/third_party/x.js", False),
            ("**/vendor/**", "a/b/vendor/c/d.go", True),
            ("docs/**/*.md", "docs/guide/intro.md", True),
            ("docs/**/*.md", "docs/intro.md", True),
            ("docs/**/*.md", "docs/intro.txt", False),
            ("*.min.js", "static/app.min.js", True),
            ("build/", "build/out.o", True),
            ("src/app.py", "src/app.py", True),
            ("src/app.py", "src/app.pyc", False),
        ],
    )
    def test_gitwildmatch_patterns(self, pattern, path, excluded):
        w = ws(path_exclusions=[{"pattern": pattern, "reason": "vendored"}])
        findings = [og("A", path=path)]
        apply_waivers("opengrep", findings, engine(w), source_path="/s")
        assert findings[0]["waived"] is excluded
        if excluded:
            assert findings[0]["waived_by"] == {
                "kind": "path_exclusion", "ref": "path_exclusions[0]", "type": "path_exclusion",
                "pattern": pattern, "reason": "vendored",
            }

    def test_absolute_paths_are_relativized_against_source(self):
        w = ws(path_exclusions=[{"pattern": "third_party/**"}])
        findings = [og("A", path="/scan_target/third_party/x.py")]
        apply_waivers("opengrep", findings, engine(w), source_path="/scan_target")
        assert findings[0]["waived"] is True

    def test_tool_scope_on_path_exclusion(self):
        w = ws(path_exclusions=[{"pattern": "docs/**", "tools": ["trufflehog", "opengrep"]}])
        og_f = [og("A", path="docs/x.md")]
        apply_waivers("opengrep", og_f, engine(w))
        assert og_f[0]["waived"] is True
        ck = [{"fingerprints": {"rule": "Z"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "docs/x.md"}}}]}]
        apply_waivers("checkov", ck, engine(w))
        assert ck[0]["waived"] is False

    def test_grype_requires_every_location_excluded(self):
        w = ws(path_exclusions=[{"pattern": "vendor/**"}])
        both = [{"fingerprints": {"pkg": "P"}, "artifact": {"locations": [{"path": "vendor/a/req.txt"}, {"path": "vendor/b/req.txt"}]}}]
        mixed = [{"fingerprints": {"pkg": "P"}, "artifact": {"locations": [{"path": "vendor/a/req.txt"}, {"path": "requirements.txt"}]}}]
        apply_waivers("grype", both, engine(w)); apply_waivers("grype", mixed, engine(w))
        assert both[0]["waived"] is True and mixed[0]["waived"] is False

    def test_finding_without_path_is_not_excluded(self):
        w = ws(path_exclusions=[{"pattern": "**"}])
        findings = [{"fingerprints": {"pkg": "P"}, "artifact": {}}]
        apply_waivers("grype", findings, engine(w))
        assert findings[0]["waived"] is False


# ---------------------------------------------------------------------------
# usage / unused
# ---------------------------------------------------------------------------

class TestUsage:
    def test_unused_entries_reported(self):
        w = ws(
            finding_waivers=[{"fingerprint": "A", "type": "false_positive"}, {"fingerprint": "NOPE", "type": "false_positive"}],
            benchmark=[{"fingerprint": "ALSO-NOPE"}],
            path_exclusions=[{"pattern": "never/**"}],
        )
        usage = apply_waivers("opengrep", [og("A")], engine(w))
        assert usage.unused_refs(w) == ["finding_waivers[1]", "benchmark[0]", "path_exclusions[0]"]
        summary = usage.summary_dict(w)
        assert summary["unused_count"] == 3 and summary["waived"] == 1
        assert summary["entries"] == {"finding_waivers": 2, "benchmark": 1, "path_exclusions": 1}

    def test_merge_across_tools(self):
        w = ws(finding_waivers=[{"fingerprint": "A", "type": "false_positive"}, {"fingerprint": "B", "type": "risk_acceptance"}])
        total = WaiverUsage()
        total.merge(apply_waivers("opengrep", [og("A")], engine(w)))
        total.merge(apply_waivers("grype", [{"fingerprints": {"pkg": "B"}, "artifact": {}}], engine(w)))
        assert total.waived == 2 and total.total_findings == 2
        assert total.unused_refs(w) == []
        assert total.waived_by_type == {"false_positive": 1, "risk_acceptance": 1}


class TestScanRootRelativePaths:
    def test_leading_slash_path_that_exists_under_source_is_relativized(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.19.1\n")
        assert relativize_path("/requirements.txt", str(tmp_path)) == "requirements.txt"

    def test_leading_slash_path_that_does_not_exist_anywhere_is_left_alone(self, tmp_path):
        assert relativize_path("/definitely/not/here.txt", str(tmp_path)) == "/definitely/not/here.txt"

    def test_real_absolute_path_outside_source_is_kept(self, tmp_path):
        outside = tmp_path / "outside.txt"
        outside.write_text("x")
        src = tmp_path / "src"
        src.mkdir()
        assert relativize_path(str(outside), str(src)) == str(outside)

    def test_scan_dir_name_prefix_is_stripped_when_that_resolves(self, tmp_path):
        src = tmp_path / "scan_target"
        (src / "infra").mkdir(parents=True)
        (src / "infra" / "s3.tf").write_text("x")
        assert relativize_path("scan_target/infra/s3.tf", str(src)) == "infra/s3.tf"
        assert relativize_path("/scan_target/infra/s3.tf", str(src)) == "infra/s3.tf"
        # a real directory of that name inside the source wins
        (src / "scan_target").mkdir()
        (src / "scan_target" / "real.tf").write_text("x")
        assert relativize_path("scan_target/real.tf", str(src)) == "scan_target/real.tf"

    def test_checkov_absolute_path_missing_leading_slash(self, tmp_path):
        src = tmp_path / "scan_target"
        (src / "infra").mkdir(parents=True)
        (src / "infra" / "main.tf").write_text("x")
        no_slash = str(src / "infra" / "main.tf").lstrip("/")
        assert relativize_path(no_slash, str(src)) == "infra/main.tf"
