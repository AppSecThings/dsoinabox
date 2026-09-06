"""Tests for `dsoinabox waivers migrate` (W1.4) and benchmark file parity (W1.7)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from dsoinabox.waivers.loader import load_waiver_file
from dsoinabox.waivers.migrate import (
    load_round_trip,
    migrate_data,
    migrate_file,
    migration_path,
)
from dsoinabox.waivers.schema import CURRENT_SCHEMA_VERSION, SUPPORTED_SCHEMA_VERSIONS

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "waivers"


def _copy(tmp_path: Path, version: str, name: str) -> Path:
    dst = tmp_path / f"{name}.yaml"
    shutil.copy(FIXTURES / f"v{version}" / f"{name}.yaml", dst)
    return dst


class TestMigrationPath:
    def test_full_chain_is_registered(self):
        steps = migration_path(SUPPORTED_SCHEMA_VERSIONS[0], CURRENT_SCHEMA_VERSION)
        assert steps == [("1.0", "1.1")]

    def test_no_op_path(self):
        assert migration_path("1.1", "1.1") == []

    def test_backwards_is_rejected(self):
        with pytest.raises(ValueError, match="backwards"):
            migration_path("1.1", "1.0")


class TestMigrate10To11:
    def test_golden_equivalence_with_1_1_fixture(self, tmp_path):
        src = _copy(tmp_path, "1.0", "full")
        result = migrate_file(src, dry_run=True)
        assert result.from_version == "1.0" and result.to_version == "1.1" and result.changed
        migrated = yaml.safe_load(result.migrated_text)
        expected = yaml.safe_load((FIXTURES / "v1.1" / "full.yaml").read_text())
        assert migrated == expected

    def test_comments_and_order_survive(self, tmp_path):
        src = _copy(tmp_path, "1.0", "full")
        text = migrate_file(src, dry_run=True).migrated_text
        assert "# keep: comments must survive migration" in text
        assert "# already expired" in text
        assert "# overridden to benchmark on load" in text
        # key order: schema_version first, then meta, path_exclusions, finding_waivers, benchmark
        positions = [text.index(k) for k in ("schema_version", "meta:", "path_exclusions:", "finding_waivers:", "benchmark:")]
        assert positions == sorted(positions)
        assert 'schema_version: "1.1"' in text

    def test_meta_ticket_renamed_in_place(self, tmp_path):
        src = _copy(tmp_path, "1.0", "full")
        result = migrate_file(src, dry_run=True)
        assert any("renamed meta_ticket to ticket" in n for n in result.notes)
        assert "meta_ticket" not in result.migrated_text

    def test_meta_ticket_dropped_when_ticket_present(self, tmp_path):
        p = tmp_path / "w.yaml"
        p.write_text('schema_version: "1.0"\nfinding_waivers:\n  - fingerprint: "og:1:RULE:a:b"\n    type: false_positive\n    ticket: A\n    meta_ticket: B\n')
        result = migrate_file(p, dry_run=True)
        assert any("dropped meta_ticket" in n for n in result.notes)
        loaded = yaml.safe_load(result.migrated_text)
        assert loaded["finding_waivers"][0]["ticket"] == "A"
        assert "meta_ticket" not in loaded["finding_waivers"][0]

    def test_missing_version_is_added(self, tmp_path):
        src = _copy(tmp_path, "1.0", "missing_version")
        result = migrate_file(src, dry_run=True)
        assert result.migrated_text.startswith('# no schema_version') or 'schema_version: "1.1"' in result.migrated_text
        assert any("missing" in n for n in result.notes)

    def test_unquoted_version_becomes_quoted(self, tmp_path):
        src = _copy(tmp_path, "1.0", "unquoted_version_and_dates")
        text = migrate_file(src, dry_run=True).migrated_text
        assert 'schema_version: "1.1"' in text
        # unquoted dates are left alone: still valid YAML timestamps
        assert "expires_at: 2099-01-01" in text

    def test_migrated_output_loads_as_current_without_warnings(self, tmp_path):
        src = _copy(tmp_path, "1.0", "full")
        out = tmp_path / "out.yaml"
        migrate_file(src, output=out)
        ws = load_waiver_file(str(out))
        assert ws.schema_version == CURRENT_SCHEMA_VERSION
        assert ws.warnings == []

    def test_idempotent(self, tmp_path):
        src = _copy(tmp_path, "1.1", "full")
        result = migrate_file(src, dry_run=True)
        assert not result.changed
        assert result.migrated_text == result.original_text

    def test_dry_run_writes_nothing(self, tmp_path):
        src = _copy(tmp_path, "1.0", "full")
        before = src.read_text()
        migrate_file(src, in_place=True, dry_run=True)
        assert src.read_text() == before
        assert not (tmp_path / "full.yaml.bak").exists()

    def test_in_place_keeps_backup(self, tmp_path):
        src = _copy(tmp_path, "1.0", "full")
        before = src.read_text()
        result = migrate_file(src, in_place=True)
        assert result.output_path == src and result.backup_path is not None
        assert result.backup_path.read_text() == before
        assert 'schema_version: "1.1"' in src.read_text()

    def test_to_intermediate_version(self, tmp_path):
        src = _copy(tmp_path, "1.0", "minimal")
        result = migrate_file(src, to_version="1.0", dry_run=True)
        assert result.to_version == "1.0" and not result.changed

    def test_invalid_result_is_rejected(self, tmp_path):
        p = tmp_path / "w.yaml"
        p.write_text('schema_version: "1.0"\nfinding_waivers:\n  - fingerprint: "x"\n    type: nope\n')
        with pytest.raises(ValueError, match="Invalid finding_waiver type"):
            migrate_file(p, dry_run=True)

    def test_future_version_cannot_migrate(self, tmp_path):
        src = _copy(tmp_path, "1.0", "future_version")
        with pytest.raises(ValueError, match="Cannot migrate"):
            migrate_file(src, dry_run=True)

    def test_migrate_data_directly(self, tmp_path):
        data = load_round_trip(_copy(tmp_path, "1.0", "minimal"))
        from_v, to_v, _ = migrate_data(data)
        assert (from_v, to_v) == ("1.0", CURRENT_SCHEMA_VERSION)
        assert str(data["schema_version"]) == CURRENT_SCHEMA_VERSION


class TestBenchmarkParity:
    def test_generated_benchmark_is_current_schema_and_loads(self, tmp_path):
        from dsoinabox.waivers.benchmark import generate_benchmark_yaml

        out = tmp_path / "benchmark.yaml"
        generate_benchmark_yaml(
            trufflehog_data=[{"fingerprints": {"secret": "th:1:SECRET:AWS:abc"}}],
            opengrep_data={"results": [{"fingerprints": {"rule": "og:1:RULE:r:abc"}}]},
            grype_data=None,
            checkov_data=None,
            output_path=str(out),
        )
        ws = load_waiver_file(str(out))
        assert ws.schema_version == CURRENT_SCHEMA_VERSION
        assert [b.fingerprint for b in ws.benchmark] == ["th:1:SECRET:AWS:abc", "og:1:RULE:r:abc"]
        assert ws.warnings == []

    def test_old_benchmark_file_migrates(self, tmp_path):
        p = tmp_path / "benchmark.yaml"
        p.write_text('schema_version: "1.0"\nbenchmark:\n  - fingerprint: "og:1:RULE:a:b"\n    type: benchmark\n')
        result = migrate_file(p, in_place=True)
        assert result.changed
        assert load_waiver_file(str(p)).schema_version == CURRENT_SCHEMA_VERSION
