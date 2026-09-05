"""Schema version policy and cross-version compatibility tests (W1.1, W1.2, W1.3, W1.6)."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from hypothesis import given, settings
from hypothesis import strategies as st

from dsoinabox.waivers import jsonschema as schema_files
from dsoinabox.waivers.loader import load_waiver_data, load_waiver_file
from dsoinabox.waivers.matcher import check_waiver
from dsoinabox.waivers.models import (
    SCHEMA_MODELS,
    WaiverSet,
    format_datetime,
    parse_datetime,
)
from dsoinabox.waivers.schema import (
    CURRENT_SCHEMA_VERSION,
    DEPRECATED_SCHEMA_VERSIONS,
    SUPPORTED_SCHEMA_VERSIONS,
    SchemaVersionError,
    UnsupportedSchemaVersionError,
    normalize_version,
    resolve_version,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "waivers"


def fixture(version: str, name: str) -> Path:
    return FIXTURES / f"v{version}" / f"{name}.yaml"


# ---------------------------------------------------------------------------
# version policy
# ---------------------------------------------------------------------------

class TestVersionPolicy:
    def test_constants_are_consistent(self):
        assert CURRENT_SCHEMA_VERSION in SUPPORTED_SCHEMA_VERSIONS
        assert CURRENT_SCHEMA_VERSION not in DEPRECATED_SCHEMA_VERSIONS
        assert set(SCHEMA_MODELS) == set(SUPPORTED_SCHEMA_VERSIONS)
        assert list(SUPPORTED_SCHEMA_VERSIONS) == sorted(SUPPORTED_SCHEMA_VERSIONS, key=lambda v: tuple(map(int, v.split("."))))

    @pytest.mark.parametrize(
        "raw, expected",
        [("1.0", "1.0"), ("1.1", "1.1"), (1.0, "1.0"), (1.1, "1.1"), (1, "1.0"), (" 1.0 ", "1.0"), ("01.00", "1.0")],
    )
    def test_normalize_version(self, raw, expected):
        assert normalize_version(raw) == expected

    @pytest.mark.parametrize("raw", ["", "one", "1.0.0", "1.x", True, None, [1, 0]])
    def test_normalize_version_rejects_malformed(self, raw):
        with pytest.raises(SchemaVersionError):
            normalize_version(raw)

    def test_missing_version_is_oldest_with_warning(self):
        version, warnings = resolve_version(None)
        assert version == "1.0"
        assert any("missing" in w for w in warnings)

    def test_deprecated_version_warns_with_migrate_hint(self):
        version, warnings = resolve_version("1.0")
        assert version == "1.0"
        assert any("deprecated" in w and "migrate" in w for w in warnings)

    def test_current_version_has_no_warnings(self):
        version, warnings = resolve_version(CURRENT_SCHEMA_VERSION)
        assert version == CURRENT_SCHEMA_VERSION
        assert warnings == []

    def test_unquoted_version_warns_but_loads(self):
        version, warnings = resolve_version(1.0)
        assert version == "1.0"
        assert any("quoted string" in w for w in warnings)

    def test_future_version_names_newest_supported(self):
        with pytest.raises(UnsupportedSchemaVersionError, match=f"up to {CURRENT_SCHEMA_VERSION}"):
            resolve_version("7.3")

    def test_future_minor_of_current_major_is_rejected(self):
        with pytest.raises(UnsupportedSchemaVersionError):
            resolve_version("1.99")


# ---------------------------------------------------------------------------
# loading every fixture
# ---------------------------------------------------------------------------

VALID_FIXTURES = [
    ("1.0", "full"), ("1.0", "minimal"), ("1.0", "missing_version"),
    ("1.0", "unquoted_version_and_dates"), ("1.0", "unknown_keys"),
    ("1.1", "full"), ("1.1", "minimal"), ("1.1", "new_fields"),
]


class TestFixtureLoading:
    @pytest.mark.parametrize("version, name", VALID_FIXTURES)
    def test_valid_fixture_loads(self, version, name):
        ws = load_waiver_file(str(fixture(version, name)))
        assert isinstance(ws, WaiverSet)
        assert ws.schema_version == version
        assert ws.source_path == str(fixture(version, name))

    def test_full_1_0_and_1_1_produce_same_waivers(self):
        a = load_waiver_file(str(fixture("1.0", "full")))
        b = load_waiver_file(str(fixture("1.1", "full")))
        assert a.to_dict()["finding_waivers"] == b.to_dict()["finding_waivers"]
        assert a.to_dict()["path_exclusions"] == b.to_dict()["path_exclusions"]
        assert a.to_dict()["benchmark"] == b.to_dict()["benchmark"]
        # 1.0's meta_ticket became ticket
        assert a.finding_waivers[0].ticket == "SEC-1420"
        assert a.deprecated and not b.deprecated

    def test_same_match_results_across_versions(self):
        a = load_waiver_file(str(fixture("1.0", "full")))
        b = load_waiver_file(str(fixture("1.1", "full")))
        for fp in [w.fingerprint for w in a.finding_waivers] + [e.fingerprint for e in a.benchmark]:
            assert check_waiver({"x": fp}, a) is True
            assert check_waiver({"x": fp}, b) is True
        assert check_waiver({"x": "og:1:RULE:nope"}, a) is False

    def test_missing_version_fixture_warns(self, caplog):
        with caplog.at_level(logging.WARNING, logger="dsoinabox.waivers"):
            ws = load_waiver_file(str(fixture("1.0", "missing_version")))
        assert ws.schema_version == "1.0"
        assert any("schema_version is missing" in m for m in caplog.messages)

    def test_deprecated_fixture_logs_migrate_hint(self, caplog):
        with caplog.at_level(logging.WARNING, logger="dsoinabox.waivers"):
            load_waiver_file(str(fixture("1.0", "minimal")))
        assert any("deprecated" in m and "waivers migrate" in m for m in caplog.messages)

    def test_current_fixture_is_silent(self, caplog):
        with caplog.at_level(logging.WARNING, logger="dsoinabox.waivers"):
            ws = load_waiver_file(str(fixture("1.1", "minimal")))
        assert ws.warnings == []
        assert caplog.messages == []

    def test_unquoted_dates_are_parsed(self):
        ws = load_waiver_file(str(fixture("1.0", "unquoted_version_and_dates")))
        fw = ws.finding_waivers[0]
        assert fw.expires_at == datetime(2099, 1, 1, tzinfo=timezone.utc)
        assert fw.created_at == datetime(2025, 11, 8, 14, 20, tzinfo=timezone.utc)

    def test_unknown_keys_warn_and_are_ignored(self):
        ws = load_waiver_file(str(fixture("1.0", "unknown_keys")))
        joined = "\n".join(ws.warnings)
        assert "unknown key 'owner_team' in top level" in joined
        assert "unknown key 'justification' in finding_waivers[0]" in joined
        assert "justification" not in ws.to_dict()["finding_waivers"][0]

    def test_new_1_1_fields(self):
        ws = load_waiver_file(str(fixture("1.1", "new_fields")))
        assert ws.finding_waivers[0].tools == ["sast"]
        assert ws.finding_waivers[0].ticket == "SEC-1"
        assert ws.benchmark_expires_at == datetime(2099, 6, 30, tzinfo=timezone.utc)
        assert ws.benchmark[0].type == "benchmark"
        assert ws.meta["schema_url"].endswith("waivers-1.1.schema.json")

    def test_tools_are_normalized(self):
        ws = load_waiver_data({"schema_version": "1.1", "path_exclusions": [{"pattern": "x/**", "tools": "Secrets"}]})
        assert ws.path_exclusions[0].tools == ["secret"]


class TestFixtureErrors:
    def test_invalid_type(self):
        with pytest.raises(ValueError, match="Invalid finding_waiver type: accepted"):
            load_waiver_file(str(fixture("1.0", "invalid_type")))

    def test_invalid_date(self):
        with pytest.raises(ValueError, match="Invalid date 'next tuesday'"):
            load_waiver_file(str(fixture("1.0", "invalid_date")))

    def test_future_version(self):
        with pytest.raises(ValueError, match="Unsupported waiver schema version: 7.3"):
            load_waiver_file(str(fixture("1.0", "future_version")))

    def test_bad_tool_scope(self):
        with pytest.raises(ValueError, match="unknown tool 'bandit'"):
            load_waiver_file(str(fixture("1.1", "bad_tool_scope")))

    def test_empty_fingerprint(self):
        with pytest.raises(ValueError, match="'fingerprint' must not be empty"):
            load_waiver_data({"schema_version": "1.1", "finding_waivers": [{"fingerprint": "", "type": "false_positive"}]})

    def test_empty_file_is_empty_set(self, tmp_path):
        p = tmp_path / "w.yaml"
        p.write_text("")
        ws = load_waiver_file(str(p))
        assert ws.finding_waivers == [] and ws.schema_version == "1.0"


# ---------------------------------------------------------------------------
# dates
# ---------------------------------------------------------------------------

class TestDates:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("2026-01-31", datetime(2026, 1, 31, tzinfo=timezone.utc)),
            ("2026-01-31T10:20:30Z", datetime(2026, 1, 31, 10, 20, 30, tzinfo=timezone.utc)),
            ("2026-01-31T10:20:30+02:00", datetime(2026, 1, 31, 8, 20, 30, tzinfo=timezone.utc)),
            ("2026-01-31T10:20:30", datetime(2026, 1, 31, 10, 20, 30, tzinfo=timezone.utc)),
            (None, None),
            ("", None),
        ],
    )
    def test_parse_datetime(self, raw, expected):
        assert parse_datetime(raw) == expected

    def test_format_roundtrip_date_only(self):
        assert format_datetime(parse_datetime("2026-01-31")) == "2026-01-31"

    def test_format_roundtrip_full(self):
        assert format_datetime(parse_datetime("2026-01-31T10:20:30Z")) == "2026-01-31T10:20:30Z"


# ---------------------------------------------------------------------------
# round trip property
# ---------------------------------------------------------------------------

fingerprint_st = st.from_regex(r"\A(og|th|gy|ck):1:[A-Z]{3,7}:[a-z0-9._-]{1,20}:[0-9a-f]{8}\Z")
type_st = st.sampled_from(["false_positive", "risk_acceptance", "policy_waiver"])
text_st = st.text(alphabet=st.characters(blacklist_categories=("Cs", "Cc")), min_size=1, max_size=40)


@settings(max_examples=60, deadline=None)
@given(
    st.lists(
        st.fixed_dictionaries(
            {"fingerprint": fingerprint_st, "type": type_st},
            optional={"reason": text_st, "ticket": text_st, "expires_at": st.just("2099-01-01")},
        ),
        max_size=5,
    )
)
def test_to_dict_reload_is_stable(waivers):
    ws = load_waiver_data({"schema_version": CURRENT_SCHEMA_VERSION, "finding_waivers": waivers})
    again = load_waiver_data(ws.to_dict())
    assert again.to_dict() == ws.to_dict()
    assert again.schema_version == CURRENT_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# json schema files (W1.6)
# ---------------------------------------------------------------------------

class TestJsonSchemaFiles:
    @pytest.mark.parametrize("version", SUPPORTED_SCHEMA_VERSIONS)
    def test_checked_in_schema_matches_models(self, version):
        generated = schema_files.generate_schema(version)
        checked_in = schema_files.load_checked_in(version)
        assert checked_in == generated, (
            f"waivers-{version}.schema.json is stale; run `python -m dsoinabox.waivers.jsonschema --write`"
        )

    @pytest.mark.parametrize("version, name", VALID_FIXTURES)
    def test_fixtures_validate_against_their_schema(self, version, name):
        jsonschema = pytest.importorskip("jsonschema")
        data = yaml.safe_load(fixture(version, name).read_text()) or {}
        data.setdefault("schema_version", version)
        # yaml may have produced date objects; the JSON Schema sees strings
        data = json.loads(json.dumps(data, default=str))
        if not isinstance(data.get("schema_version"), str):
            data["schema_version"] = version
        jsonschema.validate(data, schema_files.load_checked_in(version))

    def test_schema_ids_are_versioned(self):
        for version in SUPPORTED_SCHEMA_VERSIONS:
            assert schema_files.load_checked_in(version)["$id"].endswith(f"waivers-{version}.schema.json")
