"""Freeze tests for fingerprint version 1 algorithms.

Policy (see docs/waivers/compatibility.md): a released fingerprint version is
frozen forever. Waiver files in the wild contain these exact strings. Any
change to a v1 string means an algorithm change, which must ship as a new
fingerprint version instead. If this test fails, do not update the golden
file; add a version 2 algorithm and keep version 1 byte-identical.

The golden file is tests/unit/fingerprints/golden_v1.json. It was captured
from the 0.1.6 implementation before any refactoring. To regenerate it
deliberately (only when adding cases, never when changing outputs), run:

    python -m tests.unit.fingerprints.test_golden_v1 --write
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

GOLDEN_PATH = Path(__file__).with_name("golden_v1.json")
PROJECT_ID = "github.com/example/frozen-repo"

# fixed file contents used for opengrep and trufflehog location-bound tiers
SOURCE_FILES = {
    "src/app.py": (
        "import os\n"
        "\n"
        "def connect():\n"
        "    # database connection\n"
        "    password = 'hunter2-super-secret'\n"
        "    url = 'postgres://admin:hunter2-super-secret@db.example.com/app'\n"
        "    return os.system('psql ' + url)\n"
    ),
    "config/settings.yaml": (
        "aws:\n"
        "  access_key_id: AKIAIOSFODNN7EXAMPLE\n"
        "  secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "region: us-east-1\r\n"
    ),
    "html/index.html": (
        "<html><head>\n"
        "<script src=\"https://cdn.example.com/lib.js\"></script>\n"
        "</head><body>hi &amp; bye</body></html>\n"
    ),
}


def _write_source_tree(root: Path) -> None:
    for rel, content in SOURCE_FILES.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8"))


def _project_key() -> bytes:
    from dsoinabox.utils.project_id import derive_project_hmac_key

    return derive_project_hmac_key(PROJECT_ID)


def build_cases(root: Path) -> dict[str, dict[str, str]]:
    """Compute every v1 fingerprint case against a source tree at `root`."""
    _write_source_tree(root)
    key = _project_key()
    cases: dict[str, dict[str, str]] = {}

    # ---------------- opengrep ----------------
    from dsoinabox.fingerprints import opengrep as og

    og_findings = {
        "og_span_with_metavars": {
            "check_id": "python.lang.security.audit.dangerous-system-call",
            "path": "src/app.py",
            "start": {"line": 7, "col": 12},
            "end": {"line": 7, "col": 38},
            "extra": {
                "severity": "ERROR",
                "message": "os.system with dynamic input",
                "lines": "    return os.system('psql ' + url)",
                "metavars": {
                    "$CMD": {"abstract_content": "'psql ' + url"},
                    "$X": {"abstract_content": "os"},
                },
            },
        },
        "og_snippet_only_no_span": {
            "check_id": "html.security.audit.missing-integrity",
            "path": "html/index.html",
            "extra": {
                "severity": "WARNING",
                "lines": '<script src="https://cdn.example.com/lib.js"></script>',
            },
        },
        "og_no_anchor": {
            "check_id": "generic.rule",
            "path": "config/settings.yaml",
            "extra": {"severity": "INFO"},
        },
    }
    for name, finding in og_findings.items():
        rule_fp, exact_fp, ctx_fp = og.fingerprint_opengrep(
            finding=finding, repo_root=str(root), project_key=key, repo_hint=PROJECT_ID
        )
        cases[name] = {"rule": rule_fp, "exact": exact_fp, "ctx": ctx_fp}

    # unlocatable path through the batch driver
    missing = {"results": [{"check_id": "x.rule", "path": "does/not/exist.py", "extra": {"lines": "foo()"}}]}
    og.fingerprint_findings(missing, str(root), project_id=PROJECT_ID)
    cases["og_unlocatable"] = dict(missing["results"][0]["fingerprints"])

    # ---------------- trufflehog ----------------
    # v1 quirk worth knowing: in filesystem mode the CTX and CTXSOFT tiers hash
    # the absolute on-disk path, so they are environment-dependent. Git-mode
    # findings hash the repo-relative path. Git mode is used for every tier
    # here; one filesystem case freezes only the path-independent tiers.
    from dsoinabox.fingerprints import trufflehog as th

    FROZEN_HEAD = "deadbeefcafe0000000000000000000000000000"
    th_findings = [
        {   # git mode, exact span, CRLF in file
            "DetectorName": "AWS",
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "RawV2": "AKIAIOSFODNN7EXAMPLE",
            "SourceMetadata": {"Data": {"Git": {"file": "config/settings.yaml", "line": 2, "commit": FROZEN_HEAD}}},
        },
        {   # git mode, uri-ish detector
            "DetectorName": "URI",
            "Raw": "postgres://admin:hunter2-super-secret@db.example.com/app",
            "SourceMetadata": {"Data": {"Git": {"file": "src/app.py", "line": 6, "commit": FROZEN_HEAD}}},
        },
        {   # candidate not present in file -> ctx_soft (note: no :R suffix in v1)
            "DetectorName": "Generic",
            "Raw": "this-string-is-not-in-the-file",
            "SourceMetadata": {"Data": {"Git": {"file": "src/app.py", "line": 1, "commit": FROZEN_HEAD}}},
        },
        {   # missing file -> secret only
            "DetectorName": "Slack",
            "Raw": "xoxb-not-real-token-value",
            "SourceMetadata": {"Data": {"Filesystem": {"file": "nope/missing.txt"}}},
        },
        {   # hex candidate (lowercased on normalize), html entity in file, no line hint
            "DetectorName": "HexKey",
            "Raw": "DEADBEEFDEADBEEFDEADBEEF",
            "SourceMetadata": {"Data": {"Git": {"file": "html/index.html", "commit": FROZEN_HEAD}}},
        },
        {   # filesystem mode: only secret/exact are frozen (ctx embeds abs path)
            "DetectorName": "AWS",
            "Raw": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "SourceMetadata": {"Data": {"Filesystem": {"file": "config/settings.yaml", "line": 3}}},
        },
    ]
    real_rev_parse = th._rev_parse_head
    th._rev_parse_head = lambda repo_root, cache=None: FROZEN_HEAD
    try:
        th.fingerprint_findings(th_findings, str(root), project_id=PROJECT_ID)
    finally:
        th._rev_parse_head = real_rev_parse
    for i, f in enumerate(th_findings):
        fps = dict(f["fingerprints"])
        if "Filesystem" in f["SourceMetadata"]["Data"]:
            fps.pop("ctx", None)
            fps.pop("ctx_soft", None)
        cases[f"th_{i}_{f['DetectorName'].lower()}"] = {
            **fps,
            "location_status": f.get("location_status", ""),
        }

    # ---------------- grype ----------------
    from dsoinabox.fingerprints import grype as gy

    report = {
        "source": {"type": "directory", "target": {"userInput": "/scan_target"}},
        "distro": {"name": "debian", "version": "12"},
    }
    gy_matches = {
        "gy_full": {
            "vulnerability": {
                "id": "CVE-2024-12345",
                "severity": "High",
                "namespace": "github:language:python",
                "fix": {"versions": ["2.31.1", "2.32.0"]},
            },
            "artifact": {
                "name": "Requests",
                "version": "2.31.0",
                "type": "python",
                "purl": "pkg:pypi/requests@2.31.0",
                "locations": [{"path": "/scan_target/requirements.txt"}, {"path": "src/vendor/req.txt"}],
            },
            "matchDetails": [{"foundBy": "python-matcher"}],
        },
        "gy_minimal_distro_ns": {
            "vulnerability": {"id": "GHSA-xxxx-yyyy-zzzz"},
            "artifact": {"name": "libssl", "version": "3.0.1", "type": "deb"},
        },
    }
    for name, m in gy_matches.items():
        pkg, exact, ctx = gy.fingerprint_grype_match(m, report, key, PROJECT_ID)
        cases[name] = {"pkg": pkg, "exact": exact, "ctx": ctx}

    # ---------------- checkov ----------------
    from dsoinabox.fingerprints import checkov as ck

    sarif = {
        "runs": [{
            "tool": {"driver": {"rules": [
                {"id": "CKV_AWS_20", "properties": {"security-severity": 7.5}},
            ]}},
        }]
    }
    ck_results = {
        "ck_abs_path_with_snippet": {
            "ruleId": "CKV_AWS_20",
            "ruleIndex": 0,
            "level": "error",
            "message": {"text": "S3 bucket public"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "/scan_target/infra/s3.tf"},
                "region": {"startLine": 3, "endLine": 9, "snippet": {"text": "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"public-read\"\n}"}},
            }}],
        },
        "ck_relative_no_snippet": {
            "ruleId": "CKV_K8S_1",
            "level": "warning",
            "message": {"text": "k8s thing"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "k8s/deploy.yaml"},
                "region": {"startLine": 12},
            }}],
        },
        "ck_no_location": {"ruleIndex": 0, "level": "note", "message": {"text": "no loc"}},
    }
    for name, r in ck_results.items():
        rule, exact, ctx = ck.fingerprint_checkov_result(r, sarif, "/scan_target", key, PROJECT_ID)
        cases[name] = {"rule": rule, "exact": exact, "ctx": ctx}

    return cases


def _load_golden() -> dict[str, dict[str, str]]:
    with GOLDEN_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def computed(tmp_path_factory) -> dict[str, dict[str, str]]:
    root = tmp_path_factory.mktemp("frozen_repo")
    return build_cases(root)


def test_golden_file_exists():
    assert GOLDEN_PATH.exists(), "golden_v1.json missing; see module docstring"


def test_case_set_matches_golden(computed):
    golden = _load_golden()
    assert set(computed) == set(golden), (
        "case names differ from golden file; adding cases requires --write, "
        "removing cases is not allowed"
    )


@pytest.mark.parametrize("case", sorted(json.loads(GOLDEN_PATH.read_text())) if GOLDEN_PATH.exists() else [])
def test_v1_fingerprint_is_frozen(computed, case):
    golden = _load_golden()
    assert computed[case] == golden[case], (
        f"v1 fingerprint for {case} changed. v1 is frozen; ship the change as a new "
        "fingerprint version instead of editing v1."
    )


def test_all_v1_strings_declare_version_1(computed):
    for case, fps in computed.items():
        for tier, value in fps.items():
            if tier == "location_status":
                continue
            parts = value.split(":")
            assert parts[0] in {"og", "th", "gy", "ck"}, (case, tier, value)
            assert parts[1] == "1", (case, tier, value)


if __name__ == "__main__":  # pragma: no cover
    if "--write" not in sys.argv:
        print(__doc__)
        sys.exit(2)
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        data = build_cases(Path(tmp))
    GOLDEN_PATH.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(data)} cases to {GOLDEN_PATH}")
