# Output Formats and Report Layout

## Formats

| `-o` value | File | Notes |
|---|---|---|
| `html` | `<name>.html` | single-file interactive report with summary, per-tool tables, waivers section |
| `jenkins_html` | `<name>_jenkins.html` + `assets/` | same content with external assets for Jenkins' CSP |
| `json` | `<name>.json` | machine-readable run: metadata, normalized `findings`, raw per-tool payloads |
| `ndjson` | `<name>.ndjson` | one metadata line, then one finding per line |
| `sarif` | `<name>.sarif` | SARIF 2.1.0, one run per scanner |
| `cyclonedx` | `sbom.cdx.json` | Syft SBOM as CycloneDX JSON (requires `syft` in `--tools`) |
| `spdx` | `sbom.spdx.json` | Syft SBOM as SPDX JSON |

`<name>` is `dsoinabox_unified_report_<timestamp>` unless `--report_name` is set.

## Layout

```text
reports/
├── latest -> dsoinabox_<timestamp>/      # always the newest run (symlink, or a copy on filesystems without symlinks)
└── dsoinabox_<timestamp>/
    ├── <name>.html
    ├── <name>.sarif
    ├── <name>.json
    ├── sbom.cdx.json                     # with -o cyclonedx
    ├── benchmark.yaml                    # with --benchmark
    └── tools_output/                     # with --tool_output: raw checkov.sarif, grype.json, opengrep.json, syft.json, trufflehog.json
```

In Docker, when `/reports` is mounted, the timestamped directory is copied there as well. CI can read
`reports/latest/<name>.sarif` without searching.

## JSON report

```json
{
  "metadata": {
    "dsoinabox_version": "1.0.0",
    "scan_timestamp": "2026_09_05T14_44_34",
    "project_id": "github.com/example/demo",
    "tool_versions": {"opengrep": "1.29.0", "grype": "0.118.0 (db built 2026-09-01...)"},
    "scanners": [{"tool": "opengrep", "status": "ok", "duration_s": 12.3, "findings": 4, "active": 3, "waived": 1}],
    "severity_counts": {"critical": 0, "high": 1, "medium": 2, "low": 0, "info": 0, "unknown": 0},
    "policy": {"failure_threshold": "high", "fail_on_secrets": false, "threshold_exceeded": true, "exit_code": 1},
    "waivers": {"waived": 1, "waived_by_type": {"false_positive": 1}, "expired_matches": 0, "unused": []},
    "baseline": {"file": "benchmark.yaml", "new": 1, "known": 3},
    "fingerprint_aliases": {}
  },
  "findings": [
    {"tool": "opengrep", "category": "sast", "rule_id": "...", "severity": "high", "path": "src/app.py",
     "start_line": 7, "fingerprints": {"rule": "og:1:RULE:...", "exact": "...", "ctx": "..."},
     "waived": false, "baseline_status": "new", "raw": {"...": "the untouched scanner record"}}
  ],
  "trufflehog_data": [], "opengrep_data": {}, "syft_data": {}, "grype_data": {}, "checkov_data": {}
}
```

`findings` is the normalized list every consumer should use. The per-tool payloads are the raw scanner
output with `fingerprints`, `waived`, `waived_by`, `expired_waivers` and `baseline_status` added to each
record, kept for tool-specific detail. Paths are repo-relative POSIX everywhere.

## SARIF

- One `run` per scanner with the real tool version and `informationUri`.
- `invocations[0].executionSuccessful` is false for a failed scanner, with the error in
  `toolExecutionNotifications`.
- Waived findings carry `suppressions` with the waiver reason as `justification`, so GitHub code scanning
  closes them instead of leaving alerts open.
- Rules carry `security-severity` and `defaultConfiguration.level`; URIs are relative to `%SRCROOT%`.
- `automationDetails.id` is `dsoinabox/<tool>/` so several uploads do not collide.
- Secret snippets are never emitted.

## Console

The run ends with a summary block (always printed, even with `--quiet`):

```text
[dsoinabox] dsoinabox 1.0.0  project=github.com/example/demo  source=/scan_target
[dsoinabox] tools: trufflehog 3.97.4 (4.1s), opengrep 1.29.0 (22.0s), syft 1.51.1 (3.2s), grype 0.118.0 (6.8s), checkov 3.3.16 (9.4s)
[dsoinabox] findings: critical=1 high=2 medium=2 low=1 info=0
[dsoinabox] waived: 1 (false_positive=1)  expired=1  unused=2  (from /scan_target/.dsoinabox_waivers.yaml)
[dsoinabox] baseline: new=6 known=1  (from /scan_target/benchmark.yaml, 1 entries)
[dsoinabox] reports:
  - /reports/dsoinabox_2026_09_05T14_44_34/demo.html
  - /reports/dsoinabox_2026_09_05T14_44_34/demo.sarif
[dsoinabox] latest: /reports/latest
[dsoinabox] policy: failure_threshold=high fail_on_secrets=false threshold exceeded (grype=2) -> FAIL
[dsoinabox] exit_code=1
```

`--show_findings true` prints a compact table of active findings before the summary; `full` prints details.
