# CLI and Policy Reference

`dsoinabox` has subcommands. A leading flag means `scan`, so every pre-1.0 invocation
(`dsoinabox -t all -o html`) still works unchanged.

| Command | Purpose |
|---|---|
| `dsoinabox scan [flags]` | run scanners and build reports (default) |
| `dsoinabox waivers validate PATH... [--strict]` | check a waiver file: schema version, expired, duplicate and malformed entries |
| `dsoinabox waivers migrate PATH... [--in-place \| --output P] [--dry-run] [--to VERSION] [--from-report REPORT.json]` | rewrite a waiver file to the current schema, preserving comments |
| `dsoinabox waivers prune PATH... [--in-place] [--report REPORT.json] [--dry-run]` | remove expired entries (and unused ones named by a report) |
| `dsoinabox waivers add --fingerprint FP --type TYPE [--reason ...] [--expires 90d] [--ticket ...] [--tools sast]` | append a waiver, creating the file if needed |
| `dsoinabox baseline update --from REPORT.json [--file benchmark.yaml] [--prune] [--expires DATE]` | refresh a baseline from a run |
| `dsoinabox config init [--source DIR]` | write a starter `.dsoinabox.yaml` (never overwrites) |
| `dsoinabox tools versions` | print dsoinabox and every scanner version |
| `dsoinabox tools help TOOL` | print a scanner's own help |

Every `--snake_case` flag also accepts `--kebab-case` (`--failure-threshold`). The snake_case
form is the documented one.

## Tool Selection

- `--tools`, `-t` (default `all`): comma-separated tool names or categories.
- Tools: `trufflehog`, `opengrep`, `syft`, `grype`, `checkov`.
- Categories: `secret` (or `secrets`), `sast`, `sbom`, `sca`, `iac`.
- Unknown values are a usage error (exit 3).

## Source and Output Paths

- `--source`: default `/scan_target` in Docker, `.` otherwise.
- `--report_directory`: default `reports`, resolved from the current working directory, never from `--source`.
  Each run writes to `<report_directory>/dsoinabox_<timestamp>/` and refreshes `<report_directory>/latest/`.
- `--report_name`: base file name for reports (default `dsoinabox_unified_report_<timestamp>`).
  With `--report_name dsoinabox` the files are `dsoinabox.html`, `dsoinabox.sarif`, and so on.
- `--output`, `-o` (default `html`): comma-separated formats: `html`, `jenkins_html`, `json`, `ndjson`, `sarif`,
  `cyclonedx`, `spdx`. The last two write the Syft SBOM as `sbom.cdx.json` / `sbom.spdx.json`.
- `--tool_output`: keep raw scanner output under `tools_output/`.

## Policy Gate

The gate decides the exit code. It never removes findings from reports.

- `--failure_threshold` (default `none`): `none`, `info`, `low`, `medium`, `high`, `critical`.
  Exit 1 when unwaived findings at or above this severity exist. Secrets are not part of this gate.
- `--fail_on_secrets [any|verified]`: exit 1 when unwaived secrets are found. `verified` counts only
  secrets TruffleHog verified as live and implies `--verify_secrets`.
- `--baseline FILE` and `--fail_on new`: classify findings against a benchmark file and gate only
  findings that are not in it. See [baselines](../waivers/README.md#baselines).

## Report Content

- `--report_threshold` (default `none`): hide findings below this severity from reports and the console
  table. The gate is unaffected. The summary prints how many findings were hidden.
  To reproduce the pre-1.0 behaviour (reports trimmed to the gate), set `report_threshold` to the same
  value as `failure_threshold` in `.dsoinabox.yaml`.
- `--show_findings [false|true|full]` (default `false`): after the summary, list active findings as a
  compact table (`true`) or as detailed blocks (`full`).

## Waivers

- `--waiver_file` (default `.dsoinabox_waivers.yaml`, relative to `--source`). A missing default file is
  fine; a missing explicit file is a usage error.
- `--waiver_grace_days N` (default 0): keep expired waivers active for N extra days, flagged as expiring.
- `--benchmark`: write `benchmark.yaml` with the fingerprints of all active findings.
- `--sarif_include_waived`: emit waived findings in SARIF as suppressed results (off by default; GitHub
  code scanning ignores suppressions).

See [Waivers](../waivers/README.md).

## Scanner Behaviour

- `--scan_timeout SECONDS` (default 1800): per-scanner limit. A timeout is a scanner failure.
- `--fail_fast`: stop launching scanners after the first failure. Default is to run everything and report.
- `--verify_secrets`: let TruffleHog verify candidates against providers (network calls). Off by default,
  so every secret shows as unverified unless enabled.
- `--grype_db auto|offline`: `offline` never downloads the vulnerability database and fails clearly when
  none is cached.
- `--<tool>_args "..."`: extra arguments appended to a scanner's command line
  (`--trufflehog_args`, `--opengrep_args`, `--syft_args`, `--grype_args`, `--checkov_args`).
  Use the `--flag=value` form when the value itself starts with a dash: `--opengrep_args="--severity ERROR"`.

## Project and Runtime Config

- `--project_id`: explicit project identifier. Required for non-git sources. Otherwise derived from the
  git remote URL, then the initial commit hash. It seeds the per-project fingerprint key.
- `--config_file`: default `.dsoinabox.yaml` under `--source`; env `DSOINABOX_CONFIG`.
- Precedence: config file, then `DSOINABOX_*` environment variables, then flags. See [Runtime Config](../config/README.md).

## Logging

- `--verbose`, `-v`: DEBUG logging. `--quiet`, `-q`: WARNING and above. The summary block is always printed.
- `--version`: print the dsoinabox version.

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | scans completed and the policy passed |
| 1 | policy failed: threshold exceeded or secrets found (reports written) |
| 2 | one or more scanners failed or timed out (reports written for the rest) |
| 3 | usage or configuration error: bad flag value, missing source, missing explicit waiver file, invalid waiver file, scanner binary not on PATH |

Any non-zero code still means "do not pass". Pipelines that only check `!= 0` need no change.

## Deprecated Flags

`--tool_versions`, `--init-config` and `--<tool>_help` still work for one release and print a notice
pointing at `tools versions`, `config init` and `tools help TOOL`.
