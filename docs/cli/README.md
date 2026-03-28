# CLI and Policy Reference

## Tool Selection

- `--tools`, `-t` (default: `all`)
- Comma-separated tools or categories
- Tools: `trufflehog`, `opengrep`, `syft`, `grype`, `checkov`
- Categories: `SAST`, `SBOM`, `SECRET`, `SCA`, `IAC`

Examples:

- `-t trufflehog,opengrep`
- `-t SAST,SECRET`

## Source and Output Paths

- `--source`
- Default: `/scan_target` in Docker, `.` for direct runs

- `--report_directory`
- Default: `reports`
- If `/reports` is mounted in Docker, reports are copied there

- `--output`, `-o`
- Default: `html`
- Options: `html`, `jenkins_html`, `json`, `ndjson`, `sarif`
- Comma-separated list supported

- `--tool_output`
- Keep raw scanner output files under `tools_output/`

## Project and Runtime Config

- `--project-id`
- Explicit project identifier (useful outside git repos)

- `--config_file`
- Default: `.dsoinabox.yaml` relative to `--source`
- Can also be set via `DSOINABOX_CONFIG`

- `--init-config`
- Writes starter config and exits
- Does not overwrite an existing file

Config precedence:

`config file defaults -> DSOINABOX_* env vars -> CLI flags`

See [Runtime Config docs](../config/README.md).

## Security Gating

- `--failure_threshold` (default: `none`)
- Options: `none`, `info`, `low`, `medium`, `high`, `critical`
- Returns non-zero when findings at or above threshold are present

- `--fail_on_secrets`
- Returns non-zero if TruffleHog finds any secrets

## Findings and Waivers

- `--show_findings` (default: `True`)
- Set `--show_findings false` to suppress finding output in terminal

- `--waiver_file` (default: `.dsoinabox_waivers.yaml`)
- Applies matching waivers by fingerprint

- `--benchmark`
- Writes `benchmark.yaml` with all findings for baseline workflows

See [Waiver docs](../waivers/README.md).

## Tool-Specific Pass-Through Args

- `--trufflehog_args`
- `--opengrep_args`
- `--syft_args`
- `--grype_args`
- `--checkov_args`

## Help and Version Flags

- `--version`
- `--tool_versions`
- `--trufflehog_help`
- `--opengrep_help`
- `--syft_help`
- `--grype_help`
- `--checkov_help`

## Exit Codes

- `0`: scans completed and policy checks passed
- `1`: scan failure or policy threshold exceeded
