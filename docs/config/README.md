# Runtime Config

`dsoinabox` reads repository defaults from `.dsoinabox.yaml` in the source directory.

## Quick Start

```bash
dsoinabox config init          # writes ./.dsoinabox.yaml, never overwrites
```

Precedence, lowest to highest: `.dsoinabox.yaml`, `DSOINABOX_*` environment variables, CLI flags.

## Keys

| Key | Env var | Values | Notes |
|---|---|---|---|
| `source` | `DSOINABOX_SOURCE` | path | |
| `report_directory` | `DSOINABOX_REPORT_DIRECTORY` | path | relative to the invocation directory |
| `report_name` | `DSOINABOX_REPORT_NAME` | string | base file name for reports |
| `project_id` | `DSOINABOX_PROJECT_ID` | string | |
| `tools` | `DSOINABOX_TOOLS` | list or comma string | names or categories |
| `failure_threshold` | `DSOINABOX_FAILURE_THRESHOLD` | none, info, low, medium, high, critical | policy gate |
| `report_threshold` | `DSOINABOX_REPORT_THRESHOLD` | same | what reports show |
| `fail_on_secrets` | `DSOINABOX_FAIL_ON_SECRETS` | false, true, verified | |
| `verify_secrets` | `DSOINABOX_VERIFY_SECRETS` | bool | |
| `grype_db` | `DSOINABOX_GRYPE_DB` | auto, offline | |
| `show_findings` | `DSOINABOX_SHOW_FINDINGS` | false, true, full | |
| `waiver_file` | `DSOINABOX_WAIVER_FILE` | path | relative to source |
| `waiver_grace_days` | `DSOINABOX_WAIVER_GRACE_DAYS` | int | |
| `baseline` | `DSOINABOX_BASELINE` | path | benchmark file |
| `fail_on` | `DSOINABOX_FAIL_ON` | all, new | |
| `output` | `DSOINABOX_OUTPUT` | list or comma string | |
| `tool_output` | `DSOINABOX_TOOL_OUTPUT` | bool | |
| `benchmark` | `DSOINABOX_BENCHMARK` | bool | |
| `scan_timeout` | `DSOINABOX_SCAN_TIMEOUT` | seconds | |
| `tool_timeouts` | `DSOINABOX_TOOL_TIMEOUTS` | mapping; env as `grype=900,trufflehog=600` | per-tool overrides |
| `fail_fast` | `DSOINABOX_FAIL_FAST` | bool | |
| `<tool>_args` | `DSOINABOX_<TOOL>_ARGS` | string or list | also as a `tool_args:` mapping |

Example:

```yaml
tools: all
failure_threshold: high
report_threshold: low        # hide info findings from reports, gate is still high
fail_on_secrets: verified
waiver_file: .dsoinabox_waivers.yaml
waiver_grace_days: 7
baseline: benchmark.yaml
fail_on: new
output: html,sarif
show_findings: true
scan_timeout: 1800
tool_timeouts:
  grype: 900
tool_args:
  opengrep: "--severity ERROR"
  checkov: "--framework terraform"
```

`examples/.dsoinabox.yaml` is the starter file `config init` writes.
