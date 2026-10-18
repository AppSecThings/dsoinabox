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
| `db_cache` | `DSOINABOX_DB_CACHE` | path | Grype DB kept in `<path>/grype`; relative to the invocation directory; set to `/var/cache/dsoinabox` in the image |
| `always_update` | `DSOINABOX_ALWAYS_UPDATE` | bool | check for a newer Grype DB every run; not with `grype_db: offline` |
| `opengrep_rules` | `DSOINABOX_OPENGREP_RULES` | YAML string/list; env comma string | default `auto`; paths relative to source |
| `show_findings` | `DSOINABOX_SHOW_FINDINGS` | false, true, full | |
| `waiver_file` | `DSOINABOX_WAIVER_FILE` | path | relative to source |
| `waiver_grace_days` | `DSOINABOX_WAIVER_GRACE_DAYS` | int | |
| `baseline` | `DSOINABOX_BASELINE` | path | benchmark file |
| `fail_on` | `DSOINABOX_FAIL_ON` | all, new | |
| `sarif_include_waived` | `DSOINABOX_SARIF_INCLUDE_WAIVED` | bool | waived findings as SARIF suppressions |
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
opengrep_rules:
  - rules/security.yml
  - rules/team
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

## Grype DB cache

`db_cache` keeps Grype's vulnerability database in `<db_cache>/grype` between runs. Grype reuses it
without touching the network until its last update check is 24 hours old, then downloads only when a
newer DB exists (Grype's own `GRYPE_DB_MAX_UPDATE_CHECK_FREQUENCY`). Grype still replaces a cached DB
built more than 5 days ago (its `max-allowed-built-age`) whatever the check age. `always_update: true`
makes it check on every run; combining it with `grype_db: offline` is a usage error (exit 3). Without
`db_cache` and `always_update`, Grype uses its own default cache exactly as before.

The image sets `DSOINABOX_DB_CACHE=/var/cache/dsoinabox`, owned by `appuser` (uid 1001). Mount a named
volume there (`-v dsoinabox-db:/var/cache/dsoinabox`) to keep the DB; a bind-mounted host directory must
be writable by uid 1001, otherwise Grype fails (exit 2) with a message saying so. With a populated
cache, `grype_db: offline` scans without network access.

An explicit `GRYPE_DB_CACHE_DIR` in the environment wins over `db_cache` (dsoinabox logs that it is
used); the check frequency still applies. In the image, Grype's default path
`/home/appuser/.cache/grype/db` links to `/var/cache/dsoinabox/grype`, so DB mounts made for earlier
images keep working. `DSOINABOX_DB_CACHE=` (empty) turns the image's default cache off.

Grype trusts a DB it finds in the cache, so the cache directory must be writable only by the identity
that runs scans.

## Offline OpenGrep rules

The default `opengrep_rules: auto` contacts semgrep.dev. For an offline or deny-egress run, configure
one or more local rule files/directories. YAML accepts either a string or list; the CLI
`--opengrep_rules` / `--opengrep-rules` and `DSOINABOX_OPENGREP_RULES` use comma-separated entries.
Each entry becomes an OpenGrep `--config`, and relative paths resolve against `--source`. Do not combine
`auto` with local paths. Missing local paths fail before scans with usage exit 3; an `auto` download
failure is scanner exit 2 with local-rule guidance.

Custom rules append ` (rules <configured-source>)` to OpenGrep tool-version metadata in summaries
and reports. `auto` has no suffix, preserving existing output. In containers, mount rules read-only,
for example `-v ./rules:/rules:ro -e DSOINABOX_OPENGREP_RULES=/rules`. OpenGrep also requires its
self-extracted runtime cache to live on a filesystem that permits execution. The project image
prewarms the `appuser` cache; custom installs, cache mounts, and read-only hardening must preserve an
executable cache path.
