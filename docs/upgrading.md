# Upgrading

## 0.1.x to 1.0.0

Everything that reads files or exit codes keeps working; a few defaults changed on purpose. Each change lists
the one-line way to restore the old behaviour.

**Waiver files** need no changes. Schema 1.0 files load with a deprecation notice. Run
`dsoinabox waivers migrate .dsoinabox_waivers.yaml --in-place` when convenient.

**Expired waivers now expire.** `expires_at` was never enforced before. Findings hidden by expired entries
reappear and may fail the gate. Check with `dsoinabox waivers validate --strict` before upgrading; use
`--waiver_grace_days 30` for a transition window.

**Path exclusions now work.** `path_exclusions` were parsed and ignored before. Findings under excluded paths
are now waived.

**Reports are no longer trimmed by `--failure_threshold`.** The gate decides the exit code; reports show every
active finding. To keep the old, trimmed reports set `report_threshold` to the same value as
`failure_threshold` (flag `--report_threshold` or the config key).

**Waived findings stay in reports** with `waived: true` and a `waived_by` record (JSON, NDJSON) and in a
collapsed section of the HTML. They were deleted before. SARIF still omits them (GitHub ignores
suppressions); `--sarif_include_waived` adds them as suppressed results.

**Exit codes.** `1` is now only a policy failure. Scanner failures return `2` (reports are still written for the
scanners that succeeded) and configuration errors return `3`. Pipelines checking `!= 0` are unaffected. Add
`--fail_fast` to abort on the first scanner failure as before.

**Console output.** The per-finding dump is gone; a summary block is always printed. `--show_findings` now
defaults to `false` and accepts `true` (compact table) or `full` (details). Pass `--show_findings full` for
the old verbosity.

**JSON report shape.** `metadata` gained versions, scanner status, policy and waiver summaries; a normalized
`findings` list was added. The per-tool payloads are still present. Paths are repo-relative instead of
`<ROOT>/...`.

**Report file names.** Unchanged by default. `--report_name` sets a stable name and `reports/latest/` always
points at the newest run; CI examples use it instead of `find`.

**Legacy flags.** `--tool_versions`, `--init-config` and `--<tool>_help` print a deprecation notice and map to
`tools versions`, `config init`, `tools help TOOL`. They will be removed in a later release.

**Fingerprints did not change.** Version 1 algorithms are byte-identical; existing fingerprints keep matching.
A project id is now required to compute fingerprints (the CLI always has one; library callers must pass
`project_id`).

**Docker image.** Runtime is Python 3.12, scanner versions are pinned, and the image is published for
`linux/amd64` and `linux/arm64`. Apple Silicon no longer needs `--platform linux/amd64`.
