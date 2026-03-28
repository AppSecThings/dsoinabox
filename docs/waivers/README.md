# Waivers

This section documents the waiver file format and provides ready-to-copy examples.

## Purpose

Waivers let teams suppress known findings in a controlled way (for example false positives or risk acceptances) without disabling scanners.

## Default Waiver File

By default, `dsoinabox` looks for:

- `.dsoinabox_waivers.yaml` in the source directory

You can override this with:

- CLI: `--waiver_file <path>`
- Runtime config: `waiver_file: <path>`

## Schema

Waiver files are YAML with schema version `1.0`.

Common sections:

- `schema_version`
- `meta`
- `path_exclusions`
- `finding_waivers`
- `benchmark`

Supported waiver `type` values in `finding_waivers`:

- `false_positive`
- `risk_acceptance`
- `policy_waiver`

## Examples

- `examples/.dsoinabox_waivers.yaml`: practical waiver file example.
- `../../dsoinabox/waivers/waiver_schema_1.0_example.yaml`: full schema-focused reference.

## Notes

- Fingerprints must match findings exactly.
- Missing default waiver file is non-fatal.
- Missing custom waiver file (explicitly provided) is treated as an error.
