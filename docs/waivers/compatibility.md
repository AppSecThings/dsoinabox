# Waiver and Fingerprint Compatibility

Waiver files are long-lived, hand-maintained, and committed next to the code. dsoinabox promises that a
newer version always reads a file written for an older one. This document is the contract.

## Schema versions

Files declare `schema_version: "MAJOR.MINOR"`.

- **MINOR** bumps add optional fields or relax validation. Every loader for the same MAJOR reads every MINOR.
- **MAJOR** bumps change meaning or remove fields and come with a migration step.
- A **missing** `schema_version` is treated as `1.0`, the oldest version, never as "latest". Reinterpreting an
  old file under new rules could silently change what it waives. A warning asks you to add the field.
- **Deprecated** versions load and apply fully. A one-line warning points at `dsoinabox waivers migrate`.
- **Unknown future** versions fail with an error naming the newest version this build supports, so the fix
  is "upgrade dsoinabox", not "edit the file".

Current: `1.1`. Supported: `1.0`, `1.1`. Deprecated: `1.0`.

| Version | dsoinabox | Changes |
|---|---|---|
| 1.0 | 0.1.x | original format: `meta`, `path_exclusions`, `finding_waivers`, `benchmark` |
| 1.1 | 1.0.0 | `ticket` is the single ticket field (`meta_ticket` migrates to it); `finding_waivers[].tools`; top-level `benchmark_expires_at`; `meta.schema_url` |

Benchmark files (`--benchmark`, `baseline update`) use the same schema and the same rules.

JSON Schema documents for every version ship with the package under
`dsoinabox/waivers/schema_files/waivers-<version>.schema.json`. Point your editor at one with
`# yaml-language-server: $schema=...` to get validation while typing.

## Migrating

```bash
dsoinabox waivers migrate .dsoinabox_waivers.yaml --dry-run     # unified diff, nothing written
dsoinabox waivers migrate .dsoinabox_waivers.yaml --in-place    # rewrite; the original is kept as .bak
dsoinabox waivers migrate old.yaml --output new.yaml
dsoinabox waivers migrate old.yaml --to 1.1                     # stop at an intermediate version
```

Migration uses a round-trip YAML parser: comments, key order and quoting survive. The migrated file is
validated with the normal loader before anything is written. Migrating a file that is already current exits
1 when `--in-place` was requested, so scripted use notices that nothing happened.

## Fingerprint versions

Fingerprints look like `<tool>:<fp_version>:<TIER>:<data>[:R:<repo8>]`. The number after the tool prefix is
the algorithm version.

- A released fingerprint version is **frozen forever**. `tests/unit/fingerprints/golden_v1.json` pins the exact
  strings the version 1 algorithms produce; the suite fails if they change.
- Any algorithm change ships as a **new version**. For at least one major release the scanner emits the current
  version in `fingerprints` and the previous one under `fingerprints.legacy`, so existing waivers keep
  matching.
- The matcher **always accepts legacy values**. `waivers validate` flags entries that use a legacy or
  unsupported version.
- Every JSON report records `metadata.fingerprint_aliases` (legacy to current). Rewrite a waiver file with
  `dsoinabox waivers migrate --from-report reports/latest/<name>.json --in-place`.

Current fingerprint version for every tool: 1.

## Keys

Fingerprints are HMAC-keyed with a key derived (HKDF-SHA256) from the project id: the normalized git remote
URL, else the initial commit hash, else `--project_id`. The same repository therefore produces the same
fingerprints on every machine. `DSOB_PROJECT_HMAC_KEY` overrides the derived key; setting it changes every
fingerprint and existing waiver files stop matching, so dsoinabox logs a warning whenever it is set.

## What the test suite guarantees

- `tests/compat/` loads, schema-validates and migrates every waiver file this repository ships or documents.
- `tests/unit/waivers/test_schema_versions.py` covers every version with fixtures, including missing,
  unquoted, deprecated and future versions.
- `tests/unit/fingerprints/test_golden_v1.py` freezes version 1 fingerprints.
