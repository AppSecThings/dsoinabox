# Waivers

Waivers suppress known findings in a controlled way (false positives, risk acceptance, policy exceptions) without disabling scanners.

## Default File Location

By default, `dsoinabox` looks for:

- `.dsoinabox_waivers.yaml` in the source directory

Override options:

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

Supported `finding_waivers[].type` values:

- `false_positive`
- `risk_acceptance`
- `policy_waiver`

## Waiver File Example

```yaml
schema_version: "1.0"

meta:
  owner: "Security Engineering"
  created_by: "alice@example.com"
  created_at: "2025-11-08T14:20:00Z"
  notes: "Initial waiver set"

path_exclusions:
  - pattern: "third_party/**"
    reason: "Vendored code"
    expires_at: "2026-01-31T00:00:00Z"
    tools: ["trufflehog", "opengrep"]

finding_waivers:
  - fingerprint: "og:1:CTX:html.security.audit.missing-integrity.missing-integrity:0c065896:a9ef9d591c62c38b:R:a3d1696c"
    type: "false_positive"
    reason: "Static context proved safe"
    expires_at: "2026-05-01T00:00:00Z"
    created_by: "alice@example.com"
    created_at: "2025-11-01"
    meta_ticket: "SEC-1420"
```

## Benchmark Section

A waiver file can include `benchmark` entries with the same shape as `finding_waivers`.

Behavior:

- Entries in `benchmark` are treated as `type: "benchmark"` during load
- Benchmark entries participate in waiver matching the same way as finding waivers

Example:

```yaml
schema_version: "1.0"

finding_waivers:
  - fingerprint: "og:1:RULE:test:abc"
    type: "false_positive"
    reason: "Known false positive"

benchmark:
  - fingerprint: "og:1:RULE:baseline:xyz"
    type: "risk_acceptance"  # overridden to "benchmark"
    reason: "Baseline finding"
```

## Matching and Error Behavior

- Fingerprints must match findings exactly.
- Missing default waiver file is non-fatal.
- Missing custom waiver file (explicitly provided) is an error.

## References

- `examples/.dsoinabox_waivers.yaml`: practical sample
- `../../dsoinabox/waivers/waiver_schema_1.0_example.yaml`: schema reference
