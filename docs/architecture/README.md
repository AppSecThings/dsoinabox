# Architecture

```text
cli.py ─ parse flags / config / env ─► ScanOptions
                                          │
run.py ─ run_scan(options) ─► ScanRun ────┼─► console.py (summary, findings table)
   │                                      └─► reporting/ (html, jenkins_html, json, ndjson, sarif, sbom export)
   ├─ scanners/registry.py   one ScannerSpec per tool: run, fingerprint, normalize, depends_on
   ├─ fingerprints/          versioned, project-keyed fingerprints (v1 frozen by golden tests)
   ├─ normalize/             raw scanner record ─► model.Finding (unified severity, repo-relative path)
   ├─ waivers/               loader (schema 1.0/1.1) ─► WaiverSet ─► WaiverEngine (fingerprints, paths, expiry)
   ├─ waivers/baseline.py    new/known classification
   └─ policy.py              PolicyResult and exit code
```

## Execution model

1. `select_tools` resolves `--tools` against the registry (names, categories, aliases).
2. Every selected scanner's binary is checked and its version probed in parallel.
3. Scanners run in a thread pool. `depends_on` only orders them: Grype waits for Syft's SBOM but falls back
   to a directory scan if Syft failed. A failing or timed-out scanner becomes a `ScanResult` with
   `status: failed`; the others continue unless `--fail_fast`.
4. Per scanner, still in its thread: fingerprint the raw records, normalize them into `Finding` objects
   (raw record attached), apply the waiver engine.
5. Back on the main thread: baseline classification, policy evaluation, benchmark file, reports,
   `latest/` pointer, cleanup of `tools_output/`.

## The normalized model (`model.py`)

`Finding` carries tool, category, rule id, message, unified `severity` (plus the tool's original string),
repo-relative `path`, lines, snippet, fingerprints (current and legacy), waiver annotations, baseline status,
package details for SCA and the untouched `raw` record. `ScanResult` groups findings per tool with status,
duration and version; `ScanRun` is the whole run and is what every report is built from.

Severity mapping: OpenGrep `ERROR/WARNING/INFO` become high/medium/low; Grype `Negligible` is info;
Checkov SARIF levels map error/warning/note/none to high/medium/low/info and `security-severity` overrides
them; secrets are always high.

## Project identification

Project ids are resolved from `--project_id`, else the normalized git remote URL, else the initial commit
hash. The id seeds the HMAC key that makes fingerprints stable across machines and safe to publish.

## Adding a scanner

See [adding-a-scanner.md](adding-a-scanner.md).
