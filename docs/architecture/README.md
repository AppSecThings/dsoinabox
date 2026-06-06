# Architecture Notes

`dsoinabox` orchestrates scanners in parallel where possible, then normalizes and merges findings.

## Scan Execution Model

1. Parallel independent scans:
- TruffleHog (secrets)
- OpenGrep (SAST)
- Syft (SBOM)
- Checkov (IaC)

2. Dependent scan:
- Grype (SCA), using Syft SBOM output

3. Unified processing:
- Parse tool outputs
- Normalize severities and finding contracts
- Apply waiver matching
- Generate requested report formats
- Apply failure policy checks

## Project Identification

Project IDs are resolved in this order:

1. Explicit `--project-id`
2. Git remote URL
3. Initial commit hash

This helps keep finding fingerprints stable across runs.
