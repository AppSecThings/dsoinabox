# dsoinabox

Run best-of-breed OSS AppSec scanners through one container.

- Get one normalized severity model and one policy contract
- Use one waiver file instead of five scanner-specific ignore systems
- Keep one benchmark and one build-breaking contract across tools
- Drop it into any CI with minimal CI-specific logic

Use the best tool for each job, without inheriting five incompatible workflows.

## Why DSOInABox?

Every scanner has different:

- severity scales
- output shapes
- ignore mechanisms
- baseline handling

Most teams can wire scanners together. The hard part is making exceptions and enforcement coherent across all of them.

DSOInABox gives you:

- one normalized severity model
- one waiver file for false positives, risk acceptance, and policy waivers
- one benchmark mechanism for baselining and expiration-driven revalidation
- one build-breaking contract for CI/CD

This unified exception model is the core differentiator: path exclusions, waiver lifecycle, benchmark baselines, and policy enforcement all run through one system.

## Why Not DIY?

You can run TruffleHog, OpenGrep, Grype, Checkov, and Syft yourself in separate jobs. The cost is operational complexity and policy drift.

DIY means inheriting multiple:

- suppression models
- severity mappings
- output contracts
- baseline workflows
- CI failure behaviors

DSOInABox standardizes these into one repo-level contract: one severity model, one waiver system, one baseline/benchmark mechanism, and one build-breaking policy gate.

## Demo

Run one command:

```bash
docker run --rm \
  -v $(pwd):/scan_target \
  -v $(pwd)/reports:/reports \
  appsecthings/dsoinabox:latest \
  -t all \
  -o html,sarif \
  --failure_threshold high \
  --fail_on_secrets \
  --show_findings false
```

Output:

```text
[dsoinabox] tools: trufflehog, opengrep, syft, grype, checkov
[dsoinabox] findings: critical=0 high=1 medium=4 low=9 info=12
[dsoinabox] waived: 3 (from .dsoinabox_waivers.yaml)
[dsoinabox] reports:
  - reports/dsoinabox_unified_report_<timestamp>.html
  - reports/dsoinabox_unified_report_<timestamp>.sarif
[dsoinabox] policy: failure_threshold=high fail_on_secrets=true
[dsoinabox] exit_code=1
```

HTML report example:

![Example HTML report screenshot](docs/demo/images/html-report-example.png)

SARIF result in GitHub Code Scanning example:

![Example GitHub SARIF result screenshot](docs/demo/images/github-sarif-example.svg)

Example waiver file (`.dsoinabox_waivers.yaml`):

```yaml
schema_version: "1.0"
finding_waivers:
  - fingerprint: "og:1:RULE:sql-injection-risk:abc123"
    type: "false_positive"
    reason: "Validated safe by parameterization in wrapper layer"
    created_by: "security@example.com"
    created_at: "2026-03-28"
```

## GitHub Action Quick Start

Use the composite action for the easiest GitHub Actions adoption:

```yaml
name: AppSec Scan
on:
  pull_request:
    branches: [dev, main]
  push:
    branches: [dev, main]

jobs:
  dsoinabox:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Run dsoinabox composite action
        uses: owner/repo/.github/actions/dsoinabox-scan@v0.1.4
        with:
          image: appsecthings/dsoinabox:latest
          failure_threshold: high
          targets: all
          extra_args: --fail_on_secrets --show_findings false

      - name: Find SARIF report
        id: find_sarif
        if: always()
        shell: bash
        run: |
          sarif_file="$(find reports -type f -name '*.sarif' -print -quit || true)"
          if [ -n "${sarif_file}" ]; then
            echo "found=true" >> "$GITHUB_OUTPUT"
            echo "sarif_file=${sarif_file}" >> "$GITHUB_OUTPUT"
          else
            echo "found=false" >> "$GITHUB_OUTPUT"
          fi

      - name: Upload SARIF to GitHub Security
        if: always() && steps.find_sarif.outputs.found == 'true'
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.find_sarif.outputs.sarif_file }}
          category: dsoinabox

      - name: Persist artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: dsoinabox-reports
          path: reports/**
```

`extra_args` is passed through bash and shell-split, so quote/escape values that contain spaces.
For full CI docs and raw Docker examples, see [docs/ci/github-actions.md](docs/ci/github-actions.md).

## Releasing

Releases no longer depend on Git tags.

- Pushes to `dev` publish Docker development images.
- Pushes to `main` always publish traceable Docker images for that commit.
- PyPI and versioned Docker releases happen only when `pyproject.toml` contains a new version.

Typical flow:

1. Make your code changes locally.
2. Bump `project.version` in `pyproject.toml` when you want a release.
3. Merge locally into `dev` and push `dev`.
4. Open and merge a PR from `dev` to `main`.

## What It Runs

`dsoinabox` orchestrates:

- `TruffleHog` (secrets)
- `OpenGrep` (SAST)
- `Syft` (SBOM)
- `Grype` (SCA)
- `Checkov` (IaC)

## Quick Start (Docker)

```bash
docker run --rm \
  -v /path/to/your/code:/scan_target \
  -v /path/to/reports:/reports \
  appsecthings/dsoinabox:latest \
  --show_findings false \
  -t all \
  -o sarif,html,ndjson \
  --tool_output
```

Apple Silicon (M1/M2/M3):

```bash
docker run --rm --platform linux/amd64 \
  -v /path/to/your/code:/scan_target \
  -v /path/to/reports:/reports \
  appsecthings/dsoinabox:latest \
  --show_findings false \
  -t all \
  -o html
```

## Typical CI Gate

```bash
docker run --rm \
  -v $(pwd):/scan_target \
  -v $(pwd)/reports:/reports \
  appsecthings/dsoinabox:latest \
  --show_findings false \
  -t all \
  -o sarif \
  --failure_threshold high \
  --fail_on_secrets
```

Exit codes:

- `0`: success, no threshold violations
- `1`: scan failure or policy threshold exceeded

## Docs

- [Documentation Index](docs/README.md)
- [Getting Started](docs/getting-started/README.md)
- [CLI and Policy Reference](docs/cli/README.md)
- [Runtime Config (`.dsoinabox.yaml`)](docs/config/README.md)
- [Waivers (`.dsoinabox_waivers.yaml`)](docs/waivers/README.md)
- [Output Formats and Report Layout](docs/output/README.md)
- [CI Examples (GitHub Actions, GitLab CI, Jenkins, Azure DevOps)](docs/ci/README.md)
- [Usage Examples](docs/examples/README.md)
- [Architecture Notes](docs/architecture/README.md)
