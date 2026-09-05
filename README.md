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
  --report_name dsoinabox \
  --failure_threshold high \
  --fail_on_secrets
```

Output (the block every run ends with):

```text
[dsoinabox] dsoinabox 1.0.0  project=github.com/example/app  source=/scan_target
[dsoinabox] tools: trufflehog 3.97.4 (0.9s), opengrep 1.29.0 (4.5s), syft 1.51.1 (0.8s), grype 0.118.0 (db built 2026-09-05T06:27:00Z) (33.9s), checkov 3.3.16 (1.7s)
[dsoinabox] findings: critical=3 high=3 medium=5 low=0 info=0
[dsoinabox] waived: 2 (false_positive=1, risk_acceptance=1)  expired=1  unused=0  (from /scan_target/.dsoinabox_waivers.yaml)
[dsoinabox] reports:
  - /reports/dsoinabox_2026_09_05T14_45_12/dsoinabox.html
  - /reports/dsoinabox_2026_09_05T14_45_12/dsoinabox.sarif
[dsoinabox] latest: /reports/latest
[dsoinabox] policy: failure_threshold=high fail_on_secrets=true threshold exceeded (checkov=1, grype=4, opengrep=1) -> FAIL
[dsoinabox] exit_code=1
```

Exit codes: `0` pass, `1` policy failed, `2` a scanner failed (reports still written), `3` usage error.
Add `--show_findings true` for a table of active findings.

HTML report example:

![Example HTML report screenshot](docs/demo/images/html-report-example.png)

SARIF result in GitHub Code Scanning example:

![Example GitHub SARIF result screenshot](docs/demo/images/github-sarif-example.svg)

Example waiver file (`.dsoinabox_waivers.yaml`, schema 1.1; older files keep working):

```yaml
schema_version: "1.1"
path_exclusions:
  - pattern: "third_party/**"
    reason: "Vendored code"
finding_waivers:
  - fingerprint: "og:1:RULE:python.lang.security.audit.dangerous-system-call:abc123...:R:3895f288"
    type: "risk_acceptance"
    reason: "Input comes from a fixed allow-list"
    expires_at: "2027-03-28"
    ticket: "SEC-142"
```

Waivers are applied to results, never to the scanners: path exclusions use gitignore globs, expired entries
stop suppressing and are reported, waived findings stay visible (collapsed in HTML, `suppressions` in
SARIF), and the run summary counts what each waiver did. `dsoinabox waivers validate|migrate|prune|add`
maintain the file; `--baseline benchmark.yaml --fail_on new` gates only regressions on a legacy codebase.
See [docs/waivers](docs/waivers/README.md) and the [compatibility contract](docs/waivers/compatibility.md).

## GitHub Action Quick Start

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

      - name: Run dsoinabox
        uses: AppSecThings/dsoinabox/.github/actions/dsoinabox-scan@main
        with:
          image: appsecthings/dsoinabox:latest
          failure_threshold: high
          targets: all
          extra_args: --fail_on_secrets

      - name: Upload SARIF to GitHub Security
        if: always() && hashFiles('reports/latest/dsoinabox.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/latest/dsoinabox.sarif
          category: dsoinabox

      - name: Persist reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: dsoinabox-reports
          path: reports/**
```

The action writes `reports/latest/dsoinabox.{html,sarif}` on every run, so no directory search is needed.
`extra_args` is shell-split; quote values containing spaces. See [docs/ci](docs/ci/README.md) for GitLab,
Jenkins and Azure DevOps.

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
  -t all \
  -o html,sarif,json
```

The image is published for `linux/amd64` and `linux/arm64`; Apple Silicon runs it natively.
Direct installs (`pip install dsoinabox`) need the five scanners on `PATH`.

## Typical CI Gate

```bash
docker run --rm \
  -v $(pwd):/scan_target \
  -v $(pwd)/reports:/reports \
  appsecthings/dsoinabox:latest \
  -t all \
  -o sarif \
  --report_name dsoinabox \
  --failure_threshold high \
  --report_threshold medium \
  --fail_on_secrets verified
```

- `--failure_threshold` decides the exit code; `--report_threshold` decides what reports show. They are independent.
- `--fail_on_secrets verified` fails only on credentials TruffleHog could verify as live.
- On a legacy codebase: `dsoinabox baseline update --from reports/latest/dsoinabox.json`, then add
  `--baseline benchmark.yaml --fail_on new` so only regressions fail.

## Documentation

- [Getting started](docs/getting-started/README.md), [CLI and exit codes](docs/cli/README.md), [runtime config](docs/config/README.md)
- [Waivers and baselines](docs/waivers/README.md), [waiver and fingerprint compatibility](docs/waivers/compatibility.md)
- [Output formats and layout](docs/output/README.md), [CI examples](docs/ci/README.md), [architecture](docs/architecture/README.md)
- [Upgrading to 1.0](docs/upgrading.md)
