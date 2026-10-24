# GitHub Actions

## Composite action

```yaml
name: dsoinabox
on:
  pull_request:
    branches: [dev, main]
  push:
    branches: [dev, main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Run dsoinabox composite action
        uses: AppSecThings/dsoinabox/.github/actions/dsoinabox-scan@main
        with:
          image: appsecthings/dsoinabox:latest
          failure_threshold: high
          targets: all

      - name: Upload SARIF to GitHub Security
        if: always() && hashFiles('reports/latest/dsoinabox.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/latest/dsoinabox.sarif
          category: dsoinabox

      - name: Persist artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: dsoinabox-reports
          path: reports/**
```

## Raw Docker run

```yaml
name: dsoinabox
on:
  pull_request:
    branches: [dev, main]
  push:
    branches: [dev, main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Run dsoinabox (mount repo + threshold gate)
        run: |
          mkdir -p reports
          docker run --rm \
            -v "$PWD:/scan_target" \
            -v "$PWD/reports:/reports" \
            appsecthings/dsoinabox:latest \
            -t all \
            -o sarif,html \
            --report_name dsoinabox \
            --failure_threshold high

      - name: Upload SARIF to GitHub Security
        if: always() && hashFiles('reports/latest/dsoinabox.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/latest/dsoinabox.sarif
          category: dsoinabox

      - name: Persist artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: dsoinabox-reports
          path: reports/**
```

- Mount repo: `-v "$PWD:/scan_target"`
- Stable paths: `--report_name dsoinabox` plus `reports/latest/` means no directory search
- Persist artifacts: `actions/upload-artifact` with `path: reports/**`
- Gate: `--failure_threshold high` exits 1; a scanner failure exits 2; both are non-zero

## Cache the Grype DB

Add these steps before the raw Docker run and mount the directory at the image's cache path. The key
changes once a day, so the cache is saved at most daily, in step with Grype's 24-hour update check.
GitHub-hosted Ubuntu runners run as uid 1001, the image's `appuser`, so the directory needs no chown.
The composite action does not mount a cache; use the raw Docker run for this.

```yaml
      - name: Day stamp for the Grype DB cache
        id: day
        run: echo "day=$(date -u +%F)" >> "$GITHUB_OUTPUT"

      - name: Restore Grype DB cache
        uses: actions/cache@v4
        with:
          path: ${{ runner.temp }}/dsoinabox-db
          key: dsoinabox-db-${{ steps.day.outputs.day }}
          restore-keys: dsoinabox-db-

      - name: Run dsoinabox (mount repo + threshold gate)
        run: |
          mkdir -p reports "$RUNNER_TEMP/dsoinabox-db"
          docker run --rm \
            -v "$PWD:/scan_target" \
            -v "$PWD/reports:/reports" \
            -v "$RUNNER_TEMP/dsoinabox-db:/var/cache/dsoinabox" \
            appsecthings/dsoinabox:latest \
            -t all \
            -o sarif,html \
            --report_name dsoinabox \
            --failure_threshold high
```

The cache lives in `runner.temp`, outside the checkout, so it is never scanned.

## Release workflow

This repository publishes without Git release tags.

- Pushes to `dev` can publish development Docker tags.
- Pushes to `main` always publish branch/SHA Docker tags.
- PyPI and versioned Docker tags publish only when `project.version` in `pyproject.toml` changes.
