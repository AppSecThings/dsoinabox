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
        uses: owner/repo/.github/actions/dsoinabox-scan@main
        with:
          image: appsecthings/dsoinabox:latest
          failure_threshold: high
          targets: all

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
            --failure_threshold high

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

- Mount repo: `-v "$PWD:/scan_target"`
- Persist artifacts: `actions/upload-artifact` with `path: reports/**`
- Fail build on threshold: `--failure_threshold high` returns non-zero exit code

## Release workflow

This repository publishes without Git release tags.

- Pushes to `dev` can publish development Docker tags.
- Pushes to `main` always publish branch/SHA Docker tags.
- PyPI and versioned Docker tags publish only when `project.version` in `pyproject.toml` changes.
