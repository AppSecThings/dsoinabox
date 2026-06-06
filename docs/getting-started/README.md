# Getting Started

## Installation

Install with pip:

```bash
pip install dsoinabox
```

Recommended: run via Docker image so scanner dependencies are preinstalled.

## Docker Usage

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

This command:

- Mounts code at `/scan_target`
- Writes reports under `/reports`
- Runs all scanners with normalized output
- Keeps raw per-tool output with `--tool_output`

## Apple Silicon (M1/M2/M3)

The published image is `amd64`. On Apple Silicon use:

```bash
docker run --rm --platform linux/amd64 \
  -v /path/to/your/code:/scan_target \
  -v /path/to/reports:/reports \
  appsecthings/dsoinabox:latest \
  --show_findings false \
  -t all \
  -o html
```

## Direct (Non-Docker) Usage

You can run directly if all scanners are already installed and in your `PATH`:

```bash
# Run against current directory
dsoinabox --source . --report_directory ./reports

# Explicit paths
dsoinabox --source /path/to/code --report_directory /path/to/reports
```

When run directly:

- `--source` defaults to `.`
- `--report_directory` defaults to `reports`
- Tool availability is validated from your local `PATH`

## Local Tool Prerequisites (Non-Docker)

Required scanners:

- `trufflehog`
- `opengrep`
- `syft`
- `grype`
- `checkov`

References:

- Grype: <https://github.com/anchore/grype>
- Syft: <https://github.com/anchore/syft>
- OpenGrep: <https://github.com/opengrep/opengrep>
- TruffleHog: <https://github.com/trufflesecurity/trufflehog>
- Checkov: <https://github.com/bridgecrewio/checkov>

For Linux/macOS install snippets and platform caveats, use each tool's official install docs.
