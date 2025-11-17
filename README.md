# DevSecOps in a Box (dsoinabox)

 **Most DevSecOps teams rely on multiple scanners, but managing their inconsistencies is a challenging**. Different outputs, incompatible severity scales, duplicated findings across multiple reports, and separate waiver/exception files needed for every tool all complicate an already complex process.

 **DSO in a Box (`dsoinabox`)** unifies industry leading open source security tools (**TruffleHog, OpenGrep, Syft, Grype, and Checkov**) into one consistent, configurable workflow.

 Instead of reinventing scanning, `dsoinabox` standardizes these proven tools with:

 * **Normalized severity and thresholding**, so build breaking decisions are predictable across all scanners
 * A powerful **waiver and benchmarking layer**, helping teams:
   * Track technical debt without blocking releases
   * Manage false positives, risk acceptances, and policy exceptions

 Perfect for **CI/CD pipelines, PR checks, and automated security workflows**, `dsoinabox` gives you scalable vulnerability detection without the noise or chaos.

## Features

- **Multi-Scanner Support**: Orchestrates multiple security scanners in parallel
- **Unified Reporting**: Consolidates findings from all scanners into a single report
- **Multiple Output Formats**: Supports HTML, Jenkins HTML, JSON, and SARIF formats
- **Security Gating**: Configurable failure thresholds based on finding severity
- **Waiver System**: YAML-based waiver management for false positives and risk acceptance
- **Benchmark Mode**: Generate benchmark.yaml files with all findings for baseline establishment
- **Project Identification**: Automatic project ID derivation from Git repositories
- **CI/CD Ready**: Returns appropriate exit codes for pipeline integration

## Supported Scanners

dsoinabox integrates the following security scanners:

| Scanner | Category | Purpose |
|---------|----------|---------|
| **TruffleHog** | SECRET | Secrets detection and scanning |
| **OpenGrep** | SAST | Static Application Security Testing |
| **Syft** | SBOM | Software Bill of Materials generation |
| **Grype** | SCA | Software Composition Analysis / Vulnerability scanning |
| **Checkov** | IaC | Infrastructure as Code security scanning |

## Quick Start

### Installation

Install dsoinabox using pip:

```bash
pip install dsoinabox
```

### Docker Usage

The recommended way to use dsoinabox is via Docker:

```bash
docker run --rm \
  -v /path/to/your/code:/scan_target \
  -v /path/to/reports:/reports \
  appsecthings/dsoinabox:latest \
  --show_findings false \
  -t all \
  -o sarif,html \
  --tool_output
```

### Example: Scanning a Repository

```bash
docker run --rm \
  -v /path/to/your/code:/scan_target \
  -v /path/to/reports:/reports \
  appsecthings/dsoinabox:latest \
  --show_findings false \
  -t all \
  -o sarif,html \
  --tool_output
```

This command:
- Mounts your code to `/scan_target` inside the container
- Mounts a reports directory to `/reports` for output
- Runs all scanners (`-t all`)
- Generates reports in both SARIF and HTML formats (`-o sarif,html`)
- Suppresses CLI output of findings (`--show_findings false`)
- Preserves raw tool output files (`--tool_output`)

### Running on macOS (Apple Silicon)

The published Docker image is built for `amd64` architecture. When running on Apple Silicon (M1/M2/M3) Macs, you need to specify the platform:

```bash
docker run --rm --platform linux/amd64 \
  -v /path/to/your/code:/scan_target \
  -v /path/to/reports:/reports \
  appsecthings/dsoinabox:latest \
  --show_findings false \
  -t all \
  -o html
```

**Example: Scanning a Repository on Mac**

```bash
docker run --rm --platform linux/amd64 \
  -v /path/to/your/code:/scan_target \
  -v /path/to/reports:/reports \
  appsecthings/dsoinabox:latest \
  --show_findings false \
  -t all \
  -o html
```

The `--platform linux/amd64` flag tells Docker to run the amd64 image using emulation. The rest of the command syntax is identical to Linux usage.

### Direct Usage (Non-Docker)

dsoinabox can also be run directly on your system without Docker. This requires that all scanner tools (trufflehog, opengrep, syft, grype, checkov) are installed and available in your PATH.

```bash
# Install dsoinabox
pip install dsoinabox

# Run scan on current directory
dsoinabox --source . --report_directory ./reports

# Or with explicit paths
dsoinabox --source /path/to/code --report_directory /path/to/reports
```

**Note**: When running directly (not in Docker), dsoinabox will:
- Default `--source` to the current directory (`.`) instead of `/scan_target`
- Default `--report_directory` to `reports` (relative to source)
- Check that all required scanner tools are available in PATH before running
- Skip copying reports to `/reports` mount (Docker-only feature)

**Prerequisites for Direct Usage**:
- Python 3.11+
- All scanner tools installed and in PATH:
  - `trufflehog`
  - `opengrep`
  - `syft`
  - `grype`
  - `checkov`

## Local tool installation (required for non-docker usage)

dsoinabox requires the following scanner tools to be installed and available in your `PATH`:
- **Grype** - Software Composition Analysis ([GitHub](https://github.com/anchore/grype))
- **Syft** - SBOM generation ([GitHub](https://github.com/anchore/syft))
- **Opengrep** - Static Application Security Testing ([GitHub](https://github.com/opengrep/opengrep))
- **TruffleHog** - Secrets detection ([GitHub](https://github.com/trufflesecurity/trufflehog))
- **Checkov** - Infrastructure as Code scanning ([GitHub](https://github.com/bridgecrewio/checkov))

### Linux

Run the following script to install all required tools:

```bash
#!/bin/bash
set -e

# Install Grype
curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin

# Install Syft
curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin

# Install Opengrep
curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash

# Install TruffleHog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Install Checkov (requires Python 3)
pip3 install checkov

# Verify installations
echo "Verifying installations..."
grype --version && syft version && opengrep --version && trufflehog --version && checkov --version
```

**Note**: Ensure `$HOME/.local/bin` (where Opengrep installs) is on your `PATH`. Add to `~/.bashrc` or `~/.zshrc`:
```bash
export PATH="$HOME/.local/bin:$PATH"
```

### macOS

Run the following script to install all required tools:

```bash
#!/bin/bash
set -e

# Install Grype via Homebrew
brew tap anchore/grype
brew install grype

# Install Syft via Homebrew
brew install syft

# Install Opengrep
curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash

# Install TruffleHog via Homebrew
brew install trufflehog

# Install Checkov (requires Python 3)
pip3 install checkov

# Verify installations
echo "Verifying installations..."
grype --version && syft version && opengrep --version && trufflehog --version && checkov --version
```

**Note**: Ensure `$HOME/.local/bin` (where Opengrep installs) is on your `PATH`. Add to `~/.zshrc`:
```bash
export PATH="$HOME/.local/bin:$PATH"
```

### Windows

**Not all scanner tools have native Windows support.** The recommended approaches are:

1. **Use Docker** (recommended): Run dsoinabox via the Docker image, which includes all tools pre-installed. See the [Docker Usage](#docker-usage) section above.

2. **Use WSL2**: Install a Linux distribution via Windows Subsystem for Linux and follow the Linux installation instructions in the section above.

While some tools (Syft, Opengrep, Checkov) have Windows binaries available, others (Grype) do not provide official Windows builds. Using Docker or WSL ensures all tools work correctly and is the most reliable path for Windows users.


## Command-Line Arguments

### Tool Selection

- `--tools`, `-t` (default: `all`)
  - Comma-separated list of tools to run
  - Options: `trufflehog`, `opengrep`, `syft`, `grype`, `checkov`
  - Categories: `SAST`, `SBOM`, `SECRET`, `SCA`, `IAC`
  - Example: `-t trufflehog,opengrep` or `-t SAST,SECRET`

### Source and Output

- `--source` (default: `/scan_target` in Docker, `.` when run directly)
  - Path to code to scan
  - In Docker: mount code to container at this path (default: `/scan_target`)
  - When run directly: path to code directory (default: current directory)

- `--report_directory` (default: `reports`)
  - Directory to store reports in (created relative to source path)
  - In Docker: if `/reports` mount exists, copies reports there automatically
  - When run directly: reports are stored in the specified directory

- `--output`, `-o` (default: `html`)
  - Output format(s) for the report
  - Comma-separated list: `html`, `jenkins_html`, `json`, `sarif`
  - Example: `--output json,html,sarif`

- `--tool_output` (default: `False`)
  - If enabled, keeps tool output files in `tools_output` subdirectory
  - Default behavior: tool outputs are deleted after report generation

### Project Configuration

- `--project-id`
  - Explicit project identifier (required for non-git directories)
  - If not provided, will be derived from git remote or initial commit

### Security Gating

- `--failure_threshold` (default: `none`)
  - Failure threshold for the scan
  - Options: `none`, `info`, `low`, `medium`, `high`, `critical`
  - Returns non-zero exit code if findings at or above this severity are found

- `--fail_on_secrets`
  - Fail the scan if any secrets are found (TruffleHog findings)

### Display Options

- `--show_findings` (default: `True`)
  - Show findings from tools in CLI output
  - Use `--show_findings False` to disable

### Waiver Management

- `--waiver_file` (default: `.dsoinabox_waivers.yaml`)
  - Path to waiver file (YAML format)
  - If provided, findings matching waiver fingerprints will be marked as waived
  - Path is relative to the source directory

- `--benchmark`
  - Generate `benchmark.yaml` file with all findings from all tools
  - Benchmark entries will have `type: "benchmark"` and can be used as waiver files
  - Output is written to the report directory

### Tool-Specific Options

Each scanner supports additional arguments:

- `--trufflehog_args`: Extra args to pass to TruffleHog
- `--opengrep_args`: Extra args to pass to OpenGrep
- `--syft_args`: Extra args to pass to Syft
- `--grype_args`: Extra args to pass to Grype
- `--checkov_args`: Extra args to pass to Checkov

### Help and Version

- `--version`: Show the app version and exit
- `--tool_versions`: Show tool versions and exit
- `--trufflehog_help`: Show TruffleHog help and exit
- `--opengrep_help`: Show OpenGrep help and exit
- `--syft_help`: Show Syft help and exit
- `--grype_help`: Show Grype help and exit
- `--checkov_help`: Show Checkov help and exit

## Output Formats

### HTML (`html`)
Standard HTML report with interactive findings display. Includes consolidated results from all scanners.

### Jenkins HTML (`jenkins_html`)
HTML report optimized for Jenkins pipeline integration with enhanced styling and layout.

### JSON (`json`)
Machine-readable JSON format containing all scan data:
- Metadata (scan timestamp, git repo info)
- Findings from all scanners
- Tool-specific data structures

### SARIF (`sarif`)
SARIF (Static Analysis Results Interchange Format) output for integration with:
- GitHub Security
- Azure DevOps
- Other SARIF-compatible tools

## Waiver System

dsoinabox supports a YAML-based waiver system for managing false positives and risk acceptance. Create a `.dsoinabox_waivers.yaml` file in your repository root.

### Waiver File Structure

```yaml
schema_version: "1.0"

meta:
  owner: "Security Engineering"
  created_by: "alice@example.com"
  created_at: "2025-11-08T14:20:00Z"
  notes: "Initial waiver set for MVP"

# Path-based exclusions (repo-root-relative, .gitignore-style globs)
path_exclusions:
  - pattern: "third_party/**"
    reason: "Vendored code"
    expires_at: "2026-01-31T00:00:00Z"
    tools: ["trufflehog", "opengrep"]  # Optional: specific tools or categories

# Finding-level waivers by fingerprint
finding_waivers:
  - fingerprint: "og:1:CTX:html.security.audit.missing-integrity.missing-integrity:0c065896:a9ef9d591c62c38b:R:a3d1696c"
    type: "false_positive"  # false_positive | risk_acceptance | policy_waiver
    reason: "Static context proved safe"
    expires_at: "2026-05-01T00:00:00Z"
    created_by: "alice@example.com"
    created_at: "2025-11-01"
    meta_ticket: "SEC-1420"
```

### Waiver Types

- **false_positive**: Finding is not a real security issue
- **risk_acceptance**: Security risk is acknowledged and accepted
- **policy_waiver**: Policy exception granted
- **benchmark**: Baseline finding (automatically set when loading benchmark section)

### Benchmark Section

Waiver files can include a `benchmark` section with the same structure as `finding_waivers`. All entries in the `benchmark` section automatically have their `type` overridden to `"benchmark"`, regardless of what is specified in the file. This allows you to establish baselines of expected findings.

```yaml
schema_version: "1.0"

finding_waivers:
  - fingerprint: "og:1:RULE:test:abc"
    type: "false_positive"
    reason: "Known false positive"

benchmark:
  - fingerprint: "og:1:RULE:baseline:xyz"
    type: "risk_acceptance"  # This will be overridden to "benchmark"
    reason: "Baseline finding"
```

When loading waiver files, the `benchmark` section is automatically included in waiver matching, so benchmark entries will waive matching findings just like regular waiver entries.

## Exit Codes

dsoinabox uses exit codes for CI/CD integration:

- `0`: All scans completed successfully, no threshold violations
- `1`: Scan failed or threshold exceeded

Threshold violations occur when:
- Findings exceed the `--failure_threshold` severity level
- Secrets are found and `--fail_on_secrets` is enabled

## Examples

### Basic Scan with HTML Report

```bash
docker run --rm \
  -v $(pwd):/scan_target \
  -v $(pwd)/reports:/reports \
  appsecthings/dsoinabox:latest \
  -t all \
  -o html
```

### SAST and Secrets Scanning Only

```bash
docker run --rm \
  -v $(pwd):/scan_target \
  -v $(pwd)/reports:/reports \
  appsecthings/dsoinabox:latest \
  -t SAST,SECRET \
  -o json,html
```

### CI/CD Pipeline with Gating

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

This will fail the pipeline if:
- Any findings with severity `high` or `critical` are found
- Any secrets are detected

### Custom Tool Arguments

```bash
docker run --rm \
  -v $(pwd):/scan_target \
  -v $(pwd)/reports:/reports \
  appsecthings/dsoinabox:latest \
  -t checkov \
  --checkov_args "--framework terraform --skip-check CKV_AWS_123"
```

### With Waiver File

```bash
docker run --rm \
  -v $(pwd):/scan_target \
  -v $(pwd)/reports:/reports \
  appsecthings/dsoinabox:latest \
  -t all \
  -o html \
  --waiver_file .dsoinabox_waivers.yaml
```

### Generate Benchmark File

```bash
docker run --rm \
  -v $(pwd):/scan_target \
  -v $(pwd)/reports:/reports \
  appsecthings/dsoinabox:latest \
  -t all \
  -o html \
  --benchmark
```

This will generate a `benchmark.yaml` file in the report directory containing all findings from all tools. The benchmark file can be used as a waiver file, with all entries having `type: "benchmark"`.

## Report Structure

Reports are generated in the `report_directory` with timestamped filenames:

```
reports/
├── dsoinabox_unified_report_2025_11_13T22_55_15.html
├── dsoinabox_unified_report_2025_11_13T22_55_15.json
├── dsoinabox_unified_report_2025_11_13T22_55_15.sarif
├── benchmark.yaml  # Only if --benchmark is enabled
└── tools_output/  # Only if --tool_output is enabled
    ├── checkov.json
    ├── grype.json
    ├── opengrep.json
    ├── syft.json
    └── trufflehog.json
```

If a `/reports` volume is mounted, reports are also copied to `/reports/dsoinabox_<timestamp>/`.

## Architecture

dsoinabox orchestrates scanners in parallel for efficiency:

1. **Independent Scans** (parallel):
   - TruffleHog (secrets)
   - OpenGrep (SAST)
   - Syft (SBOM)
   - Checkov (IaC)

2. **Dependent Scan** (after Syft):
   - Grype (SCA) - requires SBOM from Syft

3. **Report Generation**:
   - Parses and normalizes all scanner outputs
   - Applies waivers
   - Generates unified reports in requested formats
   - Applies failure thresholds for gating

## Project Identification

dsoinabox automatically derives project IDs from:
1. Git remote URL (if available)
2. Git initial commit hash (if no remote)
3. Explicit `--project-id` argument (if provided)

This ensures consistent fingerprinting across scans and environments.


