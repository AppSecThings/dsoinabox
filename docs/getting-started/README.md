# Getting Started

## Installation

```bash
pip install dsoinabox
```

Recommended: run the Docker image so the scanners come preinstalled and pinned. The image is published for
`linux/amd64` and `linux/arm64`, so Apple Silicon runs it natively.

## Docker

```bash
docker run --rm \
  -v /path/to/your/code:/scan_target \
  -v /path/to/reports:/reports \
  appsecthings/dsoinabox:latest \
  -t all \
  -o html,sarif,json \
  --failure_threshold high
```

- Mounts code at `/scan_target` and writes reports under `/reports/dsoinabox_<timestamp>/` (and
  `/reports/latest/`).
- Prints a summary block and exits 0 (pass), 1 (policy failed), 2 (a scanner failed) or 3 (usage error).
- Add `--show_findings true` for a table of active findings, `--tool_output` to keep raw scanner output.

## Direct (non-Docker)

Requires `trufflehog`, `opengrep`, `syft`, `grype` and `checkov` on `PATH`.

```bash
dsoinabox --source . --report_directory ./reports -o html
dsoinabox tools versions
```

Non-git directories need `--project_id`.

## Next steps

- Set repository defaults: `dsoinabox config init`, then edit `.dsoinabox.yaml` ([Runtime Config](../config/README.md)).
- Waive false positives and accepted risk in `.dsoinabox_waivers.yaml` ([Waivers](../waivers/README.md)).
- Adopt on a legacy codebase with a baseline: `dsoinabox baseline update --from reports/latest/<name>.json`,
  then `--baseline benchmark.yaml --fail_on new`.
- Wire it into CI ([CI examples](../ci/README.md)).
