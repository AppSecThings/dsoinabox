# Runtime Config

`dsoinabox` supports repo-level defaults via `.dsoinabox.yaml`.

## Quick Start

1. Generate a starter file:

```bash
dsoinabox --init-config
```

2. Edit `.dsoinabox.yaml` in your repo root.

3. Run scans normally; values are merged with this precedence:

`config defaults -> DSOINABOX_* environment variables -> CLI flags`

## Init Behavior

- `--init-config` writes a starter config file and exits.
- By default it writes `./.dsoinabox.yaml` (or `<source>/.dsoinabox.yaml` if `--source` is set).
- You can target another path with `--config_file` or `DSOINABOX_CONFIG`.
- Existing files are not overwritten.

## Supported Keys

- `source`
- `report_directory`
- `project_id`
- `tools`
- `failure_threshold`
- `fail_on_secrets`
- `show_findings`
- `waiver_file`
- `output`
- `tool_output`
- `benchmark`
- `trufflehog_args`
- `opengrep_args`
- `syft_args`
- `grype_args`
- `checkov_args`

You can also define tool args with nested maps:

- `tool_args`
- `extra_tool_args`

Example:

```yaml
tool_args:
  opengrep: "--severity high"
  checkov: "--framework terraform"
```

## Example Files

- `examples/.dsoinabox.yaml`: starter config template.
