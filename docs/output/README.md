# Output Formats and Report Layout

## Formats

- `html`: standard interactive human-readable report
- `jenkins_html`: Jenkins-oriented HTML variant
- `json`: full machine-readable report payload
- `ndjson`: newline-delimited JSON for streaming/log pipelines
- `sarif`: SARIF output for GitHub/Azure/SARIF consumers

## Report Structure

Reports are written to `report_directory` with timestamped names:

```text
reports/
├── dsoinabox_unified_report_<timestamp>.html
├── dsoinabox_unified_report_<timestamp>.json
├── dsoinabox_unified_report_<timestamp>.ndjson
├── dsoinabox_unified_report_<timestamp>.sarif
├── benchmark.yaml      # only when --benchmark is enabled
└── tools_output/       # only when --tool_output is enabled
    ├── checkov.json
    ├── grype.json
    ├── opengrep.json
    ├── syft.json
    └── trufflehog.json
```

When `/reports` is mounted in Docker, report artifacts are copied to `/reports/dsoinabox_<timestamp>/`.
