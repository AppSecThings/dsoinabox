# GitHub Actions

```yaml
name: dsoinabox
on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
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
            -o sarif,html,json \
            --failure_threshold high

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
