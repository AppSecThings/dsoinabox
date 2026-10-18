# Examples

All examples use Docker; drop the `docker run ... appsecthings/dsoinabox:latest` prefix to run the installed
CLI directly.

## Basic scan (HTML)

```bash
docker run --rm -v $(pwd):/scan_target -v $(pwd)/reports:/reports appsecthings/dsoinabox:latest \
  -t all -o html
```

## SAST and secrets only, with a findings table in the terminal

```bash
docker run --rm -v $(pwd):/scan_target -v $(pwd)/reports:/reports appsecthings/dsoinabox:latest \
  -t sast,secret -o json,html --show_findings true
```

## CI gate: fail on high, fail on verified secrets, stable report names

```bash
docker run --rm -v $(pwd):/scan_target -v $(pwd)/reports:/reports appsecthings/dsoinabox:latest \
  -t all -o sarif,html --report_name dsoinabox \
  --failure_threshold high --fail_on_secrets verified
# reports/latest/dsoinabox.sarif is ready to upload
```

## Uncluttered reports while still gating on high

```bash
... --failure_threshold high --report_threshold medium
```

## Adopt on a legacy codebase: only new findings fail

```bash
... -o json --report_name run
dsoinabox baseline update --from reports/latest/run.json --file benchmark.yaml --expires 2027-01-01
... --baseline benchmark.yaml --fail_on new --failure_threshold low
```

## Waiver maintenance

```bash
dsoinabox waivers validate .dsoinabox_waivers.yaml --strict
dsoinabox waivers migrate .dsoinabox_waivers.yaml --in-place
dsoinabox waivers add -p "og:1:RULE:python.lang.security.audit.dangerous-system-call:...:R:3895f288" \
  -t risk_acceptance -r "Input is a fixed allow-list" -e 180d --ticket SEC-42
dsoinabox waivers prune .dsoinabox_waivers.yaml --in-place --report reports/latest/run.json
```

## Reuse the Grype DB between runs

```bash
docker volume create dsoinabox-db
docker run --rm -v $(pwd):/scan_target -v $(pwd)/reports:/reports \
  -v dsoinabox-db:/var/cache/dsoinabox appsecthings/dsoinabox:latest -t all
# installed CLI: dsoinabox -t all --db_cache ~/.cache/dsoinabox
```

The second run within 24 hours of Grype's last update check skips the download. Add `--always_update`
to check for a newer DB every run.

## Dirty working folder: scan only what git tracks

```bash
... -t all -o html --git_tracked_only
# untracked/ignored venv/, node_modules/, build/ are skipped; uncommitted edits are scanned
```

## Air-gapped runner

```bash
... -v dsoinabox-db:/var/cache/dsoinabox --grype_db offline --scan_timeout 900
# the volume must already hold a DB from an online run
```

## Standalone SBOM

```bash
... -t sbom -o cyclonedx,spdx
# reports/latest/sbom.cdx.json and sbom.spdx.json
```

## Checkov with extra arguments

```bash
... -t checkov --checkov_args="--framework terraform --skip-check CKV_AWS_123"
```
