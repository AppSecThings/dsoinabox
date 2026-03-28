# Examples

## Basic Scan (HTML)

```bash
docker run --rm \
  -v $(pwd):/scan_target \
  -v $(pwd)/reports:/reports \
  appsecthings/dsoinabox:latest \
  -t all \
  -o html
```

## SAST + Secrets Only

```bash
docker run --rm \
  -v $(pwd):/scan_target \
  -v $(pwd)/reports:/reports \
  appsecthings/dsoinabox:latest \
  -t SAST,SECRET \
  -o json,html
```

## CI Gate with Severity + Secrets

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

## Checkov with Custom Args

```bash
docker run --rm \
  -v $(pwd):/scan_target \
  -v $(pwd)/reports:/reports \
  appsecthings/dsoinabox:latest \
  -t checkov \
  --checkov_args "--framework terraform --skip-check CKV_AWS_123"
```

## Apply Waivers

```bash
docker run --rm \
  -v $(pwd):/scan_target \
  -v $(pwd)/reports:/reports \
  appsecthings/dsoinabox:latest \
  -t all \
  -o html \
  --waiver_file .dsoinabox_waivers.yaml
```

## Generate Benchmark Baseline

```bash
docker run --rm \
  -v $(pwd):/scan_target \
  -v $(pwd)/reports:/reports \
  appsecthings/dsoinabox:latest \
  -t all \
  -o html \
  --benchmark
```
