# GitLab CI

```yaml
stages:
  - security

dsoinabox:
  stage: security
  image: docker:27
  services:
    - docker:27-dind
  variables:
    DOCKER_HOST: tcp://docker:2375
    DOCKER_TLS_CERTDIR: ""
  script:
    - mkdir -p reports
    - |
      docker run --rm \
        -v "$CI_PROJECT_DIR:/scan_target" \
        -v "$CI_PROJECT_DIR/reports:/reports" \
        appsecthings/dsoinabox:latest \
        -t all \
        -o sarif,html,json \
        --report_name dsoinabox \
        --failure_threshold high
  artifacts:
    when: always
    paths:
      - reports/
    expire_in: 7 days
```

- Mount repo: `-v "$CI_PROJECT_DIR:/scan_target"`
- Persist artifacts: `artifacts.paths: reports/`
- Gate: `--failure_threshold high` exits 1; a scanner failure exits 2; both are non-zero
- Newest reports are always under `reports/latest/` (`dsoinabox.sarif`, `dsoinabox.html`, ...)

## Cache the Grype DB

With `docker:dind` the daemon and its volumes disappear with the job, so use the GitLab cache. GitLab
only caches paths inside the project directory: mask the cache inside `/scan_target` with an anonymous
volume so it is not scanned, and hand it to uid 1001 (the image's `appuser`).

```yaml
dsoinabox:
  # ...as above, plus:
  cache:
    key: dsoinabox-db
    paths:
      - .dsoinabox-db/
  script:
    - mkdir -p reports .dsoinabox-db && chown -R 1001:1001 .dsoinabox-db
    - |
      docker run --rm \
        -v "$CI_PROJECT_DIR:/scan_target" \
        -v "$CI_PROJECT_DIR/reports:/reports" \
        -v "$CI_PROJECT_DIR/.dsoinabox-db:/var/cache/dsoinabox" \
        -v /scan_target/.dsoinabox-db \
        appsecthings/dsoinabox:latest \
        -t all \
        -o sarif,html,json \
        --report_name dsoinabox \
        --failure_threshold high
```

The DB is about 3 GB unpacked and GitLab re-uploads the cache after each job. On runners that use the
host Docker socket instead of `dind`, a named volume (`-v dsoinabox-db:/var/cache/dsoinabox`) persists
without any upload.
