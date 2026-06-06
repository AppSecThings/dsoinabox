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
        --failure_threshold high
  artifacts:
    when: always
    paths:
      - reports/
    expire_in: 7 days
```

- Mount repo: `-v "$CI_PROJECT_DIR:/scan_target"`
- Persist artifacts: `artifacts.paths: reports/`
- Fail build on threshold: `--failure_threshold high` returns non-zero exit code
