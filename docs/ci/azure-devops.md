# Azure DevOps

```yaml
trigger:
  branches:
    include:
      - main

pr:
  branches:
    include:
      - "*"

pool:
  vmImage: ubuntu-latest

steps:
  - checkout: self

  - script: |
      mkdir -p reports
      docker run --rm \
        -v "$(Build.SourcesDirectory):/scan_target" \
        -v "$(Build.SourcesDirectory)/reports:/reports" \
        appsecthings/dsoinabox:latest \
        -t all \
        -o sarif,html,json \
        --report_name dsoinabox \
        --failure_threshold high
    displayName: Run dsoinabox (mount repo + threshold gate)

  - task: PublishBuildArtifacts@1
    displayName: Persist artifacts
    condition: always()
    inputs:
      PathtoPublish: '$(Build.SourcesDirectory)/reports'
      ArtifactName: 'dsoinabox-reports'
      publishLocation: 'Container'
```

- Mount repo: `-v "$(Build.SourcesDirectory):/scan_target"`
- Persist artifacts: `PublishBuildArtifacts@1` from `$(Build.SourcesDirectory)/reports`
- Gate: `--failure_threshold high` exits 1; a scanner failure exits 2; both are non-zero
- Newest reports are always under `reports/latest/` (`dsoinabox.sarif`, `dsoinabox.html`, ...)
