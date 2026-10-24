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

## Cache the Grype DB

Microsoft-hosted agents start clean, so restore the DB with `Cache@2` from a directory outside the
checkout. The key changes once a day, in step with Grype's 24-hour update check. The directory is
handed to uid 1001 (the image's `appuser`) for the run and back to the agent user so the cache can be
saved.

```yaml
  - script: echo "##vso[task.setvariable variable=DbCacheDay]$(date -u +%F)"
    displayName: Day stamp for the Grype DB cache

  - task: Cache@2
    displayName: Restore Grype DB cache
    inputs:
      key: 'dsoinabox-db | "$(DbCacheDay)"'
      restoreKeys: 'dsoinabox-db'
      path: $(Pipeline.Workspace)/dsoinabox-db

  - script: |
      mkdir -p reports "$(Pipeline.Workspace)/dsoinabox-db"
      sudo chown -R 1001:1001 "$(Pipeline.Workspace)/dsoinabox-db"
      docker run --rm \
        -v "$(Build.SourcesDirectory):/scan_target" \
        -v "$(Build.SourcesDirectory)/reports:/reports" \
        -v "$(Pipeline.Workspace)/dsoinabox-db:/var/cache/dsoinabox" \
        appsecthings/dsoinabox:latest \
        -t all \
        -o sarif,html,json \
        --report_name dsoinabox \
        --failure_threshold high
    displayName: Run dsoinabox (mount repo + threshold gate)

  - script: sudo chown -R "$(id -u):$(id -g)" "$(Pipeline.Workspace)/dsoinabox-db"
    displayName: Return the Grype DB cache to the agent user
    condition: always()
```

On self-hosted agents with a persistent Docker host, a named volume
(`-v dsoinabox-db:/var/cache/dsoinabox`) is enough.
