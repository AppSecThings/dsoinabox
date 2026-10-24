# CI Examples

Copy-paste CI examples for running `dsoinabox` in common platforms.

- [GitHub Actions](github-actions.md)
- [GitLab CI](gitlab-ci.md)
- [Jenkins](jenkins.md)
- [Azure DevOps](azure-devops.md)

Output format reference:

- [Output Formats and Report Layout](../output/README.md)

## Tracked files only

CI checkouts are usually clean. When earlier steps leave files in the workspace (installed
dependencies, build output, caches), `--git_tracked_only` (or `-e DSOINABOX_GIT_TRACKED_ONLY=true`)
keeps them out of the scan: OpenGrep, Checkov, Syft and Grype see only git-tracked files, with their
working-tree content. Syft and Grype then read tracked manifests and lockfiles, not packages installed
into the workspace. TruffleHog's git history scan is unaffected. The workspace must be a git checkout;
otherwise the run stops with usage exit 3.

## Deny-egress OpenGrep

OpenGrep's default rules source is `auto`, which contacts semgrep.dev. CI jobs without egress should
mount version-controlled rules and select them explicitly:

```bash
docker run --rm \
  -v "$PWD:/scan_target:ro" \
  -v "$PWD/reports:/reports" \
  -v "$PWD/rules:/rules:ro" \
  -e DSOINABOX_OPENGREP_RULES=/rules \
  appsecthings/dsoinabox:latest \
  -t opengrep \
  -o sarif,html \
  --report_name dsoinabox
```

You can instead pass `--opengrep_rules /rules` (or `--opengrep-rules`) or use the
`opengrep_rules` config key. YAML supports a string or list; environment/CLI values are
comma-separated. Each local entry becomes `--config`, relative paths resolve against `--source`,
and `auto` cannot be mixed with local paths. Missing paths are usage exit 3 before scans. If `auto`
cannot download, the run reports scanner exit 2 and advises local rules.

Custom rules add ` (rules <configured-source>)` to OpenGrep version metadata in summaries and
reports; the default `auto` output remains unchanged. The project image prewarms OpenGrep's self-extracted cache
for `appuser`. Custom images or hardened mounts must leave that cache on a filesystem that supports
execution.

## Reuse the Grype DB

Without a cache every job downloads Grype's vulnerability database. The image keeps it under
`/var/cache/dsoinabox` (`DSOINABOX_DB_CACHE`); persist that directory and Grype reuses the DB without
touching the network until its last update check is 24 hours old. `--always_update` checks on every
run instead and still downloads only when a newer DB exists.

- Persistent Docker host (self-hosted agents): mount a named volume, `-v dsoinabox-db:/var/cache/dsoinabox`.
- Ephemeral runners: restore and save a host directory with the platform's cache and mount it there.
  Keep the directory outside the checkout: the DB is about 3 GB unpacked and would otherwise be scanned.
- A host directory must be writable by uid 1001 (the image's `appuser`); otherwise Grype fails (exit 2)
  with a message saying so.
- `--grype_db offline` scans against a restored cache without network access.

Per-platform snippets: [GitHub Actions](github-actions.md#cache-the-grype-db),
[GitLab CI](gitlab-ci.md#cache-the-grype-db), [Jenkins](jenkins.md),
[Azure DevOps](azure-devops.md#cache-the-grype-db).
