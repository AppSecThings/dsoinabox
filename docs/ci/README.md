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
