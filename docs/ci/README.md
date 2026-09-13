# CI Examples

Copy-paste CI examples for running `dsoinabox` in common platforms.

- [GitHub Actions](github-actions.md)
- [GitLab CI](gitlab-ci.md)
- [Jenkins](jenkins.md)
- [Azure DevOps](azure-devops.md)

Output format reference:

- [Output Formats and Report Layout](../output/README.md)

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
