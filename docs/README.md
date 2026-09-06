# Docs

- `getting-started/`: install, Docker usage, first steps
- `cli/`: every subcommand and flag, policy gate, exit codes
- `config/`: `.dsoinabox.yaml` keys, precedence, examples
- `waivers/`: the unified exception model (waivers, path exclusions, expiry, baselines) and the
  [compatibility contract](waivers/compatibility.md) for waiver files and fingerprints
- `output/`: report formats, directory layout, JSON and SARIF details, console summary
- `ci/`: GitHub Actions, GitLab CI, Jenkins, Azure DevOps snippets
- `examples/`: copy-paste commands for common workflows
- `architecture/`: pipeline, normalized model, [adding a scanner](architecture/adding-a-scanner.md)
- [`upgrading.md`](upgrading.md): what changed in 1.0.0 and how to keep old behaviour
- `demo/`: README images

Conventions: the root README stays short; long-form material lives here, one self-contained topic per directory.
