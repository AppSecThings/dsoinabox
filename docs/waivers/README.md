# Waivers

One waiver file, `.dsoinabox_waivers.yaml` in the repository root, covers every scanner: false positives,
accepted risk, policy exceptions, path exclusions and baselines. Nothing is disabled at the scanner;
everything is applied when findings are processed, so the raw tool output stays complete.

Waiver files are versioned. Any file written for an earlier dsoinabox keeps working; see
[compatibility.md](compatibility.md) for the policy and [`waiver_schema_1.1_example.yaml`](../../dsoinabox/waivers/waiver_schema_1.1_example.yaml)
for every field.

## File layout (schema 1.1)

```yaml
schema_version: "1.1"

meta:                                    # informational
  owner: "Security Engineering"
  notes: "Initial waiver set"

path_exclusions:                         # gitignore-style globs, repo-root relative
  - pattern: "third_party/**"
    reason: "Vendored code"
    expires_at: "2027-01-31"
    tools: ["sast", "secret"]            # optional: tool names or categories, default all

finding_waivers:                         # exact fingerprint match, any tier
  - fingerprint: "og:1:RULE:python.flask.security.xss...:8e50b606...:R:05e2617e"
    type: "false_positive"               # false_positive | risk_acceptance | policy_waiver
    reason: "Offline template rendering, no request input"
    expires_at: "2026-12-31"             # strongly recommended
    created_by: "alice@example.com"
    created_at: "2026-06-06"
    ticket: "SEC-1420"
    tools: ["opengrep"]                  # optional scope

benchmark_expires_at: "2027-06-30"       # optional: the whole baseline must be revalidated by then
benchmark:                               # baseline entries; suppress like waivers, reported as type "benchmark"
  - fingerprint: "gy:1:PKG:CVE-2024-12345:abcdef...:R:05e2617e"
```

Dates accept `YYYY-MM-DD` or ISO 8601 (`2026-01-31T00:00:00Z`), both UTC. Quote `schema_version`.

## What each mechanism does

**Finding waivers** match when any of a finding's fingerprints equals the entry's `fingerprint`. Fingerprints
come in tiers (`RULE`/`SECRET`/`PKG`, `EXACT`, `CTX`); pick the tier that matches how broad the waiver should
be. The HTML report offers each tier in a dropdown and can export a ready-to-commit YAML snippet, and
`dsoinabox waivers add` does the same from the terminal.

**Path exclusions** use gitignore semantics (`pathspec`), including `**` and negation. A finding is excluded
when every path it points at matches; SCA findings can reference several manifests. Exclusions are applied
to results, never to the scanner invocation, so `tools_output/` still contains everything.

**Benchmark entries** are a baseline: findings that were known when the tool was adopted. They suppress
exactly like finding waivers and show up as type `benchmark`. Generate them with `--benchmark` or
`dsoinabox baseline update`.

**`type`** does not change matching. It is carried into the report, the SARIF suppression justification and
the run summary (`waived: 3 (false_positive=2, risk_acceptance=1)`) so exceptions can be audited.

**`tools`** scopes an entry to tool names (`trufflehog`, `opengrep`, `syft`, `grype`, `checkov`) or
categories (`secret`, `sast`, `sbom`, `sca`, `iac`).

## Expiry

An entry whose `expires_at` has passed stops suppressing. The finding is reported as active again, the
Waivers section of the HTML report lists it under "Expired waivers", and the summary counts it
(`expired=1`). `--waiver_grace_days N` keeps expired entries active for N more days, flagged as expiring, to
give teams a warning window. `benchmark_expires_at` expires every benchmark entry at once.

## What waived findings look like

Waived findings are never deleted. In JSON and NDJSON they carry `waived: true` and a `waived_by` record
(kind, type, reason, ticket, expiry, the matching entry). In SARIF they become `suppressions`. In the HTML
report they move out of the per-tool tables into a collapsed "Waived findings" list. The gate, the console
table and `--benchmark` consider only active findings.

Entries that matched nothing in a run are counted as unused (`unused=2`) and listed in the JSON report
under `metadata.waivers.unused`; `waivers prune --report` removes them.

## Maintaining the file

```bash
dsoinabox waivers validate .dsoinabox_waivers.yaml --strict      # CI / pre-commit: fails on expired, duplicate, malformed entries
dsoinabox waivers migrate .dsoinabox_waivers.yaml --dry-run      # show what upgrading to the current schema changes
dsoinabox waivers migrate .dsoinabox_waivers.yaml --in-place     # upgrade, keeping comments; writes a .bak
dsoinabox waivers prune .dsoinabox_waivers.yaml --in-place --report reports/latest/dsoinabox.json
dsoinabox waivers add --fingerprint "og:1:RULE:..." --type false_positive --reason "..." --expires 90d --ticket SEC-1
```

All writers use a round-trip YAML parser, so comments, ordering and quoting in a hand-maintained file survive.

## Baselines

A baseline separates "what this change introduced" from "what was already there".

```bash
dsoinabox scan -o json --report_name run                    # scan
dsoinabox baseline update --from reports/latest/run.json    # write benchmark.yaml from the active findings
dsoinabox scan --baseline benchmark.yaml --fail_on new --failure_threshold high
```

With `--baseline`, every finding is classified `new` or `known` (summary, JSON `baseline_status`, SARIF
properties, a NEW badge in the HTML report). `--fail_on new` makes the gate ignore known findings, so a
legacy codebase can adopt the tool without waiving hundreds of findings while still blocking regressions.
`baseline update --prune` drops entries that no longer match; `--expires` forces a revalidation date.

## Error behaviour

- A missing default waiver file is fine. A missing `--waiver_file` you asked for is a usage error (exit 3).
- An invalid file (bad type, malformed date, unknown tool scope, unsupported schema version) is a usage error
  with a message naming the entry.
- Unknown keys are reported as warnings and ignored.

## Fingerprint format

`<tool>:<fingerprint_version>:<TIER>:<data...>[:R:<repo8>]`, for example
`og:1:RULE:python.lang.security.audit.dangerous-system-call:…:R:3895f288`. Tool prefixes are `th`
(TruffleHog), `og` (OpenGrep), `gy` (Grype), `ck` (Checkov). Fingerprints are HMAC-keyed per project so they
never expose the underlying secret or code, and the same finding gets the same fingerprint on every machine
that scans the same repository. See [compatibility.md](compatibility.md) for what happens when an
algorithm changes.
