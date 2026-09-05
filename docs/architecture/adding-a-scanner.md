# Adding a Scanner

Adding a tool touches four places. Nothing in `run.py`, `cli.py` or `policy.py` is tool-specific.

1. **Wrapper** in `dsoinabox/scanners/<category>/<tool>.py`: subclass `BaseScanner`, implement
   `run_scan(source_path, extra_tool_args, report_directory, timeout=None) -> raw payload`, and write the raw
   output into `report_directory` as `<tool>.json`. Expose module-level `run_scan` and `_scanner` like the
   existing wrappers (the registry calls `module.run_scan` so tests can monkeypatch it).

2. **Fingerprints** in `dsoinabox/fingerprints/<tool>.py`: a `fingerprint_findings(raw, source_path,
   project_id=...)` that adds `fingerprints: {tier: "<prefix>:1:<TIER>:..."}` to every record. Use
   `resolve_project_key(project_id)` and `repo_hint_for(project_id)` from `fingerprints/registry.py`; register
   the tool prefix in `TOOL_PREFIX` and its version in `CURRENT_FP_VERSION` / `SUPPORTED_FP_VERSIONS`. Add
   cases to `tests/unit/fingerprints/test_golden_v1.py` and regenerate the golden file (adding cases is
   allowed; changing existing outputs is not).

3. **Normalizer** in `dsoinabox/normalize/<tool>.py`: `normalize(raw, source_path) -> list[Finding]`. Map the
   tool's severity in `model.normalize_severity`, call `attach_common(...)` so paths are relativized and waiver
   annotations are picked up, and register it in `normalize/__init__.py`. Extend
   `reporting/fields.py::finding_paths` so path exclusions know where the tool keeps its file paths.

4. **Registry entry** in `dsoinabox/scanners/registry.py`: a `ScannerSpec` with name, category, executable,
   module, `run`, `fingerprint`, `normalize`, optional `depends_on` and aliases.

Then add:

- an HTML partial `default_<tool>.html` in both `templates/html/` and `templates/jenkins_html/`, included from
  `default_unified_report.html`, with finding rows tagged `data-report-row data-severity=... data-baseline=...`
  and `data-fingerprints=...` so pagination, filters and the waiver export work;
- a fixture `tests/fixtures/scanner_outputs/<tool>.json` (the `fake_runner` fixture serves it by command name);
- `TOOL_INFO` in `reporting/sarif_run.py` for the tool name and URL;
- a planted finding in `tests/fixtures/sample_repo/` for the live smoke test;
- the Dockerfile install step with a pinned version and a Renovate comment.

`tests/unit/scanners/test_registry.py` fails until the partials, fixture and normalizer exist.
