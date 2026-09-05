"""Scan orchestration: run selected scanners, fingerprint, normalize, apply waivers,
evaluate policy and write reports. Pure function of ``ScanOptions``; no argv here.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from typing import Any

from . import __version__
from .model import Finding, ScanOptions, ScanResult, ScanRun, severity_at_or_above
from .policy import evaluate
from .reporting.report_builder import report_builder
from .scanners.base import ScannerError
from .scanners.registry import RunContext, ScannerSpec, select_tools
from .utils import environment
from .utils.deterministic import utcnow
from .utils.git import GitRepoInfo, set_git_safe_directory
from .utils.project_id import derive_project_id, is_git
from .waivers import generate_benchmark_yaml, load_waiver_file
from .waivers.apply import WaiverEngine, WaiverUsage, apply_waivers_to_model
from .waivers.baseline import apply_baseline
from .waivers.models import WaiverSet

logger = logging.getLogger(__name__)

REPORT_OUTPUTS: tuple[str, ...] = ("html", "jenkins_html", "json", "ndjson", "sarif")
SBOM_OUTPUTS: tuple[str, ...] = ("cyclonedx", "spdx")
VALID_OUTPUTS: tuple[str, ...] = REPORT_OUTPUTS + SBOM_OUTPUTS


class UsageError(ValueError):
    """Configuration or environment problem; maps to exit code 3."""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _load_waivers(options: ScanOptions) -> WaiverSet | None:
    if not options.waiver_file:
        return None
    path = os.path.join(options.source, options.waiver_file)
    try:
        ws = load_waiver_file(path)
    except FileNotFoundError:
        if options.waiver_file_is_default:
            logger.info(f"Did not find waiver file: {options.waiver_file}")
            return None
        raise UsageError(f"Failed to load the specified waiver file: {options.waiver_file}.") from None
    except ValueError as exc:
        raise UsageError(f"An error occurred while loading the waiver file: {exc}") from None
    logger.info(
        f"Waiver file loaded (schema {ws.schema_version}): {len(ws.finding_waivers)} finding waivers, "
        f"{len(ws.benchmark)} benchmark entries, {len(ws.path_exclusions)} path exclusions"
    )
    return ws


def _tool_versions(specs: list[ScannerSpec]) -> dict[str, str]:
    versions: dict[str, str] = {}

    def one(spec: ScannerSpec) -> tuple[str, str]:
        try:
            return spec.name, spec.get_version()
        except Exception as exc:  # version is best-effort
            logger.debug(f"{spec.name} version check failed: {exc}")
            return spec.name, ""

    with ThreadPoolExecutor(max_workers=max(1, len(specs))) as ex:
        for name, version in ex.map(one, specs):
            versions[name] = version
    return versions


def _run_one(spec: ScannerSpec, ctx: RunContext, engine: WaiverEngine | None) -> tuple[ScanResult, WaiverUsage]:
    result = ScanResult(tool=spec.name, category=spec.category)
    usage = WaiverUsage()
    logger.info(f"Running {spec.display_name} scan on {ctx.source}")
    started = time.perf_counter()
    try:
        raw = spec.run(ctx)
        result.duration_s = time.perf_counter() - started
        logger.info(f"{spec.display_name} scan completed in {result.duration_s:.2f} seconds")
        if spec.fingerprint is not None:
            raw = spec.fingerprint(raw, ctx) or raw
        result.raw = raw
        if spec.normalize is not None:
            result.findings = spec.normalize(raw, ctx.source)
            usage = apply_waivers_to_model(spec.name, result.findings, engine)
        if spec.raw_output_filename:
            candidate = os.path.join(ctx.tools_output_dir, spec.raw_output_filename)
            if os.path.exists(candidate):
                result.raw_output_path = candidate
        result.status = "ok"
    except subprocess.TimeoutExpired:
        result.duration_s = time.perf_counter() - started
        result.status = "failed"
        result.error = f"timed out after {ctx.timeout} seconds"
        logger.error(f"{spec.display_name} {result.error}")
    except ScannerError as exc:
        result.duration_s = time.perf_counter() - started
        result.status = "failed"
        result.error = str(exc).strip()
        logger.error(f"Scanner error running {spec.name}: {result.error}")
    except Exception as exc:  # keep the run going; report the failure
        result.duration_s = time.perf_counter() - started
        result.status = "failed"
        result.error = f"{type(exc).__name__}: {exc}"
        logger.error(f"Error running {spec.name}: {result.error}")
    return result, usage


def _schedule(
    specs: list[ScannerSpec],
    ctx_for: Any,
    engine: WaiverEngine | None,
    *,
    fail_fast: bool,
    max_workers: int,
) -> tuple[list[ScanResult], WaiverUsage]:
    """Run specs in parallel honoring ``depends_on`` ordering. Never raises for a tool failure."""
    selected = {s.name for s in specs}
    pending: dict[str, ScannerSpec] = {s.name: s for s in specs}
    results: dict[str, ScanResult] = {}
    total_usage = WaiverUsage()
    aborted = False

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(specs) or 1))) as ex:
        futures: dict[Future, str] = {}
        while pending or futures:
            if not aborted:
                for name, spec in list(pending.items()):
                    deps = [d for d in spec.depends_on if d in selected]
                    if all(d in results for d in deps):
                        futures[ex.submit(_run_one, spec, ctx_for(spec), engine)] = name
                        del pending[name]
            if not futures:
                break
            done, _ = wait(list(futures), return_when=FIRST_COMPLETED)
            for fut in done:
                name = futures.pop(fut)
                result, usage = fut.result()
                results[name] = result
                total_usage.merge(usage)
                if result.status == "failed" and fail_fast and not aborted:
                    aborted = True
                    logger.error(f"--fail_fast: {name} failed, skipping remaining scanners")
            if aborted and pending:
                for name, spec in pending.items():
                    results[name] = ScanResult(tool=name, category=spec.category, status="skipped",
                                               error="skipped because an earlier scanner failed (--fail_fast)")
                pending.clear()

    ordered = [results[s.name] for s in specs if s.name in results]
    return ordered, total_usage


def _report_payload(result: ScanResult, report_threshold: Any) -> tuple[Any, int]:
    """Raw payload for reports with findings below report_threshold removed. Returns (payload, hidden)."""
    from .reporting.report_builder import _with_findings

    if result.raw is None or report_threshold is None or not result.findings:
        return result.raw, 0
    keep: list[dict[str, Any]] = []
    hidden = 0
    for f in result.findings:
        if severity_at_or_above(f.severity, report_threshold):
            keep.append(f.raw)
        else:
            hidden += 1
    if hidden == 0:
        return result.raw, 0
    return _with_findings(result.tool, result.raw, keep), hidden


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def run_scan(options: ScanOptions) -> ScanRun:
    """Run a scan end to end. Raises ``UsageError`` for configuration problems; tool failures are recorded."""
    started_at = utcnow()

    if not os.path.exists(options.source):
        raise UsageError(f"Source code path {options.source} does not exist.")

    for fmt in options.outputs:
        if fmt not in VALID_OUTPUTS:
            raise UsageError(f"Invalid output format: {fmt}. Supported formats: {', '.join(VALID_OUTPUTS)}")

    try:
        specs = select_tools(options.tools)
    except ValueError as exc:
        raise UsageError(str(exc)) from None
    if not specs:
        raise UsageError("No tools selected.")

    is_git_repo = is_git(options.source)
    logger.info(f"Source is {'a' if is_git_repo else 'not a'} git repository: {options.source}")

    os.makedirs(options.report_directory, exist_ok=True)
    tools_output_dir = os.path.join(options.report_directory, "tools_output")
    os.makedirs(tools_output_dir, exist_ok=True)
    set_git_safe_directory(options.source)

    try:
        project_id = derive_project_id(options.source, options.project_id)
    except ValueError as exc:
        raise UsageError(str(exc)) from None
    logger.info(f"Using project ID: {project_id}")

    missing = [s.executable for s in specs if not environment.check_tool_available(s.executable)]
    if missing:
        raise UsageError(
            f"The following required tools are not available in PATH: {', '.join(missing)}. "
            "Please ensure these tools are installed and available in your PATH."
        )

    waiver_set = _load_waivers(options)
    engine = WaiverEngine(waiver_set, grace_days=options.waiver_grace_days) if waiver_set else None

    git_info = None
    try:
        git_info = GitRepoInfo(options.source).as_dict()
    except ValueError:
        logger.debug(f"{options.source} is not a git repository, continuing without git info")

    versions = _tool_versions(specs)

    def ctx_for(spec: ScannerSpec) -> RunContext:
        return RunContext(
            source=options.source,
            tools_output_dir=tools_output_dir,
            project_id=project_id,
            is_git_repo=is_git_repo,
            extra_args=options.tool_args.get(spec.name),
            timeout=options.tool_timeouts.get(spec.name, options.scan_timeout),
        )

    results, usage = _schedule(specs, ctx_for, engine, fail_fast=options.fail_fast, max_workers=options.max_workers)
    for r in results:
        r.tool_version = versions.get(r.tool, "")

    run = ScanRun(
        started_at=started_at,
        dsoinabox_version=__version__,
        timestamp=options.timestamp,
        project_id=project_id,
        source=options.source,
        report_directory=options.report_directory,
        git_info=git_info,
        results=results,
        waiver_summary=usage.summary_dict(waiver_set) if waiver_set else None,
    )
    if options.baseline:
        try:
            run.baseline_summary = apply_baseline(run.findings, os.path.join(options.source, options.baseline)
                                                   if not os.path.isabs(options.baseline) else options.baseline)
        except FileNotFoundError:
            raise UsageError(f"Baseline file not found: {options.baseline}") from None
        except ValueError as exc:
            raise UsageError(f"Invalid baseline file {options.baseline}: {exc}") from None
        bs = run.baseline_summary
        logger.info(f"Baseline {bs['file']}: {bs['new']} new, {bs['known']} known finding(s)")
    run.policy = evaluate(run, options)
    run.fingerprint_aliases = fingerprint_aliases(run.findings)

    if run.waiver_summary:
        ws = run.waiver_summary
        by_type = ", ".join(f"{k}={v}" for k, v in sorted(ws["waived_by_type"].items())) or "none"
        logger.info(
            f"Waivers applied: {ws['waived']} waived ({by_type}); {ws['expired_matches']} expired match(es); "
            f"{ws['unused_count']} unused entr{'y' if ws['unused_count'] == 1 else 'ies'}"
        )
        for ref in ws["unused"]:
            logger.debug(f"Unused waiver entry: {ref}")

    # benchmark of active findings
    if options.benchmark:
        benchmark_path = os.path.join(options.report_directory, "benchmark.yaml")
        payloads: dict[str, Any] = {}
        for r in results:
            if r.raw is None or r.category == "sbom":
                continue
            from .reporting.report_builder import _with_findings

            payloads[r.tool] = _with_findings(r.tool, r.raw, [f.raw for f in r.active_findings])
        generate_benchmark_yaml(
            trufflehog_data=payloads.get("trufflehog"),
            opengrep_data=payloads.get("opengrep"),
            grype_data=payloads.get("grype"),
            checkov_data=payloads.get("checkov"),
            output_path=benchmark_path,
        )
        logger.info(f"Benchmark file generated: {benchmark_path}")
        run.report_paths.append(benchmark_path)

    # reports (report_threshold trims what is shown, never what is gated)
    report_data: dict[str, Any] = {}
    hidden_total = 0
    for r in results:
        payload, hidden = _report_payload(r, options.report_threshold)
        report_data[r.tool] = payload
        hidden_total += hidden
    run.hidden_by_report_threshold = hidden_total

    for fmt in [f for f in options.outputs if f in REPORT_OUTPUTS]:
        path = report_builder(
            reports_directory=options.report_directory,
            output_dir=options.report_directory,
            timestamp=options.timestamp,
            git_repo_info=git_info,
            data=(
                report_data.get("trufflehog"),
                report_data.get("opengrep"),
                report_data.get("syft"),
                report_data.get("grype"),
                report_data.get("checkov"),
            ),
            output_format=fmt,
            waiver_data=waiver_set,
            waiver_summary=run.waiver_summary,
            scan_run=run,
            report_name=options.report_name,
        )
        if path:
            run.report_paths.append(path)

    _export_sboms(run, options, tools_output_dir)

    if not options.keep_tool_output and os.path.exists(tools_output_dir):
        shutil.rmtree(tools_output_dir)
        for r in results:
            r.raw_output_path = ""

    run.latest_directory = _update_latest_pointer(options)
    run.finished_at = utcnow()
    return run


def _export_sboms(run: ScanRun, options: ScanOptions, tools_output_dir: str) -> None:
    """Write the Syft SBOM as standalone CycloneDX / SPDX files when requested."""
    wanted = [f for f in options.outputs if f in SBOM_OUTPUTS]
    if not wanted:
        return
    syft_result = run.result_for("syft")
    if syft_result is None or syft_result.status != "ok":
        logger.warning("SBOM output requested but syft did not run successfully; skipping cyclonedx/spdx export")
        return
    syft_json = os.path.join(tools_output_dir, "syft.json")
    if not os.path.exists(syft_json):
        logger.warning(f"SBOM output requested but {syft_json} is missing; skipping export")
        return
    from .scanners.sbom import syft as syft_mod

    for fmt in wanted:
        _syft_fmt, default_name = syft_mod.SyftScanner.SBOM_FORMATS[fmt]
        name = f"{options.report_name}.{default_name.split('.', 1)[1]}" if options.report_name else default_name
        out = os.path.join(options.report_directory, name)
        try:
            syft_mod.convert(syft_json, out, fmt, timeout=options.tool_timeouts.get("syft", options.scan_timeout))
            run.report_paths.append(out)
            logger.info(f"SBOM written: {out}")
        except ScannerError as exc:
            logger.error(str(exc))
            syft_result.status = "failed"
            syft_result.error = str(exc)
            run.policy = evaluate(run, options)


def _update_latest_pointer(options: ScanOptions) -> str | None:
    """Maintain <base_report_directory>/latest -> this run (symlink, or a copy where symlinks are unavailable)."""
    base = options.base_report_directory
    if not base:
        return None
    latest = os.path.join(base, "latest")
    target = options.report_directory
    try:
        if os.path.islink(latest) or os.path.isfile(latest):
            os.unlink(latest)
        elif os.path.isdir(latest):
            shutil.rmtree(latest)
        try:
            os.symlink(os.path.basename(target), latest, target_is_directory=True)
        except (OSError, NotImplementedError):
            shutil.copytree(target, latest)
        return latest
    except OSError as exc:
        logger.warning(f"Could not update {latest}: {exc}")
        return None


def fingerprint_aliases(findings: list[Finding]) -> dict[str, str]:
    """Map every legacy fingerprint to the current fingerprint of the same tier."""
    from .fingerprints.registry import parse_fingerprint

    aliases: dict[str, str] = {}
    for f in findings:
        if not f.legacy_fingerprints:
            continue
        by_tier: dict[str, str] = {}
        for value in f.fingerprints.values():
            parsed = parse_fingerprint(value)
            if parsed:
                by_tier[parsed[2]] = value
        for legacy in f.legacy_fingerprints:
            parsed = parse_fingerprint(legacy)
            if parsed and parsed[2] in by_tier:
                aliases[legacy] = by_tier[parsed[2]]
    return aliases


def findings_for_console(run: ScanRun) -> list[Finding]:
    return run.active_findings
