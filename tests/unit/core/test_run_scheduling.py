"""Scheduler behaviour: dependency order, partial failure, fail-fast, timeouts (W4.1, W4.3)."""

from __future__ import annotations

import subprocess
import threading
import time

from dsoinabox.model import Finding
from dsoinabox.run import _schedule
from dsoinabox.scanners.base import ScannerError
from dsoinabox.scanners.registry import RunContext, ScannerSpec


def _ctx(spec):
    return RunContext(source="/s", tools_output_dir="/tmp/x", project_id="p", is_git_repo=False, timeout=5)


def _spec(name, run, depends_on=(), category="sast"):
    def norm(raw, source):
        return [Finding(tool=name, category=category, rule_id=str(i)) for i in range(len(raw or []))]

    return ScannerSpec(name=name, category=category, display_name=name, executable=name, module="x",
                       run=run, normalize=norm, depends_on=list(depends_on))


def test_dependency_runs_after_its_dependency():
    order = []
    lock = threading.Lock()

    def make(name, delay=0.0):
        def run(ctx):
            time.sleep(delay)
            with lock:
                order.append(name)
            return [1]
        return run

    specs = [_spec("syft", make("syft", 0.05), category="sbom"), _spec("grype", make("grype"), depends_on=["syft"], category="sca"), _spec("og", make("og"))]
    results, _ = _schedule(specs, _ctx, None, fail_fast=False, max_workers=4)
    assert [r.tool for r in results] == ["syft", "grype", "og"]
    assert order.index("syft") < order.index("grype")
    assert all(r.status == "ok" for r in results)


def test_failure_does_not_abort_others():
    def boom(ctx):
        raise ScannerError("grype exploded")

    specs = [_spec("grype", boom), _spec("og", lambda ctx: [1, 2])]
    results, _ = _schedule(specs, _ctx, None, fail_fast=False, max_workers=2)
    by = {r.tool: r for r in results}
    assert by["grype"].status == "failed" and "exploded" in by["grype"].error
    assert by["og"].status == "ok" and len(by["og"].findings) == 2


def test_unexpected_exception_is_a_failure_not_a_crash():
    def boom(ctx):
        raise KeyError("results")

    results, _ = _schedule([_spec("og", boom)], _ctx, None, fail_fast=False, max_workers=1)
    assert results[0].status == "failed" and results[0].error.startswith("KeyError")


def test_timeout_is_a_failure_with_message():
    def slow(ctx):
        raise subprocess.TimeoutExpired(cmd=["og"], timeout=5)

    results, _ = _schedule([_spec("og", slow)], _ctx, None, fail_fast=False, max_workers=1)
    assert results[0].status == "failed" and "timed out after 5 seconds" in results[0].error


def test_fail_fast_skips_pending_dependents():
    def boom(ctx):
        raise ScannerError("no")

    specs = [_spec("syft", boom, category="sbom"), _spec("grype", lambda ctx: [1], depends_on=["syft"], category="sca")]
    results, _ = _schedule(specs, _ctx, None, fail_fast=True, max_workers=2)
    by = {r.tool: r for r in results}
    assert by["syft"].status == "failed"
    assert by["grype"].status == "skipped" and "fail_fast" in by["grype"].error


def test_dependency_failure_still_runs_dependent_without_fail_fast():
    def boom(ctx):
        raise ScannerError("no")

    specs = [_spec("syft", boom, category="sbom"), _spec("grype", lambda ctx: [1], depends_on=["syft"], category="sca")]
    results, _ = _schedule(specs, _ctx, None, fail_fast=False, max_workers=2)
    by = {r.tool: r for r in results}
    assert by["grype"].status == "ok", "grype falls back to a directory scan when the SBOM is missing"


def test_dependency_not_selected_is_ignored():
    specs = [_spec("grype", lambda ctx: [1], depends_on=["syft"], category="sca")]
    results, _ = _schedule(specs, _ctx, None, fail_fast=False, max_workers=1)
    assert results[0].status == "ok"
