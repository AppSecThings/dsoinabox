"""Scanner registry: one place that knows how to run, fingerprint and normalize each tool.

Adding a scanner means adding a ``ScannerSpec`` here (plus a normalizer, an
HTML partial and a test fixture). Nothing in ``run.py`` or the CLI is
tool-specific.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..model import Category, Finding

# --- run context -----------------------------------------------------------


@dataclass
class RunContext:
    source: str
    tools_output_dir: str
    project_id: str
    is_git_repo: bool
    extra_args: Any = None
    timeout: int | None = None
    verify_secrets: bool = False
    grype_db: str = "auto"


# --- spec ------------------------------------------------------------------


@dataclass
class ScannerSpec:
    name: str
    category: Category
    display_name: str
    executable: str
    module: str
    """Import path of the wrapper module exposing ``run_scan`` and ``get_version``."""
    run: Callable[[RunContext], Any]
    """Invoke the tool; returns the raw payload."""
    fingerprint: Callable[[Any, RunContext], Any] | None = None
    """Annotate raw payload with fingerprints (in place); None for tools without findings."""
    normalize: Callable[[Any, str], list[Finding]] | None = None
    findings_key: str | None = None
    """Where the findings list lives in the raw payload (documentation only)."""
    depends_on: list[str] = field(default_factory=list)
    """Tools that must finish first (ordering only; the tool decides how to cope if a dep failed)."""
    aliases: tuple[str, ...] = ()
    raw_output_filename: str = ""

    @property
    def selectors(self) -> set[str]:
        return {self.name, self.category, *self.aliases}

    def wrapper(self) -> Any:
        return importlib.import_module(self.module)

    def get_version(self) -> str:
        return self.wrapper()._scanner.get_version()


# --- per-tool glue ---------------------------------------------------------


def _run_trufflehog(ctx: RunContext) -> Any:
    from .secrets import trufflehog

    return trufflehog.run_scan(ctx.source, ctx.extra_args, ctx.tools_output_dir, git_repo=ctx.is_git_repo,
                               timeout=ctx.timeout, verify=ctx.verify_secrets)


def _run_opengrep(ctx: RunContext) -> Any:
    from .sast import opengrep

    return opengrep.run_scan(ctx.source, ctx.extra_args, ctx.tools_output_dir, timeout=ctx.timeout)


def _run_syft(ctx: RunContext) -> Any:
    from .sbom import syft

    return syft.run_scan(ctx.source, ctx.extra_args, ctx.tools_output_dir, timeout=ctx.timeout)


def _run_grype(ctx: RunContext) -> Any:
    from .sca import grype

    return grype.run_scan(ctx.source, ctx.extra_args, ctx.tools_output_dir, timeout=ctx.timeout, db_mode=ctx.grype_db)


def _run_checkov(ctx: RunContext) -> Any:
    from .iac import checkov

    return checkov.run_scan(ctx.source, ctx.extra_args, ctx.tools_output_dir, timeout=ctx.timeout)


def _fp_trufflehog(raw: Any, ctx: RunContext) -> Any:
    from ..fingerprints.trufflehog import fingerprint_findings

    return fingerprint_findings(raw, ctx.source, project_id=ctx.project_id)


def _fp_opengrep(raw: Any, ctx: RunContext) -> Any:
    from ..fingerprints.opengrep import fingerprint_findings

    return fingerprint_findings(raw, ctx.source, project_id=ctx.project_id)


def _fp_grype(raw: Any, ctx: RunContext) -> Any:
    from ..fingerprints.grype import fingerprint_findings

    return fingerprint_findings(raw, project_id=ctx.project_id)


def _fp_checkov(raw: Any, ctx: RunContext) -> Any:
    from ..fingerprints.checkov import fingerprint_findings

    return fingerprint_findings(raw, ctx.source, project_id=ctx.project_id)


def _norm(tool: str) -> Callable[[Any, str], list[Finding]]:
    def _inner(raw: Any, source: str) -> list[Finding]:
        from ..normalize import normalize

        return normalize(tool, raw, source)

    return _inner


REGISTRY: dict[str, ScannerSpec] = {}


def register(spec: ScannerSpec) -> ScannerSpec:
    REGISTRY[spec.name] = spec
    return spec


register(ScannerSpec(
    name="trufflehog", category="secret", display_name="TruffleHog", executable="trufflehog",
    module="dsoinabox.scanners.secrets.trufflehog", run=_run_trufflehog, fingerprint=_fp_trufflehog,
    normalize=_norm("trufflehog"), findings_key=None, aliases=("secrets",), raw_output_filename="trufflehog.json",
))
register(ScannerSpec(
    name="opengrep", category="sast", display_name="OpenGrep", executable="opengrep",
    module="dsoinabox.scanners.sast.opengrep", run=_run_opengrep, fingerprint=_fp_opengrep,
    normalize=_norm("opengrep"), findings_key="results", raw_output_filename="opengrep.json",
))
register(ScannerSpec(
    name="syft", category="sbom", display_name="Syft", executable="syft",
    module="dsoinabox.scanners.sbom.syft", run=_run_syft, raw_output_filename="syft.json",
))
register(ScannerSpec(
    name="grype", category="sca", display_name="Grype", executable="grype",
    module="dsoinabox.scanners.sca.grype", run=_run_grype, fingerprint=_fp_grype,
    normalize=_norm("grype"), findings_key="matches", depends_on=["syft"], raw_output_filename="grype.json",
))
register(ScannerSpec(
    name="checkov", category="iac", display_name="Checkov", executable="checkov",
    module="dsoinabox.scanners.iac.checkov", run=_run_checkov, fingerprint=_fp_checkov,
    normalize=_norm("checkov"), findings_key="results", raw_output_filename="checkov.json",
))

TOOL_ORDER: tuple[str, ...] = tuple(REGISTRY)


def all_selectors() -> set[str]:
    out = {"all"}
    for spec in REGISTRY.values():
        out |= spec.selectors
    return out


def select_tools(selection: list[str] | str) -> list[ScannerSpec]:
    """Resolve ``--tools`` values (names, categories, aliases, ``all``) to specs in registry order."""
    if isinstance(selection, str):
        selection = selection.split(",")
    wanted = {s.strip().lower() for s in selection if s and s.strip()}
    unknown = wanted - all_selectors()
    if unknown:
        raise ValueError(
            f"Unknown tool selector(s): {', '.join(sorted(unknown))}. "
            f"Valid values: {', '.join(sorted(all_selectors()))}"
        )
    if "all" in wanted:
        return list(REGISTRY.values())
    return [spec for spec in REGISTRY.values() if spec.selectors & wanted]
