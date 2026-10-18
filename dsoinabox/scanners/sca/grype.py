from __future__ import annotations

import json
import logging
import os

from ..base import BaseScanner, ScannerError

logger = logging.getLogger(__name__)

# reuse a cached DB until grype last checked for an update this long ago; 0s checks every run
DB_CACHE_CHECK_FREQUENCY = "24h"
ALWAYS_UPDATE_CHECK_FREQUENCY = "0s"


def db_cache_dir(db_cache: str | None) -> str | None:
    """grype's DB directory inside a --db_cache root (None when no cache is configured)."""
    return os.path.join(db_cache, "grype") if db_cache else None


def user_cache_dir() -> str | None:
    """GRYPE_DB_CACHE_DIR set by the user; an explicit grype setting wins over --db_cache."""
    return os.environ.get("GRYPE_DB_CACHE_DIR") or None


def db_env(db_mode: str = "auto", db_cache: str | None = None, always_update: bool = False) -> dict[str, str] | None:
    """env overrides for grype; None when nothing is configured so grype behaves exactly as by default."""
    env: dict[str, str] = {}
    if db_mode == "offline":
        env.update({"GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_DB_VALIDATE_AGE": "false"})
    cache_dir = db_cache_dir(db_cache)
    if cache_dir:
        if not user_cache_dir():
            env["GRYPE_DB_CACHE_DIR"] = cache_dir
        env["GRYPE_DB_MAX_UPDATE_CHECK_FREQUENCY"] = DB_CACHE_CHECK_FREQUENCY
    if always_update:
        env["GRYPE_DB_MAX_UPDATE_CHECK_FREQUENCY"] = ALWAYS_UPDATE_CHECK_FREQUENCY
    return env or None


def _unwritable_cache_message(cache_dir: str) -> str:
    return (
        f"Grype DB cache directory {cache_dir} is not writable. Mount a named Docker volume "
        "(e.g. -v dsoinabox-db:/var/cache/dsoinabox) or use a host directory writable by uid 1001 "
        "(the image's appuser)."
    )


class GrypeScanner(BaseScanner):
    """grype scanner for sca vulnerability scanning."""

    def __init__(self):
        super().__init__("grype", help_command="help")

    def run_scan(
        self,
        source_path: str,
        extra_tool_args: str | list[str] | tuple[str, ...] | None = "",
        report_directory: str = "reports",
        timeout: int | None = None,
        db_mode: str = "auto",
        db_cache: str | None = None,
        always_update: bool = False,
        cwd: str | None = None,
    ) -> dict:
        """run the grype cli scan. db_mode=offline disables DB auto-update and fails clearly without a cached DB.

        db_cache keeps the DB under ``<db_cache>/grype``; always_update checks for a newer DB on every run.
        """
        own_cache = db_cache_dir(db_cache)
        user_cache = user_cache_dir()
        if own_cache and user_cache:
            logger.info(f"GRYPE_DB_CACHE_DIR={user_cache} is set; grype uses it instead of {own_cache} (--db_cache)")
            own_cache = None
        cache_dir = user_cache or own_cache
        if own_cache and db_mode != "offline":
            try:
                os.makedirs(own_cache, exist_ok=True)
            except OSError as exc:
                raise ScannerError(f"Grype scan failed: {_unwritable_cache_message(own_cache)} ({exc})") from None
            if not os.access(own_cache, os.W_OK):
                raise ScannerError(f"Grype scan failed: {_unwritable_cache_message(own_cache)}")
        #check for syft.json in report_directory (could be tools_output or reports)
        syft_json_path = os.path.join(report_directory, "syft.json")
        if os.path.exists(syft_json_path):
            if cwd:
                syft_json_path = os.path.abspath(syft_json_path)
            args = [f"sbom:{syft_json_path}", "-o", "json"]
        else:
            args = [f"dir:{source_path}", "-o", "json"]
        args.extend(self._parse_extra_tool_args(extra_tool_args))
        env = db_env(db_mode, db_cache, always_update)
        result = self._run_command(args, timeout=timeout, env=env, cwd=cwd)
        if result.returncode == 0:
            json_result = json.loads(result.stdout.strip())
            self._write_json_report(json_result, report_directory, "grype.json")
            return json_result
        stderr = result.stderr if isinstance(result.stderr, str) else result.stderr.decode("utf-8", "replace")
        low = stderr.lower()
        if db_mode == "offline" and ("db" in low or "database" in low) and any(k in low for k in ("not found", "no vulnerability database", "unable to load", "does not exist")):
            if cache_dir:
                where = (f"Cache in use: {cache_dir}. Populate it with one online run using the same cache "
                         "(--db_cache or GRYPE_DB_CACHE_DIR), or mount the volume that holds it.")
            else:
                where = ("No --db_cache is set, so grype looks in its default cache. Set --db_cache PATH "
                         "(DSOINABOX_DB_CACHE) or mount a volume at the image's /var/cache/dsoinabox, and populate it "
                         "with one online run.")
            raise ScannerError(
                "Grype scan failed: no vulnerability database is cached and --grype_db offline forbids downloading one. "
                f"{where} Original error: " + stderr.strip()
            )
        if cache_dir and cache_dir in stderr and "permission denied" in low:
            raise ScannerError(f"Grype scan failed: {_unwritable_cache_message(cache_dir)} Original error: {stderr.strip()}")
        raise ScannerError(f"Grype scan failed: {stderr}")

    def db_status(self, timeout: int | None = 60, db_cache: str | None = None, always_update: bool = False) -> str:
        """one-line summary of the vulnerability database (built date), best effort."""
        result = self._run_command(["db", "status", "-o", "json"], timeout=timeout,
                                   env=db_env(db_cache=db_cache, always_update=always_update))
        if result.returncode != 0:
            return ""
        text = result.stdout if isinstance(result.stdout, str) else result.stdout.decode("utf-8", "replace")
        try:
            data = json.loads(text)
        except ValueError:
            first = next((line.strip() for line in text.splitlines() if "built" in line.lower()), "")
            return first[:120]
        if not isinstance(data, dict):
            return ""
        built = data.get("built") or data.get("Built") or ""
        schema = data.get("schemaVersion") or data.get("schema") or ""
        return (f"built {built}" + (f" (schema {schema})" if schema else "")) if built else ""

    def _write_json_report(self, data: dict | list, report_directory: str, filename: str) -> None:
        """write json report to file."""
        os.makedirs(report_directory, exist_ok=True)
        with open(f"{report_directory}/{filename}", "w") as fd:
            json.dump(data, fd, indent=4)


#module-level functions for backward compatibility
_scanner = GrypeScanner()
show_version = _scanner.show_version
show_help = _scanner.show_help
run_scan = _scanner.run_scan
db_status = _scanner.db_status
