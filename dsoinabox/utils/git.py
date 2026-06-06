import os
import subprocess
from typing import Optional, Dict
import logging

from .runner import run_cmd


# process-local registry for git safe directories. this avoids mutating user global config.
_GIT_SAFE_DIRECTORIES: set[str] = set()


def _canonicalize_git_path(path: str) -> str:
    """Return canonical absolute path suitable for git safe.directory values."""
    return os.path.realpath(os.path.abspath(path))


def _safe_directory_values(path: str) -> tuple[str, str]:
    repo_path = _canonicalize_git_path(path)
    return repo_path, _canonicalize_git_path(os.path.join(repo_path, ".git"))


def build_git_safe_env(path: Optional[str] = None) -> Optional[dict[str, str]]:
    """Build per-process git safe.directory env overrides for a git command.

    If no directories are registered (and no path provided), returns None.
    """
    safe_dirs = set(_GIT_SAFE_DIRECTORIES)
    if path:
        safe_dirs.update(_safe_directory_values(path))

    if not safe_dirs:
        return None

    env: dict[str, str] = {"GIT_CONFIG_COUNT": str(len(safe_dirs))}
    for idx, safe_dir in enumerate(sorted(safe_dirs)):
        env[f"GIT_CONFIG_KEY_{idx}"] = "safe.directory"
        env[f"GIT_CONFIG_VALUE_{idx}"] = safe_dir
    return env


def run_git_cmd(
    args: list[str],
    *,
    repo_path: Optional[str] = None,
    cwd: Optional[str] = None,
    text: bool = True,
    check: bool = False,
) -> tuple[int, str | bytes, str | bytes]:
    """Run a git command with process-scoped safe.directory overrides."""
    return run_cmd(
        ["git"] + args,
        cwd=cwd,
        env=build_git_safe_env(repo_path or cwd),
        text=text,
        check=check,
    )


class GitRepoInfo:
    def __init__(self, repo_path: str):
        self.repo_path = _canonicalize_git_path(repo_path)
        if not os.path.isdir(os.path.join(self.repo_path, ".git")):
            raise ValueError(f"{repo_path} is not a valid git repository.")

        self._info = self._gather_info()

    def _run_git(self, args: list[str]) -> str:
        try:
            returncode, stdout, stderr = run_git_cmd(
                args,
                cwd=self.repo_path,
                repo_path=self.repo_path,
                text=True,
                check=True,
            )
            return stdout.strip()
        except subprocess.CalledProcessError:
            return ""

    def _gather_info(self) -> Dict[str, Optional[str]]:
        #attempt to determine repo name (from folder name or remote url)
        origin_url = self._run_git(["config", "--get", "remote.origin.url"])
        if origin_url:
            repo_name = os.path.splitext(os.path.basename(origin_url.rstrip('/').replace('.git', '')))[0]
        else:
            repo_name = os.path.basename(self.repo_path.rstrip('/'))

        #some origin urls may be of the form git@host:user/repo.git, or https, etc. strip .git if present.
        if origin_url.endswith('.git'):
            origin_url = origin_url[:-4]

        branch = self._run_git(["rev-parse", "--abbrev-ref", "HEAD"])
        last_commit_id = self._run_git(["rev-parse", "HEAD"])
        last_commit_date = self._run_git(["log", "-1", "--format=%cI"])

        return {
            "repo_name": repo_name,
            "origin_url": origin_url,
            "branch": branch,
            "last_commit_id": last_commit_id,
            "last_commit_date": last_commit_date
        }

    @property
    def repo_name(self) -> Optional[str]:
        return self._info.get("repo_name")

    @property
    def origin_url(self) -> Optional[str]:
        return self._info.get("origin_url")

    @property
    def branch(self) -> Optional[str]:
        return self._info.get("branch")

    @property
    def last_commit_id(self) -> Optional[str]:
        return self._info.get("last_commit_id")

    @property
    def last_commit_date(self) -> Optional[str]:
        return self._info.get("last_commit_date")

    def as_dict(self) -> Dict[str, Optional[str]]:
        return self._info.copy()


# register git safe directories for this process only.
def set_git_safe_directory(scan_target: str) -> None:
    logging.info(f"Registering process-local git safe directory for {scan_target}")
    _GIT_SAFE_DIRECTORIES.update(_safe_directory_values(scan_target))
