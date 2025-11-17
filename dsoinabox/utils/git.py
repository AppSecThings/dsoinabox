import os
import subprocess
from typing import Optional, Dict
import logging

from .runner import run_cmd

class GitRepoInfo:
    def __init__(self, repo_path: str):
        self.repo_path = os.path.abspath(repo_path)
        if not os.path.isdir(os.path.join(self.repo_path, ".git")):
            raise ValueError(f"{repo_path} is not a valid git repository.")

        self._info = self._gather_info()

    def _run_git(self, args: list[str]) -> str:
        try:
            returncode, stdout, stderr = run_cmd(
                ["git"] + args,
                cwd=self.repo_path,
                text=True,
                check=True
            )
            return stdout.strip()
        except subprocess.CalledProcessError as e:
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

#function to set git config --global --add safe.directory /scan_target
def set_git_safe_directory(scan_target: str) -> None:
    logging.info(f"Setting git safe directory to {scan_target}")

    env = os.environ.copy()
    env["GIT_CONFIG_COUNT"] = "2"
    env["GIT_CONFIG_KEY_0"] = "safe.directory"
    env["GIT_CONFIG_VALUE_0"] = scan_target
    env["GIT_CONFIG_KEY_1"] = "safe.directory"
    #resolve canonical path inside the container; if running outside, resolve host path accordingly
    env["GIT_CONFIG_VALUE_1"] = scan_target

    #set safe dir
    run_cmd(["git", "config", "--global", "--add", "safe.directory", scan_target], check=True)
    run_cmd(["git", "config", "--global", "--add", "safe.directory", scan_target + "/.git"], check=True)