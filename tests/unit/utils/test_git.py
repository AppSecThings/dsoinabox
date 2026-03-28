"""Unit tests for git helper safe-directory behavior."""

from __future__ import annotations

import os

from dsoinabox.utils import git as git_utils


def test_set_git_safe_directory_is_process_local(monkeypatch, tmp_path):
    """Registering safe dirs should not execute git config --global commands."""
    repo = tmp_path / "repo"
    repo.mkdir()

    calls: list[list[str]] = []
    monkeypatch.setattr(git_utils, "_GIT_SAFE_DIRECTORIES", set())

    def _fake_run_cmd(cmd, **kwargs):
        calls.append(list(cmd))
        return (0, "", "")

    monkeypatch.setattr(git_utils, "run_cmd", _fake_run_cmd)

    git_utils.set_git_safe_directory(str(repo))

    assert calls == []


def test_run_git_cmd_sets_scoped_safe_directory_env(monkeypatch, tmp_path):
    """run_git_cmd should pass safe.directory values via command-scoped env vars."""
    repo = tmp_path / "repo"
    repo.mkdir()

    captured_env = {}
    monkeypatch.setattr(git_utils, "_GIT_SAFE_DIRECTORIES", set())

    def _fake_run_cmd(cmd, *, cwd=None, env=None, timeout=None, text=True, check=False):
        captured_env.update(env or {})
        return (0, "main\n", "")

    monkeypatch.setattr(git_utils, "run_cmd", _fake_run_cmd)

    rc, stdout, stderr = git_utils.run_git_cmd(
        ["rev-parse", "--abbrev-ref", "HEAD"],
        repo_path=str(repo),
        cwd=str(repo),
        text=True,
        check=False,
    )

    assert rc == 0
    assert stdout.strip() == "main"
    assert captured_env.get("GIT_CONFIG_COUNT") == "2"

    safe_values = {
        captured_env.get("GIT_CONFIG_VALUE_0"),
        captured_env.get("GIT_CONFIG_VALUE_1"),
    }
    expected_repo = os.path.realpath(str(repo))
    assert expected_repo in safe_values
    assert os.path.realpath(str(repo / ".git")) in safe_values
