"""Tracked-files copy behind --git_tracked_only."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile

import pytest

from dsoinabox.utils import tracked as tracked_mod
from dsoinabox.utils.git import git_work_tree_problem, is_git_work_tree
from dsoinabox.utils.tracked import NothingTrackedError, TrackedCopy, copy_tracked_files, tracked_paths


def git(repo, *args):
    subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "init.defaultBranch=main",
                    "-c", "protocol.file.allow=always", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    (root / ".gitignore").write_text("build/\n*.log\n")
    (root / "app.py").write_text("print('committed')\n")
    (root / "gone.py").write_text("print('deleted later')\n")
    (root / "run.sh").write_text("#!/bin/sh\necho hi\n")
    (root / "run.sh").chmod(0o755)
    (root / "with space.py").write_text("x = 1\n")
    (root / "new\nline.py").write_text("y = 2\n")
    (root / "ünïcode.py").write_text("z = 3\n")
    (root / "src").mkdir()
    (root / "src" / "lib.py").write_text("import os\n")
    os.symlink("src/lib.py", root / "link.py")
    os.symlink("/etc/hosts", root / "outside_link")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "init")
    return root


def _tree(path):
    out = set()
    for dirpath, dirnames, filenames in os.walk(path):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            if not os.path.isdir(full) or os.path.islink(full):
                out.add(os.path.relpath(full, path))
    return out


def test_copy_has_tracked_working_tree_content_only(repo, tmp_path):
    (repo / "app.py").write_text("print('uncommitted edit')\n")
    (repo / "gone.py").unlink()
    (repo / "untracked.py").write_text("secret = 'x'\n")
    (repo / "venv").mkdir()
    (repo / "venv" / "lib.py").write_text("junk\n")
    (repo / "build").mkdir()
    (repo / "build" / "out.py").write_text("ignored\n")
    (repo / "debug.log").write_text("ignored\n")
    dest = tmp_path / "copy"
    dest.mkdir()

    count = copy_tracked_files(str(repo), str(dest))

    expected = {".gitignore", "app.py", "run.sh", "with space.py", "new\nline.py", "ünïcode.py", "src/lib.py",
                "link.py", "outside_link"}
    assert _tree(dest) == expected
    assert count == len(expected)
    assert (dest / "app.py").read_text() == "print('uncommitted edit')\n"


def test_symlinks_are_copied_as_links_never_followed(repo, tmp_path):
    dest = tmp_path / "copy"
    dest.mkdir()
    copy_tracked_files(str(repo), str(dest))
    assert os.path.islink(dest / "link.py") and os.readlink(dest / "link.py") == "src/lib.py"
    assert os.path.islink(dest / "outside_link") and os.readlink(dest / "outside_link") == "/etc/hosts"


def test_file_modes_are_preserved(repo, tmp_path):
    (repo / "app.py").chmod(0o444)
    dest = tmp_path / "copy"
    dest.mkdir()
    copy_tracked_files(str(repo), str(dest))
    assert stat.S_IMODE(os.stat(dest / "run.sh").st_mode) == 0o755
    assert stat.S_IMODE(os.stat(dest / "app.py").st_mode) == 0o444


def test_submodule_contents_are_skipped(repo, tmp_path):
    sub = repo / "vendor"
    sub.mkdir()
    git(sub, "init", "-q")
    (sub / "dep.py").write_text("dep\n")
    git(sub, "add", "-A")
    git(sub, "commit", "-qm", "sub")
    git(repo, "add", "vendor")  # recorded as a gitlink
    git(repo, "commit", "-qm", "gitlink")
    assert "vendor" not in tracked_paths(str(repo))
    dest = tmp_path / "copy"
    dest.mkdir()
    copy_tracked_files(str(repo), str(dest))
    assert not (dest / "vendor").exists()


def test_directory_swapped_for_outside_symlink_is_not_read(repo, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "lib.py").write_text("not from the repo\n")
    (repo / "src" / "lib.py").unlink()
    (repo / "src").rmdir()
    os.symlink(outside, repo / "src")
    dest = tmp_path / "copy"
    dest.mkdir()
    copy_tracked_files(str(repo), str(dest))
    assert not (dest / "src").exists()


def test_read_only_source(repo, tmp_path):
    paths = [repo] + [p for p in repo.rglob("*") if ".git" not in p.parts and not p.is_symlink()]
    modes = {p: stat.S_IMODE(os.stat(p).st_mode) for p in paths}
    try:
        for p in paths:
            p.chmod(modes[p] & ~0o222)
        tracked = TrackedCopy.create(str(repo))
        try:
            copy_root = tracked.source_arg
            assert (open(os.path.join(copy_root, "app.py")).read()) == "print('committed')\n"
        finally:
            tracked.cleanup()
        assert not os.path.exists(tracked.root)
    finally:
        for p in paths:
            p.chmod(modes[p])


def test_create_mirrors_absolute_source_and_cwd(repo, tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "tmp"))
    (tmp_path / "tmp").mkdir()
    tracked = TrackedCopy.create(str(repo))
    try:
        assert tracked.source_arg == tracked.root + str(repo)
        assert tracked.cwd == tracked.root + os.getcwd()
        assert os.path.isdir(tracked.cwd)
        assert os.path.isfile(os.path.join(tracked.source_arg, "src", "lib.py"))
    finally:
        tracked.cleanup()
    assert os.listdir(tmp_path / "tmp") == []


def test_create_keeps_relative_source_relative_to_mirrored_cwd(repo, monkeypatch):
    monkeypatch.chdir(repo.parent)
    tracked = TrackedCopy.create("repo")
    try:
        assert tracked.source_arg == "repo"
        assert os.path.isfile(os.path.join(tracked.cwd, "repo", "app.py"))
    finally:
        tracked.cleanup()


def test_restore_strips_copy_root_from_payload_and_output_file(tmp_path):
    root = str(tmp_path / "dsoinabox-tracked-x")
    tracked = TrackedCopy(root, "/src", root)
    raw = {"results": [{"path": f"{root}/src/app.py", "extra": {"lines": "x"}}],
           "paths": {"scanned": [f"{root}/src/app.py"]}, f"{root}/key": 1, "n": 3}
    out = tmp_path / "opengrep.json"
    out.write_text(json.dumps(raw, indent=4))
    restored = tracked.restore(raw, str(out))
    expected = {"results": [{"path": "/src/app.py", "extra": {"lines": "x"}}],
                "paths": {"scanned": ["/src/app.py"]}, "/key": 1, "n": 3}
    assert restored == expected
    assert json.loads(out.read_text()) == expected


def test_restore_recomputes_syft_directory_source_id(tmp_path):
    root = str(tmp_path / "dsoinabox-tracked-x")
    tracked = TrackedCopy(root, "/scan_target", root)
    copy_path = root + "/scan_target"
    raw = {"source": {"id": hashlib.sha256(copy_path.encode()).hexdigest(), "name": copy_path, "type": "directory",
                      "metadata": {"path": copy_path}}}
    out = tmp_path / "syft.json"
    out.write_text(json.dumps(raw))
    restored = tracked.restore(raw, str(out))
    expected_id = hashlib.sha256(b"/scan_target").hexdigest()
    assert restored["source"] == {"id": expected_id, "name": "/scan_target", "type": "directory",
                                  "metadata": {"path": "/scan_target"}}
    assert json.loads(out.read_text())["source"]["id"] == expected_id


def test_is_git_work_tree(repo, tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    assert is_git_work_tree(str(repo))
    assert is_git_work_tree(str(repo / "src"))
    assert not is_git_work_tree(str(plain))
    assert not is_git_work_tree(str(tmp_path / "missing"))


def test_untracked_subdirectory_has_nothing_to_copy(repo, tmp_path):
    (repo / "proj").mkdir()
    (repo / "proj" / "app.py").write_text("import os\nos.system(x)\n")
    with pytest.raises(NothingTrackedError, match="nothing under .* is tracked"):
        TrackedCopy.create(str(repo / "proj"))


def test_repository_fsmonitor_command_is_not_run(repo, tmp_path):
    marker = tmp_path / "fsmonitor-ran"
    git(repo, "config", "core.fsmonitor", f"touch {marker}; echo")
    subprocess.run(["git", "status"], cwd=repo, capture_output=True)
    assert marker.exists(), "precondition: plain git runs the configured fsmonitor command"
    marker.unlink()
    assert is_git_work_tree(str(repo))
    assert "app.py" in tracked_paths(str(repo))
    assert not marker.exists()


def test_work_tree_problem_reports_gits_reason(tmp_path, monkeypatch):
    import dsoinabox.utils.git as git_utils

    monkeypatch.setattr(git_utils, "run_cmd", lambda cmd, **kw: (128, "", "fatal: detected dubious ownership in "
                                                                           "repository at '/scan_target'\n"))
    assert "dubious ownership" in git_work_tree_problem(str(tmp_path))


def _swapped_lstat(path_to_fake, mode):
    real_lstat = os.lstat

    def fake(path, *a, **k):
        st = real_lstat(path, *a, **k)
        if str(path) == str(path_to_fake):
            return os.stat_result((mode | stat.S_IMODE(st.st_mode),) + tuple(st)[1:])
        return st

    return fake


def test_fifo_swapped_in_after_lstat_is_skipped_without_blocking(repo, tmp_path, monkeypatch):
    target = repo / "app.py"
    target.unlink()
    os.mkfifo(target)
    monkeypatch.setattr(tracked_mod.os, "lstat", _swapped_lstat(target, stat.S_IFREG))
    dest = tmp_path / "copy"
    dest.mkdir()
    copy_tracked_files(str(repo), str(dest))
    assert not (dest / "app.py").exists()
    assert (dest / "run.sh").exists()


def test_symlink_swapped_in_after_lstat_is_not_followed(repo, tmp_path, monkeypatch):
    outside = tmp_path / "outside.txt"
    outside.write_text("not from the repo\n")
    target = repo / "app.py"
    target.unlink()
    os.symlink(outside, target)
    monkeypatch.setattr(tracked_mod.os, "lstat", _swapped_lstat(target, stat.S_IFREG))
    dest = tmp_path / "copy"
    dest.mkdir()
    copy_tracked_files(str(repo), str(dest))
    assert not (dest / "app.py").exists()


def test_file_replaced_after_lstat_is_skipped(repo, tmp_path, monkeypatch):
    target = repo / "app.py"
    real_lstat = os.lstat
    other = real_lstat(repo / "run.sh")

    def fake(path, *a, **k):
        return other if str(path) == str(target) else real_lstat(path, *a, **k)

    monkeypatch.setattr(tracked_mod.os, "lstat", fake)
    dest = tmp_path / "copy"
    dest.mkdir()
    copy_tracked_files(str(repo), str(dest))
    assert not (dest / "app.py").exists()
    assert (dest / "run.sh").exists()
