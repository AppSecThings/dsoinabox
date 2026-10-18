"""Temporary copy of the git-tracked files of a source tree (``--git_tracked_only``).

Scanners that walk the source run against the copy, so untracked and ignored
files (virtualenvs, build output, caches) are never visited. The copy sits at
the source's own absolute path mirrored under a temp root, and scanners run
from the mirrored working directory. Paths a tool prints relative to its
working directory or to the scanned directory therefore come out exactly as
in a normal scan; absolute paths only gain the temp-root prefix, which
``restore`` strips again before fingerprinting.
"""

from __future__ import annotations

import errno
import hashlib
import logging
import os
import shutil
import stat
import tempfile
import time
from typing import Any

from .git import NO_FSMONITOR, run_git_cmd

logger = logging.getLogger(__name__)

GITLINK_MODE = b"160000"
# never follow a final-component symlink; never block opening a FIFO swapped in after lstat
OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)


class NothingTrackedError(Exception):
    """No tracked file exists under the source, so a tracked-only scan would scan nothing."""


def _mirror(root: str, path: str) -> str:
    """``path`` (absolute) re-rooted under ``root``."""
    return os.path.join(root, os.path.splitdrive(path)[1].lstrip(os.sep))


def tracked_paths(source: str) -> list[str]:
    """Paths git tracks under ``source``, relative to it. Submodules (gitlinks) are left out."""
    _rc, stdout, _err = run_git_cmd([*NO_FSMONITOR, "ls-files", "-z", "--stage"], cwd=source, repo_path=source,
                                    text=False, check=True)
    listing = stdout if isinstance(stdout, bytes) else os.fsencode(stdout)
    paths: dict[str, None] = {}  # unmerged files appear once per stage
    for entry in listing.split(b"\0"):
        meta, _, path = entry.partition(b"\t")
        if not path or meta.split(b" ", 1)[0] == GITLINK_MODE:
            continue
        paths[os.fsdecode(path)] = None
    return list(paths)


def copy_tracked_files(source: str, dest: str) -> int:
    """Copy the working-tree content of every tracked file under ``source`` into ``dest``. Returns the count.

    Tracked files deleted from the working tree are skipped. Symlinks are
    recreated as symlinks, never followed, and nothing is read through a
    directory that resolves outside ``source``. File modes are preserved.

    A directory swapped for a symlink between the check and the read can still
    redirect a read; that needs local write access during the scan and is no
    worse than a normal scan, whose scanners follow symlinks anyway.
    """
    real_source = os.path.realpath(source)
    inside: dict[str, bool] = {}
    copied = 0
    for rel in tracked_paths(source):
        src = os.path.join(source, rel)
        parent = os.path.dirname(src)
        if parent not in inside:
            real_parent = os.path.realpath(parent)
            inside[parent] = real_parent == real_source or real_parent.startswith(real_source + os.sep)
        if not inside[parent]:
            logger.debug(f"git_tracked_only: skipping {rel} (its directory resolves outside the source)")
            continue
        try:
            st = os.lstat(src)
        except (FileNotFoundError, NotADirectoryError):
            continue  # deleted in the working tree
        dst = os.path.join(dest, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if stat.S_ISLNK(st.st_mode):
            os.symlink(os.readlink(src), dst)
        elif stat.S_ISREG(st.st_mode):
            if not _copy_regular(src, dst, st):
                continue
        else:
            continue
        try:  # keep ownership where allowed; Syft records it
            os.chown(dst, st.st_uid, st.st_gid, follow_symlinks=False)
        except OSError:
            pass
        copied += 1
    return copied


def _copy_regular(src: str, dst: str, st: os.stat_result) -> bool:
    """Copy ``src`` if it is still the regular file ``st`` describes. False when it was swapped."""
    try:
        fd = os.open(src, OPEN_FLAGS)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOENT, errno.ENOTDIR, errno.ENXIO):
            logger.debug(f"git_tracked_only: skipping {src} (changed while copying)")
            return False
        raise
    with os.fdopen(fd, "rb") as reader:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
            logger.debug(f"git_tracked_only: skipping {src} (changed while copying)")
            return False
        with open(dst, "xb") as writer:
            shutil.copyfileobj(reader, writer)
        os.chmod(dst, stat.S_IMODE(opened.st_mode))
    return True


class TrackedCopy:
    """A tracked-files copy of ``source``; scan ``source_arg`` from ``cwd``, then ``restore`` the output."""

    def __init__(self, root: str, source: str, cwd: str):
        self.root = root
        self.source_arg = root + source if os.path.isabs(source) else source
        self.cwd = cwd

    @classmethod
    def create(cls, source: str) -> TrackedCopy:
        started = time.perf_counter()
        root = os.path.realpath(tempfile.mkdtemp(prefix="dsoinabox-tracked-"))
        try:
            copy_root = _mirror(root, os.path.abspath(source))
            os.makedirs(copy_root)
            count = copy_tracked_files(source, copy_root)
            if count == 0:
                raise NothingTrackedError(
                    f"nothing under {source} is tracked by git (is it untracked or ignored in its parent "
                    "repository?), so --git_tracked_only would scan nothing."
                )
            cwd = _mirror(root, os.getcwd())
            os.makedirs(cwd, exist_ok=True)
        except BaseException:
            shutil.rmtree(root, ignore_errors=True)
            raise
        logger.info(f"git_tracked_only: copied {count} tracked files in {time.perf_counter() - started:.2f} seconds")
        return cls(root, source, cwd)

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _replacements(self, raw: Any) -> list[tuple[str, str]]:
        pairs = [(self.root, "")]
        # syft names a directory source by the sha256 of the path it was given
        src = raw.get("source") if isinstance(raw, dict) else None
        if isinstance(src, dict) and src.get("type") == "directory" and isinstance(src.get("name"), str):
            name = src["name"]
            if self.root in name and src.get("id") == hashlib.sha256(name.encode()).hexdigest():
                pairs.append((src["id"], hashlib.sha256(name.replace(self.root, "").encode()).hexdigest()))
        return pairs

    def restore(self, raw: Any, output_file: str | None = None) -> Any:
        """Map copy paths in a tool's payload (and its saved output file) back to the original source."""
        pairs = self._replacements(raw)

        def fix(value: Any) -> Any:
            if isinstance(value, str):
                for old, new in pairs:
                    value = value.replace(old, new)
                return value
            if isinstance(value, dict):
                return {fix(k): fix(v) for k, v in value.items()}
            if isinstance(value, list):
                return [fix(v) for v in value]
            return value

        if output_file and os.path.isfile(output_file):
            with open(output_file, "r", encoding="utf-8", errors="surrogateescape") as fd:
                text = fd.read()
            fixed = text
            for old, new in pairs:
                fixed = fixed.replace(old, new)
            if fixed != text:
                with open(output_file, "w", encoding="utf-8", errors="surrogateescape") as fd:
                    fd.write(fixed)
        return fix(raw)
