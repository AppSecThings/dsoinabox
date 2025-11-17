"""environment detection utilities for docker and tool availability."""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def is_running_in_docker() -> bool:
    """check if the process is running inside a docker container."""
    return os.path.exists("/.dockerenv")


def check_tool_available(tool_name: str) -> bool:
    """check if a tool executable is available in the system path."""
    return shutil.which(tool_name) is not None


def get_tool_path(tool_name: str) -> str | None:
    """get the full path to a tool executable if it exists in path."""
    return shutil.which(tool_name)

