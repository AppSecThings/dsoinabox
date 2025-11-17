"""Centralized subprocess execution for testability."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Union


def run_cmd(
    cmd: list[str],
    *,
    cwd: Union[str, Path, None] = None,
    env: dict | None = None,
    timeout: int | None = None,
    text: bool = True,
    check: bool = False,
) -> tuple[int, Union[str, bytes], Union[str, bytes]]:
    """Run a command and return (returncode, stdout, stderr).
    
    This is the single point where subprocess.run is called, making it
    easy to mock in tests.
    
    Args:
        cmd: Command to run as a list of strings
        cwd: Working directory for the command
        env: Environment variables (merged with os.environ if provided)
        timeout: Timeout in seconds
        text: If True, return stdout/stderr as strings; if False, as bytes
        check: If True, raise CalledProcessError on non-zero returncode
        
    Returns:
        Tuple of (returncode, stdout, stderr) as strings or bytes depending on text
    """
    # Merge env with os.environ if provided
    if env is not None:
        merged_env = os.environ.copy()
        merged_env.update(env)
        env = merged_env
    
    result = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        timeout=timeout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
        check=check,
    )
    return result.returncode, result.stdout, result.stderr

