"""base scanner class with shared functionality."""

from __future__ import annotations

import sys
from types import SimpleNamespace

from ..utils.runner import run_cmd


class ScannerError(Exception):
    """base exception for scanner errors."""
    pass


class BaseScanner:
    """base class for all scanner implementations."""

    def __init__(self, cli_name: str, help_command: str = "help"):
        """initialize base scanner."""
        self.cli_name = cli_name
        self.help_command = help_command

    def _run_command(self, args: str) -> SimpleNamespace:
        """run the cli tool with the provided args."""
        command = [self.cli_name] + args.split()
        returncode, stdout, stderr = run_cmd(command)
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    def show_version(self) -> None:
        """print the installed tool version to stdout."""
        result = self._run_command("--version")
        if result.returncode == 0:
            print(result.stdout.strip())
        else:
            sys.stderr.write(result.stderr)
            raise ScannerError(f"{self.cli_name} version check failed: {result.stderr}")

    def show_help(self) -> None:
        """print the help for the cli tool to stdout."""
        result = self._run_command(self.help_command)
        if result.returncode == 0:
            print(result.stdout.strip())
        else:
            sys.stderr.write(result.stderr)
            raise ScannerError(f"{self.cli_name} help failed: {result.stderr}")

