"""base scanner class with shared functionality."""

from __future__ import annotations

import shlex
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

    def _normalize_args(self, args: str | list[str] | tuple[str, ...] | None) -> list[str]:
        """normalize args into tokenized list suitable for subprocess calls."""
        if args is None:
            return []
        if isinstance(args, str):
            return shlex.split(args)
        return [str(arg) for arg in args]

    def _parse_extra_tool_args(self, extra_tool_args: str | list[str] | tuple[str, ...] | None) -> list[str]:
        """parse optional extra tool args from CLI into a token list."""
        if not extra_tool_args:
            return []
        return self._normalize_args(extra_tool_args)

    def _run_command(
        self,
        args: str | list[str] | tuple[str, ...] | None,
        *,
        env: dict[str, str] | None = None,
        text: bool = True,
        timeout: int | None = None,
    ) -> SimpleNamespace:
        """run the cli tool with the provided args."""
        command = [self.cli_name] + self._normalize_args(args)
        returncode, stdout, stderr = run_cmd(command, env=env, text=text, timeout=timeout)
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    def get_version(self) -> str:
        """return the installed tool version as a single line, or raise ScannerError."""
        result = self._run_command("--version", timeout=60)
        if result.returncode != 0:
            raise ScannerError(f"{self.cli_name} version check failed: {result.stderr}")
        text = result.stdout if isinstance(result.stdout, str) else result.stdout.decode("utf-8", "replace")
        first = next((line.strip() for line in text.splitlines() if line.strip()), "")
        return first

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
