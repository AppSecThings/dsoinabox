"""Deliberately vulnerable sample used by the live smoke test. Never deploy."""
import os
import subprocess


def run(cmd: str) -> int:
    # SAST: shell injection via os.system with user input
    return os.system("ls " + cmd)


def run2(cmd: str) -> None:
    subprocess.call(cmd, shell=True)  # SAST: subprocess with shell=True
