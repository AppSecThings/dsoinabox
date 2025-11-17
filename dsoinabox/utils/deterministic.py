"""Deterministic helpers for reporting and testing.

This module provides utilities to make output deterministic and testable:
- normalize_path: Normalizes absolute paths to a consistent format
- utcnow: Mockable UTC datetime function for consistent timestamps
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Callable, Optional


# Allow tests to override utcnow by setting this callable
_utcnow_override: Optional[Callable[[], datetime]] = None


def normalize_path(p: str) -> str:
    """
    Normalize absolute paths by replacing the root with <ROOT>.
    
    This makes paths deterministic across different machines and environments.
    For example:
        /Users/chris/project/file.py -> <ROOT>/project/file.py
        /home/user/project/file.py -> <ROOT>/project/file.py
        C:\\Users\\user\\file.py -> <ROOT>\\Users\\user\\file.py
    
    Args:
        p: Path string to normalize
        
    Returns:
        Normalized path string with absolute root replaced by <ROOT>
    """
    if not isinstance(p, str):
        return p
    
    # If not an absolute path, return as-is
    if not os.path.isabs(p):
        return p
    
    # Normalize path separators for consistent handling
    normalized = os.path.normpath(p)
    
    # Replace the root directory with <ROOT>
    # For Unix-like paths: / -> <ROOT>
    # For Windows paths: C:\ -> <ROOT>\
    if os.name == 'nt' and len(normalized) >= 3 and normalized[1] == ':':
        # Windows absolute path: C:\path\to\file
        return '<ROOT>' + normalized[2:]
    elif normalized.startswith('/'):
        # Unix-like absolute path: /path/to/file
        return '<ROOT>' + normalized
    
    # Fallback: if we can't determine the root, just return the basename
    return '<ROOT>/' + os.path.basename(normalized)


def utcnow() -> datetime:
    """
    Get the current UTC datetime.
    
    This is a wrapper around datetime.utcnow() that can be overridden
    in tests for deterministic timestamps. Use this instead of calling
    datetime.utcnow() or time.strftime() directly.
    
    Returns:
        Current UTC datetime, or the overridden value if set in tests
    """
    if _utcnow_override is not None:
        return _utcnow_override()
    return datetime.now(timezone.utc)


def set_utcnow_override(override: Optional[Callable[[], datetime]]) -> None:
    """
    Set an override function for utcnow().
    
    This is primarily for testing. Set to None to restore default behavior.
    
    Args:
        override: Callable that returns a datetime, or None to restore default
    """
    global _utcnow_override
    _utcnow_override = override

