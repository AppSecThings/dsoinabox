"""Unit tests for deterministic helpers (path normalization, utcnow)."""

from __future__ import annotations

import pytest
import os
from datetime import datetime, timezone

from dsoinabox.utils.deterministic import normalize_path, utcnow, set_utcnow_override


class TestNormalizePath:
    """Test path normalization edge cases."""
    
    def test_normalize_path_windows_absolute(self):
        """Test that Windows absolute paths are normalized."""
        if os.name == 'nt':
            path = r"C:\Users\file.py"
            normalized = normalize_path(path)
            assert normalized.startswith("<ROOT>")
            assert "file.py" in normalized
        else:
            pytest.skip("Windows-specific test")
    
    def test_normalize_path_unix_absolute(self):
        """Test that Unix absolute paths are normalized."""
        path = "/home/user/file.py"
        normalized = normalize_path(path)
        assert normalized.startswith("<ROOT>")
        assert "file.py" in normalized
    
    def test_normalize_path_relative_passthrough(self):
        """Test that relative paths pass through unchanged."""
        path = "src/file.py"
        normalized = normalize_path(path)
        assert normalized == "src/file.py"
    
    def test_normalize_path_relative_with_dot_slash(self):
        """Test that relative paths with ./ pass through."""
        path = "./src/file.py"
        normalized = normalize_path(path)
        # Relative paths should pass through (normalization only affects absolute)
        assert normalized == "./src/file.py" or normalized == "src/file.py"
    
    def test_normalize_path_empty_string(self):
        """Test that empty string returns as-is."""
        path = ""
        normalized = normalize_path(path)
        assert normalized == ""
    
    def test_normalize_path_non_string_passthrough(self):
        """Test that non-string inputs return as-is."""
        # Test with None
        result = normalize_path(None)
        assert result is None
        
        # Test with int
        result = normalize_path(123)
        assert result == 123
        
        # Test with list
        result = normalize_path(["path1", "path2"])
        assert result == ["path1", "path2"]
    
    def test_normalize_path_path_with_dot_dot(self):
        """Test that paths with .. components are handled."""
        path = "/home/user/../other/file.py"
        normalized = normalize_path(path)
        # Should normalize the .. component
        assert "<ROOT>" in normalized or "/other/file.py" in normalized
    
    def test_normalize_path_multiple_slashes(self):
        """Test that multiple slashes are normalized."""
        path = "/home//user///file.py"
        normalized = normalize_path(path)
        # Should normalize multiple slashes
        assert "<ROOT>" in normalized


class TestUtcnow:
    """Test utcnow() function and override mechanism."""
    
    def test_utcnow_returns_datetime(self):
        """Test that utcnow() returns a datetime object."""
        result = utcnow()
        assert isinstance(result, datetime)
        assert result.tzinfo is not None  # Should have timezone info
    
    def test_utcnow_override_in_tests(self):
        """Test that utcnow() can be overridden in tests."""
        fixed_time = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        
        def override():
            return fixed_time
        
        # Set override
        set_utcnow_override(override)
        
        try:
            result = utcnow()
            assert result == fixed_time
        finally:
            # Restore default
            set_utcnow_override(None)
    
    def test_utcnow_restore_default(self):
        """Test that setting override to None restores default behavior."""
        fixed_time = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        
        def override():
            return fixed_time
        
        # Set override
        set_utcnow_override(override)
        assert utcnow() == fixed_time
        
        # Restore default
        set_utcnow_override(None)
        result = utcnow()
        assert isinstance(result, datetime)
        assert result != fixed_time  # Should be current time
    
    def test_utcnow_timezone_utc(self):
        """Test that utcnow() returns UTC timezone."""
        result = utcnow()
        assert result.tzinfo == timezone.utc or result.tzinfo.utcoffset(None).total_seconds() == 0

