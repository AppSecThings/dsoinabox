"""Tests for environment detection utilities."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from dsoinabox.utils.environment import is_running_in_docker, check_tool_available, get_tool_path


class TestDockerDetection:
    """Tests for Docker environment detection."""
    
    def test_is_running_in_docker_when_dockerenv_exists(self, monkeypatch):
        """Test that Docker is detected when /.dockerenv exists."""
        with patch("dsoinabox.utils.environment.os.path.exists") as mock_exists:
            mock_exists.return_value = True
            assert is_running_in_docker() is True
            mock_exists.assert_called_once_with("/.dockerenv")
    
    def test_is_running_in_docker_when_dockerenv_not_exists(self, monkeypatch):
        """Test that Docker is not detected when /.dockerenv doesn't exist."""
        with patch("dsoinabox.utils.environment.os.path.exists") as mock_exists:
            mock_exists.return_value = False
            assert is_running_in_docker() is False
            mock_exists.assert_called_once_with("/.dockerenv")


class TestToolAvailability:
    """Tests for tool availability checking."""
    
    def test_check_tool_available_when_tool_exists(self, monkeypatch):
        """Test that tool availability check returns True when tool exists."""
        with patch("dsoinabox.utils.environment.shutil.which") as mock_which:
            mock_which.return_value = "/usr/bin/syft"
            assert check_tool_available("syft") is True
            mock_which.assert_called_once_with("syft")
    
    def test_check_tool_available_when_tool_not_exists(self, monkeypatch):
        """Test that tool availability check returns False when tool doesn't exist."""
        with patch("dsoinabox.utils.environment.shutil.which") as mock_which:
            mock_which.return_value = None
            assert check_tool_available("nonexistent") is False
            mock_which.assert_called_once_with("nonexistent")
    
    def test_get_tool_path_when_tool_exists(self, monkeypatch):
        """Test that get_tool_path returns path when tool exists."""
        expected_path = "/usr/local/bin/grype"
        with patch("dsoinabox.utils.environment.shutil.which") as mock_which:
            mock_which.return_value = expected_path
            assert get_tool_path("grype") == expected_path
            mock_which.assert_called_once_with("grype")
    
    def test_get_tool_path_when_tool_not_exists(self, monkeypatch):
        """Test that get_tool_path returns None when tool doesn't exist."""
        with patch("dsoinabox.utils.environment.shutil.which") as mock_which:
            mock_which.return_value = None
            assert get_tool_path("nonexistent") is None
            mock_which.assert_called_once_with("nonexistent")
    
    def test_check_tool_available_with_real_tool(self):
        """Test with a real tool that should exist (python)."""
        # Python should always be available in test environment
        assert check_tool_available("python") or check_tool_available("python3")

