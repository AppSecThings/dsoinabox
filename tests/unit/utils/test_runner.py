"""Unit tests for runner utility (subprocess execution)."""

from __future__ import annotations

import pytest
import subprocess
import signal
import os

from dsoinabox.utils.runner import run_cmd


class TestRunnerUtility:
    """Test runner utility handles subprocess execution correctly."""
    
    def test_run_cmd_success_returns_zero(self):
        """Test that successful command returns zero exit code."""
        returncode, stdout, stderr = run_cmd(["echo", "test"], text=True)
        
        assert returncode == 0
        assert "test" in stdout
        assert stderr == ""
    
    def test_run_cmd_failure_returns_nonzero(self):
        """Test that failed command returns non-zero exit code."""
        returncode, stdout, stderr = run_cmd(["false"], text=True)
        
        assert returncode != 0
    
    def test_run_cmd_stderr_captured(self):
        """Test that stderr is captured correctly."""
        # Use sh -c to write to stderr
        returncode, stdout, stderr = run_cmd(
            ["sh", "-c", "echo 'error message' >&2"],
            text=True
        )
        
        assert returncode == 0
        assert "error message" in stderr
    
    def test_run_cmd_env_merged(self, monkeypatch):
        """Test that environment variables are merged with os.environ."""
        # Set a test env var
        monkeypatch.setenv("TEST_VAR", "test_value")
        
        returncode, stdout, stderr = run_cmd(
            ["sh", "-c", "echo $TEST_VAR"],
            text=True,
            env={"ANOTHER_VAR": "another_value"}
        )
        
        assert returncode == 0
        # Both TEST_VAR (from os.environ) and ANOTHER_VAR (from env param) should be available
        # Note: exact behavior depends on shell, but TEST_VAR should be in merged env
        assert "test_value" in stdout or "TEST_VAR" in stdout
    
    def test_run_cmd_check_true_raises_on_failure(self):
        """Test that check=True raises CalledProcessError on failure."""
        with pytest.raises(subprocess.CalledProcessError):
            run_cmd(["false"], text=True, check=True)
    
    def test_run_cmd_check_false_does_not_raise(self):
        """Test that check=False doesn't raise on failure."""
        returncode, stdout, stderr = run_cmd(["false"], text=True, check=False)
        
        assert returncode != 0
        # Should not raise
    
    def test_run_cmd_bytes_mode(self):
        """Test that text=False returns bytes."""
        returncode, stdout, stderr = run_cmd(["echo", "test"], text=False)
        
        assert isinstance(stdout, bytes)
        assert isinstance(stderr, bytes)
        assert b"test" in stdout
    
    def test_run_cmd_text_mode(self):
        """Test that text=True returns strings."""
        returncode, stdout, stderr = run_cmd(["echo", "test"], text=True)
        
        assert isinstance(stdout, str)
        assert isinstance(stderr, str)
        assert "test" in stdout
    
    @pytest.mark.skipif(os.name == 'nt', reason="Timeout behavior differs on Windows")
    def test_run_cmd_timeout_raises(self):
        """Test that timeout raises TimeoutExpired.
        
        Note: This test may be flaky; skip on Windows where timeout behavior differs.
        """
        with pytest.raises(subprocess.TimeoutExpired):
            run_cmd(["sleep", "10"], text=True, timeout=1)
    
    def test_run_cmd_cwd_set(self, tmp_path):
        """Test that cwd parameter sets working directory."""
        test_file = tmp_path / "test_file.txt"
        test_file.write_text("test content")
        
        returncode, stdout, stderr = run_cmd(
            ["cat", "test_file.txt"],
            cwd=str(tmp_path),
            text=True
        )
        
        assert returncode == 0
        assert "test content" in stdout
    
    def test_run_cmd_empty_command_handled(self):
        """Test that empty command list raises IndexError (subprocess limitation)."""
        # Empty command list causes subprocess to fail with IndexError
        # This is expected behavior - subprocess.run requires at least one argument
        with pytest.raises((IndexError, ValueError)):
            run_cmd([], text=True)

