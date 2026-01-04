"""Unit tests for project ID derivation and HMAC key generation."""

from __future__ import annotations

import pytest
import os
import tempfile
import subprocess
from pathlib import Path

from dsoinabox.utils.project_id import (
    is_git,
    normalize_git_remote,
    get_initial_commit_hash,
    derive_project_id,
    derive_project_hmac_key,
)


class TestNormalizeGitRemote:
    """Test git remote URL normalization."""
    
    def test_normalize_ssh_format(self):
        """Test SSH format: git@host:path"""
        url = "git@github.com:user/repo.git"
        result = normalize_git_remote(url)
        assert result == "github.com/user/repo"
    
    def test_normalize_https_format(self):
        """Test HTTPS format: https://host/path"""
        url = "https://github.com/user/repo.git"
        result = normalize_git_remote(url)
        assert result == "github.com/user/repo"
    
    def test_normalize_with_credentials(self):
        """Test URL with credentials (should be stripped)"""
        url = "https://token@github.com/user/repo.git"
        result = normalize_git_remote(url)
        assert result == "github.com/user/repo"
    
    def test_normalize_with_user_pass(self):
        """Test URL with user:pass credentials"""
        url = "https://user:pass@github.com/user/repo.git"
        result = normalize_git_remote(url)
        assert result == "github.com/user/repo"
    
    def test_normalize_custom_port_ssh(self):
        """Test SSH format with custom port"""
        url = "git@gitlab.com:2222:group/project.git"
        result = normalize_git_remote(url)
        assert result == "gitlab.com/group/project"
    
    def test_normalize_already_normalized(self):
        """Test already normalized URL"""
        url = "github.com/user/repo"
        result = normalize_git_remote(url)
        assert result == "github.com/user/repo"
    
    def test_normalize_no_dot_git(self):
        """Test URL without .git suffix"""
        url = "https://github.com/user/repo"
        result = normalize_git_remote(url)
        assert result == "github.com/user/repo"
    
    def test_normalize_gitlab(self):
        """Test GitLab URL"""
        url = "git@gitlab.com:group/project.git"
        result = normalize_git_remote(url)
        assert result == "gitlab.com/group/project"
    
    def test_normalize_bitbucket(self):
        """Test Bitbucket URL"""
        url = "https://bitbucket.org/user/repo.git"
        result = normalize_git_remote(url)
        assert result == "bitbucket.org/user/repo"
    
    def test_normalize_nested_path(self):
        """Test URL with nested path"""
        url = "https://github.com/org/group/repo.git"
        result = normalize_git_remote(url)
        assert result == "github.com/org/group/repo"
    
    def test_normalize_empty_string(self):
        """Test empty string"""
        url = ""
        result = normalize_git_remote(url)
        assert result == ""
    
    def test_normalize_lowercase_hostname(self):
        """Test that hostname is lowercased"""
        url = "https://GitHub.com/user/repo.git"
        result = normalize_git_remote(url)
        assert result == "github.com/user/repo"


class TestGetInitialCommitHash:
    """Test getting initial commit hash from git repository."""
    
    def test_get_initial_commit_hash_valid_repo(self, tmp_path):
        """Test getting initial commit hash from valid git repo"""
        # Create a git repository
        repo_path = tmp_path / "test_repo"
        repo_path.mkdir()
        
        # Initialize git repo
        subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_path, check=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_path, check=True)
        
        # Create initial commit
        (repo_path / "file.txt").write_text("test")
        subprocess.run(["git", "add", "file.txt"], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_path, check=True, capture_output=True)
        
        # Get initial commit hash
        result = get_initial_commit_hash(str(repo_path))
        assert result is not None
        assert len(result) == 40  # SHA-1 hash is 40 characters
        assert all(c in '0123456789abcdef' for c in result)
    
    def test_get_initial_commit_hash_non_git(self, tmp_path):
        """Test getting initial commit hash from non-git directory"""
        result = get_initial_commit_hash(str(tmp_path))
        assert result is None
    
    def test_get_initial_commit_hash_no_commits(self, tmp_path):
        """Test getting initial commit hash from git repo with no commits"""
        repo_path = tmp_path / "test_repo"
        repo_path.mkdir()
        
        # Initialize git repo but don't commit
        subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
        
        # Should return None (no commits)
        result = get_initial_commit_hash(str(repo_path))
        assert result is None


class TestDeriveProjectId:
    """Test project ID derivation."""
    
    def test_derive_project_id_with_override(self, tmp_path):
        """Test that override takes priority"""
        override = "my-custom-project-id"
        result = derive_project_id(str(tmp_path), project_id_override=override)
        assert result == override
    
    def test_derive_project_id_git_with_remote(self, tmp_path):
        """Test deriving from git repo with remote"""
        repo_path = tmp_path / "test_repo"
        repo_path.mkdir()
        
        # Initialize git repo
        subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_path, check=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_path, check=True)
        
        # Add remote
        subprocess.run(
            ["git", "remote", "add", "origin", "https://github.com/user/repo.git"],
            cwd=repo_path,
            check=True,
            capture_output=True
        )
        
        # Create initial commit
        (repo_path / "file.txt").write_text("test")
        subprocess.run(["git", "add", "file.txt"], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_path, check=True, capture_output=True)
        
        result = derive_project_id(str(repo_path))
        assert result == "github.com/user/repo"
    
    def test_derive_project_id_git_without_remote(self, tmp_path):
        """Test deriving from git repo without remote (uses initial commit)"""
        repo_path = tmp_path / "test_repo"
        repo_path.mkdir()
        
        # Initialize git repo
        subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_path, check=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo_path, check=True)
        
        # Create initial commit
        (repo_path / "file.txt").write_text("test")
        subprocess.run(["git", "add", "file.txt"], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_path, check=True, capture_output=True)
        
        result = derive_project_id(str(repo_path))
        assert result is not None
        assert len(result) == 40  # Should be commit hash
        assert all(c in '0123456789abcdef' for c in result)
    
    def test_derive_project_id_non_git_with_override(self, tmp_path):
        """Test non-git directory with override"""
        override = "my-project"
        result = derive_project_id(str(tmp_path), project_id_override=override)
        assert result == override
    
    def test_derive_project_id_non_git_without_override(self, tmp_path):
        """Test non-git directory without override (should raise ValueError)"""
        with pytest.raises(ValueError, match="not a git repository"):
            derive_project_id(str(tmp_path))
    
    def test_derive_project_id_git_no_commits(self, tmp_path):
        """Test git repo with no commits (should raise ValueError)"""
        repo_path = tmp_path / "test_repo"
        repo_path.mkdir()
        
        # Initialize git repo but don't commit
        subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
        
        with pytest.raises(ValueError, match="no remote and no commits"):
            derive_project_id(str(repo_path))


class TestDeriveProjectHmacKey:
    """Test HMAC key derivation from project ID."""
    
    def test_derive_key_deterministic(self):
        """Test that same project_id produces same key"""
        project_id = "github.com/user/repo"
        key1 = derive_project_hmac_key(project_id)
        key2 = derive_project_hmac_key(project_id)
        assert key1 == key2
    
    def test_derive_key_different_project_ids(self):
        """Test that different project_ids produce different keys"""
        project_id1 = "github.com/user/repo1"
        project_id2 = "github.com/user/repo2"
        key1 = derive_project_hmac_key(project_id1)
        key2 = derive_project_hmac_key(project_id2)
        assert key1 != key2
    
    def test_derive_key_length(self):
        """Test that key is exactly 32 bytes"""
        project_id = "github.com/user/repo"
        key = derive_project_hmac_key(project_id)
        assert len(key) == 32
    
    def test_derive_key_type(self):
        """Test that key is bytes"""
        project_id = "github.com/user/repo"
        key = derive_project_hmac_key(project_id)
        assert isinstance(key, bytes)
    
    def test_derive_key_various_project_ids(self):
        """Test key derivation with various project ID formats"""
        test_cases = [
            "github.com/user/repo",
            "gitlab.com/group/project",
            "abc123def456",  # commit hash
            "my-custom-project-id",
            "org/suborg/repo",
        ]
        
        keys = {}
        for project_id in test_cases:
            key = derive_project_hmac_key(project_id)
            assert len(key) == 32
            assert isinstance(key, bytes)
            # Ensure uniqueness
            assert key not in keys.values()
            keys[project_id] = key


class TestIsGit:
    """Test is_git() function."""
    
    def test_is_git_returns_true_for_git_repo(self, tmp_path):
        """Test that is_git returns True for a git repository."""
        repo_path = tmp_path / "test_repo"
        repo_path.mkdir()
        
        # Initialize git repo
        subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
        
        result = is_git(str(repo_path))
        assert result is True
    
    def test_is_git_returns_false_for_non_git_dir(self, tmp_path):
        """Test that is_git returns False for a non-git directory."""
        non_git_path = tmp_path / "not_a_repo"
        non_git_path.mkdir()
        
        result = is_git(str(non_git_path))
        assert result is False
    
    def test_is_git_returns_false_for_file(self, tmp_path):
        """Test that is_git returns False for a file (not a directory)."""
        file_path = tmp_path / "some_file.txt"
        file_path.write_text("test")
        
        result = is_git(str(file_path))
        assert result is False
    
    def test_is_git_returns_false_for_nonexistent_path(self, tmp_path):
        """Test that is_git returns False for a nonexistent path."""
        nonexistent_path = tmp_path / "nonexistent"
        
        result = is_git(str(nonexistent_path))
        assert result is False

