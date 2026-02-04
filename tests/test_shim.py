"""Tests for the repo-root bbail shim script."""

import os
import subprocess
import sys
from pathlib import Path

import pytest


def get_repo_root() -> Path:
    """Find the repository root directory."""
    # Start from the test file location and go up
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / ".git").is_dir() and (parent / "bbail").is_file():
            return parent
    pytest.skip("Could not find repo root with bbail shim")


class TestBbailShim:
    """Tests for the bbail shim script at repo root."""

    @pytest.fixture
    def repo_root(self) -> Path:
        """Get the repo root path."""
        return get_repo_root()

    @pytest.fixture
    def bbail_shim(self, repo_root: Path) -> Path:
        """Get the bbail shim path."""
        shim = repo_root / "bbail"
        if not shim.exists():
            pytest.skip("bbail shim not found at repo root")
        return shim

    def test_shim_exists_and_is_executable(self, bbail_shim: Path):
        """Shim should exist and be executable."""
        assert bbail_shim.exists()
        assert os.access(bbail_shim, os.X_OK)

    def test_shim_help_exits_zero(self, bbail_shim: Path):
        """./bbail --help should exit 0."""
        result = subprocess.run(
            [str(bbail_shim), "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "BBAIL system management CLI" in result.stdout

    def test_shim_version_exits_zero(self, bbail_shim: Path):
        """./bbail version should exit 0."""
        result = subprocess.run(
            [str(bbail_shim), "version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "bbail" in result.stdout.lower()

    def test_shim_doctor_exits_zero(self, bbail_shim: Path):
        """./bbail doctor should exit 0 (all checks pass on dev host)."""
        result = subprocess.run(
            [str(bbail_shim), "doctor", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert '"overall_status"' in result.stdout

    def test_shim_works_from_subdirectory(self, repo_root: Path, bbail_shim: Path):
        """Shim should work when invoked from a subdirectory."""
        docs_dir = repo_root / "docs"
        if not docs_dir.exists():
            pytest.skip("docs directory not found")

        # Use relative path from docs directory
        relative_shim = Path("..") / "bbail"

        result = subprocess.run(
            [str(relative_shim), "--help"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(docs_dir),
        )
        assert result.returncode == 0
        assert "BBAIL system management CLI" in result.stdout

    def test_shim_pr_create_help_exits_zero(self, bbail_shim: Path):
        """./bbail pr create --help should exit 0."""
        result = subprocess.run(
            [str(bbail_shim), "pr", "create", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "--title" in result.stdout
        assert "--body" in result.stdout
