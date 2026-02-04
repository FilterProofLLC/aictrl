"""Tests for bbail support-bundle command."""

import json
import os
import sys
import tarfile
import tempfile
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from aictrl.commands.support_bundle import create_support_bundle

import pytest


class TestSupportBundle:
    """Tests for the support-bundle command."""

    def test_create_bundle_returns_dict(self):
        """Create bundle should return a dictionary."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = create_support_bundle(output_path=tmpdir)
            assert isinstance(result, dict)

    def test_create_bundle_success(self):
        """Create bundle should succeed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = create_support_bundle(output_path=tmpdir)
            assert result["success"] is True
            assert "bundle_path" in result
            assert "created_at" in result

    def test_create_bundle_creates_file(self):
        """Create bundle should create a tar.gz file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = create_support_bundle(output_path=tmpdir)
            bundle_path = Path(result["bundle_path"])
            assert bundle_path.exists()
            assert bundle_path.suffix == ".gz"
            assert ".tar" in bundle_path.name

    def test_bundle_is_valid_tarfile(self):
        """Bundle should be a valid tar.gz file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = create_support_bundle(output_path=tmpdir)
            bundle_path = result["bundle_path"]
            assert tarfile.is_tarfile(bundle_path)

    def test_bundle_contains_required_files(self):
        """Bundle should contain required files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = create_support_bundle(output_path=tmpdir)
            bundle_path = result["bundle_path"]

            with tarfile.open(bundle_path, "r:gz") as tar:
                names = tar.getnames()

                # Required aictrl outputs
                assert "aictrl/version.json" in names
                assert "aictrl/status.json" in names
                assert "aictrl/doctor.json" in names

                # Required metadata
                assert "meta/created_at.txt" in names

    def test_bundle_version_json_valid(self):
        """Bundle version.json should be valid JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = create_support_bundle(output_path=tmpdir)
            bundle_path = result["bundle_path"]

            with tarfile.open(bundle_path, "r:gz") as tar:
                version_file = tar.extractfile("aictrl/version.json")
                version_data = json.load(version_file)
                assert "name" in version_data
                assert version_data["name"] == "aictrl"
                assert "version" in version_data

    def test_bundle_status_json_valid(self):
        """Bundle status.json should be valid JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = create_support_bundle(output_path=tmpdir)
            bundle_path = result["bundle_path"]

            with tarfile.open(bundle_path, "r:gz") as tar:
                status_file = tar.extractfile("aictrl/status.json")
                status_data = json.load(status_file)
                assert "timestamp_utc" in status_data
                assert "host" in status_data

    def test_bundle_doctor_json_valid(self):
        """Bundle doctor.json should be valid JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = create_support_bundle(output_path=tmpdir)
            bundle_path = result["bundle_path"]

            with tarfile.open(bundle_path, "r:gz") as tar:
                doctor_file = tar.extractfile("aictrl/doctor.json")
                doctor_data = json.load(doctor_file)
                assert "timestamp_utc" in doctor_data
                assert "checks" in doctor_data

    def test_bundle_default_output_path(self):
        """Bundle should default to current directory."""
        # Save current dir and change to temp
        original_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                os.chdir(tmpdir)
                result = create_support_bundle()
                bundle_path = Path(result["bundle_path"])
                assert bundle_path.parent == Path(tmpdir)
            finally:
                os.chdir(original_cwd)
