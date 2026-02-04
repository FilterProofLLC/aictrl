"""Tests for the aictrl demo command."""

import json
import os
import tempfile
from pathlib import Path

import pytest


class TestDemoCommand:
    """Test cases for aictrl demo command."""

    def test_demo_quick_exits_zero(self):
        """Test that `aictrl demo --quick` exits 0 and produces expected artifacts."""
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "demo_test"

            # Run demo command
            result = subprocess.run(
                [sys.executable, "-m", "aictrl", "demo", "--quick", "--out", str(out_dir)],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=Path(__file__).parent.parent,
            )

            # Check exit code
            assert result.returncode == 0, f"Demo failed with stderr: {result.stderr}"

            # Check expected artifacts exist
            expected_files = [
                "aictrl-baseline-report.txt",
                "aictrl-baseline-attestation.json",
                "aictrl-spec-coverage.txt",
                "aictrl-baseline.digest.txt",
                "aictrl-baseline-manifest.json",
            ]

            for filename in expected_files:
                artifact_path = out_dir / filename
                assert artifact_path.exists(), f"Missing artifact: {filename}"

    def test_demo_output_contains_verify_instruction(self):
        """Test that demo output contains 'Verify offline' instruction."""
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "demo_verify_test"

            result = subprocess.run(
                [sys.executable, "-m", "aictrl", "demo", "--quick", "--out", str(out_dir)],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=Path(__file__).parent.parent,
            )

            assert result.returncode == 0
            assert "Verify offline" in result.stdout, "Output should contain verification instructions"

    def test_demo_labels_expected_failures(self):
        """Test that expected failures are labeled in demo output."""
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "demo_expected_test"

            result = subprocess.run(
                [sys.executable, "-m", "aictrl", "demo", "--quick", "--out", str(out_dir)],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=Path(__file__).parent.parent,
            )

            assert result.returncode == 0

            # Check for expected failure labeling
            # The demo should mention expected failures if BL-080 is present
            stdout = result.stdout

            # Either "Expected Failures" appears or the attestation has them
            attestation_path = out_dir / "aictrl-baseline-attestation.json"
            if attestation_path.exists():
                with open(attestation_path) as f:
                    attestation = json.load(f)

                expected_count = attestation.get("summary", {}).get("expected_failures", 0)
                if expected_count > 0:
                    # Should be labeled in output
                    assert "Expected Failures" in stdout or "expected" in stdout.lower(), \
                        "Expected failures should be labeled in output"

    def test_demo_attestation_schema(self):
        """Test that generated attestation conforms to expected schema."""
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "demo_schema_test"

            result = subprocess.run(
                [sys.executable, "-m", "aictrl", "demo", "--quick", "--out", str(out_dir)],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=Path(__file__).parent.parent,
            )

            assert result.returncode == 0

            # Load and validate attestation
            attestation_path = out_dir / "aictrl-baseline-attestation.json"
            assert attestation_path.exists()

            with open(attestation_path) as f:
                attestation = json.load(f)

            # Check required fields
            assert "schema_version" in attestation
            assert attestation["schema_version"] == "1.1"
            assert "summary" in attestation
            assert "test_results" in attestation

            # Check summary fields
            summary = attestation["summary"]
            assert "total_tests" in summary
            assert "passed" in summary
            assert "expected_failures" in summary
            assert "unexpected_failures" in summary
            assert "overall_result" in summary

    def test_demo_artifacts_ascii_only(self):
        """Test that text artifacts contain only ASCII characters."""
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "demo_ascii_test"

            result = subprocess.run(
                [sys.executable, "-m", "aictrl", "demo", "--quick", "--out", str(out_dir)],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=Path(__file__).parent.parent,
            )

            assert result.returncode == 0

            # Check text files are ASCII-only
            text_files = [
                "aictrl-baseline-report.txt",
                "aictrl-spec-coverage.txt",
                "aictrl-baseline.digest.txt",
            ]

            for filename in text_files:
                file_path = out_dir / filename
                if file_path.exists():
                    with open(file_path, "rb") as f:
                        content = f.read()
                    # Check all bytes are ASCII (0-127)
                    non_ascii = [b for b in content if b > 127]
                    assert len(non_ascii) == 0, f"{filename} contains non-ASCII characters"


class TestDemoIntegration:
    """Integration tests for demo command with verification."""

    def test_demo_then_verify(self):
        """Test that demo artifacts can be verified."""
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "demo_verify_integration"
            baseline_dir = Path(__file__).parent.parent / "baseline"

            # Run demo
            demo_result = subprocess.run(
                [sys.executable, "-m", "aictrl", "demo", "--quick", "--out", str(out_dir)],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=Path(__file__).parent.parent,
            )
            assert demo_result.returncode == 0

            # Run verification
            verify_result = subprocess.run(
                [sys.executable, str(baseline_dir / "run_baseline.py"), "--verify", str(out_dir)],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=baseline_dir,
            )

            assert verify_result.returncode == 0, f"Verification failed: {verify_result.stdout}"
            assert "VERIFICATION: PASS" in verify_result.stdout
