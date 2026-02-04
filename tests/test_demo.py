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

            # Check expected baseline artifacts exist
            baseline_files = [
                "aictrl-baseline-report.txt",
                "aictrl-baseline-attestation.json",
                "aictrl-spec-coverage.txt",
                "aictrl-baseline.digest.txt",
                "aictrl-baseline-manifest.json",
            ]

            for filename in baseline_files:
                artifact_path = out_dir / filename
                assert artifact_path.exists(), f"Missing baseline artifact: {filename}"

            # Check expected v1.2-v1.4 demo artifacts exist
            demo_artifacts = [
                "version.json",
                "crypto_status.json",
                "baseline_summary.txt",
                "exec_proposal.json",
                "exec_review_valid.json",
                "exec_propose_dangerous_blocked.txt",
                "exec_review_tampered.json",
                "demo_digest.txt",
            ]

            for filename in demo_artifacts:
                artifact_path = out_dir / filename
                assert artifact_path.exists(), f"Missing demo artifact: {filename}"

    def test_demo_output_contains_verify_instruction(self):
        """Test that demo output contains verification instruction."""
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
            assert "Verify baseline" in result.stdout, "Output should contain verification instructions"

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
                "baseline_summary.txt",
                "exec_propose_dangerous_blocked.txt",
                "exec_review_tampered.json",
                "demo_digest.txt",
            ]

            for filename in text_files:
                file_path = out_dir / filename
                if file_path.exists():
                    with open(file_path, "rb") as f:
                        content = f.read()
                    # Check all bytes are ASCII (0-127)
                    non_ascii = [b for b in content if b > 127]
                    assert len(non_ascii) == 0, f"{filename} contains non-ASCII characters"


class TestDemoPhase12:
    """Tests for Phase 12 Part 1 demo features."""

    def test_demo_phase12_proposal_valid(self):
        """Test that demo produces valid exec proposal."""
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "demo_phase12_test"

            result = subprocess.run(
                [sys.executable, "-m", "aictrl", "demo", "--quick", "--out", str(out_dir)],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=Path(__file__).parent.parent,
            )

            assert result.returncode == 0

            # Validate exec_proposal.json
            proposal_path = out_dir / "exec_proposal.json"
            assert proposal_path.exists()

            with open(proposal_path) as f:
                proposal = json.load(f)

            # Check required fields
            assert "proposal_id" in proposal
            assert "content_hash" in proposal
            assert "status" in proposal
            assert proposal["status"] == "proposed"
            assert "request" in proposal
            assert proposal["request"]["adapter"] == "noop"
            assert proposal["request"]["action"] == "read"

    def test_demo_phase12_review_valid(self):
        """Test that demo produces valid exec review."""
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "demo_review_test"

            result = subprocess.run(
                [sys.executable, "-m", "aictrl", "demo", "--quick", "--out", str(out_dir)],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=Path(__file__).parent.parent,
            )

            assert result.returncode == 0

            # Validate exec_review_valid.json
            review_path = out_dir / "exec_review_valid.json"
            assert review_path.exists()

            with open(review_path) as f:
                review = json.load(f)

            # Check required fields
            assert "hash_verified" in review
            assert review["hash_verified"] is True

    def test_demo_phase12_dangerous_blocked(self):
        """Test that demo shows dangerous gate blocking."""
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "demo_dangerous_test"

            result = subprocess.run(
                [sys.executable, "-m", "aictrl", "demo", "--quick", "--out", str(out_dir)],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=Path(__file__).parent.parent,
            )

            assert result.returncode == 0

            # Validate exec_propose_dangerous_blocked.txt
            blocked_path = out_dir / "exec_propose_dangerous_blocked.txt"
            assert blocked_path.exists()

            with open(blocked_path) as f:
                content = f.read()

            assert "Exit code: 2" in content

    def test_demo_phase12_tamper_detected(self):
        """Test that demo shows tamper detection."""
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "demo_tamper_test"

            result = subprocess.run(
                [sys.executable, "-m", "aictrl", "demo", "--quick", "--out", str(out_dir)],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=Path(__file__).parent.parent,
            )

            assert result.returncode == 0

            # Validate exec_review_tampered.json
            tampered_path = out_dir / "exec_review_tampered.json"
            assert tampered_path.exists()

            with open(tampered_path) as f:
                content = f.read()

            assert "Exit code: 2" in content


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
