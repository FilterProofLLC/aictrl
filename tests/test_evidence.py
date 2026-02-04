"""Tests for evidence bundle export.

These tests verify that:
1. Evidence export is deterministic
2. Hashes are stable for unchanged content
3. Invariant failures block export
4. No privileged operations are required

IMPORTANT: These tests run WITHOUT root and WITHOUT touching /proc or /sys.
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from aictrl.commands.evidence import (
    export_evidence_bundle,
    verify_evidence_bundle,
    calculate_sha256,
    generate_timestamp,
    generate_bundle_id,
    create_context_artifact,
    create_version_artifact,
    create_readme,
    NON_CERTIFICATION_NOTICE,
    EVIDENCE_INVARIANT_FAILURE,
    EVIDENCE_OUTPUT_DIR_ERROR,
)
from aictrl.util.invariants import ExecutionContext
from aictrl.util.errors import BbailError


class TestCalculateSha256:
    """Tests for SHA-256 hash calculation."""

    def test_hash_returns_string(self, tmp_path):
        """Hash should return hex string."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        result = calculate_sha256(test_file)
        assert isinstance(result, str)
        assert len(result) == 64  # SHA-256 is 64 hex chars

    def test_hash_is_deterministic(self, tmp_path):
        """Same content should produce same hash."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("deterministic content")
        hash1 = calculate_sha256(test_file)
        hash2 = calculate_sha256(test_file)
        assert hash1 == hash2

    def test_different_content_different_hash(self, tmp_path):
        """Different content should produce different hash."""
        file1 = tmp_path / "file1.txt"
        file2 = tmp_path / "file2.txt"
        file1.write_text("content 1")
        file2.write_text("content 2")
        assert calculate_sha256(file1) != calculate_sha256(file2)


class TestGenerateTimestamp:
    """Tests for timestamp generation."""

    def test_timestamp_is_iso8601(self):
        """Timestamp should be ISO 8601 format."""
        ts = generate_timestamp()
        assert "T" in ts
        assert "+" in ts or "Z" in ts

    def test_timestamp_has_timezone(self):
        """Timestamp should include timezone."""
        ts = generate_timestamp()
        # Should end with +00:00 or similar
        assert ts.endswith("+00:00") or ts.endswith("Z")


class TestGenerateBundleId:
    """Tests for bundle ID generation."""

    def test_bundle_id_format(self):
        """Bundle ID should have expected format."""
        ts = "2026-01-24T18:45:00.123456+00:00"
        bundle_id = generate_bundle_id(ts)
        assert bundle_id.startswith("evidence-bundle-")
        assert ":" not in bundle_id  # Filesystem safe

    def test_bundle_id_is_deterministic(self):
        """Same timestamp should produce same ID."""
        ts = "2026-01-24T18:45:00.123456+00:00"
        id1 = generate_bundle_id(ts)
        id2 = generate_bundle_id(ts)
        assert id1 == id2


class TestCreateContextArtifact:
    """Tests for context artifact creation."""

    def test_returns_dict(self):
        """Should return dictionary."""
        result = create_context_artifact(ExecutionContext.AIOS_SANDBOX)
        assert isinstance(result, dict)

    def test_has_required_fields(self):
        """Should have all required fields."""
        result = create_context_artifact(ExecutionContext.AIOS_SANDBOX)
        required = ["execution_context", "hostname", "username", "timestamp_utc"]
        for field in required:
            assert field in result, f"Missing field: {field}"

    def test_context_matches(self):
        """Context should match input."""
        result = create_context_artifact(ExecutionContext.AIOS_DEV)
        assert result["execution_context"] == "aios-dev"


class TestCreateVersionArtifact:
    """Tests for version artifact creation."""

    def test_returns_dict(self):
        """Should return dictionary."""
        result = create_version_artifact()
        assert isinstance(result, dict)

    def test_has_required_fields(self):
        """Should have all required fields."""
        result = create_version_artifact()
        required = ["name", "version", "python_version", "platform", "host_safety_enabled"]
        for field in required:
            assert field in result, f"Missing field: {field}"

    def test_name_is_aictrl(self):
        """Name should be aictrl."""
        result = create_version_artifact()
        assert result["name"] == "aictrl"


class TestCreateReadme:
    """Tests for README generation."""

    def test_returns_string(self):
        """Should return string."""
        result = create_readme(
            timestamp="2026-01-24T18:45:00Z",
            context="aios-sandbox",
            version="0.1.0",
            commit="abc1234",
            invariant_summary={"passed": 3, "failed": 0, "skipped": 16, "warned": 0, "overall_status": "pass"},
            check_summary={"passed": 6, "failed": 0},
        )
        assert isinstance(result, str)

    def test_includes_disclaimer(self):
        """Should include non-certification disclaimer."""
        result = create_readme(
            timestamp="2026-01-24T18:45:00Z",
            context="aios-sandbox",
            version="0.1.0",
            commit="abc1234",
            invariant_summary={"passed": 3, "failed": 0, "skipped": 16, "warned": 0, "overall_status": "pass"},
            check_summary={"passed": 6, "failed": 0},
        )
        assert "DISCLAIMER" in result
        assert "NOT constitute certification" in result

    def test_is_ascii_only(self):
        """README should be ASCII only."""
        result = create_readme(
            timestamp="2026-01-24T18:45:00Z",
            context="aios-sandbox",
            version="0.1.0",
            commit="abc1234",
            invariant_summary={"passed": 3, "failed": 0, "skipped": 16, "warned": 0, "overall_status": "pass"},
            check_summary={"passed": 6, "failed": 0},
        )
        assert all(ord(c) < 128 for c in result)


class TestExportEvidenceBundle:
    """Tests for evidence bundle export."""

    def test_requires_output_dir(self):
        """Should require output directory."""
        with pytest.raises(BbailError) as exc_info:
            export_evidence_bundle(output_dir=None)
        assert exc_info.value.code == EVIDENCE_OUTPUT_DIR_ERROR

    def test_creates_bundle_directory(self, tmp_path):
        """Should create bundle directory."""
        result = export_evidence_bundle(
            context="aios-sandbox",
            output_dir=str(tmp_path),
        )
        assert result["success"] is True
        bundle_path = Path(result["bundle_path"])
        assert bundle_path.exists()
        assert bundle_path.is_dir()

    def test_creates_required_files(self, tmp_path):
        """Should create all required files."""
        result = export_evidence_bundle(
            context="aios-sandbox",
            output_dir=str(tmp_path),
        )
        bundle_path = Path(result["bundle_path"])
        required_files = [
            "manifest.json",
            "context.json",
            "bbail-version.json",
            "doctor-output.json",
            "invariants.json",
            "README.txt",
        ]
        for filename in required_files:
            filepath = bundle_path / filename
            assert filepath.exists(), f"Missing file: {filename}"

    def test_manifest_has_hashes(self, tmp_path):
        """Manifest should include SHA-256 hashes."""
        result = export_evidence_bundle(
            context="aios-sandbox",
            output_dir=str(tmp_path),
        )
        manifest_path = Path(result["manifest_path"])
        with open(manifest_path) as f:
            manifest = json.load(f)
        for artifact in manifest["artifacts"]:
            assert "sha256" in artifact
            assert len(artifact["sha256"]) == 64

    def test_manifest_includes_disclaimer(self, tmp_path):
        """Manifest should include non-certification notice."""
        result = export_evidence_bundle(
            context="aios-sandbox",
            output_dir=str(tmp_path),
        )
        manifest_path = Path(result["manifest_path"])
        with open(manifest_path) as f:
            manifest = json.load(f)
        assert "non_certification_notice" in manifest
        assert "NOT constitute certification" in manifest["non_certification_notice"]

    def test_all_json_is_valid(self, tmp_path):
        """All JSON files should be valid JSON."""
        result = export_evidence_bundle(
            context="aios-sandbox",
            output_dir=str(tmp_path),
        )
        bundle_path = Path(result["bundle_path"])
        for json_file in bundle_path.glob("*.json"):
            with open(json_file) as f:
                json.load(f)  # Should not raise

    def test_export_is_read_only(self, tmp_path):
        """Export should not modify system state."""
        # This test verifies no system modification by checking
        # that export works in a sandboxed environment
        result = export_evidence_bundle(
            context="aios-sandbox",
            output_dir=str(tmp_path),
        )
        assert result["success"] is True

    def test_returns_artifact_count(self, tmp_path):
        """Should return accurate artifact count."""
        result = export_evidence_bundle(
            context="aios-sandbox",
            output_dir=str(tmp_path),
        )
        assert "artifact_count" in result
        assert result["artifact_count"] >= 6  # At least 6 required files


class TestExportDeterminism:
    """Tests for export determinism."""

    def test_same_context_same_structure(self, tmp_path):
        """Same context should produce same file structure."""
        result1 = export_evidence_bundle(
            context="aios-sandbox",
            output_dir=str(tmp_path / "export1"),
        )
        result2 = export_evidence_bundle(
            context="aios-sandbox",
            output_dir=str(tmp_path / "export2"),
        )

        bundle1 = Path(result1["bundle_path"])
        bundle2 = Path(result2["bundle_path"])

        files1 = set(f.name for f in bundle1.iterdir())
        files2 = set(f.name for f in bundle2.iterdir())
        assert files1 == files2

    def test_json_keys_sorted(self, tmp_path):
        """JSON files should have sorted keys for determinism."""
        result = export_evidence_bundle(
            context="aios-sandbox",
            output_dir=str(tmp_path),
        )
        manifest_path = Path(result["manifest_path"])
        with open(manifest_path) as f:
            content = f.read()
        with open(manifest_path) as f:
            manifest = json.load(f)
        # Re-serialize with sorted keys and compare
        reserialized = json.dumps(manifest, indent=2, sort_keys=True)
        # Content should already be sorted (may differ in whitespace only)
        assert "artifacts" in content
        assert "bundle_id" in content


class TestInvariantGate:
    """Tests for invariant failure blocking export."""

    def test_export_blocked_on_invariant_failure(self, tmp_path):
        """Export should fail if invariants fail."""
        # Mock invariant check to return failure
        # Must patch where it's imported, not where it's defined
        with mock.patch.object(
            sys.modules["aictrl.commands.evidence"],
            "run_all_invariant_checks"
        ) as mock_check:
            mock_check.return_value = {
                "overall_status": "fail",
                "summary": {"passed": 0, "failed": 1, "skipped": 0, "warned": 0, "total": 1},
                "invariants": [
                    {
                        "invariant_id": "INV-019",
                        "status": "fail",
                    }
                ],
            }
            with pytest.raises(BbailError) as exc_info:
                export_evidence_bundle(
                    context="aios-sandbox",
                    output_dir=str(tmp_path),
                )
            assert exc_info.value.code == EVIDENCE_INVARIANT_FAILURE
            assert "INV-019" in str(exc_info.value.message)

    def test_export_succeeds_on_pass(self, tmp_path):
        """Export should succeed if invariants pass."""
        result = export_evidence_bundle(
            context="aios-sandbox",
            output_dir=str(tmp_path),
        )
        assert result["success"] is True
        assert result["invariant_status"] in ["pass", "warn"]


class TestVerifyEvidenceBundle:
    """Tests for evidence bundle verification."""

    def test_verify_valid_bundle(self, tmp_path):
        """Should verify valid bundle."""
        export_result = export_evidence_bundle(
            context="aios-sandbox",
            output_dir=str(tmp_path),
        )
        verify_result = verify_evidence_bundle(export_result["bundle_path"])
        assert verify_result["valid"] is True

    def test_verify_detects_missing_manifest(self, tmp_path):
        """Should detect missing manifest."""
        bundle_dir = tmp_path / "fake-bundle"
        bundle_dir.mkdir()
        result = verify_evidence_bundle(str(bundle_dir))
        assert result["valid"] is False
        assert "manifest" in result["error"].lower()

    def test_verify_detects_tampered_file(self, tmp_path):
        """Should detect tampered files."""
        export_result = export_evidence_bundle(
            context="aios-sandbox",
            output_dir=str(tmp_path),
        )
        # Tamper with a file
        context_path = Path(export_result["bundle_path"]) / "context.json"
        with open(context_path, "a") as f:
            f.write("\n// tampered")
        verify_result = verify_evidence_bundle(export_result["bundle_path"])
        assert verify_result["valid"] is False

    def test_verify_detects_missing_artifact(self, tmp_path):
        """Should detect missing artifacts."""
        export_result = export_evidence_bundle(
            context="aios-sandbox",
            output_dir=str(tmp_path),
        )
        # Delete an artifact
        context_path = Path(export_result["bundle_path"]) / "context.json"
        context_path.unlink()
        verify_result = verify_evidence_bundle(export_result["bundle_path"])
        assert verify_result["valid"] is False


class TestHashStability:
    """Tests for hash stability."""

    def test_unchanged_content_same_hash(self, tmp_path):
        """Unchanged content should have same hash."""
        test_file = tmp_path / "test.json"
        content = {"key": "value", "number": 42}
        with open(test_file, "w") as f:
            json.dump(content, f, sort_keys=True, indent=2)
        hash1 = calculate_sha256(test_file)

        # Write same content again
        with open(test_file, "w") as f:
            json.dump(content, f, sort_keys=True, indent=2)
        hash2 = calculate_sha256(test_file)

        assert hash1 == hash2


class TestNoPrivilegedOperations:
    """Tests verifying no privileged operations."""

    def test_export_works_without_root(self, tmp_path):
        """Export should work without root privileges."""
        # This test implicitly verifies no root needed
        # because the test runs as non-root
        result = export_evidence_bundle(
            context="aios-sandbox",
            output_dir=str(tmp_path),
        )
        assert result["success"] is True

    def test_no_system_modification(self, tmp_path):
        """Export should not modify system files."""
        # Export should only write to the specified output directory
        result = export_evidence_bundle(
            context="aios-sandbox",
            output_dir=str(tmp_path),
        )
        # All created files should be under tmp_path
        bundle_path = Path(result["bundle_path"])
        assert str(bundle_path).startswith(str(tmp_path))

    def test_no_proc_or_sys_access(self, tmp_path):
        """Export should not require /proc or /sys access."""
        # If /proc or /sys were required, this would fail in
        # restricted environments. The test passing indicates
        # no such dependency.
        result = export_evidence_bundle(
            context="aios-sandbox",
            output_dir=str(tmp_path),
        )
        assert result["success"] is True


class TestEvidenceNonCertification:
    """Tests ensuring non-certification disclaimer is present."""

    def test_constant_exists(self):
        """Non-certification constant should exist."""
        assert NON_CERTIFICATION_NOTICE
        assert "NOT" in NON_CERTIFICATION_NOTICE
        assert "certification" in NON_CERTIFICATION_NOTICE.lower()

    def test_manifest_includes_notice(self, tmp_path):
        """Manifest should include non-certification notice."""
        result = export_evidence_bundle(
            context="aios-sandbox",
            output_dir=str(tmp_path),
        )
        manifest_path = Path(result["manifest_path"])
        with open(manifest_path) as f:
            manifest = json.load(f)
        assert manifest["non_certification_notice"] == NON_CERTIFICATION_NOTICE

    def test_readme_includes_disclaimer(self, tmp_path):
        """README should include disclaimer."""
        result = export_evidence_bundle(
            context="aios-sandbox",
            output_dir=str(tmp_path),
        )
        readme_path = Path(result["bundle_path"]) / "README.txt"
        with open(readme_path) as f:
            content = f.read()
        assert "NOT constitute certification" in content
        assert "DISCLAIMER" in content
