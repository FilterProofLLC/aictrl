"""Tests for bbail boot command - boot measurement simulation.

These tests verify that boot measurements are:
1. Simulation only - no real boot operations
2. Deterministic - same inputs produce same outputs
3. Safe - no privileged operations

CRITICAL: No test may execute real boot operations.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from aictrl.commands.boot import (
    BOOT_CONTEXT_ERROR,
    BOOT_SANDBOX_ERROR,
    MEASUREMENT_POINTS,
    SIMULATION_WARNING,
    calculate_sha256,
    compute_combined_hash,
    compute_measurement,
    generate_simulated_content,
    get_sandbox_path,
    simulate_boot_measurements,
    verify_boot_identity,
)
from aictrl.util.errors import BbailError


class TestBootMeasurementBasics:
    """Test basic boot measurement functionality."""

    def test_measurement_points_defined(self):
        """Verify all six measurement points are defined."""
        assert len(MEASUREMENT_POINTS) == 6
        ids = [m["id"] for m in MEASUREMENT_POINTS]
        assert ids == ["M1", "M2", "M3", "M4", "M5", "M6"]

    def test_measurement_stages(self):
        """Verify measurement stages are ordered correctly."""
        stages = [m["stage"] for m in MEASUREMENT_POINTS]
        assert stages == [1, 1, 1, 2, 3, 3]

    def test_simulation_warning_present(self):
        """Verify simulation warning is defined."""
        assert "Simulated" in SIMULATION_WARNING
        assert "not from real boot" in SIMULATION_WARNING


class TestHashFunctions:
    """Test cryptographic hash functions."""

    def test_sha256_deterministic(self):
        """SHA-256 produces same hash for same content."""
        content = b"test content"
        hash1 = calculate_sha256(content)
        hash2 = calculate_sha256(content)
        assert hash1 == hash2

    def test_sha256_different_content(self):
        """SHA-256 produces different hash for different content."""
        hash1 = calculate_sha256(b"content1")
        hash2 = calculate_sha256(b"content2")
        assert hash1 != hash2

    def test_sha256_format(self):
        """SHA-256 produces 64-char lowercase hex string."""
        hash_value = calculate_sha256(b"test")
        assert len(hash_value) == 64
        assert hash_value == hash_value.lower()
        assert all(c in "0123456789abcdef" for c in hash_value)


class TestCombinedHash:
    """Test combined hash computation."""

    def test_combined_hash_deterministic(self):
        """Combined hash is deterministic for same measurements."""
        measurements = [
            {"id": "M1", "hash": "a" * 64},
            {"id": "M2", "hash": "b" * 64},
        ]
        hash1 = compute_combined_hash(measurements)
        hash2 = compute_combined_hash(measurements)
        assert hash1 == hash2

    def test_combined_hash_order_independent(self):
        """Combined hash sorts by ID for consistency."""
        measurements_ordered = [
            {"id": "M1", "hash": "a" * 64},
            {"id": "M2", "hash": "b" * 64},
        ]
        measurements_reversed = [
            {"id": "M2", "hash": "b" * 64},
            {"id": "M1", "hash": "a" * 64},
        ]
        hash1 = compute_combined_hash(measurements_ordered)
        hash2 = compute_combined_hash(measurements_reversed)
        assert hash1 == hash2

    def test_combined_hash_changes_with_measurement(self):
        """Combined hash changes when any measurement changes."""
        measurements1 = [
            {"id": "M1", "hash": "a" * 64},
            {"id": "M2", "hash": "b" * 64},
        ]
        measurements2 = [
            {"id": "M1", "hash": "a" * 64},
            {"id": "M2", "hash": "c" * 64},  # Different
        ]
        hash1 = compute_combined_hash(measurements1)
        hash2 = compute_combined_hash(measurements2)
        assert hash1 != hash2


class TestSimulatedContent:
    """Test simulated content generation."""

    def test_m1_content_deterministic(self):
        """M1 (bootloader config) content is deterministic."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir)
            content1 = generate_simulated_content("M1", sandbox)
            content2 = generate_simulated_content("M1", sandbox)
            assert content1 == content2

    def test_m2_content_deterministic(self):
        """M2 (kernel) content is deterministic."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir)
            content1 = generate_simulated_content("M2", sandbox)
            content2 = generate_simulated_content("M2", sandbox)
            assert content1 == content2
            assert b"SIMULATED-KERNEL" in content1

    def test_m3_content_from_sandbox(self):
        """M3 (cmdline) reads from sandbox if available."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir)
            proc_dir = sandbox / "proc"
            proc_dir.mkdir()
            cmdline = proc_dir / "cmdline"
            cmdline.write_bytes(b"root=/dev/sda1 quiet")

            content = generate_simulated_content("M3", sandbox)
            assert content == b"root=/dev/sda1 quiet"

    def test_m4_content_deterministic(self):
        """M4 (initramfs) content is deterministic."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir)
            content1 = generate_simulated_content("M4", sandbox)
            content2 = generate_simulated_content("M4", sandbox)
            assert content1 == content2
            assert b"SIMULATED-INITRAMFS" in content1

    def test_m5_uses_os_release(self):
        """M5 (rootfs) uses os-release if available."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir)
            etc_dir = sandbox / "etc"
            etc_dir.mkdir()
            os_release = etc_dir / "os-release"
            os_release.write_bytes(b"NAME=AIOS\nVERSION=1.0\n")

            content = generate_simulated_content("M5", sandbox)
            assert content == b"NAME=AIOS\nVERSION=1.0\n"

    def test_m6_combines_etc_files(self):
        """M6 (service configs) combines /etc files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir)
            etc_dir = sandbox / "etc"
            etc_dir.mkdir()
            (etc_dir / "a.conf").write_bytes(b"file_a")
            (etc_dir / "b.conf").write_bytes(b"file_b")

            content = generate_simulated_content("M6", sandbox)
            # Files should be concatenated in sorted order
            assert b"file_a" in content
            assert b"file_b" in content


class TestMeasurementComputation:
    """Test measurement computation."""

    def test_compute_measurement_format(self):
        """Verify measurement record format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir)
            measurement_point = MEASUREMENT_POINTS[0]  # M1

            measurement = compute_measurement(
                measurement_point, sandbox, "2026-01-24T12:00:00+00:00"
            )

            assert "id" in measurement
            assert "name" in measurement
            assert "component" in measurement
            assert "source" in measurement
            assert "algorithm" in measurement
            assert "hash" in measurement
            assert "timestamp_utc" in measurement
            assert "stage" in measurement

            assert measurement["id"] == "M1"
            assert measurement["algorithm"] == "SHA-256"
            assert len(measurement["hash"]) == 64

    def test_compute_measurement_deterministic(self):
        """Same inputs produce same measurement hash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir)
            measurement_point = MEASUREMENT_POINTS[0]
            timestamp = "2026-01-24T12:00:00+00:00"

            m1 = compute_measurement(measurement_point, sandbox, timestamp)
            m2 = compute_measurement(measurement_point, sandbox, timestamp)

            assert m1["hash"] == m2["hash"]


class TestSimulateBootMeasurements:
    """Test full boot measurement simulation."""

    @pytest.fixture
    def mock_sandbox(self, tmp_path):
        """Create a mock sandbox structure."""
        rootfs = tmp_path / "sandbox" / "aios-dev" / "rootfs"
        rootfs.mkdir(parents=True)

        # Create /etc
        etc = rootfs / "etc"
        etc.mkdir()
        (etc / "hostname").write_bytes(b"aios-sandbox")
        (etc / "os-release").write_bytes(b"NAME=AIOS\nVERSION=1.0\n")

        # Create /proc
        proc = rootfs / "proc"
        proc.mkdir()
        (proc / "cmdline").write_bytes(b"root=/dev/sda2 ro selinux=1")

        return tmp_path

    def test_simulation_returns_expected_structure(self, mock_sandbox):
        """Verify simulation returns expected structure."""
        with mock.patch(
            "aictrl.commands.boot.get_sandbox_path",
            return_value=mock_sandbox / "sandbox" / "aios-dev" / "rootfs",
        ):
            result = simulate_boot_measurements(context="aios-sandbox")

            assert result["simulated"] is True
            assert result["context"] == "aios-sandbox"
            assert "measurement_log" in result
            assert "boot_identity" in result
            assert result["warning"] == SIMULATION_WARNING

    def test_simulation_has_all_measurements(self, mock_sandbox):
        """Verify all six measurements are present."""
        with mock.patch(
            "aictrl.commands.boot.get_sandbox_path",
            return_value=mock_sandbox / "sandbox" / "aios-dev" / "rootfs",
        ):
            result = simulate_boot_measurements(context="aios-sandbox")

            measurements = result["measurement_log"]["measurements"]
            assert len(measurements) == 6
            ids = [m["id"] for m in measurements]
            assert ids == ["M1", "M2", "M3", "M4", "M5", "M6"]

    def test_simulation_deterministic(self, mock_sandbox):
        """Same sandbox produces same measurements."""
        with mock.patch(
            "aictrl.commands.boot.get_sandbox_path",
            return_value=mock_sandbox / "sandbox" / "aios-dev" / "rootfs",
        ):
            result1 = simulate_boot_measurements(context="aios-sandbox")
            result2 = simulate_boot_measurements(context="aios-sandbox")

            # Measurement hashes should be identical
            for m1, m2 in zip(
                result1["measurement_log"]["measurements"],
                result2["measurement_log"]["measurements"],
            ):
                assert m1["hash"] == m2["hash"]

            # Combined hash should be identical
            assert (
                result1["measurement_log"]["combined_hash"]
                == result2["measurement_log"]["combined_hash"]
            )

    def test_simulation_rejects_non_sandbox_context(self, mock_sandbox):
        """Simulation rejects non-sandbox contexts."""
        with mock.patch(
            "aictrl.commands.boot.get_sandbox_path",
            return_value=mock_sandbox / "sandbox" / "aios-dev" / "rootfs",
        ):
            with pytest.raises(BbailError) as exc_info:
                simulate_boot_measurements(context="aios-base")

            assert exc_info.value.code == BOOT_CONTEXT_ERROR


class TestVerifyBootIdentity:
    """Test boot identity verification."""

    def test_verify_self_consistent(self):
        """Verify returns true for consistent measurement log."""
        measurements = [
            {"id": "M1", "hash": "a" * 64},
            {"id": "M2", "hash": "b" * 64},
        ]
        combined = compute_combined_hash(measurements)

        log = {
            "measurement_log": {
                "measurements": measurements,
                "combined_hash": combined,
            }
        }

        result = verify_boot_identity(log)
        assert result["valid"] is True
        assert result["self_consistent"] is True

    def test_verify_detects_tampering(self):
        """Verify detects when combined hash doesn't match."""
        measurements = [
            {"id": "M1", "hash": "a" * 64},
            {"id": "M2", "hash": "b" * 64},
        ]

        log = {
            "measurement_log": {
                "measurements": measurements,
                "combined_hash": "wrong" * 16,  # Tampered hash
            }
        }

        result = verify_boot_identity(log)
        assert result["valid"] is False
        assert result["self_consistent"] is False

    def test_verify_against_expected(self):
        """Verify can compare against expected hash."""
        measurements = [
            {"id": "M1", "hash": "a" * 64},
            {"id": "M2", "hash": "b" * 64},
        ]
        combined = compute_combined_hash(measurements)

        log = {
            "measurement_log": {
                "measurements": measurements,
                "combined_hash": combined,
            }
        }

        # Matches expected
        result = verify_boot_identity(log, expected_hash=combined)
        assert result["valid"] is True
        assert result["matches_expected"] is True

        # Doesn't match expected
        result = verify_boot_identity(log, expected_hash="different" * 16)
        assert result["valid"] is False
        assert result["matches_expected"] is False

    def test_verify_empty_log(self):
        """Verify handles empty measurement log."""
        log = {"measurement_log": {"measurements": []}}
        result = verify_boot_identity(log)
        assert result["valid"] is False
        assert "No measurements" in result.get("error", "")


class TestNoPrivilegedOperations:
    """Test that boot commands don't execute privileged operations."""

    def test_no_reboot_command(self):
        """Verify no reboot commands are used."""
        from aictrl.commands import boot

        source = open(boot.__file__).read()
        dangerous_commands = [
            "reboot",
            "shutdown",
            "systemctl reboot",
            "init 0",
            "init 6",
            "poweroff",
            "halt",
        ]
        for cmd in dangerous_commands:
            assert cmd not in source, f"Dangerous command '{cmd}' found in boot.py"

    def test_no_kernel_operations(self):
        """Verify no kernel operations are used."""
        from aictrl.commands import boot

        source = open(boot.__file__).read()
        # Note: /dev/ appears in simulated content strings (root=/dev/sda2) which is OK
        # We check for dangerous operations, not simulation content
        kernel_ops = [
            "kexec",
            "modprobe",
            "insmod",
            "rmmod",
            "mknod",
            "os.mknod",
        ]
        for op in kernel_ops:
            assert op not in source, f"Kernel operation '{op}' found in boot.py"

    def test_no_firmware_operations(self):
        """Verify no firmware operations are used."""
        from aictrl.commands import boot

        source = open(boot.__file__).read()
        firmware_ops = [
            "efibootmgr",
            "grub-install",
            "update-grub",
            "/sys/firmware",
        ]
        for op in firmware_ops:
            assert op not in source, f"Firmware operation '{op}' found in boot.py"

    def test_no_sudo_usage(self):
        """Verify no sudo is used."""
        from aictrl.commands import boot

        source = open(boot.__file__).read()
        assert "sudo" not in source, "sudo found in boot.py"

    def test_no_subprocess_dangerous_calls(self):
        """Verify no dangerous subprocess calls."""
        from aictrl.commands import boot

        source = open(boot.__file__).read()
        # Boot module shouldn't use subprocess at all
        assert "subprocess" not in source, "subprocess import found in boot.py"
        assert "run_checked" not in source, "run_checked found in boot.py"


class TestCLIIntegration:
    """Test CLI integration for boot commands."""

    def test_boot_measure_cli(self, mock_sandbox, tmp_path):
        """Test boot measure via CLI."""
        from aictrl.cli import main

        with mock.patch(
            "aictrl.commands.boot.get_sandbox_path",
            return_value=mock_sandbox / "sandbox" / "aios-dev" / "rootfs",
        ):
            result = main(["boot", "measure", "--context", "aios-sandbox"])
            assert result == 0

    @pytest.fixture
    def mock_sandbox(self, tmp_path):
        """Create a mock sandbox structure."""
        rootfs = tmp_path / "sandbox" / "aios-dev" / "rootfs"
        rootfs.mkdir(parents=True)

        etc = rootfs / "etc"
        etc.mkdir()
        (etc / "hostname").write_bytes(b"aios-sandbox")
        (etc / "os-release").write_bytes(b"NAME=AIOS\nVERSION=1.0\n")

        proc = rootfs / "proc"
        proc.mkdir()
        (proc / "cmdline").write_bytes(b"root=/dev/sda2 ro selinux=1")

        return tmp_path

    def test_boot_verify_cli(self, tmp_path):
        """Test boot verify via CLI."""
        from aictrl.cli import main

        # Create a measurement log file
        measurements = [{"id": "M1", "hash": "a" * 64}]
        combined = compute_combined_hash(measurements)
        log = {"measurement_log": {"measurements": measurements, "combined_hash": combined}}

        log_path = tmp_path / "measurement.json"
        with open(log_path, "w") as f:
            json.dump(log, f)

        result = main(["boot", "verify", "--log", str(log_path)])
        assert result == 0


class TestEvidenceIntegration:
    """Test integration with evidence bundles."""

    @pytest.fixture
    def mock_sandbox(self, tmp_path):
        """Create a mock sandbox structure."""
        rootfs = tmp_path / "sandbox" / "aios-dev" / "rootfs"
        rootfs.mkdir(parents=True)

        etc = rootfs / "etc"
        etc.mkdir()
        (etc / "hostname").write_bytes(b"aios-sandbox")
        (etc / "os-release").write_bytes(b"NAME=AIOS\n")

        proc = rootfs / "proc"
        proc.mkdir()
        (proc / "cmdline").write_bytes(b"root=/dev/sda2")

        return tmp_path

    def test_measurement_log_json_serializable(self, mock_sandbox):
        """Verify measurement log can be serialized to JSON."""
        with mock.patch(
            "aictrl.commands.boot.get_sandbox_path",
            return_value=mock_sandbox / "sandbox" / "aios-dev" / "rootfs",
        ):
            result = simulate_boot_measurements(context="aios-sandbox")

            # Should not raise
            json_str = json.dumps(result)
            assert json_str is not None

            # Should round-trip
            parsed = json.loads(json_str)
            assert parsed["simulated"] is True

    def test_measurement_format_matches_spec(self, mock_sandbox):
        """Verify measurement format matches MEASURED_STARTUP.md spec."""
        with mock.patch(
            "aictrl.commands.boot.get_sandbox_path",
            return_value=mock_sandbox / "sandbox" / "aios-dev" / "rootfs",
        ):
            result = simulate_boot_measurements(context="aios-sandbox")

            log = result["measurement_log"]

            # Required fields from spec
            assert "version" in log
            assert "boot_id" in log
            assert "started_at" in log
            assert "completed_at" in log
            assert "measurements" in log
            assert "combined_hash" in log

            # Each measurement should have required fields
            for m in log["measurements"]:
                assert "id" in m
                assert "name" in m
                assert "component" in m
                assert "source" in m
                assert "algorithm" in m
                assert "hash" in m
                assert "timestamp_utc" in m
                assert "stage" in m
