"""Tests for doctor command network checks (Tailscale).

These tests use mocked command runners to test various Tailscale states
without requiring actual Tailscale installation.
"""

import subprocess
import sys
from pathlib import Path
from typing import Any, List, Optional, Union
from unittest import mock

import pytest

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from aictrl.commands.doctor import (
    run_doctor,
    _check_tailscale_cli_available,
    _check_tailscaled_service_running,
    _check_tailscale_authenticated,
    _check_tailscale_interface_present,
    _run_network_checks,
    _truncate_output,
)


class MockCompletedProcess:
    """Mock subprocess.CompletedProcess for testing."""

    def __init__(
        self,
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
    ):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def make_mock_runner(
    responses: dict[str, tuple[int, str, str]],
    default_returncode: int = 1,
    default_stdout: str = "",
) -> callable:
    """Create a mock command runner with predefined responses.

    Args:
        responses: Dict mapping command patterns to (returncode, stdout, stderr) tuples
        default_returncode: Return code for unknown commands
        default_stdout: Default stdout for unknown commands

    Returns:
        Mock command runner function
    """
    def runner(
        command: Union[str, List[str]],
        shell: bool = True,
        timeout: Optional[float] = None,
        **kwargs,
    ) -> MockCompletedProcess:
        # Convert list to string for pattern matching
        if isinstance(command, list):
            cmd_str = " ".join(command)
        else:
            cmd_str = command

        # Find matching response
        for pattern, (rc, stdout, stderr) in responses.items():
            if pattern in cmd_str:
                return MockCompletedProcess(rc, stdout, stderr)

        return MockCompletedProcess(default_returncode, default_stdout, "")

    return runner


class TestTailscaleCliAvailable:
    """Tests for tailscale_cli_available check."""

    def test_tailscale_found(self):
        """PASS when tailscale binary is in PATH."""
        with mock.patch("shutil.which", return_value="/usr/bin/tailscale"):
            result = _check_tailscale_cli_available()

        assert result["id"] == "tailscale_cli_available"
        assert result["status"] == "pass"
        assert "Found at /usr/bin/tailscale" in result["evidence"]

    def test_tailscale_not_found(self):
        """WARN when tailscale binary is not in PATH."""
        with mock.patch("shutil.which", return_value=None):
            result = _check_tailscale_cli_available()

        assert result["id"] == "tailscale_cli_available"
        assert result["status"] == "warn"
        assert "not found in PATH" in result["evidence"]
        assert "Install Tailscale" in result["remediation"]


class TestTailscaledServiceRunning:
    """Tests for tailscaled_service_running check."""

    def test_service_active(self):
        """PASS when tailscaled service is active."""
        runner = make_mock_runner({
            "systemctl is-active tailscaled": (0, "active", ""),
        })

        with mock.patch("shutil.which", return_value="/usr/bin/systemctl"):
            result = _check_tailscaled_service_running(runner=runner)

        assert result["id"] == "tailscaled_service_running"
        assert result["status"] == "pass"
        assert "Service_active=true" in result["evidence"]

    def test_service_inactive(self):
        """WARN when tailscaled service is inactive."""
        runner = make_mock_runner({
            "systemctl is-active tailscaled": (3, "inactive", ""),
        })

        with mock.patch("shutil.which", return_value="/usr/bin/systemctl"):
            result = _check_tailscaled_service_running(runner=runner)

        assert result["id"] == "tailscaled_service_running"
        assert result["status"] == "warn"
        assert "Service_active=false" in result["evidence"]
        assert "systemctl start tailscaled" in result["remediation"]

    def test_systemd_not_available(self):
        """WARN (skip-equivalent) when systemd is not available."""
        with mock.patch("shutil.which", return_value=None):
            result = _check_tailscaled_service_running()

        assert result["id"] == "tailscaled_service_running"
        assert result["status"] == "warn"
        assert "systemd not available" in result["evidence"]

    def test_service_query_error(self):
        """WARN when service query fails with exception."""
        def raise_exception(*args, **kwargs):
            raise subprocess.TimeoutExpired("systemctl", 5)

        with mock.patch("shutil.which", return_value="/usr/bin/systemctl"):
            result = _check_tailscaled_service_running(runner=raise_exception)

        assert result["id"] == "tailscaled_service_running"
        assert result["status"] == "warn"
        assert "Could not query service status" in result["evidence"]


class TestTailscaleAuthenticated:
    """Tests for tailscale_authenticated_or_connected check."""

    def test_connected_with_ip_non_debug(self):
        """PASS when tailscale has IP, non-debug mode redacts IPs."""
        runner = make_mock_runner({
            "tailscale ip -4": (0, "100.64.1.2\n", ""),
        })

        result = _check_tailscale_authenticated(debug=False, runner=runner)

        assert result["id"] == "tailscale_authenticated_or_connected"
        assert result["status"] == "pass"
        assert "Connected=true" in result["evidence"]
        assert "IPs_present=true" in result["evidence"]
        assert "count=1" in result["evidence"]
        # Non-debug: actual IP should NOT be in evidence
        assert "100.64.1.2" not in result["evidence"]

    def test_connected_with_ip_debug(self):
        """PASS when tailscale has IP, debug mode shows IPs."""
        runner = make_mock_runner({
            "tailscale ip -4": (0, "100.64.1.2\n", ""),
        })

        result = _check_tailscale_authenticated(debug=True, runner=runner)

        assert result["id"] == "tailscale_authenticated_or_connected"
        assert result["status"] == "pass"
        assert "Connected=true" in result["evidence"]
        # Debug: actual IP SHOULD be in evidence
        assert "100.64.1.2" in result["evidence"]

    def test_connected_with_multiple_ips(self):
        """PASS when tailscale has multiple IPs."""
        runner = make_mock_runner({
            "tailscale ip -4": (0, "100.64.1.2\n100.64.1.3\n100.64.1.4\n", ""),
        })

        result = _check_tailscale_authenticated(debug=False, runner=runner)

        assert result["status"] == "pass"
        assert "count=3" in result["evidence"]

    def test_not_connected_no_ips(self):
        """WARN when tailscale has no IPs (logged out)."""
        runner = make_mock_runner({
            "tailscale ip -4": (1, "", "not logged in"),
        })

        result = _check_tailscale_authenticated(debug=False, runner=runner)

        assert result["id"] == "tailscale_authenticated_or_connected"
        assert result["status"] == "warn"
        assert "Connected=false" in result["evidence"]
        assert "IPs_present=false" in result["evidence"]
        assert "tailscale up" in result["remediation"]

    def test_tailscale_query_error(self):
        """WARN when tailscale query fails with exception."""
        def raise_exception(*args, **kwargs):
            raise OSError("tailscale not working")

        result = _check_tailscale_authenticated(debug=False, runner=raise_exception)

        assert result["id"] == "tailscale_authenticated_or_connected"
        assert result["status"] == "warn"
        assert "Could not query tailscale status" in result["evidence"]


class TestTailscaleInterfacePresent:
    """Tests for tailscale_interface_present check."""

    def test_interface_present_non_debug(self):
        """PASS when tailscale0 interface exists, non-debug redacts details."""
        runner = make_mock_runner({
            "ip link show tailscale0": (
                0,
                "4: tailscale0: <POINTOPOINT,UP,LOWER_UP> mtu 1280\n"
                "    link/none\n",
                "",
            ),
        })

        with mock.patch("shutil.which", return_value="/sbin/ip"):
            result = _check_tailscale_interface_present(debug=False, runner=runner)

        assert result["id"] == "tailscale_interface_present"
        assert result["status"] == "pass"
        assert "interface_detected=true" in result["evidence"]
        # Non-debug: details should NOT be in evidence
        assert "POINTOPOINT" not in result["evidence"]

    def test_interface_present_debug(self):
        """PASS when tailscale0 interface exists, debug shows details."""
        runner = make_mock_runner({
            "ip link show tailscale0": (
                0,
                "4: tailscale0: <POINTOPOINT,UP,LOWER_UP> mtu 1280\n"
                "    link/none\n",
                "",
            ),
        })

        with mock.patch("shutil.which", return_value="/sbin/ip"):
            result = _check_tailscale_interface_present(debug=True, runner=runner)

        assert result["id"] == "tailscale_interface_present"
        assert result["status"] == "pass"
        assert "interface_detected=true" in result["evidence"]
        # Debug: details SHOULD be in evidence
        assert "details=" in result["evidence"]

    def test_interface_not_present(self):
        """WARN (not FAIL) when interface not visible."""
        runner = make_mock_runner({
            "ip link show tailscale0": (1, "", "Device tailscale0 does not exist"),
        })

        with mock.patch("shutil.which", return_value="/sbin/ip"):
            result = _check_tailscale_interface_present(debug=False, runner=runner)

        assert result["id"] == "tailscale_interface_present"
        assert result["status"] == "warn"  # WARN, not FAIL
        assert "interface_detected=false" in result["evidence"]
        assert "userspace networking" in result["remediation"]

    def test_ip_command_not_available(self):
        """WARN when ip command is not available."""
        with mock.patch("shutil.which", return_value=None):
            result = _check_tailscale_interface_present(debug=False)

        assert result["id"] == "tailscale_interface_present"
        assert result["status"] == "warn"
        assert "ip command not available" in result["evidence"]

    def test_interface_query_error(self):
        """WARN when interface query fails with exception."""
        def raise_exception(*args, **kwargs):
            raise subprocess.TimeoutExpired("ip", 5)

        with mock.patch("shutil.which", return_value="/sbin/ip"):
            result = _check_tailscale_interface_present(debug=False, runner=raise_exception)

        assert result["id"] == "tailscale_interface_present"
        assert result["status"] == "warn"
        assert "interface_detected=unknown" in result["evidence"]


class TestRunNetworkChecks:
    """Tests for _run_network_checks integration."""

    def test_tailscale_missing_only_cli_check(self):
        """When tailscale is missing, only cli_available check runs."""
        with mock.patch("shutil.which", return_value=None):
            checks = _run_network_checks(debug=False)

        # Should only have the CLI available check
        assert len(checks) == 1
        assert checks[0]["id"] == "tailscale_cli_available"
        assert checks[0]["status"] == "warn"

    def test_tailscale_present_all_checks_run(self):
        """When tailscale is present, all 4 checks run."""
        runner = make_mock_runner({
            "systemctl is-active tailscaled": (0, "active", ""),
            "tailscale ip -4": (0, "100.64.1.2\n", ""),
            "ip link show tailscale0": (0, "4: tailscale0: ...", ""),
        })

        def mock_which(cmd):
            return f"/usr/bin/{cmd}"

        with mock.patch("shutil.which", mock_which):
            with mock.patch(
                "aictrl.commands.doctor.shutil.which",
                mock_which
            ):
                checks = _run_network_checks(debug=False, runner=runner)

        # Should have all 4 checks
        assert len(checks) == 4
        check_ids = [c["id"] for c in checks]
        assert "tailscale_cli_available" in check_ids
        assert "tailscaled_service_running" in check_ids
        assert "tailscale_authenticated_or_connected" in check_ids
        assert "tailscale_interface_present" in check_ids


class TestTruncateOutput:
    """Tests for _truncate_output helper."""

    def test_short_output_unchanged(self):
        """Short output is not truncated."""
        output = "line1\nline2\nline3"
        result = _truncate_output(output, max_lines=5)
        assert "truncated" not in result
        assert "line1" in result
        assert "line3" in result

    def test_long_output_truncated(self):
        """Long output is truncated with indicator."""
        output = "line1\nline2\nline3\nline4\nline5\nline6\nline7"
        result = _truncate_output(output, max_lines=3)
        assert "truncated" in result
        assert "line1" in result
        assert "line3" in result
        assert "line7" not in result


class TestDoctorNetworkIntegration:
    """Integration tests for network checks in run_doctor."""

    def test_doctor_includes_network_checks_tailscale_present(self):
        """run_doctor includes network checks when tailscale is present."""
        runner = make_mock_runner({
            "systemctl is-active tailscaled": (0, "active", ""),
            "tailscale ip -4": (0, "100.64.1.2\n", ""),
            "ip link show tailscale0": (0, "4: tailscale0: ...", ""),
        })

        def mock_which(cmd):
            return f"/usr/bin/{cmd}"

        with mock.patch("shutil.which", mock_which):
            with mock.patch(
                "aictrl.commands.doctor.shutil.which",
                mock_which
            ):
                result = run_doctor(
                    context="aios-sandbox",
                    include_invariants=False,
                    debug=False,
                    command_runner=runner,
                )

        check_ids = [c["id"] for c in result["checks"]]
        assert "tailscale_cli_available" in check_ids
        assert "tailscaled_service_running" in check_ids
        assert "tailscale_authenticated_or_connected" in check_ids
        assert "tailscale_interface_present" in check_ids

    def test_doctor_includes_network_checks_tailscale_missing(self):
        """run_doctor includes only cli check when tailscale is missing."""

        def selective_which(cmd):
            if cmd == "tailscale":
                return None
            # Return paths for other commands
            return f"/usr/bin/{cmd}"

        with mock.patch("shutil.which", selective_which):
            with mock.patch(
                "aictrl.commands.doctor.shutil.which",
                selective_which
            ):
                result = run_doctor(
                    context="aios-sandbox",
                    include_invariants=False,
                    debug=False,
                )

        check_ids = [c["id"] for c in result["checks"]]
        # Should have tailscale_cli_available but NOT the others
        assert "tailscale_cli_available" in check_ids

    def test_doctor_respects_debug_flag(self):
        """run_doctor respects debug flag for sensitive output."""
        runner = make_mock_runner({
            "systemctl is-active tailscaled": (0, "active", ""),
            "tailscale ip -4": (0, "100.64.123.45\n", ""),
            "ip link show tailscale0": (0, "4: tailscale0: ...", ""),
        })

        def mock_which(cmd):
            return f"/usr/bin/{cmd}"

        with mock.patch("shutil.which", mock_which):
            with mock.patch(
                "aictrl.commands.doctor.shutil.which",
                mock_which
            ):
                # Non-debug mode
                result_no_debug = run_doctor(
                    context="aios-sandbox",
                    include_invariants=False,
                    debug=False,
                    command_runner=runner,
                )

                # Debug mode
                result_debug = run_doctor(
                    context="aios-sandbox",
                    include_invariants=False,
                    debug=True,
                    command_runner=runner,
                )

        # Find the authenticated check in both results
        auth_check_no_debug = next(
            c for c in result_no_debug["checks"]
            if c["id"] == "tailscale_authenticated_or_connected"
        )
        auth_check_debug = next(
            c for c in result_debug["checks"]
            if c["id"] == "tailscale_authenticated_or_connected"
        )

        # Non-debug should NOT have the actual IP
        assert "100.64.123.45" not in auth_check_no_debug["evidence"]

        # Debug SHOULD have the actual IP
        assert "100.64.123.45" in auth_check_debug["evidence"]

    def test_doctor_network_checks_dont_affect_overall_status(self):
        """Network check warnings don't change overall status to fail."""
        runner = make_mock_runner({
            "systemctl is-active tailscaled": (3, "inactive", ""),
            "tailscale ip -4": (1, "", "not logged in"),
            "ip link show tailscale0": (1, "", "not found"),
        })

        def mock_which(cmd):
            return f"/usr/bin/{cmd}"

        with mock.patch("shutil.which", mock_which):
            with mock.patch(
                "aictrl.commands.doctor.shutil.which",
                mock_which
            ):
                result = run_doctor(
                    context="aios-sandbox",
                    include_invariants=False,
                    debug=False,
                    command_runner=runner,
                )

        # Network checks are WARN, not FAIL
        network_checks = [
            c for c in result["checks"]
            if c["id"].startswith("tailscale")
        ]
        for check in network_checks:
            # All should be warn or pass, never fail
            assert check["status"] in ("pass", "warn")

        # Overall status should be warn (not fail) due to warnings
        assert result["overall_status"] == "warn"


class TestExpectedCheckIds:
    """Test that expected check IDs are present."""

    def test_all_expected_network_checks_registered(self):
        """All expected network check IDs should be present."""
        expected_ids = [
            "tailscale_cli_available",
            "tailscaled_service_running",
            "tailscale_authenticated_or_connected",
            "tailscale_interface_present",
        ]

        runner = make_mock_runner({
            "systemctl is-active tailscaled": (0, "active", ""),
            "tailscale ip -4": (0, "100.64.1.2\n", ""),
            "ip link show tailscale0": (0, "4: tailscale0: ...", ""),
        })

        def mock_which(cmd):
            return f"/usr/bin/{cmd}"

        with mock.patch("shutil.which", mock_which):
            with mock.patch(
                "aictrl.commands.doctor.shutil.which",
                mock_which
            ):
                checks = _run_network_checks(debug=False, runner=runner)

        check_ids = [c["id"] for c in checks]
        for expected_id in expected_ids:
            assert expected_id in check_ids, f"Missing expected check: {expected_id}"
