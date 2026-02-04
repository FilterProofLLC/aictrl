"""bbail doctor command - system health diagnostics."""

import os
import re
import shutil
import sys
from datetime import datetime, timezone
from typing import Any, Callable, Literal, Optional

from ..util.safe_exec import run_checked, get_safety_status
from ..util.invariants import (
    ExecutionContext,
    detect_execution_context,
    get_context_name,
    get_context_info,
    run_all_invariant_checks,
)


# Type for command runner (allows injection for testing)
CommandRunner = Callable[..., Any]


CheckStatus = Literal["pass", "warn", "fail"]


def run_doctor(
    context: Optional[str] = None,
    include_invariants: bool = True,
    debug: bool = False,
    command_runner: Optional[CommandRunner] = None,
) -> dict[str, Any]:
    """Run all health checks.

    Args:
        context: Execution context override (aios-base, aios-dev, aios-ci, aios-sandbox)
        include_invariants: Whether to include security invariant checks
        debug: If True, include sensitive details (IPs, hostnames) in evidence
        command_runner: Optional command runner for testing (defaults to run_checked)

    Returns:
        Dictionary matching doctor.schema.json.
    """
    timestamp_utc = datetime.now(timezone.utc).isoformat()
    runner = command_runner or run_checked

    # Detect or parse execution context
    if context:
        context_map = {
            "aios-base": ExecutionContext.AIOS_BASE,
            "aios-dev": ExecutionContext.AIOS_DEV,
            "aios-ci": ExecutionContext.AIOS_CI,
            "aios-sandbox": ExecutionContext.AIOS_SANDBOX,
        }
        exec_context = context_map.get(context.lower(), ExecutionContext.UNKNOWN)
    else:
        exec_context = detect_execution_context()

    checks = [
        _check_python_version(),
        _check_disk_space(),
        _check_ssh_available(),
        _check_git_available(),
        _check_time_sync(),
        _check_host_safety(),
    ]

    # Add network checks (Tailscale)
    network_checks = _run_network_checks(debug=debug, runner=runner)
    checks.extend(network_checks)

    # Calculate summary for basic checks
    passed = sum(1 for c in checks if c["status"] == "pass")
    warned = sum(1 for c in checks if c["status"] == "warn")
    failed = sum(1 for c in checks if c["status"] == "fail")

    overall = "pass"
    if failed > 0:
        overall = "fail"
    elif warned > 0:
        overall = "warn"

    result = {
        "timestamp_utc": timestamp_utc,
        "execution_context": get_context_name(exec_context),
        "overall_status": overall,
        "summary": {
            "passed": passed,
            "warned": warned,
            "failed": failed,
            "total": len(checks),
        },
        "checks": checks,
    }

    # Add invariant checks if requested
    if include_invariants:
        invariant_results = run_all_invariant_checks(exec_context)
        result["invariants"] = invariant_results

        # Update overall status if invariants fail
        if invariant_results["overall_status"] == "fail":
            result["overall_status"] = "fail"
        elif invariant_results["overall_status"] == "warn" and result["overall_status"] == "pass":
            result["overall_status"] = "warn"

    return result


def _make_check(
    check_id: str,
    description: str,
    status: CheckStatus,
    evidence: str,
    remediation: str = None,
) -> dict[str, Any]:
    """Create a check result dictionary."""
    return {
        "id": check_id,
        "description": description,
        "status": status,
        "evidence": evidence,
        "remediation": remediation,
    }


def _check_python_version() -> dict[str, Any]:
    """Check if Python version is >= 3.10."""
    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"

    if version >= (3, 10):
        return _make_check(
            "python_version_ok",
            "Python version is 3.10 or higher",
            "pass",
            f"Python {version_str}",
        )
    else:
        return _make_check(
            "python_version_ok",
            "Python version is 3.10 or higher",
            "fail",
            f"Python {version_str}",
            "Upgrade to Python 3.10 or higher",
        )


def _check_disk_space() -> dict[str, Any]:
    """Check if there is adequate disk space."""
    try:
        # Check the root or current directory
        path = "/"
        if not os.path.exists(path):
            path = "."

        stat = os.statvfs(path)
        free_bytes = stat.f_bavail * stat.f_frsize
        total_bytes = stat.f_blocks * stat.f_frsize
        free_gb = free_bytes / (1024**3)
        total_gb = total_bytes / (1024**3)
        pct_free = (free_bytes / total_bytes * 100) if total_bytes > 0 else 0

        evidence = f"{free_gb:.1f}GB free of {total_gb:.1f}GB ({pct_free:.1f}% free)"

        if free_gb < 1:
            return _make_check(
                "disk_space_ok",
                "Adequate disk space available",
                "fail",
                evidence,
                "Free up disk space (less than 1GB available)",
            )
        elif free_gb < 5:
            return _make_check(
                "disk_space_ok",
                "Adequate disk space available",
                "warn",
                evidence,
                "Consider freeing up disk space (less than 5GB available)",
            )
        else:
            return _make_check(
                "disk_space_ok",
                "Adequate disk space available",
                "pass",
                evidence,
            )
    except Exception as e:
        return _make_check(
            "disk_space_ok",
            "Adequate disk space available",
            "warn",
            f"Could not determine disk space: {e}",
            "Check disk space manually with 'df -h'",
        )


def _check_ssh_available() -> dict[str, Any]:
    """Check if SSH client is available."""
    ssh_path = shutil.which("ssh")

    if ssh_path:
        return _make_check(
            "ssh_available",
            "SSH client is available",
            "pass",
            f"Found at {ssh_path}",
        )
    else:
        return _make_check(
            "ssh_available",
            "SSH client is available",
            "fail",
            "ssh command not found in PATH",
            "Install OpenSSH client (apt install openssh-client or equivalent)",
        )


def _check_git_available() -> dict[str, Any]:
    """Check if git is available."""
    git_path = shutil.which("git")

    if git_path:
        return _make_check(
            "git_available",
            "Git is available",
            "pass",
            f"Found at {git_path}",
        )
    else:
        return _make_check(
            "git_available",
            "Git is available",
            "fail",
            "git command not found in PATH",
            "Install git (apt install git or equivalent)",
        )


def _check_time_sync() -> dict[str, Any]:
    """Check time synchronization status (best effort)."""
    # Try timedatectl on Linux
    timedatectl_path = shutil.which("timedatectl")

    if timedatectl_path:
        try:
            result = run_checked(
                ["timedatectl", "show", "--property=NTPSynchronized"],
                shell=False,
                timeout=5,
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                if "NTPSynchronized=yes" in output:
                    return _make_check(
                        "time_sync_status",
                        "System time is synchronized",
                        "pass",
                        "NTP synchronized",
                    )
                elif "NTPSynchronized=no" in output:
                    return _make_check(
                        "time_sync_status",
                        "System time is synchronized",
                        "warn",
                        "NTP not synchronized",
                        "Enable time synchronization with 'timedatectl set-ntp true'",
                    )
        except Exception:
            pass

    # Fallback: can't determine
    return _make_check(
        "time_sync_status",
        "System time is synchronized",
        "warn",
        "Could not determine NTP status",
        "Verify time synchronization manually",
    )


def _check_host_safety() -> dict[str, Any]:
    """Check host safety guard status."""
    safety = get_safety_status()

    if safety["host_safety_enabled"]:
        return _make_check(
            "host_safety_enabled",
            "Host safety guard is active",
            "pass",
            f"Enabled (env: {safety['env_var']}, denylist: {safety['denylist_pattern_count']} patterns)",
        )
    else:
        return _make_check(
            "host_safety_enabled",
            "Host safety guard is active",
            "warn",
            f"DISABLED (env: {safety['env_var']}, risk_flag: {safety['risk_flag_passed']})",
            "Host safety should be enabled on development hosts",
        )


# =============================================================================
# Network Checks (Tailscale)
# =============================================================================
# These checks are strictly observational (read-only).
# No configuration changes, no `tailscale up`, no route/ACL edits.
# Sensitive values (IPs, hostnames, emails) are redacted unless debug mode.
# =============================================================================


def _run_network_checks(
    debug: bool = False,
    runner: Optional[CommandRunner] = None,
) -> list[dict[str, Any]]:
    """Run all network checks (Tailscale).

    Args:
        debug: If True, include sensitive details in evidence
        runner: Command runner (defaults to run_checked)

    Returns:
        List of check result dictionaries
    """
    runner = runner or run_checked
    checks = []

    # Check 1: tailscale CLI available
    checks.append(_check_tailscale_cli_available())

    # Only proceed with other Tailscale checks if CLI is available
    tailscale_path = shutil.which("tailscale")
    if tailscale_path:
        # Check 2: tailscaled service running (systemd)
        checks.append(_check_tailscaled_service_running(runner=runner))

        # Check 3: tailscale authenticated/connected
        checks.append(_check_tailscale_authenticated(debug=debug, runner=runner))

        # Check 4: tailscale interface present
        checks.append(_check_tailscale_interface_present(debug=debug, runner=runner))

    return checks


def _check_tailscale_cli_available() -> dict[str, Any]:
    """Check if tailscale CLI binary is available in PATH.

    READ-ONLY: Only checks for binary existence via shutil.which().
    """
    tailscale_path = shutil.which("tailscale")

    if tailscale_path:
        return _make_check(
            "tailscale_cli_available",
            "Tailscale CLI is available",
            "pass",
            f"Found at {tailscale_path}",
        )
    else:
        return _make_check(
            "tailscale_cli_available",
            "Tailscale CLI is available",
            "warn",
            "tailscale command not found in PATH",
            "Install Tailscale: https://tailscale.com/download",
        )


def _check_tailscaled_service_running(
    runner: Optional[CommandRunner] = None,
) -> dict[str, Any]:
    """Check if tailscaled systemd service is running.

    READ-ONLY: Only queries systemd status via `systemctl is-active`.
    SKIP: Returns skip-equivalent warning if systemd is not available.
    """
    runner = runner or run_checked

    # Check if systemctl is available
    systemctl_path = shutil.which("systemctl")
    if not systemctl_path:
        return _make_check(
            "tailscaled_service_running",
            "Tailscaled service is running",
            "warn",
            "systemd not available (cannot check service status)",
            "Manual verification required on non-systemd systems",
        )

    try:
        # Query service status (read-only)
        result = runner(
            ["systemctl", "is-active", "tailscaled"],
            shell=False,
            timeout=5,
        )

        output = result.stdout.strip() if result.stdout else ""

        if result.returncode == 0 and output == "active":
            return _make_check(
                "tailscaled_service_running",
                "Tailscaled service is running",
                "pass",
                "Service_active=true",
            )
        else:
            # Service exists but not active, or other status
            return _make_check(
                "tailscaled_service_running",
                "Tailscaled service is running",
                "warn",
                f"Service_active=false (status: {output or 'unknown'})",
                "Start tailscaled: sudo systemctl start tailscaled",
            )

    except Exception as e:
        return _make_check(
            "tailscaled_service_running",
            "Tailscaled service is running",
            "warn",
            f"Could not query service status: {type(e).__name__}",
            "Verify tailscaled status manually",
        )


def _check_tailscale_authenticated(
    debug: bool = False,
    runner: Optional[CommandRunner] = None,
) -> dict[str, Any]:
    """Check if Tailscale is authenticated and has IP addresses.

    READ-ONLY: Only queries `tailscale ip -4` to check for assigned IPs.
    Sensitive data (actual IPs) is redacted unless debug=True.
    """
    runner = runner or run_checked

    try:
        # Query tailscale IPs (read-only)
        result = runner(
            ["tailscale", "ip", "-4"],
            shell=False,
            timeout=10,
        )

        output = result.stdout.strip() if result.stdout else ""
        lines = [l.strip() for l in output.split("\n") if l.strip()]

        if result.returncode == 0 and lines:
            # Has at least one IP - authenticated and connected
            ip_count = len(lines)

            if debug:
                # Debug mode: show first IP (truncate to max 2 for safety)
                shown_ips = lines[:2]
                evidence = f"Connected=true, IPs_present=true, count={ip_count}, ips={shown_ips}"
            else:
                # Non-debug: only boolean/summary evidence
                evidence = f"Connected=true, IPs_present=true, count={ip_count}"

            return _make_check(
                "tailscale_authenticated_or_connected",
                "Tailscale is authenticated and connected",
                "pass",
                evidence,
            )
        else:
            # No IPs - likely logged out or not connected
            return _make_check(
                "tailscale_authenticated_or_connected",
                "Tailscale is authenticated and connected",
                "warn",
                "Connected=false, IPs_present=false",
                "Authenticate with: tailscale up",
            )

    except Exception as e:
        return _make_check(
            "tailscale_authenticated_or_connected",
            "Tailscale is authenticated and connected",
            "warn",
            f"Could not query tailscale status: {type(e).__name__}",
            "Verify tailscale authentication manually",
        )


def _check_tailscale_interface_present(
    debug: bool = False,
    runner: Optional[CommandRunner] = None,
) -> dict[str, Any]:
    """Check if tailscale0 network interface is present.

    READ-ONLY: Only queries `ip link show tailscale0`.
    Best-effort check - some environments may not have visible interface.
    """
    runner = runner or run_checked

    # Check if ip command is available
    ip_path = shutil.which("ip")
    if not ip_path:
        return _make_check(
            "tailscale_interface_present",
            "Tailscale network interface is present",
            "warn",
            "ip command not available (cannot check interface)",
            "Manual verification required",
        )

    try:
        # Query interface (read-only)
        result = runner(
            ["ip", "link", "show", "tailscale0"],
            shell=False,
            timeout=5,
        )

        output = result.stdout.strip() if result.stdout else ""

        if result.returncode == 0 and "tailscale0" in output:
            # Interface exists
            if debug:
                # Debug mode: show first few lines of output (truncated)
                truncated = _truncate_output(output, max_lines=3)
                evidence = f"interface_detected=true, details={truncated}"
            else:
                evidence = "interface_detected=true"

            return _make_check(
                "tailscale_interface_present",
                "Tailscale network interface is present",
                "pass",
                evidence,
            )
        else:
            # Interface not found - this is a warning, not failure
            # (userspace networking or other configs may not show interface)
            return _make_check(
                "tailscale_interface_present",
                "Tailscale network interface is present",
                "warn",
                "interface_detected=false",
                "Interface may not be visible in userspace networking mode",
            )

    except Exception as e:
        return _make_check(
            "tailscale_interface_present",
            "Tailscale network interface is present",
            "warn",
            f"interface_detected=unknown ({type(e).__name__})",
            "Verify interface manually with: ip link show",
        )


def _truncate_output(output: str, max_lines: int = 5) -> str:
    """Truncate output to a maximum number of lines for debug mode.

    Args:
        output: The output string to truncate
        max_lines: Maximum number of lines to include

    Returns:
        Truncated string with indicator if truncated
    """
    lines = output.split("\n")
    if len(lines) <= max_lines:
        # Escape for JSON embedding - replace newlines with semicolons
        return output.replace("\n", "; ").strip()

    truncated = lines[:max_lines]
    result = "; ".join(l.strip() for l in truncated)
    return f"{result} ... (truncated)"
