"""Host Safety Guard for aictrl.

This module provides a safety layer to prevent destructive operations on the
development host. It is designed to protect against accidental or malicious
execution of commands that could damage the host system.

IMPORTANT: Host safety is ENABLED BY DEFAULT. This guard is NON-NEGOTIABLE.
All external command execution MUST go through run_checked().

To disable host safety (ONLY on target systems):
    1. Set environment variable: AICTRL_HOST_SAFETY=0
    2. AND pass --i-accept-risk flag on the command line

Both conditions must be met to disable safety. This prevents accidental disabling.
"""

import os
import re
import subprocess
from typing import List, Optional, Tuple, Union

from .errors import AICtrlError

# Error codes for host safety
HOST_SAFETY_VIOLATION = "AICTRL-5010"
HOST_SAFETY_OVERRIDE_INCOMPLETE = "AICTRL-5011"

# Module-level flag to track if --i-accept-risk was passed
_risk_accepted = False

# Denylist of destructive command patterns
# Each entry is (pattern, description) for clear error messages
DENYLIST_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # Reboot/shutdown operations
    (re.compile(r"^\s*(sudo\s+)?(reboot|shutdown|poweroff|halt|init\s+[06])"),
     "system reboot/shutdown"),
    (re.compile(r"^\s*(sudo\s+)?systemctl\s+(reboot|poweroff|halt)"),
     "systemctl power control"),

    # Package managers (could modify host packages)
    (re.compile(r"^\s*(sudo\s+)?(apt|apt-get|dpkg)\s+"),
     "Debian package manager"),
    (re.compile(r"^\s*(sudo\s+)?(yum|dnf|rpm)\s+"),
     "RPM package manager"),
    (re.compile(r"^\s*(sudo\s+)?(pacman|yaourt|yay)\s+"),
     "Arch package manager"),
    (re.compile(r"^\s*(sudo\s+)?pip\s+install\s+--system"),
     "system-wide pip install"),
    (re.compile(r"^\s*(sudo\s+)?npm\s+install\s+-g"),
     "global npm install"),

    # Kernel/bootloader modifications
    (re.compile(r"^\s*(sudo\s+)?grub-"),
     "GRUB bootloader modification"),
    (re.compile(r"^\s*(sudo\s+)?update-grub"),
     "GRUB update"),
    (re.compile(r"^\s*(sudo\s+)?dracut"),
     "initramfs generation"),
    (re.compile(r"^\s*(sudo\s+)?mkinitcpio"),
     "initramfs generation"),
    (re.compile(r"^\s*(sudo\s+)?modprobe\s+(-r\s+)?"),
     "kernel module loading/unloading"),
    (re.compile(r"^\s*(sudo\s+)?insmod"),
     "kernel module insertion"),
    (re.compile(r"^\s*(sudo\s+)?rmmod"),
     "kernel module removal"),

    # Disk/partition tooling
    (re.compile(r"^\s*(sudo\s+)?(fdisk|gdisk|parted|cfdisk|sfdisk)"),
     "disk partitioning"),
    (re.compile(r"^\s*(sudo\s+)?mkfs"),
     "filesystem creation"),
    (re.compile(r"^\s*(sudo\s+)?dd\s+"),
     "raw disk write"),
    (re.compile(r"^\s*(sudo\s+)?mount\s+"),
     "filesystem mount"),
    (re.compile(r"^\s*(sudo\s+)?umount\s+"),
     "filesystem unmount"),
    (re.compile(r"^\s*(sudo\s+)?lvchange"),
     "LVM modification"),
    (re.compile(r"^\s*(sudo\s+)?vgchange"),
     "LVM volume group modification"),
    (re.compile(r"^\s*(sudo\s+)?pvcreate"),
     "LVM physical volume creation"),
    (re.compile(r"^\s*(sudo\s+)?lvcreate"),
     "LVM logical volume creation"),

    # Service mutations
    (re.compile(r"^\s*(sudo\s+)?systemctl\s+(start|stop|restart|enable|disable|mask|unmask)\s+"),
     "systemd service control"),
    (re.compile(r"^\s*(sudo\s+)?service\s+\S+\s+(start|stop|restart)"),
     "SysV service control"),

    # Dangerous file operations
    (re.compile(r"^\s*(sudo\s+)?rm\s+(-rf?|--recursive)\s+/"),
     "recursive deletion from root"),
    (re.compile(r"^\s*(sudo\s+)?chmod\s+.*\s+/"),
     "permission change on system paths"),
    (re.compile(r"^\s*(sudo\s+)?chown\s+.*\s+/"),
     "ownership change on system paths"),

    # Network configuration
    (re.compile(r"^\s*(sudo\s+)?iptables\s+"),
     "firewall rule modification"),
    (re.compile(r"^\s*(sudo\s+)?nft\s+"),
     "nftables rule modification"),
    (re.compile(r"^\s*(sudo\s+)?ip\s+(link|addr|route)\s+(add|del|set)"),
     "network interface modification"),

    # User/group modifications
    (re.compile(r"^\s*(sudo\s+)?(useradd|userdel|usermod)"),
     "user account modification"),
    (re.compile(r"^\s*(sudo\s+)?(groupadd|groupdel|groupmod)"),
     "group modification"),
    (re.compile(r"^\s*(sudo\s+)?passwd"),
     "password change"),

    # Catch-all for sudo with dangerous patterns
    (re.compile(r"^\s*sudo\s+.*>\s*/etc/"),
     "write to /etc via sudo"),
    (re.compile(r"^\s*sudo\s+tee\s+/etc/"),
     "write to /etc via sudo tee"),
]


def set_risk_accepted(accepted: bool) -> None:
    """Set the risk acceptance flag (called from CLI when --i-accept-risk is passed).

    Args:
        accepted: True if user explicitly accepted risk via CLI flag
    """
    global _risk_accepted
    _risk_accepted = accepted


def is_risk_accepted() -> bool:
    """Check if the --i-accept-risk CLI flag was passed.

    Returns:
        True if CLI flag was passed
    """
    return _risk_accepted


def is_host_safety_enabled() -> bool:
    """Check if host safety mode is enabled.

    Host safety is ENABLED BY DEFAULT. To disable, BOTH conditions must be met:
    1. Environment variable AICTRL_HOST_SAFETY must be "0" or "false"
    2. CLI flag --i-accept-risk must be passed

    Returns:
        True if host safety is enabled (default), False only if explicitly disabled
    """
    env_value = os.environ.get("AICTRL_HOST_SAFETY", "").lower()
    env_wants_disable = env_value in ("0", "false", "no", "off")

    # If env doesn't want to disable, safety is enabled
    if not env_wants_disable:
        return True

    # Env wants to disable - check if CLI flag was also passed
    if not _risk_accepted:
        # Env says disable but no CLI flag - this is an incomplete override
        # Safety remains enabled
        return True

    # Both conditions met - safety can be disabled
    return False


def check_override_validity() -> None:
    """Check if an attempted override is valid.

    Raises AICtrlError if AICTRL_HOST_SAFETY=0 but --i-accept-risk was not passed.
    Call this early in CLI processing to catch invalid override attempts.

    Raises:
        AICtrlError: If override is incomplete (env var without CLI flag)
    """
    env_value = os.environ.get("AICTRL_HOST_SAFETY", "").lower()
    env_wants_disable = env_value in ("0", "false", "no", "off")

    if env_wants_disable and not _risk_accepted:
        raise AICtrlError(
            code=HOST_SAFETY_OVERRIDE_INCOMPLETE,
            message="Incomplete host safety override",
            cause="AICTRL_HOST_SAFETY=0 requires --i-accept-risk flag",
            remediation=[
                "To disable host safety, you must BOTH:",
                "  1. Set AICTRL_HOST_SAFETY=0",
                "  2. Pass --i-accept-risk flag",
                "This prevents accidental disabling of safety guards.",
                "Only disable on target systems, never on dev hosts.",
            ],
        )


def check_command_safety(command: str) -> Optional[Tuple[str, str]]:
    """Check if a command matches any denylist patterns.

    Args:
        command: The command string to check

    Returns:
        None if command is safe, or (pattern_description, matched_text) if denied
    """
    for pattern, description in DENYLIST_PATTERNS:
        match = pattern.search(command)
        if match:
            return (description, match.group(0).strip())
    return None


def run_checked(
    command: Union[str, List[str]],
    shell: bool = True,
    capture_output: bool = True,
    text: bool = True,
    timeout: Optional[float] = None,
    check: bool = False,
    **kwargs
) -> subprocess.CompletedProcess:
    """Execute a command with host safety checks.

    This is the ONLY approved way to run external commands. It checks commands
    against the denylist before execution when host safety is enabled (default).

    Args:
        command: Command to execute (string or list)
        shell: Whether to execute through shell (default True)
        capture_output: Capture stdout/stderr (default True)
        text: Return output as text not bytes (default True)
        timeout: Timeout in seconds
        check: Raise CalledProcessError on non-zero exit
        **kwargs: Additional arguments passed to subprocess.run

    Returns:
        subprocess.CompletedProcess result

    Raises:
        BbailError: If command matches denylist and host safety is enabled
        subprocess.CalledProcessError: If check=True and command fails
        subprocess.TimeoutExpired: If timeout is exceeded
    """
    # Convert list commands to string for pattern matching
    if isinstance(command, list):
        cmd_str = " ".join(command)
    else:
        cmd_str = command

    # Check against denylist if host safety is enabled
    if is_host_safety_enabled():
        violation = check_command_safety(cmd_str)
        if violation:
            description, matched = violation
            raise AICtrlError(
                code=HOST_SAFETY_VIOLATION,
                message=f"Host safety violation: {description}",
                cause=f"Command matched denylist pattern: '{matched}'",
                remediation=[
                    "This command is blocked by host safety (enabled by default)",
                    "To disable (ONLY on target systems):",
                    "  AICTRL_HOST_SAFETY=0 aictrl --i-accept-risk ...",
                    "Or use an alternative approach that doesn't require this operation"
                ]
            )

    # Execute the command
    return subprocess.run(
        command,
        shell=shell,
        capture_output=capture_output,
        text=text,
        timeout=timeout,
        check=check,
        **kwargs
    )


def get_denylist_summary() -> List[dict]:
    """Get a summary of all denylist patterns.

    Returns:
        List of dicts with 'category' and 'description' for each pattern
    """
    return [
        {"pattern": pattern.pattern, "description": description}
        for pattern, description in DENYLIST_PATTERNS
    ]


def get_safety_status() -> dict:
    """Get current host safety status for diagnostics.

    Returns:
        Dict with safety status information
    """
    env_value = os.environ.get("AICTRL_HOST_SAFETY", "")
    return {
        "host_safety_enabled": is_host_safety_enabled(),
        "env_var": env_value or "(not set, defaults to enabled)",
        "risk_flag_passed": _risk_accepted,
        "denylist_pattern_count": len(DENYLIST_PATTERNS),
    }
