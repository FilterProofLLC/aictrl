"""Sandbox command for aictrl.

This module provides sandbox status reporting via aictrl CLI.
It integrates with the aios_sandbox module to read sandbox state.

Usage:
    aictrl sandbox status
    aictrl sandbox start
    aictrl sandbox stop

IMPORTANT: The status command NEVER mutates state - it only reads and reports.
"""

import sys
from pathlib import Path
from typing import Optional

from ..util.errors import AICtrlError


# Error codes for sandbox operations
SANDBOX_NOT_FOUND = "AICTRL-6010"
SANDBOX_IMPORT_FAILED = "AICTRL-6011"
SANDBOX_START_FAILED = "AICTRL-6012"
SANDBOX_STOP_FAILED = "AICTRL-6013"


def _get_sandbox():
    """Import and return a Sandbox instance.

    We import lazily to avoid hard dependency on aios_sandbox
    being installed in all environments.

    Returns:
        Sandbox instance

    Raises:
        AICtrlError: If sandbox module not found or import fails
    """
    try:
        from aios_sandbox import Sandbox
        return Sandbox()
    except ImportError:
        # Try to add the aios_sandbox module to path
        # This supports running from repo root without pip install
        repo_root = Path(__file__).resolve().parents[4]
        sandbox_module = repo_root / "tools" / "aios_sandbox"

        if sandbox_module.is_dir():
            sys.path.insert(0, str(sandbox_module))
            try:
                from aios_sandbox import Sandbox
                return Sandbox()
            except ImportError as e:
                raise AICtrlError(
                    code=SANDBOX_IMPORT_FAILED,
                    message="Failed to import aios_sandbox module",
                    cause=str(e),
                    remediation=[
                        "Install the module: pip install -e tools/aios_sandbox",
                        "Or run from repo root with proper PYTHONPATH",
                    ],
                )
        else:
            raise AICtrlError(
                code=SANDBOX_NOT_FOUND,
                message="aios_sandbox module not found",
                cause="Could not locate tools/aios_sandbox directory",
                remediation=[
                    "Ensure you are running from the AIOS repository",
                    "Or install: pip install -e tools/aios_sandbox",
                ],
            )


def get_sandbox_status() -> dict:
    """Get sandbox status without mutating state.

    Returns:
        Dict with sandbox status information

    Raises:
        AICtrlError: If sandbox module not found or status check fails
    """
    sandbox = _get_sandbox()
    return sandbox.status()


def start_sandbox() -> dict:
    """Start the sandbox.

    Returns:
        Dict with start result

    Raises:
        AICtrlError: If sandbox module not found or start fails
    """
    sandbox = _get_sandbox()
    result = sandbox.start()

    if not result.get("success"):
        raise AICtrlError(
            code=SANDBOX_START_FAILED,
            message=result.get("message", "Failed to start sandbox"),
            cause="Sandbox start returned failure",
            remediation=[
                "Check sandbox state: bbail sandbox status",
                "Reset sandbox if needed: sandbox.reset() via Python",
            ],
        )

    return result


def stop_sandbox() -> dict:
    """Stop the sandbox.

    Returns:
        Dict with stop result

    Raises:
        AICtrlError: If sandbox module not found or stop fails
    """
    sandbox = _get_sandbox()
    result = sandbox.stop()

    if not result.get("success"):
        raise AICtrlError(
            code=SANDBOX_STOP_FAILED,
            message=result.get("message", "Failed to stop sandbox"),
            cause="Sandbox stop returned failure",
            remediation=[
                "Check sandbox state: bbail sandbox status",
                "The sandbox may already be stopped",
            ],
        )

    return result
