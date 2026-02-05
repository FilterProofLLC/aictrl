"""Location enforcement for aictrl (Phase 15).

Detects whether aictrl is running from the canonical working copy
or a non-canonical location (submodule, alternate clone, etc.).

CRITICAL: This module supports flag-gated enforcement.
- When AICTRL_ENFORCE_LOCATION is unset or "0": warn-only (Phase 14 behavior)
- When AICTRL_ENFORCE_LOCATION is "1": deny on violation (Phase 15 behavior)

Enforcement NEVER blocks when:
- Flag is off (default)
- CI environment is detected

All failures degrade gracefully to warnings.
"""

import os
import subprocess
from typing import Any, Optional

from .invariants import ExecutionContext, detect_execution_context

# Canonical location for standalone aictrl development
CANONICAL_PATH = os.path.expanduser("~/work/aictrl")

# Environment variable for enforcement
ENFORCE_LOCATION_VAR = "AICTRL_ENFORCE_LOCATION"

# Error codes (Phase 15, 7xxx range)
LOCATION_NON_CANONICAL = "AICTRL-7001"
LOCATION_SUBMODULE_DETECTED = "AICTRL-7002"
LOCATION_REMOTE_MISMATCH = "AICTRL-7003"


def is_enforcement_enabled() -> bool:
    """Check if location enforcement is enabled.

    Returns:
        True if AICTRL_ENFORCE_LOCATION is set to "1" or "true".
    """
    val = os.environ.get(ENFORCE_LOCATION_VAR, "").lower()
    return val in ("1", "true")


def is_ci_environment() -> bool:
    """Check if running in a CI environment.

    CI environments are exempt from location enforcement.

    Returns:
        True if CI environment detected.
    """
    ctx = detect_execution_context()
    return ctx == ExecutionContext.AIOS_CI


def _find_git_root() -> Optional[str]:
    """Find git repository root from current directory.

    Returns:
        Repository root path, or None if not in a git repo.
    """
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
    except Exception:
        pass
    return None


def _is_submodule(git_root: str) -> bool:
    """Check if the git root is a submodule.

    A submodule has a .git FILE (not directory) containing a gitdir: pointer.

    Args:
        git_root: Path to the git repository root.

    Returns:
        True if this is a submodule.
    """
    git_path = os.path.join(git_root, ".git")
    return os.path.isfile(git_path)


def _get_parent_repo(git_root: str) -> Optional[str]:
    """Get parent repository path for a submodule.

    Args:
        git_root: Path to the submodule root.

    Returns:
        Parent repository root path, or None.
    """
    git_file = os.path.join(git_root, ".git")
    try:
        if not os.path.isfile(git_file):
            return None
        with open(git_file, "r") as f:
            content = f.read().strip()
        if not content.startswith("gitdir:"):
            return None
        gitdir_rel = content[len("gitdir:"):].strip()
        gitdir_abs = os.path.realpath(os.path.join(git_root, gitdir_rel))
        # The gitdir is inside parent_repo/.git/modules/...
        parts = gitdir_abs.split(os.sep)
        if ".git" in parts:
            git_idx = parts.index(".git")
            parent = os.sep.join(parts[:git_idx])
            return parent if parent else None
    except Exception:
        pass
    return None


def detect_location_context() -> dict[str, Any]:
    """Detect location context for observability and enforcement.

    This function NEVER raises exceptions. All errors are captured
    in the returned dictionary.

    Returns:
        Dictionary with location context fields:
        - canonical_path: The expected canonical path
        - actual_path: The resolved current path (git root or cwd)
        - is_canonical: Whether running from canonical location
        - is_submodule: Whether running inside a git submodule
        - parent_repo: Parent repository path (if submodule)
        - detection_error: Error string if detection failed, else None
    """
    result = {
        "canonical_path": CANONICAL_PATH,
        "actual_path": None,
        "is_canonical": False,
        "is_submodule": False,
        "parent_repo": None,
        "detection_error": None,
    }

    try:
        # Find git root, fall back to cwd
        git_root = _find_git_root()
        actual = os.path.realpath(git_root or os.getcwd())
        result["actual_path"] = actual

        canonical_resolved = os.path.realpath(CANONICAL_PATH)
        result["is_canonical"] = actual == canonical_resolved

        # Check for submodule
        if git_root:
            result["is_submodule"] = _is_submodule(git_root)
            if result["is_submodule"]:
                result["parent_repo"] = _get_parent_repo(git_root)

    except Exception as e:
        result["detection_error"] = str(e)

    return result


def evaluate_location_policy() -> dict[str, Any]:
    """Evaluate location policy for enforcement.

    This is the main entry point for Phase 15 enforcement.

    Returns:
        Dictionary with:
        - enforce: Whether enforcement is enabled
        - ci_exempt: Whether CI exemption applies
        - context: Location context from detect_location_context()
        - warnings: List of observability warnings (Phase 14 format)
        - denial: Denial dict if enforcement triggers, else None
                  Contains: code, message, hint
    """
    enforce = is_enforcement_enabled()
    ci_exempt = is_ci_environment()
    context = detect_location_context()

    warnings = []
    denial = None

    # Build warnings (always, regardless of enforcement)
    if context.get("detection_error"):
        warnings.append({
            "source": "observability",
            "message": "Location detection failed: " + context["detection_error"],
            "artifact": "location",
        })
    elif not context.get("is_canonical"):
        warnings.append({
            "source": "observability",
            "message": (
                "Non-canonical working location: "
                + str(context.get("actual_path", "unknown"))
                + " (expected: "
                + str(context.get("canonical_path", "unknown"))
                + ")"
            ),
            "artifact": "location",
            "code": LOCATION_NON_CANONICAL,
        })

    if context.get("is_submodule"):
        parent = context.get("parent_repo", "unknown")
        warnings.append({
            "source": "observability",
            "message": "Running as git submodule of: " + str(parent),
            "artifact": "location",
            "code": LOCATION_SUBMODULE_DETECTED,
        })

    # Enforcement logic (only when flag ON and not CI)
    if enforce and not ci_exempt:
        # Check for submodule first (more specific)
        if context.get("is_submodule"):
            parent = context.get("parent_repo", "unknown")
            denial = {
                "code": LOCATION_SUBMODULE_DETECTED,
                "message": "Execution from git submodule is not permitted",
                "hint": (
                    "Run from the canonical standalone clone at "
                    + str(context.get("canonical_path", CANONICAL_PATH))
                ),
                "parent_repo": parent,
                "actual_path": context.get("actual_path"),
            }
        # Then check for non-canonical path
        elif not context.get("is_canonical") and not context.get("detection_error"):
            denial = {
                "code": LOCATION_NON_CANONICAL,
                "message": "Non-canonical working location detected",
                "hint": (
                    "Run from the canonical location: "
                    + str(context.get("canonical_path", CANONICAL_PATH))
                ),
                "actual_path": context.get("actual_path"),
                "expected_path": context.get("canonical_path"),
            }

    return {
        "enforce": enforce,
        "ci_exempt": ci_exempt,
        "context": context,
        "warnings": warnings,
        "denial": denial,
    }
