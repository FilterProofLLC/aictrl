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
LOCATION_DETACHED_HEAD = "AICTRL-7004"
LOCATION_SYMLINK_DETECTED = "AICTRL-7005"

# Canonical remote URL patterns (FilterProofLLC/aictrl)
CANONICAL_REMOTE_PATTERNS = (
    "https://github.com/FilterProofLLC/aictrl",
    "https://github.com/FilterProofLLC/aictrl.git",
    "git@github.com:FilterProofLLC/aictrl",
    "git@github.com:FilterProofLLC/aictrl.git",
    "ssh://git@github.com/FilterProofLLC/aictrl",
    "ssh://git@github.com/FilterProofLLC/aictrl.git",
)


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


def _get_origin_remote_url() -> Optional[str]:
    """Get the URL of the 'origin' remote.

    Returns:
        The origin remote URL, or None if not available.
    """
    try:
        proc = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
    except Exception:
        pass
    return None


def _normalize_remote_url(url: str) -> str:
    """Normalize a git remote URL for comparison.

    Extracts the owner/repo part from various GitHub URL formats and
    returns it in a canonical form for comparison.

    Handles:
    - https://github.com/owner/repo.git
    - git@github.com:owner/repo.git
    - ssh://git@github.com/owner/repo.git

    Args:
        url: The remote URL to normalize.

    Returns:
        Normalized string in form "github.com/owner/repo" (lowercase).
    """
    if not url:
        return ""
    normalized = url.strip().lower()
    # Remove trailing .git
    if normalized.endswith(".git"):
        normalized = normalized[:-4]

    # Extract owner/repo from different formats
    # HTTPS: https://github.com/owner/repo
    if normalized.startswith("https://github.com/"):
        path = normalized[len("https://github.com/"):]
        return "github.com/" + path

    # SSH with protocol: ssh://git@github.com/owner/repo
    if normalized.startswith("ssh://git@github.com/"):
        path = normalized[len("ssh://git@github.com/"):]
        return "github.com/" + path

    # SSH shorthand: git@github.com:owner/repo
    if normalized.startswith("git@github.com:"):
        path = normalized[len("git@github.com:"):]
        return "github.com/" + path

    # Fallback: return as-is
    return normalized


def _is_canonical_remote(url: Optional[str]) -> bool:
    """Check if a remote URL matches the canonical FilterProofLLC/aictrl repo.

    Args:
        url: The remote URL to check.

    Returns:
        True if the URL matches canonical patterns, False otherwise.
        Returns True if URL is None (unknown = no denial, only warn).
    """
    if url is None:
        # Unknown remote = cannot prove mismatch, so no denial
        return True
    normalized = _normalize_remote_url(url)
    canonical_normalized = _normalize_remote_url("https://github.com/FilterProofLLC/aictrl")
    return normalized == canonical_normalized


def _is_detached_head() -> Optional[bool]:
    """Check if HEAD is in detached state.

    Returns:
        True if detached, False if attached, None if detection failed.
    """
    try:
        proc = subprocess.run(
            ["git", "symbolic-ref", "-q", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # Non-zero exit = detached HEAD
        return proc.returncode != 0
    except Exception:
        return None


def _is_symlinked_path(path: str) -> bool:
    """Check if a path involves symlink traversal.

    Compares the given path against its realpath to detect symlinks.

    Args:
        path: The path to check.

    Returns:
        True if the path differs from its realpath (symlink detected).
    """
    if not path:
        return False
    try:
        real = os.path.realpath(path)
        # Also resolve the input path but don't follow symlinks for the last component
        # to detect if the input itself is a symlink
        return os.path.abspath(path) != real
    except Exception:
        return False


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
        - origin_remote: Origin remote URL (or None if unavailable)
        - is_canonical_remote: Whether origin matches canonical repo
        - is_detached_head: Whether HEAD is detached (or None if unknown)
        - is_symlinked: Whether path involves symlink traversal
        - detection_error: Error string if detection failed, else None
    """
    result = {
        "canonical_path": CANONICAL_PATH,
        "actual_path": None,
        "is_canonical": False,
        "is_submodule": False,
        "parent_repo": None,
        "origin_remote": None,
        "is_canonical_remote": True,  # Default True = unknown means no denial
        "is_detached_head": None,
        "is_symlinked": False,
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

        # Check origin remote (Phase 15.2)
        origin_url = _get_origin_remote_url()
        result["origin_remote"] = origin_url
        if origin_url is not None:
            result["is_canonical_remote"] = _is_canonical_remote(origin_url)
        # If origin_url is None, is_canonical_remote stays True (unknown = no denial)

        # Check for detached HEAD (Phase 15.2)
        result["is_detached_head"] = _is_detached_head()

        # Check for symlinked path (Phase 15.2)
        # Compare cwd against its realpath
        cwd = os.getcwd()
        result["is_symlinked"] = _is_symlinked_path(cwd)

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

    # Phase 15.2: Remote mismatch warning
    if not context.get("is_canonical_remote") and context.get("origin_remote"):
        warnings.append({
            "source": "observability",
            "message": (
                "Origin remote mismatch: "
                + str(context.get("origin_remote", "unknown"))
                + " (expected: FilterProofLLC/aictrl)"
            ),
            "artifact": "location",
            "code": LOCATION_REMOTE_MISMATCH,
        })

    # Phase 15.2: Detached HEAD warning
    if context.get("is_detached_head") is True:
        warnings.append({
            "source": "observability",
            "message": "Detached HEAD state detected",
            "artifact": "location",
            "code": LOCATION_DETACHED_HEAD,
        })

    # Phase 15.2: Symlinked path warning
    if context.get("is_symlinked"):
        warnings.append({
            "source": "observability",
            "message": "Symlinked working path detected",
            "artifact": "location",
            "code": LOCATION_SYMLINK_DETECTED,
        })

    # Enforcement logic (only when flag ON and not CI)
    if enforce and not ci_exempt:
        # Check for submodule first (most specific)
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
        # Phase 15.2: Remote mismatch (only if we have a remote and it mismatches)
        elif not context.get("is_canonical_remote") and context.get("origin_remote"):
            denial = {
                "code": LOCATION_REMOTE_MISMATCH,
                "message": "Origin remote does not match canonical repository",
                "hint": (
                    "Expected origin: https://github.com/FilterProofLLC/aictrl"
                ),
                "actual_remote": context.get("origin_remote"),
            }
        # Non-canonical path
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
        # Phase 15.2: Detached HEAD
        elif context.get("is_detached_head") is True:
            denial = {
                "code": LOCATION_DETACHED_HEAD,
                "message": "Detached HEAD state detected",
                "hint": "Checkout a branch before running aictrl commands",
            }
        # Phase 15.2: Symlinked path
        elif context.get("is_symlinked"):
            denial = {
                "code": LOCATION_SYMLINK_DETECTED,
                "message": "Symlinked working path detected",
                "hint": (
                    "Run from the actual path, not via symlink: "
                    + str(context.get("actual_path", "unknown"))
                ),
            }

    return {
        "enforce": enforce,
        "ci_exempt": ci_exempt,
        "context": context,
        "warnings": warnings,
        "denial": denial,
    }


def diagnose_location() -> dict[str, Any]:
    """Run location diagnosis for operability (Phase 16).

    This function provides a comprehensive diagnostic view of the
    current location state for operators and developers.

    IMPORTANT: This function ALWAYS succeeds (never raises).
    It is for diagnosis only, not enforcement.

    Returns:
        Dictionary with all location state fields and a status summary.
    """
    context = detect_location_context()
    enforce = is_enforcement_enabled()
    ci = is_ci_environment()

    # Determine overall status
    violations = []
    if not context.get("is_canonical") and not context.get("detection_error"):
        violations.append(LOCATION_NON_CANONICAL)
    if context.get("is_submodule"):
        violations.append(LOCATION_SUBMODULE_DETECTED)
    if not context.get("is_canonical_remote") and context.get("origin_remote"):
        violations.append(LOCATION_REMOTE_MISMATCH)
    if context.get("is_detached_head") is True:
        violations.append(LOCATION_DETACHED_HEAD)
    if context.get("is_symlinked"):
        violations.append(LOCATION_SYMLINK_DETECTED)

    if context.get("detection_error"):
        status = "ERROR (detection failed)"
    elif not violations:
        status = "OK (no violations detected)"
    else:
        status = "VIOLATIONS DETECTED: " + ", ".join(violations)

    return {
        "cwd_realpath": context.get("actual_path"),
        "canonical_path": context.get("canonical_path"),
        "is_canonical": context.get("is_canonical"),
        "is_submodule": context.get("is_submodule"),
        "parent_repo": context.get("parent_repo"),
        "origin_url": context.get("origin_remote"),
        "is_canonical_remote": context.get("is_canonical_remote"),
        "is_detached_head": context.get("is_detached_head"),
        "is_symlinked": context.get("is_symlinked"),
        "enforcement_enabled": enforce,
        "ci_detected": ci,
        "detection_error": context.get("detection_error"),
        "violations": violations,
        "status": status,
    }


def format_diagnosis_text(diag: dict[str, Any]) -> str:
    """Format diagnosis dictionary as human-readable text.

    Args:
        diag: Diagnosis dictionary from diagnose_location().

    Returns:
        ASCII text suitable for terminal output.
    """
    lines = [
        "=== aictrl location diagnosis ===",
        f"cwd_realpath:        {diag.get('cwd_realpath', 'unknown')}",
        f"canonical_path:      {diag.get('canonical_path', 'unknown')}",
        f"is_canonical:        {str(diag.get('is_canonical', False)).lower()}",
        f"is_submodule:        {str(diag.get('is_submodule', False)).lower()}",
    ]
    if diag.get("parent_repo"):
        lines.append(f"parent_repo:         {diag.get('parent_repo')}")
    lines.extend([
        f"origin_url:          {diag.get('origin_url') or '(not detected)'}",
        f"is_canonical_remote: {str(diag.get('is_canonical_remote', True)).lower()}",
        f"is_detached_head:    {str(diag.get('is_detached_head')).lower() if diag.get('is_detached_head') is not None else 'unknown'}",
        f"is_symlinked:        {str(diag.get('is_symlinked', False)).lower()}",
        f"enforcement_enabled: {str(diag.get('enforcement_enabled', False)).lower()}",
        f"ci_detected:         {str(diag.get('ci_detected', False)).lower()}",
    ])
    if diag.get("detection_error"):
        lines.append(f"detection_error:     {diag.get('detection_error')}")
    if diag.get("violations"):
        lines.append(f"violations:          {', '.join(diag.get('violations', []))}")
    lines.append(f"status:              {diag.get('status', 'unknown')}")
    return "\n".join(lines)
