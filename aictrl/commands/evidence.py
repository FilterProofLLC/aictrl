"""aictrl evidence command - evidence bundle export.

This module generates deterministic evidence bundles for audit support.
Evidence export is a READ-ONLY operation that produces reproducible artifacts.

IMPORTANT: Evidence bundles do NOT constitute certification.
See docs/audit/EVIDENCE_BUNDLE.md for details.
"""

import hashlib
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..util.errors import AICtrlError
from ..util.invariants import (
    ExecutionContext,
    detect_execution_context,
    get_context_name,
    run_all_invariant_checks,
)
from ..util.safe_exec import get_safety_status
from .. import __version__


# Error codes for evidence export
EVIDENCE_INVARIANT_FAILURE = "AICTRL-6001"
EVIDENCE_OUTPUT_DIR_ERROR = "AICTRL-6002"
EVIDENCE_ARTIFACT_ERROR = "AICTRL-6003"
EVIDENCE_MANIFEST_ERROR = "AICTRL-6004"
EVIDENCE_HASH_ERROR = "AICTRL-6005"


# Non-certification disclaimer text
NON_CERTIFICATION_NOTICE = (
    "This evidence bundle does NOT constitute certification. "
    "See EVIDENCE_BUNDLE.md Section B."
)


def get_git_commit() -> Optional[str]:
    """Get current git commit hash if available."""
    try:
        from ..util.safe_exec import run_checked
        result = run_checked(
            ["git", "rev-parse", "--short", "HEAD"],
            shell=False,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def calculate_sha256(filepath: Path) -> str:
    """Calculate SHA-256 hash of a file.

    Args:
        filepath: Path to file

    Returns:
        Hex-encoded lowercase SHA-256 hash
    """
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_timestamp() -> str:
    """Generate ISO 8601 timestamp with timezone."""
    return datetime.now(timezone.utc).isoformat()


def generate_bundle_id(timestamp: str) -> str:
    """Generate bundle ID from timestamp.

    Args:
        timestamp: ISO 8601 timestamp

    Returns:
        Bundle ID string
    """
    # Replace colons and plus signs for filesystem compatibility
    safe_ts = timestamp.replace(":", "-").replace("+", "-").split(".")[0]
    return f"evidence-bundle-{safe_ts}"


def create_context_artifact(context: ExecutionContext) -> dict[str, Any]:
    """Create context.json artifact content.

    Args:
        context: Execution context

    Returns:
        Context artifact dictionary
    """
    return {
        "execution_context": get_context_name(context),
        "context_detected": context == detect_execution_context(),
        "detection_method": _get_detection_reason(),
        "environment": {
            "AIOS_CONTEXT": os.environ.get("AIOS_CONTEXT"),
            "CI": os.environ.get("CI"),
            "GITHUB_ACTIONS": os.environ.get("GITHUB_ACTIONS"),
        },
        "hostname": platform.node(),
        "username": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "working_directory": os.getcwd(),
        "timestamp_utc": generate_timestamp(),
    }


def create_version_artifact() -> dict[str, Any]:
    """Create bbail-version.json artifact content.

    Returns:
        Version artifact dictionary
    """
    safety = get_safety_status()
    return {
        "name": "aictrl",
        "version": __version__,
        "commit": get_git_commit(),
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "platform": sys.platform,
        "host_safety_enabled": safety["host_safety_enabled"],
    }


def create_readme(
    timestamp: str,
    context: str,
    version: str,
    commit: Optional[str],
    invariant_summary: dict,
    check_summary: dict,
) -> str:
    """Create README.txt content.

    Args:
        timestamp: Generation timestamp
        context: Execution context name
        version: bbail version
        commit: Git commit hash
        invariant_summary: Invariant check summary
        check_summary: Health check summary

    Returns:
        README text content
    """
    commit_str = commit or "unknown"
    return f"""AIOS Evidence Bundle
====================

Generated: {timestamp}
Context: {context}
Generator: bbail {version} ({commit_str})

DISCLAIMER
----------
This evidence bundle does NOT constitute certification or compliance
with any security framework. It is provided for audit preparation
and self-assessment purposes only.

See docs/audit/EVIDENCE_BUNDLE.md Section B for details.

SUMMARY
-------
Overall Status: {invariant_summary.get('overall_status', 'unknown').upper()}

Invariant Checks:
  Passed:  {invariant_summary.get('passed', 0)}
  Failed:  {invariant_summary.get('failed', 0)}
  Skipped: {invariant_summary.get('skipped', 0)}
  Warned:  {invariant_summary.get('warned', 0)}

Health Checks:
  Passed:  {check_summary.get('passed', 0)}
  Failed:  {check_summary.get('failed', 0)}

CONTENTS
--------
manifest.json      - Artifact inventory with SHA-256 hashes
context.json       - Execution context details
bbail-version.json - Tool version information
doctor-output.json - Full health check results
invariants.json    - Invariant check details
README.txt         - This file

VERIFICATION
------------
To verify bundle integrity:

  sha256sum -c <(jq -r '.artifacts[] | "\\(.sha256)  \\(.path)"' manifest.json)

USAGE
-----
This bundle is intended for:
  - Internal audit preparation
  - Self-assessment support
  - Change verification
  - Diagnostic review

This bundle is NOT intended for:
  - Compliance certification
  - Third-party attestation
  - Regulatory submission (without independent verification)
"""


def _get_detection_reason() -> str:
    """Get reason for context detection."""
    explicit = os.environ.get("AIOS_CONTEXT", "")
    if explicit:
        return f"AIOS_CONTEXT environment variable set to '{explicit}'"

    ci_vars = ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL"]
    for var in ci_vars:
        if os.environ.get(var):
            return f"CI environment detected ({var} is set)"

    return "Developer host detected (default to sandbox)"


def export_evidence_bundle(
    context: Optional[str] = None,
    output_dir: str = None,
    include_system: bool = False,
    pretty: bool = True,
) -> dict[str, Any]:
    """Export an evidence bundle.

    This is a READ-ONLY operation that generates audit artifacts.
    Export FAILS if any invariant check fails (fail-safe).

    Args:
        context: Execution context override (auto-detected if None)
        output_dir: Output directory (required)
        include_system: Include optional system artifacts
        pretty: Pretty-print JSON files

    Returns:
        Export result dictionary

    Raises:
        AICtrlError: On export failure
    """
    if not output_dir:
        raise AICtrlError(
            EVIDENCE_OUTPUT_DIR_ERROR,
            "Output directory is required",
        )

    # Parse context
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

    # Run invariant checks - MUST pass for export
    invariant_results = run_all_invariant_checks(exec_context)

    if invariant_results["overall_status"] == "fail":
        failed_invariants = [
            inv["invariant_id"]
            for inv in invariant_results["invariants"]
            if inv["status"] == "fail"
        ]
        raise AICtrlError(
            EVIDENCE_INVARIANT_FAILURE,
            f"Invariant check failed: {', '.join(failed_invariants)}",
            cause="One or more invariant checks failed",
            remediation=["Fix invariant violations before exporting evidence"],
        )

    # Generate timestamps and IDs
    timestamp = generate_timestamp()
    bundle_id = generate_bundle_id(timestamp)

    # Create bundle directory
    output_path = Path(output_dir)
    bundle_path = output_path / bundle_id

    try:
        bundle_path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise AICtrlError(
            EVIDENCE_OUTPUT_DIR_ERROR,
            f"Cannot create output directory: {e}",
        )

    # Generate artifacts
    artifacts = []
    json_indent = 2 if pretty else None

    try:
        # 1. context.json
        context_data = create_context_artifact(exec_context)
        context_path = bundle_path / "context.json"
        with open(context_path, "w") as f:
            json.dump(context_data, f, indent=json_indent, sort_keys=True)
        artifacts.append(("context.json", context_path))

        # 2. bbail-version.json
        version_data = create_version_artifact()
        version_path = bundle_path / "bbail-version.json"
        with open(version_path, "w") as f:
            json.dump(version_data, f, indent=json_indent, sort_keys=True)
        artifacts.append(("bbail-version.json", version_path))

        # 3. doctor-output.json (full doctor output)
        from .doctor import run_doctor
        doctor_data = run_doctor(
            context=get_context_name(exec_context),
            include_invariants=True,
        )
        doctor_path = bundle_path / "doctor-output.json"
        with open(doctor_path, "w") as f:
            json.dump(doctor_data, f, indent=json_indent, sort_keys=True)
        artifacts.append(("doctor-output.json", doctor_path))

        # 4. invariants.json (dedicated invariant results)
        invariants_path = bundle_path / "invariants.json"
        with open(invariants_path, "w") as f:
            json.dump(invariant_results, f, indent=json_indent, sort_keys=True)
        artifacts.append(("invariants.json", invariants_path))

        # 5. README.txt
        readme_content = create_readme(
            timestamp=timestamp,
            context=get_context_name(exec_context),
            version=__version__,
            commit=version_data.get("commit"),
            invariant_summary=invariant_results["summary"],
            check_summary=doctor_data["summary"],
        )
        readme_path = bundle_path / "README.txt"
        with open(readme_path, "w") as f:
            f.write(readme_content)
        artifacts.append(("README.txt", readme_path))

    except Exception as e:
        # Cleanup on failure
        _cleanup_bundle(bundle_path)
        raise AICtrlError(
            EVIDENCE_ARTIFACT_ERROR,
            f"Failed to generate artifact: {e}",
        )

    # Generate manifest with hashes
    try:
        manifest_artifacts = []
        for name, path in artifacts:
            file_hash = calculate_sha256(path)
            file_size = path.stat().st_size
            manifest_artifacts.append({
                "path": name,
                "sha256": file_hash,
                "size_bytes": file_size,
            })

        manifest = {
            "schema_version": "1.0",
            "bundle_id": bundle_id,
            "generated_at": timestamp,
            "generator": {
                "name": "aictrl",
                "version": __version__,
                "commit": version_data.get("commit"),
            },
            "context": {
                "execution_context": get_context_name(exec_context),
                "hostname": platform.node(),
                "username": os.environ.get("USER", "unknown"),
            },
            "artifacts": manifest_artifacts,
            "invariant_summary": {
                "passed": invariant_results["summary"]["passed"],
                "failed": invariant_results["summary"]["failed"],
                "skipped": invariant_results["summary"]["skipped"],
                "warned": invariant_results["summary"]["warned"],
                "overall_status": invariant_results["overall_status"],
            },
            "non_certification_notice": NON_CERTIFICATION_NOTICE,
        }

        manifest_path = bundle_path / "manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=json_indent, sort_keys=True)

    except Exception as e:
        _cleanup_bundle(bundle_path)
        raise AICtrlError(
            EVIDENCE_MANIFEST_ERROR,
            f"Failed to create manifest: {e}",
        )

    return {
        "success": True,
        "bundle_path": str(bundle_path),
        "bundle_id": bundle_id,
        "manifest_path": str(manifest_path),
        "invariant_status": invariant_results["overall_status"],
        "artifact_count": len(artifacts) + 1,  # +1 for manifest
    }


def _cleanup_bundle(bundle_path: Path) -> None:
    """Clean up partial bundle on failure.

    Args:
        bundle_path: Path to bundle directory
    """
    import shutil
    try:
        if bundle_path.exists():
            shutil.rmtree(bundle_path)
    except Exception:
        pass  # Best effort cleanup


def verify_evidence_bundle(bundle_path: str) -> dict[str, Any]:
    """Verify integrity of an evidence bundle.

    Args:
        bundle_path: Path to bundle directory

    Returns:
        Verification result dictionary
    """
    bundle = Path(bundle_path)
    manifest_path = bundle / "manifest.json"

    if not manifest_path.exists():
        return {
            "valid": False,
            "error": "manifest.json not found",
        }

    try:
        with open(manifest_path) as f:
            manifest = json.load(f)
    except json.JSONDecodeError as e:
        return {
            "valid": False,
            "error": f"Invalid manifest JSON: {e}",
        }

    # Verify each artifact
    results = []
    all_valid = True

    for artifact in manifest.get("artifacts", []):
        artifact_path = bundle / artifact["path"]
        expected_hash = artifact["sha256"]

        if not artifact_path.exists():
            results.append({
                "path": artifact["path"],
                "status": "missing",
                "expected_hash": expected_hash,
            })
            all_valid = False
            continue

        actual_hash = calculate_sha256(artifact_path)
        if actual_hash == expected_hash:
            results.append({
                "path": artifact["path"],
                "status": "valid",
                "hash": actual_hash,
            })
        else:
            results.append({
                "path": artifact["path"],
                "status": "invalid",
                "expected_hash": expected_hash,
                "actual_hash": actual_hash,
            })
            all_valid = False

    return {
        "valid": all_valid,
        "bundle_id": manifest.get("bundle_id"),
        "generated_at": manifest.get("generated_at"),
        "artifact_results": results,
    }
