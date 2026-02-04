#!/usr/bin/env python3
"""AICtrl Baseline Test Runner.

Executes baseline tests defined in baseline_tests.yaml and generates
a timestamped UTF-8 ASCII-safe text report.

Usage:
    python run_baseline.py [--emit-json] [--emit-coverage] [--emit-digest]
    python run_baseline.py [--emit-coverage-json]
    python run_baseline.py [--gpg-sign [--gpg-key-id KEY_ID]]
    python run_baseline.py --verify <artifact_dir>
    python run_baseline.py --verify-gpg <artifact_dir>

Options:
    --emit-json          Also emit a JSON attestation artifact
    --emit-coverage      Also emit a spec coverage index (text format)
    --emit-coverage-json Also emit a spec coverage index (JSON format)
    --emit-digest        Also emit a cryptographic digest file and manifest
    --gpg-sign           Sign attestation and digest files with GPG (opt-in)
    --gpg-key-id KEY_ID  Use specific GPG key for signing (default: default key)
    --validate-schema    Validate JSON attestation against schema (auto in CI)
    --verify <dir>       Verify existing artifacts (read-only, no test execution)
    --verify-gpg <dir>   Verify GPG signatures in artifact directory

Exit codes:
    0 - All tests passed (or verification succeeded)
    1 - One or more tests failed (or verification failed)
"""

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


# Determine paths
SCRIPT_DIR = Path(__file__).parent.resolve()
BASELINE_FILE = SCRIPT_DIR / "baseline_tests.yaml"
MANIFEST_FILE = SCRIPT_DIR / "baseline_manifest.json"
RESULTS_DIR = SCRIPT_DIR / "results"

# Schema path (relative to repo root)
REPO_ROOT = SCRIPT_DIR.parent
SCHEMA_FILE = REPO_ROOT / "docs" / "schemas" / "aictrl_baseline_attestation.schema.json"


def is_ascii_only(text: str) -> bool:
    """Check if text contains only ASCII characters (0x00-0x7F)."""
    try:
        text.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def sanitize_for_ascii(text: str) -> str:
    """Replace non-ASCII characters with replacement marker."""
    return text.encode("ascii", errors="replace").decode("ascii")


def load_baseline() -> dict:
    """Load baseline test definitions from YAML file."""
    if not BASELINE_FILE.exists():
        print(f"ERROR: Baseline file not found: {BASELINE_FILE}", file=sys.stderr)
        sys.exit(1)

    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_manifest() -> dict:
    """Load baseline manifest from JSON file."""
    if not MANIFEST_FILE.exists():
        print(f"ERROR: Manifest file not found: {MANIFEST_FILE}", file=sys.stderr)
        sys.exit(1)

    with open(MANIFEST_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_attestation_schema(attestation: dict) -> tuple[bool, list[str]]:
    """Validate attestation against schema (lightweight, stdlib-only).

    This implements essential schema validation without external dependencies.
    For full JSON Schema validation, use jsonschema library.

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    # Required top-level fields
    required_fields = [
        "schema_version", "attestation_type", "baseline_name", "baseline_version",
        "aictrl_version", "timestamp_utc", "execution_context", "provenance",
        "host_metadata", "summary", "test_results"
    ]

    for field in required_fields:
        if field not in attestation:
            errors.append(f"Missing required field: {field}")

    # Validate schema_version
    if attestation.get("schema_version") != "1.1":
        errors.append(f"Invalid schema_version: expected '1.1', got '{attestation.get('schema_version')}'")

    # Validate attestation_type
    if attestation.get("attestation_type") != "aictrl-baseline-result":
        errors.append(f"Invalid attestation_type: expected 'aictrl-baseline-result'")

    # Validate execution_context
    valid_contexts = ["local", "github-actions", "gitlab-ci", "ci-unknown"]
    if attestation.get("execution_context") not in valid_contexts:
        errors.append(f"Invalid execution_context: must be one of {valid_contexts}")

    # Validate timestamp format
    import re
    timestamp = attestation.get("timestamp_utc", "")
    if not re.match(r"^\d{4}-\d{2}-\d{2}T\d{6}Z$", timestamp):
        errors.append(f"Invalid timestamp_utc format: expected YYYY-MM-DDTHHMMSSZ")

    # Validate summary structure
    summary = attestation.get("summary", {})
    summary_required = ["total_tests", "passed", "failed", "expected_failures",
                        "unexpected_failures", "overall_result"]
    for field in summary_required:
        if field not in summary:
            errors.append(f"Missing required summary field: {field}")

    if summary.get("overall_result") not in ["PASS", "FAIL"]:
        errors.append(f"Invalid overall_result: must be 'PASS' or 'FAIL'")

    # Validate test_results array
    test_results = attestation.get("test_results", [])
    if not isinstance(test_results, list):
        errors.append("test_results must be an array")
    else:
        test_required = ["test_id", "description", "category", "expected_result",
                         "actual_result", "pass_fail", "duration_seconds", "spec_mappings"]
        for i, result in enumerate(test_results):
            for field in test_required:
                if field not in result:
                    errors.append(f"test_results[{i}] missing required field: {field}")

            # Validate test_id format
            test_id = result.get("test_id", "")
            if not re.match(r"^BL-\d{3}$", test_id):
                errors.append(f"test_results[{i}] invalid test_id format: {test_id}")

    # Validate provenance structure
    provenance = attestation.get("provenance", {})
    if "execution_environment" not in provenance:
        errors.append("Missing required provenance field: execution_environment")

    return len(errors) == 0, errors


def get_aictrl_path() -> str:
    """Get the path to the aictrl module."""
    # Try to find aictrl in the repository
    repo_root = SCRIPT_DIR.parent.parent.parent
    aictrl_dir = repo_root / "tools" / "aictrl"
    if (aictrl_dir / "aictrl").exists():
        return str(aictrl_dir / "aictrl")
    return "aictrl"


def get_aictrl_version() -> str:
    """Get the installed aictrl version."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "aictrl", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=SCRIPT_DIR.parent,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return "unknown"
    except Exception as e:
        return f"error: {e}"


def get_host_metadata() -> dict:
    """Collect host metadata for the report."""
    return {
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "hostname": platform.node(),
        "aictrl_path": get_aictrl_path(),
        "aictrl_version": get_aictrl_version(),
    }


def get_git_provenance() -> dict:
    """Collect git provenance information for attestation.

    Returns git metadata without making any network calls.
    All information is derived from local repository state.
    """
    provenance = {
        "git_commit": None,
        "git_branch": None,
        "repository_url": None,
    }

    try:
        # Get current commit SHA
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=SCRIPT_DIR,
        )
        if result.returncode == 0:
            provenance["git_commit"] = result.stdout.strip()

        # Get current branch
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=SCRIPT_DIR,
        )
        if result.returncode == 0:
            provenance["git_branch"] = result.stdout.strip()

        # Get repository URL (from remote origin)
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=SCRIPT_DIR,
        )
        if result.returncode == 0:
            provenance["repository_url"] = result.stdout.strip()

    except Exception:
        # Silently ignore git errors - provenance is optional
        pass

    return provenance


def compute_file_hash(file_path: Path) -> str:
    """Compute SHA-256 hash of a file.

    Uses stdlib hashlib only - no external dependencies.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read in chunks for memory efficiency
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_digest_file(
    baseline_info: dict,
    timestamp: str,
    files: dict,
    git_commit: str = None
) -> str:
    """Generate cryptographic digest file content.

    Args:
        baseline_info: Baseline metadata (name, version)
        timestamp: UTC timestamp of generation
        files: Dict mapping filename to file path
        git_commit: Git commit SHA (optional)

    Returns:
        ASCII digest file content
    """
    lines = []
    lines.append("# AICtrl Baseline Attestation Digest")
    lines.append("# This file enables offline verification of baseline artifacts.")
    lines.append("#")
    lines.append("algorithm: SHA-256")
    lines.append(f"baseline_name: {baseline_info.get('name', 'unknown')}")
    lines.append(f"baseline_version: {baseline_info.get('version', 'unknown')}")
    if git_commit:
        lines.append(f"commit_sha: {git_commit}")
    lines.append(f"generated_at_utc: {timestamp}")
    lines.append("")
    lines.append("files:")

    # Sort files for deterministic output
    for filename in sorted(files.keys()):
        file_path = files[filename]
        if file_path.exists():
            file_hash = compute_file_hash(file_path)
            lines.append(f"  - {filename}: {file_hash}")

    lines.append("")
    return "\n".join(lines)


def gpg_sign_file(file_path: Path, key_id: str = None) -> tuple[bool, str, Path]:
    """Sign a file using GPG detached signature.

    This creates a .sig file alongside the original artifact.
    Uses gpg --armor --detach-sign for ASCII-armored signature.

    Args:
        file_path: Path to the file to sign
        key_id: Optional GPG key ID (uses default key if not specified)

    Returns:
        Tuple of (success, message, signature_path)
    """
    sig_path = file_path.with_suffix(file_path.suffix + ".sig")

    cmd = ["gpg", "--armor", "--detach-sign", "--output", str(sig_path)]
    if key_id:
        cmd.extend(["--local-user", key_id])
    cmd.append(str(file_path))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            return True, f"Signed: {sig_path.name}", sig_path
        else:
            return False, f"GPG error: {result.stderr.strip()}", sig_path
    except FileNotFoundError:
        return False, "GPG not found. Install gnupg to enable signing.", sig_path
    except subprocess.TimeoutExpired:
        return False, "GPG signing timed out", sig_path
    except Exception as e:
        return False, f"Signing failed: {e}", sig_path


def gpg_verify_file(file_path: Path, sig_path: Path = None) -> tuple[bool, str]:
    """Verify a GPG detached signature.

    Args:
        file_path: Path to the original file
        sig_path: Path to the .sig file (default: file_path + .sig)

    Returns:
        Tuple of (success, message)
    """
    if sig_path is None:
        sig_path = file_path.with_suffix(file_path.suffix + ".sig")

    if not sig_path.exists():
        return False, f"Signature file not found: {sig_path.name}"

    cmd = ["gpg", "--verify", str(sig_path), str(file_path)]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            # Extract signer info from stderr (GPG outputs verification info there)
            return True, f"Valid signature: {result.stderr.strip()}"
        else:
            return False, f"Invalid signature: {result.stderr.strip()}"
    except FileNotFoundError:
        return False, "GPG not found. Install gnupg to verify signatures."
    except subprocess.TimeoutExpired:
        return False, "GPG verification timed out"
    except Exception as e:
        return False, f"Verification failed: {e}"


def verify_gpg_signatures(artifact_dir: Path) -> int:
    """Verify GPG signatures for baseline artifacts.

    Args:
        artifact_dir: Directory containing artifacts and .sig files

    Returns:
        0 if all signatures valid, 1 if any verification fails
    """
    print("AICtrl Baseline GPG Signature Verification")
    print("=" * 40)
    print("")
    print(f"Artifact directory: {artifact_dir}")
    print("")

    # Files that may be signed
    signable_files = [
        "aictrl-baseline-attestation.json",
        "aictrl-baseline.digest.txt",
    ]

    all_passed = True
    verified_count = 0
    failed_count = 0
    missing_count = 0

    print("Verifying GPG signatures:")
    print("-" * 40)

    for filename in signable_files:
        file_path = artifact_dir / filename
        sig_path = artifact_dir / (filename + ".sig")

        if not file_path.exists():
            print(f"  {filename}: FILE MISSING")
            missing_count += 1
            all_passed = False
            continue

        if not sig_path.exists():
            print(f"  {filename}: NO SIGNATURE")
            missing_count += 1
            continue

        success, message = gpg_verify_file(file_path, sig_path)
        if success:
            print(f"  {filename}: VERIFIED")
            verified_count += 1
        else:
            print(f"  {filename}: FAILED")
            print(f"    {message}")
            failed_count += 1
            all_passed = False

    print("-" * 40)
    print("")
    print("GPG Verification Summary:")
    print(f"  Verified: {verified_count}")
    print(f"  Failed:   {failed_count}")
    print(f"  Missing:  {missing_count}")
    print("")

    if verified_count > 0 and failed_count == 0:
        print("GPG VERIFICATION: PASS")
        return 0
    elif verified_count == 0 and missing_count > 0:
        print("GPG VERIFICATION: NO SIGNATURES FOUND")
        print("Artifacts may not have been signed. This is not an error.")
        return 0
    else:
        print("GPG VERIFICATION: FAIL")
        return 1


def verify_artifacts(artifact_dir: Path) -> int:
    """Verify existing baseline artifacts against digest file.

    This is a read-only operation that:
    - Loads the digest file
    - Recomputes hashes for referenced files
    - Compares against stored hashes
    - Reports PASS/FAIL

    Args:
        artifact_dir: Directory containing artifacts and digest file

    Returns:
        0 if verification passes, 1 if it fails
    """
    print("AICtrl Baseline Artifact Verification")
    print("=" * 40)
    print("")
    print(f"Artifact directory: {artifact_dir}")
    print("")

    # Find digest file
    digest_files = list(artifact_dir.glob("aictrl-baseline.digest.txt")) + \
                   list(artifact_dir.glob("aictrl_baseline_*.digest.txt"))

    if not digest_files:
        print("ERROR: No digest file found in artifact directory.")
        print("Expected: aictrl-baseline.digest.txt")
        return 1

    digest_file = digest_files[0]
    print(f"Using digest file: {digest_file.name}")
    print("")

    # Parse digest file
    try:
        with open(digest_file, "r", encoding="utf-8") as f:
            digest_content = f.read()
    except Exception as e:
        print(f"ERROR: Failed to read digest file: {e}")
        return 1

    # Extract metadata and file hashes
    stored_hashes = {}
    metadata = {}
    in_files_section = False

    for line in digest_content.split("\n"):
        line = line.strip()
        if line.startswith("#") or not line:
            continue

        if line == "files:":
            in_files_section = True
            continue

        if in_files_section:
            if line.startswith("- "):
                # Parse file entry: "  - filename: hash"
                parts = line[2:].split(": ", 1)
                if len(parts) == 2:
                    stored_hashes[parts[0]] = parts[1]
        else:
            # Parse metadata
            if ": " in line:
                key, value = line.split(": ", 1)
                metadata[key] = value

    print("Digest Metadata:")
    print(f"  Algorithm:        {metadata.get('algorithm', 'unknown')}")
    print(f"  Baseline Name:    {metadata.get('baseline_name', 'unknown')}")
    print(f"  Baseline Version: {metadata.get('baseline_version', 'unknown')}")
    print(f"  Commit SHA:       {metadata.get('commit_sha', 'not recorded')}")
    print(f"  Generated At:     {metadata.get('generated_at_utc', 'unknown')}")
    print("")

    # Verify each file
    print("Verifying files:")
    print("-" * 40)

    all_passed = True
    verified_count = 0
    failed_count = 0
    missing_count = 0

    for filename, expected_hash in sorted(stored_hashes.items()):
        file_path = artifact_dir / filename
        if not file_path.exists():
            print(f"  {filename}: MISSING")
            missing_count += 1
            all_passed = False
            continue

        actual_hash = compute_file_hash(file_path)
        if actual_hash == expected_hash:
            print(f"  {filename}: VERIFIED")
            verified_count += 1
        else:
            print(f"  {filename}: TAMPERED")
            print(f"    Expected: {expected_hash}")
            print(f"    Actual:   {actual_hash}")
            failed_count += 1
            all_passed = False

    print("-" * 40)
    print("")
    print("Verification Summary:")
    print(f"  Verified: {verified_count}")
    print(f"  Failed:   {failed_count}")
    print(f"  Missing:  {missing_count}")
    print("")

    if all_passed:
        print("VERIFICATION: PASS")
        print("All artifacts are intact and untampered.")
        return 0
    else:
        print("VERIFICATION: FAIL")
        print("One or more artifacts failed verification.")
        return 1


def run_test(test: dict) -> dict:
    """Execute a single test and return results."""
    test_id = test["id"]
    title = test["title"]
    command = test["command"][:]  # Make a copy to avoid modifying original
    expect = test["expect"]
    env_overrides = test.get("env", {})
    expected_failure = test.get("expected_failure", False)

    # Replace "python" with the current interpreter for portability
    if command and command[0] == "python":
        command[0] = sys.executable

    # Build environment
    env = os.environ.copy()
    env.update(env_overrides)

    # Ensure we're running from the aictrl directory for module resolution
    cwd = SCRIPT_DIR.parent

    # Execute command
    start_time = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
            cwd=cwd,
        )
        exit_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
        error = None
    except subprocess.TimeoutExpired:
        exit_code = -1
        stdout = ""
        stderr = "TIMEOUT: Command exceeded 60 second limit"
        error = "timeout"
    except Exception as e:
        exit_code = -1
        stdout = ""
        stderr = str(e)
        error = str(e)

    duration = time.perf_counter() - start_time

    # Evaluate expectations
    passed = True
    failures = []

    # Check exit code
    if "exit_code" in expect:
        if exit_code != expect["exit_code"]:
            passed = False
            failures.append(f"exit_code: expected {expect['exit_code']}, got {exit_code}")
    elif "exit_code_in" in expect:
        if exit_code not in expect["exit_code_in"]:
            passed = False
            failures.append(f"exit_code: expected one of {expect['exit_code_in']}, got {exit_code}")

    # Check stdout contains
    if "stdout_contains" in expect:
        for expected_str in expect["stdout_contains"]:
            if expected_str not in stdout:
                passed = False
                failures.append(f"stdout missing: {expected_str!r}")

    # Check stderr contains
    if "stderr_contains" in expect:
        for expected_str in expect["stderr_contains"]:
            if expected_str not in stderr:
                passed = False
                failures.append(f"stderr missing: {expected_str!r}")

    # Check ASCII-only
    if expect.get("ascii_only", False):
        combined = stdout + stderr
        if not is_ascii_only(combined):
            passed = False
            failures.append("output contains non-ASCII characters")

    return {
        "id": test_id,
        "title": title,
        "command": command,
        "exit_code": exit_code,
        "stdout": sanitize_for_ascii(stdout),
        "stderr": sanitize_for_ascii(stderr),
        "duration": duration,
        "passed": passed,
        "failures": failures,
        "expected_failure": expected_failure,
        "spec": test.get("spec", {}),
        "notes": test.get("notes", ""),
        "error": error,
    }


def get_test_category(test_id: str) -> str:
    """Derive test category from test ID."""
    # Map ID ranges to categories
    id_num = int(test_id.split("-")[1]) if "-" in test_id else 0
    if 1 <= id_num <= 9:
        return "cli-surface"
    elif 10 <= id_num <= 19:
        return "authz-policy"
    elif 20 <= id_num <= 29:
        return "authz-enforcement"
    elif 30 <= id_num <= 39:
        return "adapter-inspection"
    elif 40 <= id_num <= 49:
        return "boundary-inspection"
    elif 50 <= id_num <= 59:
        return "execution-readiness"
    elif 60 <= id_num <= 69:
        return "safe-failure"
    elif 70 <= id_num <= 79:
        return "invalid-input"
    elif 80 <= id_num <= 89:
        return "environment-override"
    elif 90 <= id_num <= 99:
        return "ascii-compliance"
    elif 100 <= id_num <= 109:
        return "evidence-trail"
    elif 110 <= id_num <= 119:
        return "determinism"
    return "unknown"


def generate_attestation(baseline: dict, results: list, host_meta: dict,
                         timestamp: str, provenance: dict = None) -> dict:
    """Generate machine-readable JSON attestation artifact.

    This produces a deterministic, schema-stable JSON structure suitable
    for external consumption and attestation workflows.

    Args:
        baseline: Baseline definition
        results: Test execution results
        host_meta: Host metadata
        timestamp: UTC timestamp
        provenance: Git provenance metadata (optional)
    """
    baseline_info = baseline.get("baseline", {})

    # Build test results array
    test_results = []
    for result in results:
        test_results.append({
            "test_id": result["id"],
            "description": result["title"],
            "category": get_test_category(result["id"]),
            "expected_result": "fail" if result.get("expected_failure") else "pass",
            "actual_result": "pass" if result["passed"] else "fail",
            "pass_fail": "PASS" if result["passed"] else "FAIL",
            "duration_seconds": round(result["duration"], 3),
            "spec_mappings": {
                "internal": result.get("spec", {}).get("internal"),
                "nist": result.get("spec", {}).get("nist"),
                "federal": result.get("spec", {}).get("federal"),
            },
        })

    # Calculate summary with clear categorization
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed

    # Expected failures: tests marked expected_failure=True that actually failed
    expected_failure_list = [
        {
            "test_id": r["id"],
            "name": r["title"],
            "reason": "Test is designed to verify rejection of unsafe operation"
        }
        for r in results
        if r.get("expected_failure", False) and not r["passed"]
    ]
    expected_failures_count = len(expected_failure_list)

    # Unexpected failures: tests NOT marked expected_failure that failed
    unexpected_failure_list = [
        {
            "test_id": r["id"],
            "name": r["title"],
            "reason": "; ".join(r.get("failures", ["Unknown failure"]))
        }
        for r in results
        if not r["passed"] and not r.get("expected_failure", False)
    ]
    unexpected_failures_count = len(unexpected_failure_list)

    # Determine execution context and CI metadata
    execution_context = "local"
    ci_run_id = None
    if os.environ.get("GITHUB_ACTIONS"):
        execution_context = "github-actions"
        ci_run_id = os.environ.get("GITHUB_RUN_ID")
    elif os.environ.get("GITLAB_CI"):
        execution_context = "gitlab-ci"
        ci_run_id = os.environ.get("CI_JOB_ID")
    elif os.environ.get("CI"):
        execution_context = "ci-unknown"

    attestation = {
        "schema_version": "1.1",
        "attestation_type": "aictrl-baseline-result",
        "baseline_name": baseline_info.get("name", "unknown"),
        "baseline_version": baseline_info.get("version", "unknown"),
        "aictrl_version": host_meta.get("aictrl_version", "unknown"),
        "timestamp_utc": timestamp,
        "execution_context": execution_context,
        "provenance": {
            "git_commit": provenance.get("git_commit") if provenance else None,
            "git_branch": provenance.get("git_branch") if provenance else None,
            "repository_url": provenance.get("repository_url") if provenance else None,
            "ci_run_id": ci_run_id,
            "execution_environment": execution_context,
            "python_version": host_meta.get("python_version"),
            "platform": host_meta.get("platform"),
        },
        "host_metadata": {
            "python_version": host_meta.get("python_version"),
            "platform": host_meta.get("platform"),
            "hostname": host_meta.get("hostname"),
        },
        "summary": {
            "total_tests": total,
            "passed": passed,
            "failed": failed,
            "expected_failures": expected_failures_count,
            "unexpected_failures": unexpected_failures_count,
            "overall_result": "PASS" if unexpected_failures_count == 0 else "FAIL",
        },
        "expected_failure_details": expected_failure_list,
        "unexpected_failure_details": unexpected_failure_list,
        "test_results": test_results,
    }

    return attestation


def generate_coverage_index(baseline: dict) -> str:
    """Generate spec coverage index from baseline test definitions.

    Parses all tests and produces a coverage table showing which
    NIST AI RMF controls are covered by which tests.
    """
    tests = baseline.get("tests", [])

    # Collect all spec mappings
    nist_coverage = {}  # control_id -> list of test_ids
    internal_coverage = {}
    federal_coverage = {}

    for test in tests:
        test_id = test.get("id", "unknown")
        spec = test.get("spec", {})

        if spec.get("nist"):
            nist_id = spec["nist"]
            if nist_id not in nist_coverage:
                nist_coverage[nist_id] = []
            nist_coverage[nist_id].append(test_id)

        if spec.get("internal"):
            internal_id = spec["internal"]
            if internal_id not in internal_coverage:
                internal_coverage[internal_id] = []
            internal_coverage[internal_id].append(test_id)

        if spec.get("federal"):
            federal_id = spec["federal"]
            if federal_id not in federal_coverage:
                federal_coverage[federal_id] = []
            federal_coverage[federal_id].append(test_id)

    # Known NIST AI RMF controls (subset relevant to AI governance)
    known_nist_controls = [
        "AC-3", "AC-6", "AC-6(9)", "AC-3(7)",
        "AU-3", "AU-8",
        "CA-7", "CA-8",
        "CM-7",
        "GV.PO-1",
        "ID.AM-2",
        "SC-5", "SC-7",
        "SI-10", "SI-17",
    ]

    lines = []
    lines.append("=" * 80)
    lines.append("AICtrl Baseline Spec Coverage Index")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    lines.append(f"Baseline Version: {baseline.get('baseline', {}).get('version', 'unknown')}")
    lines.append("")

    # NIST AI RMF Coverage
    lines.append("-" * 80)
    lines.append("NIST AI RMF Control Coverage")
    lines.append("-" * 80)
    lines.append("")
    lines.append(f"{'Control ID':<15} {'Test IDs':<40} {'Status':<10}")
    lines.append("-" * 65)

    covered_count = 0
    partial_count = 0
    none_count = 0

    for control in sorted(known_nist_controls):
        test_ids = nist_coverage.get(control, [])
        if len(test_ids) >= 2:
            status = "FULL"
            covered_count += 1
        elif len(test_ids) == 1:
            status = "PARTIAL"
            partial_count += 1
        else:
            status = "NONE"
            none_count += 1

        test_list = ", ".join(test_ids) if test_ids else "(none)"
        if len(test_list) > 38:
            test_list = test_list[:35] + "..."
        lines.append(f"{control:<15} {test_list:<40} {status:<10}")

    lines.append("")
    lines.append(f"Coverage Summary: FULL={covered_count}, PARTIAL={partial_count}, NONE={none_count}")
    lines.append("")

    # Internal Invariant Coverage
    lines.append("-" * 80)
    lines.append("Internal Invariant Coverage")
    lines.append("-" * 80)
    lines.append("")

    for inv_id in sorted(internal_coverage.keys()):
        test_ids = internal_coverage[inv_id]
        lines.append(f"{inv_id}: {', '.join(test_ids)}")

    lines.append("")

    # Federal Policy Coverage
    lines.append("-" * 80)
    lines.append("Federal Policy Coverage")
    lines.append("-" * 80)
    lines.append("")

    for fed_id in sorted(federal_coverage.keys()):
        test_ids = federal_coverage[fed_id]
        lines.append(f"{fed_id}: {', '.join(test_ids)}")

    lines.append("")
    lines.append("=" * 80)
    lines.append("End of Coverage Index")
    lines.append("=" * 80)

    return "\n".join(lines)


def generate_coverage_index_json(baseline: dict) -> dict:
    """Generate spec coverage index in JSON format.

    Produces a machine-readable coverage report with the same data
    as the text coverage index but in structured JSON format.

    Args:
        baseline: Baseline definition dict

    Returns:
        Dict containing coverage data suitable for JSON serialization
    """
    tests = baseline.get("tests", [])
    baseline_info = baseline.get("baseline", {})

    # Collect all spec mappings
    nist_coverage = {}  # control_id -> list of test_ids
    internal_coverage = {}
    federal_coverage = {}

    for test in tests:
        test_id = test.get("id", "unknown")
        spec = test.get("spec", {})

        if spec.get("nist"):
            nist_id = spec["nist"]
            if nist_id not in nist_coverage:
                nist_coverage[nist_id] = []
            nist_coverage[nist_id].append(test_id)

        if spec.get("internal"):
            internal_id = spec["internal"]
            if internal_id not in internal_coverage:
                internal_coverage[internal_id] = []
            internal_coverage[internal_id].append(test_id)

        if spec.get("federal"):
            federal_id = spec["federal"]
            if federal_id not in federal_coverage:
                federal_coverage[federal_id] = []
            federal_coverage[federal_id].append(test_id)

    # Known NIST AI RMF controls
    known_nist_controls = [
        "AC-3", "AC-6", "AC-6(9)", "AC-3(7)",
        "AU-3", "AU-8",
        "CA-7", "CA-8",
        "CM-7",
        "GV.PO-1",
        "ID.AM-2",
        "SC-5", "SC-7",
        "SI-10", "SI-17",
    ]

    # Build NIST controls section
    nist_controls = {}
    nist_full = 0
    nist_partial = 0
    nist_none = 0

    for control in sorted(known_nist_controls):
        test_ids = nist_coverage.get(control, [])
        if len(test_ids) >= 2:
            status = "FULL"
            nist_full += 1
        elif len(test_ids) == 1:
            status = "PARTIAL"
            nist_partial += 1
        else:
            status = "NONE"
            nist_none += 1

        nist_controls[control] = {
            "control_id": control,
            "test_ids": sorted(test_ids),
            "coverage_status": status,
            "test_count": len(test_ids),
        }

    # Build internal invariants section
    internal_invariants = {}
    for inv_id in sorted(internal_coverage.keys()):
        internal_invariants[inv_id] = {
            "control_id": inv_id,
            "test_ids": sorted(internal_coverage[inv_id]),
            "coverage_status": "COVERED",
            "test_count": len(internal_coverage[inv_id]),
        }

    # Build federal policies section
    federal_policies = {}
    for fed_id in sorted(federal_coverage.keys()):
        federal_policies[fed_id] = {
            "control_id": fed_id,
            "test_ids": sorted(federal_coverage[fed_id]),
            "coverage_status": "COVERED",
            "test_count": len(federal_coverage[fed_id]),
        }

    return {
        "schema_version": "1.0",
        "coverage_type": "aictrl-spec-coverage",
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ"),
        "baseline_name": baseline_info.get("name", "unknown"),
        "baseline_version": baseline_info.get("version", "unknown"),
        "nist_controls": nist_controls,
        "internal_invariants": internal_invariants,
        "federal_policies": federal_policies,
        "summary": {
            "nist_full": nist_full,
            "nist_partial": nist_partial,
            "nist_none": nist_none,
            "nist_total": len(known_nist_controls),
            "internal_invariants_covered": len(internal_invariants),
            "federal_policies_covered": len(federal_policies),
            "total_tests": len(tests),
        },
    }


def generate_report(baseline: dict, results: list, host_meta: dict, timestamp: str) -> str:
    """Generate the text report."""
    lines = []

    # Header
    lines.append("=" * 80)
    lines.append("AICtrl Baseline Test Report")
    lines.append("=" * 80)
    lines.append("")

    # Baseline info
    baseline_info = baseline.get("baseline", {})
    lines.append(f"Baseline Name:    {baseline_info.get('name', 'unknown')}")
    lines.append(f"Baseline Version: {baseline_info.get('version', 'unknown')}")
    lines.append(f"Target Version:   {baseline_info.get('target_version', 'unknown')}")
    lines.append(f"Timestamp (UTC):  {timestamp}")
    lines.append("")

    # Host metadata
    lines.append("-" * 80)
    lines.append("Host Metadata")
    lines.append("-" * 80)
    lines.append(f"Python Version:   {host_meta['python_version']}")
    lines.append(f"Python Path:      {host_meta['python_executable']}")
    lines.append(f"Platform:         {host_meta['platform']}")
    lines.append(f"Hostname:         {host_meta['hostname']}")
    lines.append(f"AICtrl Path:      {host_meta['aictrl_path']}")
    lines.append(f"AICtrl Version:   {host_meta['aictrl_version']}")
    lines.append("")

    # Summary - compute clear categories
    total = len(results)
    passed = sum(1 for r in results if r["passed"])

    # Expected failures: tests marked expected_failure=True that actually failed
    expected_failure_results = [
        r for r in results
        if r.get("expected_failure", False) and not r["passed"]
    ]
    expected_failures_count = len(expected_failure_results)

    # Unexpected failures: tests NOT marked expected_failure that failed
    unexpected_failure_results = [
        r for r in results
        if not r["passed"] and not r.get("expected_failure", False)
    ]
    unexpected_failures_count = len(unexpected_failure_results)

    lines.append("-" * 80)
    lines.append("Summary")
    lines.append("-" * 80)
    lines.append(f"Total Tests:          {total}")
    lines.append(f"Passed:               {passed}")
    lines.append(f"Expected Failures:    {expected_failures_count}")
    lines.append(f"Unexpected Failures:  {unexpected_failures_count}")
    lines.append("")

    # Determine overall status
    # PASS only if there are zero unexpected failures
    overall_status = "PASS" if unexpected_failures_count == 0 else "FAIL"
    lines.append(f"Overall Status:       {overall_status}")
    lines.append("")

    # Add clarity note if expected failures are present
    if expected_failures_count > 0:
        lines.append("NOTE: Expected failures are intentional test cases that verify")
        lines.append("      the system correctly rejects unsafe operations.")
        lines.append("      These do not indicate regressions.")
        lines.append("")
        lines.append("Expected failure test IDs:")
        for r in expected_failure_results:
            lines.append(f"  - {r['id']}: {r['title']}")
        lines.append("")

    # Per-test results
    lines.append("=" * 80)
    lines.append("Test Results")
    lines.append("=" * 80)

    for result in results:
        lines.append("")
        lines.append("-" * 80)
        lines.append(f"Test ID: {result['id']}")
        lines.append("-" * 80)
        lines.append(f"Title:   {result['title']}")
        lines.append(f"Command: {' '.join(result['command'])}")
        lines.append(f"Result:  {'PASS' if result['passed'] else 'FAIL'}")
        if result.get("expected_failure"):
            lines.append("Note:    This is an EXPECTED FAILURE by design")
        lines.append(f"Duration: {result['duration']:.3f}s")
        lines.append(f"Exit Code: {result['exit_code']}")

        # Spec mapping
        spec = result.get("spec", {})
        if spec:
            lines.append("")
            lines.append("Spec Mapping:")
            if spec.get("internal"):
                lines.append(f"  Internal:  {spec['internal']}")
            if spec.get("nist"):
                lines.append(f"  NIST RMF:  {spec['nist']}")
            if spec.get("federal"):
                lines.append(f"  Federal:   {spec['federal']}")

        # Notes
        if result.get("notes"):
            lines.append("")
            lines.append(f"Notes: {result['notes']}")

        # Failures
        if result["failures"]:
            lines.append("")
            lines.append("Failures:")
            for failure in result["failures"]:
                lines.append(f"  - {failure}")

        # stdout
        lines.append("")
        lines.append("stdout:")
        stdout = result["stdout"].strip()
        if stdout:
            for line in stdout.split("\n")[:50]:  # Limit output
                lines.append(f"  {line}")
            if stdout.count("\n") > 50:
                lines.append("  ... (truncated)")
        else:
            lines.append("  (empty)")

        # stderr
        lines.append("")
        lines.append("stderr:")
        stderr = result["stderr"].strip()
        if stderr:
            for line in stderr.split("\n")[:20]:  # Limit output
                lines.append(f"  {line}")
            if stderr.count("\n") > 20:
                lines.append("  ... (truncated)")
        else:
            lines.append("  (empty)")

    # Footer
    lines.append("")
    lines.append("=" * 80)
    lines.append("End of Report")
    lines.append("=" * 80)
    lines.append("")

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="AICtrl Baseline Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes:
  0 - All tests passed (or verification succeeded)
  1 - One or more unexpected test failures (or verification failed)

Output files:
  aictrl_baseline_<timestamp>.txt      - ASCII report (always)
  aictrl_baseline_<timestamp>.json     - JSON attestation (--emit-json)
  aictrl_spec_coverage_<timestamp>.txt - Coverage index (--emit-coverage)
  aictrl-baseline.digest.txt           - Cryptographic digest (--emit-digest)

Verification mode:
  python run_baseline.py --verify <artifact_dir>

  Verifies existing artifacts without executing tests.
  Compares file hashes against stored digest.
"""
    )
    parser.add_argument(
        "--emit-json",
        action="store_true",
        help="Also emit a JSON attestation artifact"
    )
    parser.add_argument(
        "--emit-coverage",
        action="store_true",
        help="Also emit a spec coverage index"
    )
    parser.add_argument(
        "--emit-digest",
        action="store_true",
        help="Also emit a cryptographic digest file for verification"
    )
    parser.add_argument(
        "--emit-coverage-json",
        action="store_true",
        help="Also emit a spec coverage index in JSON format"
    )
    parser.add_argument(
        "--gpg-sign",
        action="store_true",
        help="Sign attestation and digest files with GPG (opt-in)"
    )
    parser.add_argument(
        "--gpg-key-id",
        metavar="KEY_ID",
        help="Use specific GPG key for signing (default: default key)"
    )
    parser.add_argument(
        "--verify",
        metavar="DIR",
        type=Path,
        help="Verify existing artifacts (read-only, no test execution)"
    )
    parser.add_argument(
        "--verify-gpg",
        metavar="DIR",
        type=Path,
        help="Verify GPG signatures in artifact directory"
    )
    parser.add_argument(
        "--validate-schema",
        action="store_true",
        help="Validate generated JSON attestation against schema (auto-enabled in CI)"
    )
    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Handle verification modes separately
    if args.verify:
        return verify_artifacts(args.verify)

    if args.verify_gpg:
        return verify_gpg_signatures(args.verify_gpg)

    print("AICtrl Baseline Test Runner")
    print("=" * 40)

    # Load baseline
    print("Loading baseline definitions...")
    baseline = load_baseline()
    tests = baseline.get("tests", [])
    print(f"Found {len(tests)} tests")

    # Collect host metadata
    print("Collecting host metadata...")
    host_meta = get_host_metadata()

    # Collect git provenance
    print("Collecting provenance metadata...")
    provenance = get_git_provenance()

    # Generate timestamp
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")

    # Run tests
    print("Running tests...")
    print("-" * 40)
    results = []
    for i, test in enumerate(tests, 1):
        test_id = test["id"]
        title = test["title"]
        print(f"[{i}/{len(tests)}] {test_id}: {title}...", end=" ", flush=True)

        result = run_test(test)
        results.append(result)

        status = "PASS" if result["passed"] else "FAIL"
        if result.get("expected_failure") and not result["passed"]:
            status = "FAIL (expected)"
        print(status)

    print("-" * 40)

    # Track generated files for digest
    generated_files = {}

    # Generate and write ASCII report (always)
    print("Generating ASCII report...")
    report = generate_report(baseline, results, host_meta, timestamp)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    report_filename = f"aictrl_baseline_{timestamp}.txt"
    report_path = RESULTS_DIR / report_filename

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"  Written: {report_path}")
    generated_files["aictrl-baseline-report.txt"] = report_path

    # Generate and write JSON attestation (optional)
    json_path = None
    attestation = None
    if args.emit_json:
        print("Generating JSON attestation...")
        attestation = generate_attestation(
            baseline, results, host_meta, timestamp, provenance
        )

        json_filename = f"aictrl_baseline_{timestamp}.json"
        json_path = RESULTS_DIR / json_filename

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(attestation, f, indent=2, sort_keys=True)

        print(f"  Written: {json_path}")
        generated_files["aictrl-baseline-attestation.json"] = json_path

        # Validate schema if requested or in CI mode
        should_validate = args.validate_schema or os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS")
        if should_validate:
            print("Validating attestation schema...")
            is_valid, schema_errors = validate_attestation_schema(attestation)
            if is_valid:
                print("  Schema validation: PASSED")
            else:
                print("  Schema validation: FAILED")
                for err in schema_errors:
                    print(f"    - {err}")
                # Don't fail the run, but warn
                print("  WARNING: Attestation does not conform to schema")

    # Generate and write coverage index (optional)
    if args.emit_coverage:
        print("Generating spec coverage index...")
        coverage = generate_coverage_index(baseline)

        coverage_filename = f"aictrl_spec_coverage_{timestamp}.txt"
        coverage_path = RESULTS_DIR / coverage_filename

        with open(coverage_path, "w", encoding="utf-8") as f:
            f.write(coverage)

        print(f"  Written: {coverage_path}")
        generated_files["aictrl-spec-coverage.txt"] = coverage_path

    # Generate and write JSON coverage index (optional)
    if args.emit_coverage_json:
        print("Generating JSON spec coverage index...")
        coverage_json = generate_coverage_index_json(baseline)

        coverage_json_filename = f"aictrl_spec_coverage_{timestamp}.json"
        coverage_json_path = RESULTS_DIR / coverage_json_filename

        with open(coverage_json_path, "w", encoding="utf-8") as f:
            json.dump(coverage_json, f, indent=2, sort_keys=True)

        print(f"  Written: {coverage_json_path}")
        generated_files["aictrl-spec-coverage.json"] = coverage_json_path

    # Generate and write cryptographic digest (optional)
    if args.emit_digest:
        print("Generating cryptographic digest...")
        baseline_info = baseline.get("baseline", {})

        # Create stable copies of artifacts for verification
        # The digest references stable names, so we need these copies to exist
        stable_files = {}
        for stable_name, timestamped_path in generated_files.items():
            stable_path = RESULTS_DIR / stable_name
            shutil.copy2(timestamped_path, stable_path)
            stable_files[stable_name] = stable_path

        # Copy the manifest file to results directory
        if MANIFEST_FILE.exists():
            manifest_dest = RESULTS_DIR / "aictrl-baseline-manifest.json"
            shutil.copy2(MANIFEST_FILE, manifest_dest)
            stable_files["aictrl-baseline-manifest.json"] = manifest_dest
            print(f"  Copied manifest: {manifest_dest}")

        digest_content = generate_digest_file(
            baseline_info,
            timestamp,
            stable_files,
            git_commit=provenance.get("git_commit")
        )

        digest_filename = "aictrl-baseline.digest.txt"
        digest_path = RESULTS_DIR / digest_filename

        with open(digest_path, "w", encoding="utf-8") as f:
            f.write(digest_content)

        print(f"  Written: {digest_path}")

    # GPG signing (optional, opt-in)
    if args.gpg_sign:
        print("Signing artifacts with GPG...")
        signed_files = []

        # Sign attestation JSON if it exists
        if json_path and json_path.exists():
            stable_json = RESULTS_DIR / "aictrl-baseline-attestation.json"
            success, message, sig_path = gpg_sign_file(stable_json, args.gpg_key_id)
            if success:
                print(f"  {message}")
                signed_files.append(sig_path)
            else:
                print(f"  WARNING: {message}")

        # Sign digest file if it exists
        digest_path = RESULTS_DIR / "aictrl-baseline.digest.txt"
        if digest_path.exists():
            success, message, sig_path = gpg_sign_file(digest_path, args.gpg_key_id)
            if success:
                print(f"  {message}")
                signed_files.append(sig_path)
            else:
                print(f"  WARNING: {message}")

        if signed_files:
            print(f"  Signed {len(signed_files)} file(s)")
            print("")
            print("To verify signatures:")
            print("  gpg --verify aictrl-baseline-attestation.json.sig aictrl-baseline-attestation.json")
            print("  gpg --verify aictrl-baseline.digest.txt.sig aictrl-baseline.digest.txt")
        else:
            print("  No files were signed (GPG may not be configured)")

    # Summary - compute clear categories for console output
    total = len(results)
    passed = sum(1 for r in results if r["passed"])

    # Expected failures: tests marked expected_failure=True that actually failed
    expected_failure_results = [
        r for r in results
        if r.get("expected_failure", False) and not r["passed"]
    ]
    expected_failures_count = len(expected_failure_results)

    # Unexpected failures: tests NOT marked expected_failure that failed
    unexpected_failure_results = [
        r for r in results
        if not r["passed"] and not r.get("expected_failure", False)
    ]
    unexpected_failures_count = len(unexpected_failure_results)

    print("")
    print("=" * 40)
    print("Results Summary")
    print("-" * 40)
    print(f"Total:               {total}")
    print(f"Passed:              {passed}")
    print(f"Expected Failures:   {expected_failures_count}")
    print(f"Unexpected Failures: {unexpected_failures_count}")

    # Show expected failures for clarity
    if expected_failures_count > 0:
        print("")
        print("Expected failures (by design):")
        for r in expected_failure_results:
            print(f"  - {r['id']}: {r['title']}")

    # Determine exit code based on unexpected failures only
    if unexpected_failures_count > 0:
        print("")
        print("UNEXPECTED FAILURES (regressions):")
        for r in unexpected_failure_results:
            print(f"  - {r['id']}: {r['title']}")
        print("")
        print("BASELINE: FAIL")
        return 1
    else:
        print("")
        print("BASELINE: PASS")
        return 0


if __name__ == "__main__":
    sys.exit(main())
