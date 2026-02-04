"""AICtrl Demo Command.

Provides a polished, client-facing demonstration run that showcases
key capabilities from versions 1.2.0 through 1.4.0:
- 1.2.x: Cryptographic status/readiness reporting
- 1.3.x: Baseline test and evidence artifacts workflow
- 1.4.0: Phase 12 Part 1 exec propose/review (no side effects)

This command is:
- Read-only with respect to host safety (no privileged actions)
- Deterministic and offline-safe
- Produces ASCII-only output in reports
- Only creates files under the explicit --out directory
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _run_aictrl_command(args: list[str], cwd: Path = None) -> tuple[int, str, str]:
    """Run an aictrl CLI command and return (exit_code, stdout, stderr)."""
    cmd = [sys.executable, "-m", "aictrl"] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=cwd,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "Command timed out"
    except Exception as e:
        return 1, "", str(e)


def _demo_step_version(out_path: Path, verbose: bool) -> dict[str, Any]:
    """Step 1: Version evidence."""
    if verbose:
        print("")
        print("Step 1: Version Evidence")
        print("-" * 40)

    exit_code, stdout, stderr = _run_aictrl_command(["version", "--json"])

    version_file = out_path / "version.json"
    if exit_code == 0 and stdout.strip():
        try:
            version_data = json.loads(stdout)
            with open(version_file, "w") as f:
                json.dump(version_data, f, indent=2)

            name = version_data.get("name", "unknown")
            version = version_data.get("version", "unknown")
            phase = version_data.get("phase", "unknown")
            commit = version_data.get("commit", "unknown")[:8] if version_data.get("commit") else "unknown"

            if verbose:
                print(f"  version ok: {name} v{version} phase={phase} commit={commit}")

            return {
                "success": True,
                "file": str(version_file),
                "data": version_data,
            }
        except json.JSONDecodeError:
            pass

    if verbose:
        print(f"  [WARN] version capture failed: {stderr}")
    return {"success": False, "error": stderr}


def _demo_step_crypto(out_path: Path, verbose: bool) -> dict[str, Any]:
    """Step 2: Crypto status/readiness (1.2.x)."""
    if verbose:
        print("")
        print("Step 2: Crypto Status/Readiness (1.2.x)")
        print("-" * 40)

    # Try crypto status
    exit_code, stdout, stderr = _run_aictrl_command(["crypto", "status"])

    if exit_code != 0:
        if verbose:
            print("  [SKIP] crypto status command not available")
        return {"success": False, "skipped": True, "reason": "crypto command not available"}

    crypto_data = {}
    try:
        crypto_data["status"] = json.loads(stdout)
    except json.JSONDecodeError:
        crypto_data["status_raw"] = stdout

    # Also try crypto readiness
    exit_code2, stdout2, stderr2 = _run_aictrl_command(["crypto", "readiness"])
    if exit_code2 == 0 and stdout2.strip():
        try:
            crypto_data["readiness"] = json.loads(stdout2)
        except json.JSONDecodeError:
            crypto_data["readiness_raw"] = stdout2

    crypto_file = out_path / "crypto_status.json"
    with open(crypto_file, "w") as f:
        json.dump(crypto_data, f, indent=2)

    # Extract summary info
    status = crypto_data.get("status", {})
    readiness = crypto_data.get("readiness", {})

    library = status.get("library", "unknown")
    ready = readiness.get("ready", status.get("operational", False))
    ready_str = "ready" if ready else "not ready"

    if verbose:
        print(f"  crypto ok: library={library}, status={ready_str}")

    return {
        "success": True,
        "file": str(crypto_file),
        "data": crypto_data,
    }


def _demo_step_baseline(
    out_path: Path,
    script_dir: Path,
    default_results_dir: Path,
    quick: bool,
    verbose: bool,
) -> dict[str, Any]:
    """Step 3: Baseline test evidence (1.3.x)."""
    if verbose:
        print("")
        print("Step 3: Baseline Test Evidence (1.3.x)")
        print("-" * 40)

    baseline_script = script_dir / "baseline" / "run_baseline.py"

    if not baseline_script.exists():
        if verbose:
            print("  [SKIP] baseline script not found")
        return {"success": False, "skipped": True, "reason": "baseline script not found"}

    cmd = [
        sys.executable,
        str(baseline_script),
        "--emit-json",
        "--emit-coverage",
        "--emit-digest",
    ]

    env = os.environ.copy()
    cwd = script_dir / "baseline"

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
            cwd=cwd,
        )
        exit_code = result.returncode
        stdout = result.stdout
    except subprocess.TimeoutExpired:
        if verbose:
            print("  [FAIL] baseline execution timed out")
        return {"success": False, "error": "timeout"}
    except Exception as e:
        if verbose:
            print(f"  [FAIL] baseline execution failed: {e}")
        return {"success": False, "error": str(e)}

    # Copy artifacts
    artifacts = {}
    artifact_names = [
        "aictrl-baseline-report.txt",
        "aictrl-baseline-attestation.json",
        "aictrl-spec-coverage.txt",
        "aictrl-spec-coverage.json",
        "aictrl-baseline.digest.txt",
        "aictrl-baseline-manifest.json",
    ]

    for name in artifact_names:
        src = default_results_dir / name
        if src.exists():
            dst = out_path / name
            shutil.copy2(src, dst)
            artifacts[name] = str(dst)

    # Load attestation for summary
    summary = {
        "total_tests": 0,
        "passed": 0,
        "expected_failures": 0,
        "unexpected_failures": 0,
        "overall_result": "UNKNOWN",
    }

    attestation_path = out_path / "aictrl-baseline-attestation.json"
    if attestation_path.exists():
        try:
            with open(attestation_path, "r") as f:
                attestation = json.load(f)
            summary = attestation.get("summary", summary)
        except Exception:
            pass

    # Write summary file
    summary_file = out_path / "baseline_summary.txt"
    with open(summary_file, "w") as f:
        f.write("AICtrl Baseline Test Summary\n")
        f.write("=" * 40 + "\n")
        f.write(f"Total Tests:         {summary.get('total_tests', 0)}\n")
        f.write(f"Passed:              {summary.get('passed', 0)}\n")
        f.write(f"Expected Failures:   {summary.get('expected_failures', 0)}\n")
        f.write(f"Unexpected Failures: {summary.get('unexpected_failures', 0)}\n")
        f.write(f"Overall Result:      {summary.get('overall_result', 'UNKNOWN')}\n")
    artifacts["baseline_summary.txt"] = str(summary_file)

    if verbose:
        total = summary.get("total_tests", 0)
        passed = summary.get("passed", 0)
        expected = summary.get("expected_failures", 0)
        unexpected = summary.get("unexpected_failures", 0)
        result_str = summary.get("overall_result", "UNKNOWN")
        print(f"  baseline ok: {passed}/{total} pass, {expected} expected fail, {unexpected} unexpected fail")
        print(f"  result: {result_str}")

    return {
        "success": exit_code == 0,
        "exit_code": exit_code,
        "artifacts": artifacts,
        "summary": summary,
    }


def _demo_step_exec_propose_review(out_path: Path, verbose: bool) -> dict[str, Any]:
    """Step 4: Phase 12 Part 1 exec propose/review (1.4.0)."""
    if verbose:
        print("")
        print("Step 4: Phase 12 Part 1 - Exec Propose/Review (1.4.0)")
        print("-" * 40)

    results = {
        "propose_safe": None,
        "dangerous_gate": None,
        "review_valid": None,
        "tamper_detection": None,
    }

    # 4a) Safe proposal (should succeed)
    if verbose:
        print("  4a) Safe proposal creation...")

    proposal_file = out_path / "exec_proposal.json"
    exit_code, stdout, stderr = _run_aictrl_command([
        "exec", "propose",
        "--action", "read",
        "--target", "/etc/hosts",
        "--adapter", "noop",
        "--out", str(proposal_file),
        "--overwrite",
    ])

    if exit_code == 0:
        try:
            with open(proposal_file, "r") as f:
                proposal_data = json.load(f)
            proposal_id = proposal_data.get("proposal_id", "unknown")[:12]
            content_hash = proposal_data.get("content_hash", "unknown")[:16]
            if verbose:
                print(f"      propose ok: proposal_id={proposal_id}..., content_hash={content_hash}...")
            results["propose_safe"] = {"success": True, "file": str(proposal_file)}
        except Exception as e:
            if verbose:
                print(f"      [FAIL] could not parse proposal: {e}")
            results["propose_safe"] = {"success": False, "error": str(e)}
    else:
        if verbose:
            print(f"      [FAIL] propose failed: {stderr}")
        results["propose_safe"] = {"success": False, "error": stderr}

    # 4b) Dangerous gate (should fail without --dangerous)
    if verbose:
        print("  4b) Dangerous gate test...")

    dangerous_blocked_file = out_path / "exec_propose_dangerous_blocked.txt"
    exit_code, stdout, stderr = _run_aictrl_command([
        "exec", "propose",
        "--action", "write",
        "--target", "/tmp/test",
        "--adapter", "file-write",
        "--out", str(out_path / "should_not_exist.json"),
    ])

    # Write output to file
    with open(dangerous_blocked_file, "w") as f:
        f.write(f"Exit code: {exit_code}\n")
        f.write(f"Stdout:\n{stdout}\n")
        f.write(f"Stderr:\n{stderr}\n")

    if exit_code == 2:
        if verbose:
            print("      dangerous gate ok: blocked (exit 2)")
        results["dangerous_gate"] = {"success": True, "exit_code": exit_code, "file": str(dangerous_blocked_file)}
    else:
        if verbose:
            print(f"      [FAIL] expected exit 2, got {exit_code}")
        results["dangerous_gate"] = {"success": False, "exit_code": exit_code}

    # Clean up the should_not_exist file if it was somehow created
    should_not_exist = out_path / "should_not_exist.json"
    if should_not_exist.exists():
        should_not_exist.unlink()

    # 4c) Review valid proposal (should pass)
    if verbose:
        print("  4c) Review valid proposal...")

    if proposal_file.exists():
        review_valid_file = out_path / "exec_review_valid.json"
        exit_code, stdout, stderr = _run_aictrl_command([
            "exec", "review",
            "--proposal", str(proposal_file),
        ])

        if exit_code == 0 and stdout.strip():
            try:
                review_data = json.loads(stdout)
                with open(review_valid_file, "w") as f:
                    json.dump(review_data, f, indent=2)
                hash_verified = review_data.get("hash_verified", False)
                if verbose:
                    print(f"      review ok: hash_verified={hash_verified}")
                results["review_valid"] = {"success": True, "file": str(review_valid_file)}
            except json.JSONDecodeError:
                with open(review_valid_file, "w") as f:
                    f.write(stdout)
                if verbose:
                    print("      review ok (non-JSON output)")
                results["review_valid"] = {"success": True, "file": str(review_valid_file)}
        else:
            if verbose:
                print(f"      [FAIL] review failed: {stderr}")
            results["review_valid"] = {"success": False, "error": stderr}
    else:
        if verbose:
            print("      [SKIP] no valid proposal to review")
        results["review_valid"] = {"success": False, "skipped": True}

    # 4d) Tamper detection (should fail)
    if verbose:
        print("  4d) Tamper detection test...")

    if proposal_file.exists():
        # Create tampered copy
        tampered_file = out_path / "exec_proposal_tampered.json"
        try:
            with open(proposal_file, "r") as f:
                proposal_data = json.load(f)

            # Tamper with the target field (change /etc/hosts to /etc/passwd)
            if "request" in proposal_data:
                proposal_data["request"]["target"] = "/etc/passwd"
            else:
                proposal_data["target"] = "/etc/passwd"

            # Write tampered file WITHOUT updating the hash
            with open(tampered_file, "w") as f:
                json.dump(proposal_data, f, indent=2)

            # Try to review the tampered proposal
            review_tampered_file = out_path / "exec_review_tampered.json"
            exit_code, stdout, stderr = _run_aictrl_command([
                "exec", "review",
                "--proposal", str(tampered_file),
            ])

            # Save output
            with open(review_tampered_file, "w") as f:
                f.write(f"Exit code: {exit_code}\n")
                f.write(f"Stdout:\n{stdout}\n")
                f.write(f"Stderr:\n{stderr}\n")

            if exit_code == 2:
                if verbose:
                    print("      tamper detection ok: blocked (exit 2)")
                results["tamper_detection"] = {"success": True, "exit_code": exit_code, "file": str(review_tampered_file)}
            else:
                if verbose:
                    print(f"      [FAIL] expected exit 2 for tampered proposal, got {exit_code}")
                results["tamper_detection"] = {"success": False, "exit_code": exit_code}

        except Exception as e:
            if verbose:
                print(f"      [FAIL] tamper test error: {e}")
            results["tamper_detection"] = {"success": False, "error": str(e)}
    else:
        if verbose:
            print("      [SKIP] no proposal to tamper with")
        results["tamper_detection"] = {"success": False, "skipped": True}

    return results


def _demo_step_digest(out_path: Path, verbose: bool) -> dict[str, Any]:
    """Step 5: Evidence digest."""
    if verbose:
        print("")
        print("Step 5: Evidence Digest")
        print("-" * 40)

    digest_file = out_path / "demo_digest.txt"
    digests = []

    # Hash all files in output directory
    for file_path in sorted(out_path.iterdir()):
        if file_path.is_file() and file_path.name != "demo_digest.txt":
            try:
                file_hash = _compute_sha256(file_path)
                digests.append(f"{file_hash}  {file_path.name}")
            except Exception:
                pass

    with open(digest_file, "w") as f:
        f.write("# AICtrl Demo Evidence Digest\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write("# Format: SHA-256  filename\n")
        f.write("\n")
        for line in digests:
            f.write(line + "\n")

    if verbose:
        print(f"  digest ok: {len(digests)} files hashed")

    return {"success": True, "file": str(digest_file), "count": len(digests)}


def run_demo(
    output_dir: str = None,
    quick: bool = False,
    verbose: bool = True,
) -> dict:
    """Run the AICtrl demo showcasing v1.2.0 - v1.4.0 features.

    Args:
        output_dir: Output directory for artifacts (default: auto-generated)
        quick: If True, suppress verbose baseline per-test output
        verbose: If True, print progress to stdout

    Returns:
        Dict with demo results including paths to generated artifacts
    """
    # Determine paths
    script_dir = Path(__file__).parent.parent.parent.resolve()
    default_results_dir = script_dir / "baseline" / "results"

    # Generate timestamp for output directory
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    # Determine output directory
    if output_dir:
        out_path = Path(output_dir)
    else:
        out_path = default_results_dir / f"demo_{timestamp}"

    out_path.mkdir(parents=True, exist_ok=True)

    if verbose:
        print("=" * 60)
        print("AICtrl Demo (v1.2.0 - v1.4.0 Features)")
        print("=" * 60)
        print("")
        print(f"Output directory: {out_path}")

    all_artifacts = {}
    step_results = {}

    # Step 1: Version evidence
    version_result = _demo_step_version(out_path, verbose)
    step_results["version"] = version_result
    if version_result.get("file"):
        all_artifacts["version.json"] = version_result["file"]

    # Step 2: Crypto status/readiness (1.2.x)
    crypto_result = _demo_step_crypto(out_path, verbose)
    step_results["crypto"] = crypto_result
    if crypto_result.get("file"):
        all_artifacts["crypto_status.json"] = crypto_result["file"]

    # Step 3: Baseline test evidence (1.3.x)
    baseline_result = _demo_step_baseline(
        out_path, script_dir, default_results_dir, quick, verbose
    )
    step_results["baseline"] = baseline_result
    if baseline_result.get("artifacts"):
        all_artifacts.update(baseline_result["artifacts"])

    # Step 4: Phase 12 Part 1 exec propose/review (1.4.0)
    exec_result = _demo_step_exec_propose_review(out_path, verbose)
    step_results["exec"] = exec_result

    # Step 5: Evidence digest
    digest_result = _demo_step_digest(out_path, verbose)
    step_results["digest"] = digest_result
    if digest_result.get("file"):
        all_artifacts["demo_digest.txt"] = digest_result["file"]

    # Print final summary
    if verbose:
        print("")
        print("=" * 60)
        print("Demo Complete")
        print("=" * 60)
        print("")
        print("Artifacts produced:")
        for name in sorted(out_path.iterdir()):
            if name.is_file():
                print(f"  {name.name}")
        print("")

        # Phase 12 Part 1 summary
        exec_ok = (
            exec_result.get("propose_safe", {}).get("success", False) and
            exec_result.get("dangerous_gate", {}).get("success", False) and
            exec_result.get("review_valid", {}).get("success", False) and
            exec_result.get("tamper_detection", {}).get("success", False)
        )
        print("Phase 12 Part 1 (exec propose/review):")
        print(f"  Safe proposal:     {'PASS' if exec_result.get('propose_safe', {}).get('success') else 'FAIL'}")
        print(f"  Dangerous gate:    {'PASS' if exec_result.get('dangerous_gate', {}).get('success') else 'FAIL'}")
        print(f"  Review valid:      {'PASS' if exec_result.get('review_valid', {}).get('success') else 'FAIL'}")
        print(f"  Tamper detection:  {'PASS' if exec_result.get('tamper_detection', {}).get('success') else 'FAIL'}")
        print("")

        # Baseline summary
        baseline_summary = baseline_result.get("summary", {})
        if baseline_summary.get("overall_result"):
            print(f"Baseline: {baseline_summary.get('overall_result', 'UNKNOWN')}")
            print("")

        print("-" * 60)
        print("Next Steps")
        print("-" * 60)
        print("")
        print("Verify baseline artifacts:")
        print(f"  python baseline/run_baseline.py --verify {out_path}")
        print("")
        print("Review evidence bundle:")
        print(f"  ls -la {out_path}")
        print("")
        print("=" * 60)

    # Determine overall success
    baseline_ok = baseline_result.get("success", False)
    exec_ok = all([
        exec_result.get("propose_safe", {}).get("success", False),
        exec_result.get("dangerous_gate", {}).get("success", False),
        exec_result.get("review_valid", {}).get("success", False),
        exec_result.get("tamper_detection", {}).get("success", False),
    ])

    return {
        "success": baseline_ok and exec_ok,
        "output_dir": str(out_path),
        "artifacts": all_artifacts,
        "step_results": step_results,
        "summary": baseline_result.get("summary", {}),
    }
