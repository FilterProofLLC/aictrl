"""AICtrl Demo Command.

Provides a polished, client-facing demonstration run that generates
the standard baseline artifacts and prints clear next steps.

This command is:
- Read-only with respect to host safety (no privileged actions)
- Deterministic and offline-safe
- Produces ASCII-only output in reports
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def run_demo(
    output_dir: str = None,
    quick: bool = False,
    verbose: bool = True,
) -> dict:
    """Run the AICtrl baseline demo.

    Args:
        output_dir: Output directory for artifacts (default: auto-generated)
        quick: If True, suppress verbose per-test output
        verbose: If True, print progress to stdout

    Returns:
        Dict with demo results including paths to generated artifacts
    """
    # Determine paths
    script_dir = Path(__file__).parent.parent.parent.resolve()
    baseline_script = script_dir / "baseline" / "run_baseline.py"
    default_results_dir = script_dir / "baseline" / "results"

    if not baseline_script.exists():
        return {
            "success": False,
            "error": f"Baseline script not found: {baseline_script}",
        }

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
        print("AICtrl Baseline Demo")
        print("=" * 60)
        print("")
        print(f"Output directory: {out_path}")
        print("")

    # Build baseline command
    cmd = [
        sys.executable,
        str(baseline_script),
        "--emit-json",
        "--emit-coverage",
        "--emit-digest",
    ]

    # Run baseline
    if verbose:
        if quick:
            print("Running baseline (quick mode)...")
        else:
            print("Running baseline tests...")
        print("-" * 60)

    env = os.environ.copy()
    cwd = script_dir / "baseline"

    try:
        if quick:
            # Quick mode: capture output and only show summary
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
            stderr = result.stderr

            # In quick mode, only show key lines
            if verbose:
                for line in stdout.split("\n"):
                    if any(key in line for key in [
                        "BASELINE:", "Total:", "Passed:", "Failed:",
                        "Expected Failures:", "Unexpected Failures:",
                        "Written:", "PASS", "FAIL"
                    ]):
                        print(line)
        else:
            # Full mode: stream output
            result = subprocess.run(
                cmd,
                capture_output=False,
                text=True,
                timeout=300,
                env=env,
                cwd=cwd,
            )
            exit_code = result.returncode
            stdout = ""
            stderr = ""

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Baseline execution timed out (300s limit)",
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Baseline execution failed: {e}",
        }

    if verbose:
        print("-" * 60)
        print("")

    # Copy artifacts to output directory
    artifacts = {}
    artifact_names = [
        "aictrl-baseline-report.txt",
        "aictrl-baseline-attestation.json",
        "aictrl-spec-coverage.txt",
        "aictrl-spec-coverage.json",
        "aictrl-baseline.digest.txt",
        "aictrl-baseline-manifest.json",
    ]

    if verbose:
        print("Copying artifacts to output directory...")

    for name in artifact_names:
        src = default_results_dir / name
        if src.exists():
            dst = out_path / name
            shutil.copy2(src, dst)
            artifacts[name] = str(dst)
            if verbose:
                print(f"  {name}")

    # Load attestation to get summary info
    summary = {
        "total_tests": 0,
        "passed": 0,
        "failed": 0,
        "expected_failures": 0,
        "unexpected_failures": 0,
        "overall_result": "UNKNOWN",
    }
    expected_failure_details = []

    attestation_path = out_path / "aictrl-baseline-attestation.json"
    if attestation_path.exists():
        try:
            with open(attestation_path, "r") as f:
                attestation = json.load(f)
            summary = attestation.get("summary", summary)
            expected_failure_details = attestation.get("expected_failure_details", [])
        except Exception:
            pass

    # Print demo summary
    if verbose:
        print("")
        print("=" * 60)
        print("Demo Summary")
        print("=" * 60)
        print("")
        print(f"Baseline Result: {summary.get('overall_result', 'UNKNOWN')}")
        print("")
        print("Test Results:")
        print(f"  Total:               {summary.get('total_tests', 0)}")
        print(f"  Passed:              {summary.get('passed', 0)}")
        print(f"  Expected Failures:   {summary.get('expected_failures', 0)}")
        print(f"  Unexpected Failures: {summary.get('unexpected_failures', 0)}")
        print("")

        # Show expected failures
        if expected_failure_details:
            print("Expected Failures (by design):")
            for ef in expected_failure_details:
                test_id = ef.get("test_id", "unknown")
                name = ef.get("name", "unknown")
                print(f"  - {test_id}: {name}")
            print("")
            print("NOTE: Expected failures verify that safety guards work correctly.")
            print("      These are NOT regressions.")
            print("")

        # Show artifacts produced
        print("Artifacts Produced:")
        for name, path in sorted(artifacts.items()):
            print(f"  {path}")
        print("")

        # Verification instructions
        print("-" * 60)
        print("Next Steps")
        print("-" * 60)
        print("")
        print("Verify offline (check artifact integrity):")
        print(f"  python baseline/run_baseline.py --verify {out_path}")
        print("")

        # Compare tool instruction
        compare_script = script_dir / "baseline" / "compare_baselines.py"
        if compare_script.exists():
            print("Compare two baseline runs (drift detection):")
            print(f"  python baseline/compare_baselines.py \\")
            print(f"    {out_path}/aictrl-baseline-attestation.json \\")
            print(f"    <other_run>/aictrl-baseline-attestation.json")
            print("")

        print("=" * 60)

    return {
        "success": exit_code == 0,
        "exit_code": exit_code,
        "output_dir": str(out_path),
        "artifacts": artifacts,
        "summary": summary,
        "expected_failure_details": expected_failure_details,
    }
