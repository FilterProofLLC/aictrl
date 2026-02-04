#!/usr/bin/env python3
"""AICtrl Baseline Comparison Tool.

Compares two baseline artifact directories to identify differences in:
- Manifest metadata
- Test counts and pass/fail status
- Spec coverage changes
- Expected failure changes

This tool is informational only and does not gate CI.

Usage:
    python compare_baselines.py <baseline_a_dir> <baseline_b_dir>
    python compare_baselines.py --help

Exit codes:
    0 - Comparison completed (differences may exist)
    1 - Error reading artifacts

Examples:
    python compare_baselines.py results/v1.0.0 results/v1.1.0
    python compare_baselines.py /path/to/old /path/to/new --json
"""

import argparse
import json
import sys
from pathlib import Path


def load_json_file(file_path: Path) -> dict:
    """Load and parse a JSON file."""
    if not file_path.exists():
        return None
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_baseline_artifacts(artifact_dir: Path) -> dict:
    """Load all baseline artifacts from a directory.

    Args:
        artifact_dir: Path to directory containing baseline artifacts

    Returns:
        Dict containing loaded artifacts (or None for missing files)
    """
    return {
        "manifest": load_json_file(artifact_dir / "aictrl-baseline-manifest.json"),
        "attestation": load_json_file(artifact_dir / "aictrl-baseline-attestation.json"),
        "coverage": load_json_file(artifact_dir / "aictrl-spec-coverage.json"),
        "directory": artifact_dir,
    }


def compare_manifests(manifest_a: dict, manifest_b: dict) -> list:
    """Compare two manifest files.

    Returns:
        List of difference descriptions
    """
    differences = []

    if manifest_a is None and manifest_b is None:
        return ["Both manifests missing"]
    if manifest_a is None:
        return ["Manifest A missing"]
    if manifest_b is None:
        return ["Manifest B missing"]

    # Compare versions
    ver_a = manifest_a.get("baseline_version", "unknown")
    ver_b = manifest_b.get("baseline_version", "unknown")
    if ver_a != ver_b:
        differences.append(f"baseline_version: {ver_a} -> {ver_b}")

    # Compare target versions
    target_a = manifest_a.get("target_aictrl_version", "unknown")
    target_b = manifest_b.get("target_aictrl_version", "unknown")
    if target_a != target_b:
        differences.append(f"target_aictrl_version: {target_a} -> {target_b}")

    # Compare expected fail test IDs
    fails_a = set(manifest_a.get("expected_fail_test_ids", []))
    fails_b = set(manifest_b.get("expected_fail_test_ids", []))
    if fails_a != fails_b:
        added = fails_b - fails_a
        removed = fails_a - fails_b
        if added:
            differences.append(f"expected_fail_test_ids added: {sorted(added)}")
        if removed:
            differences.append(f"expected_fail_test_ids removed: {sorted(removed)}")

    # Compare summary
    summary_a = manifest_a.get("summary", {})
    summary_b = manifest_b.get("summary", {})
    for key in ["total_tests", "expected_pass", "expected_fail"]:
        val_a = summary_a.get(key, 0)
        val_b = summary_b.get(key, 0)
        if val_a != val_b:
            delta = val_b - val_a
            sign = "+" if delta > 0 else ""
            differences.append(f"summary.{key}: {val_a} -> {val_b} ({sign}{delta})")

    return differences


def compare_test_results(attest_a: dict, attest_b: dict) -> dict:
    """Compare test results from two attestations.

    Returns:
        Dict with comparison details
    """
    result = {
        "status_changes": [],
        "added_tests": [],
        "removed_tests": [],
        "duration_changes": [],
    }

    if attest_a is None or attest_b is None:
        return result

    # Build test result maps
    tests_a = {t["test_id"]: t for t in attest_a.get("test_results", [])}
    tests_b = {t["test_id"]: t for t in attest_b.get("test_results", [])}

    ids_a = set(tests_a.keys())
    ids_b = set(tests_b.keys())

    # Find added/removed tests
    result["added_tests"] = sorted(ids_b - ids_a)
    result["removed_tests"] = sorted(ids_a - ids_b)

    # Compare common tests
    for test_id in sorted(ids_a & ids_b):
        test_a = tests_a[test_id]
        test_b = tests_b[test_id]

        # Check for pass/fail changes
        status_a = test_a.get("pass_fail", "UNKNOWN")
        status_b = test_b.get("pass_fail", "UNKNOWN")
        if status_a != status_b:
            result["status_changes"].append({
                "test_id": test_id,
                "old_status": status_a,
                "new_status": status_b,
                "description": test_b.get("description", ""),
            })

        # Check for significant duration changes (>50% change)
        dur_a = test_a.get("duration_seconds", 0)
        dur_b = test_b.get("duration_seconds", 0)
        if dur_a > 0.1 and dur_b > 0.1:  # Only compare meaningful durations
            ratio = dur_b / dur_a
            if ratio > 1.5 or ratio < 0.67:
                result["duration_changes"].append({
                    "test_id": test_id,
                    "old_duration": round(dur_a, 3),
                    "new_duration": round(dur_b, 3),
                    "change_percent": round((ratio - 1) * 100, 1),
                })

    return result


def compare_coverage(coverage_a: dict, coverage_b: dict) -> dict:
    """Compare spec coverage between two baselines.

    Returns:
        Dict with coverage comparison details
    """
    result = {
        "nist_changes": [],
        "internal_changes": [],
        "federal_changes": [],
        "summary_changes": [],
    }

    if coverage_a is None or coverage_b is None:
        return result

    # Compare NIST controls
    nist_a = coverage_a.get("nist_controls", {})
    nist_b = coverage_b.get("nist_controls", {})

    all_controls = set(nist_a.keys()) | set(nist_b.keys())
    for control in sorted(all_controls):
        ctrl_a = nist_a.get(control, {})
        ctrl_b = nist_b.get(control, {})

        status_a = ctrl_a.get("coverage_status", "NONE")
        status_b = ctrl_b.get("coverage_status", "NONE")
        count_a = ctrl_a.get("test_count", 0)
        count_b = ctrl_b.get("test_count", 0)

        if status_a != status_b or count_a != count_b:
            result["nist_changes"].append({
                "control_id": control,
                "old_status": status_a,
                "new_status": status_b,
                "old_count": count_a,
                "new_count": count_b,
            })

    # Compare summary
    summary_a = coverage_a.get("summary", {})
    summary_b = coverage_b.get("summary", {})
    for key in ["nist_full", "nist_partial", "nist_none",
                "internal_invariants_covered", "federal_policies_covered"]:
        val_a = summary_a.get(key, 0)
        val_b = summary_b.get(key, 0)
        if val_a != val_b:
            result["summary_changes"].append({
                "metric": key,
                "old_value": val_a,
                "new_value": val_b,
                "delta": val_b - val_a,
            })

    return result


def format_comparison_report(
    dir_a: Path,
    dir_b: Path,
    manifest_diff: list,
    test_diff: dict,
    coverage_diff: dict,
) -> str:
    """Format the comparison as a human-readable report.

    Returns:
        ASCII text report
    """
    lines = []
    lines.append("=" * 80)
    lines.append("AICtrl Baseline Comparison Report")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"Baseline A: {dir_a}")
    lines.append(f"Baseline B: {dir_b}")
    lines.append("")

    # Manifest differences
    lines.append("-" * 80)
    lines.append("Manifest Differences")
    lines.append("-" * 80)
    if manifest_diff:
        for diff in manifest_diff:
            lines.append(f"  {diff}")
    else:
        lines.append("  (no differences)")
    lines.append("")

    # Test result changes
    lines.append("-" * 80)
    lines.append("Test Result Changes")
    lines.append("-" * 80)

    if test_diff.get("added_tests"):
        lines.append(f"  Added tests: {', '.join(test_diff['added_tests'])}")
    if test_diff.get("removed_tests"):
        lines.append(f"  Removed tests: {', '.join(test_diff['removed_tests'])}")

    if test_diff.get("status_changes"):
        lines.append("")
        lines.append("  Status changes:")
        for change in test_diff["status_changes"]:
            lines.append(f"    {change['test_id']}: {change['old_status']} -> {change['new_status']}")
            lines.append(f"      ({change['description']})")
    elif not test_diff.get("added_tests") and not test_diff.get("removed_tests"):
        lines.append("  (no test status changes)")

    if test_diff.get("duration_changes"):
        lines.append("")
        lines.append("  Significant duration changes:")
        for change in test_diff["duration_changes"]:
            sign = "+" if change['change_percent'] > 0 else ""
            lines.append(f"    {change['test_id']}: {change['old_duration']}s -> {change['new_duration']}s ({sign}{change['change_percent']}%)")
    lines.append("")

    # Coverage changes
    lines.append("-" * 80)
    lines.append("Coverage Changes")
    lines.append("-" * 80)

    if coverage_diff.get("nist_changes"):
        lines.append("  NIST control changes:")
        for change in coverage_diff["nist_changes"]:
            lines.append(f"    {change['control_id']}: {change['old_status']}({change['old_count']}) -> {change['new_status']}({change['new_count']})")
    else:
        lines.append("  (no NIST coverage changes)")

    if coverage_diff.get("summary_changes"):
        lines.append("")
        lines.append("  Coverage summary changes:")
        for change in coverage_diff["summary_changes"]:
            sign = "+" if change['delta'] > 0 else ""
            lines.append(f"    {change['metric']}: {change['old_value']} -> {change['new_value']} ({sign}{change['delta']})")
    lines.append("")

    # Summary
    lines.append("=" * 80)
    total_changes = (
        len(manifest_diff) +
        len(test_diff.get("status_changes", [])) +
        len(test_diff.get("added_tests", [])) +
        len(test_diff.get("removed_tests", [])) +
        len(coverage_diff.get("nist_changes", [])) +
        len(coverage_diff.get("summary_changes", []))
    )

    if total_changes == 0:
        lines.append("Summary: IDENTICAL - No significant differences detected")
    else:
        lines.append(f"Summary: {total_changes} difference(s) detected")
        if test_diff.get("status_changes"):
            regression_count = sum(
                1 for c in test_diff["status_changes"]
                if c["old_status"] == "PASS" and c["new_status"] == "FAIL"
            )
            if regression_count > 0:
                lines.append(f"  WARNING: {regression_count} test regression(s) detected")
    lines.append("=" * 80)

    return "\n".join(lines)


def format_comparison_json(
    dir_a: Path,
    dir_b: Path,
    manifest_diff: list,
    test_diff: dict,
    coverage_diff: dict,
) -> dict:
    """Format the comparison as JSON."""
    return {
        "baseline_a": str(dir_a),
        "baseline_b": str(dir_b),
        "manifest_differences": manifest_diff,
        "test_result_changes": test_diff,
        "coverage_changes": coverage_diff,
        "summary": {
            "manifest_diff_count": len(manifest_diff),
            "test_status_changes": len(test_diff.get("status_changes", [])),
            "tests_added": len(test_diff.get("added_tests", [])),
            "tests_removed": len(test_diff.get("removed_tests", [])),
            "nist_changes": len(coverage_diff.get("nist_changes", [])),
            "coverage_summary_changes": len(coverage_diff.get("summary_changes", [])),
        },
    }


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Compare two AICtrl baseline artifact directories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This tool is informational only and does not gate CI.
Use it to understand changes between baseline versions.

Examples:
  python compare_baselines.py results/v1.0.0 results/v1.1.0
  python compare_baselines.py /old/artifacts /new/artifacts --json
"""
    )
    parser.add_argument(
        "baseline_a",
        type=Path,
        help="Path to first baseline artifact directory (older)"
    )
    parser.add_argument(
        "baseline_b",
        type=Path,
        help="Path to second baseline artifact directory (newer)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output comparison as JSON instead of text"
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Write output to file instead of stdout"
    )
    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Validate directories
    if not args.baseline_a.exists():
        print(f"ERROR: Directory not found: {args.baseline_a}", file=sys.stderr)
        return 1
    if not args.baseline_b.exists():
        print(f"ERROR: Directory not found: {args.baseline_b}", file=sys.stderr)
        return 1

    # Load artifacts
    artifacts_a = load_baseline_artifacts(args.baseline_a)
    artifacts_b = load_baseline_artifacts(args.baseline_b)

    # Check if we have at least some artifacts to compare
    if artifacts_a["manifest"] is None and artifacts_a["attestation"] is None:
        print(f"WARNING: No artifacts found in {args.baseline_a}", file=sys.stderr)
    if artifacts_b["manifest"] is None and artifacts_b["attestation"] is None:
        print(f"WARNING: No artifacts found in {args.baseline_b}", file=sys.stderr)

    # Perform comparisons
    manifest_diff = compare_manifests(
        artifacts_a["manifest"],
        artifacts_b["manifest"]
    )

    test_diff = compare_test_results(
        artifacts_a["attestation"],
        artifacts_b["attestation"]
    )

    coverage_diff = compare_coverage(
        artifacts_a["coverage"],
        artifacts_b["coverage"]
    )

    # Format output
    if args.json:
        output = json.dumps(
            format_comparison_json(
                args.baseline_a, args.baseline_b,
                manifest_diff, test_diff, coverage_diff
            ),
            indent=2,
            sort_keys=True
        )
    else:
        output = format_comparison_report(
            args.baseline_a, args.baseline_b,
            manifest_diff, test_diff, coverage_diff
        )

    # Write output
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Comparison written to: {args.output}")
    else:
        print(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
