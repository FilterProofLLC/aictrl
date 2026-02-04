"""aictrl CLI - main entry point.

AICtrl is a portable AI control plane that runs on top of an OS.
This is NOT an operating system - it is a management and governance tool.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, __build_timestamp__, __build_id__
from .commands.status import get_status
from .commands.doctor import run_doctor
from .commands.support_bundle import create_support_bundle
from .commands.pr import run_pr_create
from .commands.sandbox import get_sandbox_status, start_sandbox, stop_sandbox
from .commands.evidence import export_evidence_bundle, verify_evidence_bundle
from .commands.boot import simulate_boot_measurements, verify_boot_identity
from .commands.attest import (
    generate_attestation_statement,
    verify_attestation_statement,
    compare_attestation_statements,
)
from .commands.crypto import (
    get_crypto_status,
    get_crypto_readiness,
    get_crypto_algorithms,
)
from .commands.authz import (
    check_authorization,
    get_policy_summary,
    get_enforcement_points,
    VALID_SUBJECTS,
    VALID_ACTIONS,
    VALID_CONTEXTS,
)
from .commands.exec import (
    get_adapters_info,
    get_boundary_info,
    get_readiness_info,
)
from .util.errors import EXIT_SUCCESS, EXIT_FAILURE, EXIT_USAGE_ERROR, AICtrlError
from .util.json_utils import output_json
from .util.safe_exec import (
    run_checked,
    set_risk_accepted,
    check_override_validity,
    get_safety_status,
)


def get_git_commit() -> str:
    """Get current git commit hash if available."""
    try:
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


def cmd_version(args) -> int:
    """Handle version command with build watermarking."""
    data = {
        "name": "aictrl",
        "version": __version__,
        "commit": get_git_commit(),
        # Build watermarking (non-secret, traceable metadata)
        "build_timestamp": __build_timestamp__ or datetime.now(timezone.utc).isoformat(),
        "build_id": __build_id__,
        "product": "AICtrl - Portable AI Control Plane",
    }
    output_json(data, pretty=getattr(args, "pretty", False))
    return EXIT_SUCCESS


def cmd_status(args) -> int:
    """Handle status command."""
    try:
        data = get_status()
        output_json(data, pretty=args.pretty)
        return EXIT_SUCCESS
    except Exception as e:
        output_json({"error": str(e)}, pretty=args.pretty)
        return EXIT_FAILURE


def cmd_doctor(args) -> int:
    """Handle doctor command."""
    try:
        context = getattr(args, "context", None)
        include_invariants = not getattr(args, "no_invariants", False)
        debug = getattr(args, "debug", False)
        data = run_doctor(context=context, include_invariants=include_invariants, debug=debug)
        output_json(data, pretty=args.pretty)

        # Return non-zero if any checks failed
        if data.get("overall_status") == "fail":
            return EXIT_FAILURE
        return EXIT_SUCCESS
    except Exception as e:
        output_json({"error": str(e)}, pretty=args.pretty)
        return EXIT_FAILURE


def cmd_support_bundle(args) -> int:
    """Handle support-bundle command."""
    try:
        result = create_support_bundle(output_path=args.out)
        output_json(result, pretty=getattr(args, "pretty", False))
        return EXIT_SUCCESS
    except Exception as e:
        output_json({"error": str(e)}, pretty=getattr(args, "pretty", False))
        return EXIT_FAILURE


def cmd_pr_create(args) -> int:
    """Handle pr create command."""
    pretty = getattr(args, "pretty", False)
    try:
        result = run_pr_create(
            title=args.title,
            body=args.body or "",
            base=args.base,
            dry_run=args.dry_run,
        )
        output_json(result, pretty=pretty)
        return EXIT_SUCCESS
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_sandbox_status(args) -> int:
    """Handle sandbox status command."""
    pretty = getattr(args, "pretty", False)
    try:
        result = get_sandbox_status()
        output_json(result, pretty=pretty)
        return EXIT_SUCCESS
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_sandbox_start(args) -> int:
    """Handle sandbox start command."""
    pretty = getattr(args, "pretty", False)
    try:
        result = start_sandbox()
        output_json(result, pretty=pretty)
        return EXIT_SUCCESS
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_sandbox_stop(args) -> int:
    """Handle sandbox stop command."""
    pretty = getattr(args, "pretty", False)
    try:
        result = stop_sandbox()
        output_json(result, pretty=pretty)
        return EXIT_SUCCESS
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_evidence_export(args) -> int:
    """Handle evidence export command."""
    pretty = getattr(args, "pretty", True)
    try:
        result = export_evidence_bundle(
            context=getattr(args, "context", None),
            output_dir=args.out,
            include_system=getattr(args, "include_system", False),
            pretty=pretty,
        )
        output_json(result, pretty=pretty)
        return EXIT_SUCCESS
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_evidence_verify(args) -> int:
    """Handle evidence verify command."""
    pretty = getattr(args, "pretty", True)
    try:
        result = verify_evidence_bundle(args.bundle)
        output_json(result, pretty=pretty)
        if result.get("valid"):
            return EXIT_SUCCESS
        return EXIT_FAILURE
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_boot_measure(args) -> int:
    """Handle boot measure command.

    SIMULATION ONLY - no real boot operations.
    """
    pretty = getattr(args, "pretty", True)
    try:
        result = simulate_boot_measurements(
            context=getattr(args, "context", None),
        )
        output_json(result, pretty=pretty)
        return EXIT_SUCCESS
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_boot_verify(args) -> int:
    """Handle boot verify command.

    Verifies boot identity from measurement log.
    """
    pretty = getattr(args, "pretty", True)
    try:
        # Load measurement log from file
        log_path = Path(args.log)
        if not log_path.exists():
            output_json({"error": f"Measurement log not found: {args.log}"}, pretty=pretty)
            return EXIT_FAILURE

        with open(log_path, "r") as f:
            measurement_log = json.load(f)

        result = verify_boot_identity(
            measurement_log,
            expected_hash=getattr(args, "expected", None),
        )
        output_json(result, pretty=pretty)
        if result.get("valid"):
            return EXIT_SUCCESS
        return EXIT_FAILURE
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except json.JSONDecodeError as e:
        output_json({"error": f"Invalid JSON in measurement log: {e}"}, pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_attest_generate(args) -> int:
    """Handle attest generate command.

    SIMULATION ONLY - no real cryptographic signing.
    Attestation is NOT authentication. Attestation is NOT authorization.
    """
    pretty = getattr(args, "pretty", True)
    try:
        result = generate_attestation_statement(
            context=getattr(args, "context", None),
            evidence_bundle_path=getattr(args, "evidence_bundle", None),
        )

        # Optionally write to file
        out_path = getattr(args, "out", None)
        if out_path:
            with open(out_path, "w") as f:
                json.dump(result, f, sort_keys=True, indent=2)
            output_json({
                "success": True,
                "statement_id": result["attestation_statement"]["statement_id"],
                "output_path": out_path,
                "attestation_id": result["attestation_statement"]["identity"]["attestation_id"],
            }, pretty=pretty)
        else:
            output_json(result, pretty=pretty)
        return EXIT_SUCCESS
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_attest_verify(args) -> int:
    """Handle attest verify command.

    Verifies an attestation statement against current state.
    """
    pretty = getattr(args, "pretty", True)
    try:
        result = verify_attestation_statement(
            args.statement,
            allow_stale=getattr(args, "allow_stale", False),
        )
        output_json(result, pretty=pretty)
        if result.get("valid"):
            return EXIT_SUCCESS
        return EXIT_FAILURE
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_attest_compare(args) -> int:
    """Handle attest compare command.

    Compares two attestation statements for drift detection.
    """
    pretty = getattr(args, "pretty", True)
    try:
        result = compare_attestation_statements(
            args.statement1,
            args.statement2,
        )
        output_json(result, pretty=pretty)
        if result.get("identical"):
            return EXIT_SUCCESS
        return EXIT_FAILURE
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_crypto_status(args) -> int:
    """Handle crypto status command.

    CONFIGURATION REPORTING ONLY - no cryptographic operations.
    This is Phase 8 (Design Only) - all crypto operations are future work.
    """
    pretty = getattr(args, "pretty", True)
    try:
        result = get_crypto_status()
        output_json(result, pretty=pretty)
        return EXIT_SUCCESS
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_crypto_readiness(args) -> int:
    """Handle crypto readiness command.

    READINESS REPORTING ONLY - no cryptographic operations.
    This is Phase 8 (Design Only) - all crypto operations are future work.
    """
    pretty = getattr(args, "pretty", True)
    try:
        result = get_crypto_readiness()
        output_json(result, pretty=pretty)
        return EXIT_SUCCESS
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_crypto_algorithms(args) -> int:
    """Handle crypto algorithms command.

    DESIGN DOCUMENTATION ONLY - no cryptographic operations.
    This is Phase 8 (Design Only) - algorithm support is design only.
    """
    pretty = getattr(args, "pretty", True)
    try:
        result = get_crypto_algorithms()
        output_json(result, pretty=pretty)
        return EXIT_SUCCESS
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_authz_check(args) -> int:
    """Handle authz check command.

    Evaluates authorization policy. Does NOT mutate state.
    Authorization is NOT authentication.
    """
    pretty = getattr(args, "pretty", True)
    try:
        result = check_authorization(
            subject=args.subject,
            action=args.action,
            context=getattr(args, "context", None),
            target=getattr(args, "target", None),
        )
        output_json(result, pretty=pretty)

        # Return non-zero for DENY decisions
        decision = result.get("authorization_check", {}).get("decision", "DENY")
        if decision == "DENY":
            return EXIT_FAILURE
        return EXIT_SUCCESS
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_authz_policy(args) -> int:
    """Handle authz policy command.

    Shows policy summary for a context.
    """
    pretty = getattr(args, "pretty", True)
    try:
        result = get_policy_summary(
            context=getattr(args, "context", None),
        )
        output_json(result, pretty=pretty)
        return EXIT_SUCCESS
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_authz_enforcement(args) -> int:
    """Handle authz enforcement command.

    Shows enforcement points summary.
    """
    pretty = getattr(args, "pretty", True)
    try:
        result = get_enforcement_points()
        output_json(result, pretty=pretty)
        return EXIT_SUCCESS
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_exec_adapters(args) -> int:
    """Handle exec adapters command.

    INSPECTION ONLY - reports adapter type definitions.
    This command:
    - NEVER executes anything
    - NEVER touches the OS
    - NEVER calls subprocesses
    - Only reports state derived from documentation
    """
    pretty = getattr(args, "pretty", True)
    try:
        result = get_adapters_info()
        output_json(result, pretty=pretty)
        return EXIT_SUCCESS
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_exec_boundary(args) -> int:
    """Handle exec boundary command.

    INSPECTION ONLY - reports boundary definitions.
    This command:
    - NEVER executes anything
    - NEVER touches the OS
    - NEVER calls subprocesses
    - Only reports state derived from documentation
    """
    pretty = getattr(args, "pretty", True)
    try:
        result = get_boundary_info()
        output_json(result, pretty=pretty)
        return EXIT_SUCCESS
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_exec_readiness(args) -> int:
    """Handle exec readiness command.

    INSPECTION ONLY - reports readiness status.
    This command:
    - NEVER executes anything
    - NEVER touches the OS
    - NEVER calls subprocesses
    - Only reports state derived from documentation
    """
    pretty = getattr(args, "pretty", True)
    request_id = getattr(args, "request_id", None)
    try:
        result = get_readiness_info(request_id=request_id)
        output_json(result, pretty=pretty)
        return EXIT_SUCCESS
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="aictrl",
        description="AICtrl - Portable AI Control Plane CLI",
    )

    # Global flags
    parser.add_argument(
        "--version", "-V",
        action="store_true",
        help="Show version information",
    )
    parser.add_argument(
        "--i-accept-risk",
        action="store_true",
        dest="accept_risk",
        help="Required with AICTRL_HOST_SAFETY=0 to disable host safety (target environment only)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # version command
    version_parser = subparsers.add_parser(
        "version",
        help="Show version information",
    )
    version_parser.add_argument(
        "--json",
        action="store_true",
        default=True,
        help="Output as JSON (default)",
    )
    version_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )

    # status command
    status_parser = subparsers.add_parser(
        "status",
        help="Show system status",
    )
    status_parser.add_argument(
        "--json",
        action="store_true",
        default=True,
        help="Output as JSON (default)",
    )
    status_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )

    # doctor command
    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Run system health checks",
    )
    doctor_parser.add_argument(
        "--json",
        action="store_true",
        default=True,
        help="Output as JSON (default)",
    )
    doctor_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    doctor_parser.add_argument(
        "--context",
        type=str,
        choices=["aios-base", "aios-dev", "aios-ci", "aios-sandbox"],
        default=None,
        help="Override execution context (auto-detected if not specified)",
    )
    doctor_parser.add_argument(
        "--no-invariants",
        action="store_true",
        default=False,
        help="Skip security invariant checks",
    )
    doctor_parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Include sensitive details (IPs, hostnames) in network check evidence",
    )

    # support-bundle command
    bundle_parser = subparsers.add_parser(
        "support-bundle",
        help="Create diagnostic support bundle",
    )
    bundle_subparsers = bundle_parser.add_subparsers(dest="bundle_command")

    create_parser = bundle_subparsers.add_parser(
        "create",
        help="Create a new support bundle",
    )
    create_parser.add_argument(
        "--out",
        type=str,
        default=None,
        help="Output directory for bundle (default: current directory)",
    )
    create_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )

    # pr command
    pr_parser = subparsers.add_parser(
        "pr",
        help="Pull request workflow",
    )
    pr_subparsers = pr_parser.add_subparsers(dest="pr_command")

    pr_create_parser = pr_subparsers.add_parser(
        "create",
        help="Create a pull request with precondition checks",
    )
    pr_create_parser.add_argument(
        "--title", "-t",
        type=str,
        required=True,
        help="PR title",
    )
    pr_create_parser.add_argument(
        "--body", "-b",
        type=str,
        default="",
        help="PR body/description",
    )
    pr_create_parser.add_argument(
        "--base",
        type=str,
        default="main",
        help="Base branch (default: main)",
    )
    pr_create_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Check preconditions without creating PR",
    )
    pr_create_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )

    # sandbox command
    sandbox_parser = subparsers.add_parser(
        "sandbox",
        help="AICtrl Dev Sandbox management",
    )
    sandbox_subparsers = sandbox_parser.add_subparsers(dest="sandbox_command")

    sandbox_status_parser = sandbox_subparsers.add_parser(
        "status",
        help="Show sandbox status (read-only)",
    )
    sandbox_status_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )

    sandbox_start_parser = sandbox_subparsers.add_parser(
        "start",
        help="Start the sandbox",
    )
    sandbox_start_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )

    sandbox_stop_parser = sandbox_subparsers.add_parser(
        "stop",
        help="Stop the sandbox",
    )
    sandbox_stop_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )

    # evidence command
    evidence_parser = subparsers.add_parser(
        "evidence",
        help="Evidence bundle management",
    )
    evidence_subparsers = evidence_parser.add_subparsers(dest="evidence_command")

    evidence_export_parser = evidence_subparsers.add_parser(
        "export",
        help="Export an evidence bundle (read-only)",
    )
    evidence_export_parser.add_argument(
        "--context",
        type=str,
        choices=["aios-base", "aios-dev", "aios-ci", "aios-sandbox"],
        default=None,
        help="Override execution context (auto-detected if not specified)",
    )
    evidence_export_parser.add_argument(
        "--out",
        type=str,
        required=True,
        help="Output directory for evidence bundle",
    )
    evidence_export_parser.add_argument(
        "--include-system",
        action="store_true",
        default=False,
        help="Include optional system artifacts",
    )
    evidence_export_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON files (default: true)",
    )

    evidence_verify_parser = evidence_subparsers.add_parser(
        "verify",
        help="Verify an evidence bundle",
    )
    evidence_verify_parser.add_argument(
        "--bundle",
        type=str,
        required=True,
        help="Path to evidence bundle directory",
    )
    evidence_verify_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    # boot command (SIMULATION ONLY)
    boot_parser = subparsers.add_parser(
        "boot",
        help="Boot measurement simulation (SIMULATION ONLY - no real boot)",
    )
    boot_subparsers = boot_parser.add_subparsers(dest="boot_command")

    boot_measure_parser = boot_subparsers.add_parser(
        "measure",
        help="Simulate boot measurements (read-only, deterministic)",
    )
    boot_measure_parser.add_argument(
        "--context",
        type=str,
        choices=["aios-sandbox"],
        default="aios-sandbox",
        help="Execution context (only aios-sandbox supported for simulation)",
    )
    boot_measure_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    boot_verify_parser = boot_subparsers.add_parser(
        "verify",
        help="Verify boot identity from measurement log",
    )
    boot_verify_parser.add_argument(
        "--log",
        type=str,
        required=True,
        help="Path to measurement log JSON file",
    )
    boot_verify_parser.add_argument(
        "--expected",
        type=str,
        default=None,
        help="Expected boot identity hash for comparison",
    )
    boot_verify_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    # attest command (SIMULATION ONLY)
    attest_parser = subparsers.add_parser(
        "attest",
        help="Attestation simulation (SIMULATION ONLY - not cryptographically signed)",
    )
    attest_subparsers = attest_parser.add_subparsers(dest="attest_command")

    attest_generate_parser = attest_subparsers.add_parser(
        "generate",
        help="Generate an attestation statement (simulation only)",
    )
    attest_generate_parser.add_argument(
        "--context",
        type=str,
        choices=["aios-sandbox"],
        default="aios-sandbox",
        help="Execution context (only aios-sandbox supported for simulation)",
    )
    attest_generate_parser.add_argument(
        "--out",
        type=str,
        default=None,
        help="Output file path for attestation statement",
    )
    attest_generate_parser.add_argument(
        "--evidence-bundle",
        type=str,
        default=None,
        help="Path to evidence bundle to bind to attestation",
    )
    attest_generate_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    attest_verify_parser = attest_subparsers.add_parser(
        "verify",
        help="Verify an attestation statement",
    )
    attest_verify_parser.add_argument(
        "--statement",
        type=str,
        required=True,
        help="Path to attestation statement JSON file",
    )
    attest_verify_parser.add_argument(
        "--allow-stale",
        action="store_true",
        default=False,
        help="Accept statements that don't match current state",
    )
    attest_verify_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    attest_compare_parser = attest_subparsers.add_parser(
        "compare",
        help="Compare two attestation statements for drift detection",
    )
    attest_compare_parser.add_argument(
        "--statement1",
        type=str,
        required=True,
        help="Path to first attestation statement",
    )
    attest_compare_parser.add_argument(
        "--statement2",
        type=str,
        required=True,
        help="Path to second attestation statement",
    )
    attest_compare_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    # crypto command (DESIGN ONLY - no cryptographic operations)
    crypto_parser = subparsers.add_parser(
        "crypto",
        help="Cryptographic readiness reporting (DESIGN ONLY - no crypto operations)",
    )
    crypto_subparsers = crypto_parser.add_subparsers(dest="crypto_command")

    crypto_status_parser = crypto_subparsers.add_parser(
        "status",
        help="Report cryptographic configuration status (no crypto operations)",
    )
    crypto_status_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    crypto_readiness_parser = crypto_subparsers.add_parser(
        "readiness",
        help="Report cryptographic readiness assessment (no crypto operations)",
    )
    crypto_readiness_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    crypto_algorithms_parser = crypto_subparsers.add_parser(
        "algorithms",
        help="Report algorithm support information (design only)",
    )
    crypto_algorithms_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    # authz command (Authorization is NOT authentication)
    authz_parser = subparsers.add_parser(
        "authz",
        help="Authorization policy evaluation (NOT authentication)",
    )
    authz_subparsers = authz_parser.add_subparsers(dest="authz_command")

    authz_check_parser = authz_subparsers.add_parser(
        "check",
        help="Check authorization for an action (read-only, deterministic)",
    )
    authz_check_parser.add_argument(
        "--subject",
        type=str,
        required=True,
        choices=VALID_SUBJECTS,
        help="Subject type requesting action",
    )
    authz_check_parser.add_argument(
        "--action",
        type=str,
        required=True,
        choices=VALID_ACTIONS,
        help="Action type to check",
    )
    authz_check_parser.add_argument(
        "--context",
        type=str,
        choices=VALID_CONTEXTS,
        default=None,
        help="Execution context (auto-detected if not specified)",
    )
    authz_check_parser.add_argument(
        "--target",
        type=str,
        default=None,
        help="Optional action target (path, resource, etc.)",
    )
    authz_check_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    authz_policy_parser = authz_subparsers.add_parser(
        "policy",
        help="Show authorization policy summary",
    )
    authz_policy_parser.add_argument(
        "--context",
        type=str,
        choices=VALID_CONTEXTS,
        default=None,
        help="Execution context (auto-detected if not specified)",
    )
    authz_policy_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    authz_enforcement_parser = authz_subparsers.add_parser(
        "enforcement",
        help="Show enforcement points summary",
    )
    authz_enforcement_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    # exec command (INSPECTION ONLY - no execution)
    exec_parser = subparsers.add_parser(
        "exec",
        help="Execution inspection (INSPECTION ONLY - no real execution)",
    )
    exec_subparsers = exec_parser.add_subparsers(dest="exec_command")

    exec_adapters_parser = exec_subparsers.add_parser(
        "adapters",
        help="Show execution adapter types (inspection only)",
    )
    exec_adapters_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    exec_boundary_parser = exec_subparsers.add_parser(
        "boundary",
        help="Show execution boundary definitions (inspection only)",
    )
    exec_boundary_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    exec_readiness_parser = exec_subparsers.add_parser(
        "readiness",
        help="Show execution readiness status (inspection only)",
    )
    exec_readiness_parser.add_argument(
        "--request-id",
        type=str,
        default=None,
        help="Optional execution request ID to check",
    )
    exec_readiness_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    return parser


def main(argv=None) -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)

    # Set the risk acceptance flag from CLI
    set_risk_accepted(getattr(args, "accept_risk", False))

    # Check for incomplete override attempts (env var without flag)
    try:
        check_override_validity()
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=False)
        return EXIT_FAILURE

    # Handle --version flag
    if args.version:
        args.pretty = False
        return cmd_version(args)

    # Dispatch to command handler
    if args.command == "version":
        return cmd_version(args)
    elif args.command == "status":
        return cmd_status(args)
    elif args.command == "doctor":
        return cmd_doctor(args)
    elif args.command == "support-bundle":
        if args.bundle_command == "create":
            return cmd_support_bundle(args)
        else:
            # Default to create if no subcommand
            args.out = None
            args.pretty = False
            return cmd_support_bundle(args)
    elif args.command == "pr":
        if args.pr_command == "create":
            return cmd_pr_create(args)
        else:
            pr_parser = [a for a in parser._subparsers._actions
                        if isinstance(a, argparse._SubParsersAction)][0]
            pr_parser.choices["pr"].print_help()
            return EXIT_USAGE_ERROR
    elif args.command == "sandbox":
        if args.sandbox_command == "status":
            return cmd_sandbox_status(args)
        elif args.sandbox_command == "start":
            return cmd_sandbox_start(args)
        elif args.sandbox_command == "stop":
            return cmd_sandbox_stop(args)
        else:
            # Default to status if no subcommand
            args.pretty = False
            return cmd_sandbox_status(args)
    elif args.command == "evidence":
        if args.evidence_command == "export":
            return cmd_evidence_export(args)
        elif args.evidence_command == "verify":
            return cmd_evidence_verify(args)
        else:
            evidence_parser = [a for a in parser._subparsers._actions
                             if isinstance(a, argparse._SubParsersAction)][0]
            evidence_parser.choices["evidence"].print_help()
            return EXIT_USAGE_ERROR
    elif args.command == "boot":
        if args.boot_command == "measure":
            return cmd_boot_measure(args)
        elif args.boot_command == "verify":
            return cmd_boot_verify(args)
        else:
            boot_parser = [a for a in parser._subparsers._actions
                          if isinstance(a, argparse._SubParsersAction)][0]
            boot_parser.choices["boot"].print_help()
            return EXIT_USAGE_ERROR
    elif args.command == "attest":
        if args.attest_command == "generate":
            return cmd_attest_generate(args)
        elif args.attest_command == "verify":
            return cmd_attest_verify(args)
        elif args.attest_command == "compare":
            return cmd_attest_compare(args)
        else:
            attest_parser = [a for a in parser._subparsers._actions
                           if isinstance(a, argparse._SubParsersAction)][0]
            attest_parser.choices["attest"].print_help()
            return EXIT_USAGE_ERROR
    elif args.command == "crypto":
        if args.crypto_command == "status":
            return cmd_crypto_status(args)
        elif args.crypto_command == "readiness":
            return cmd_crypto_readiness(args)
        elif args.crypto_command == "algorithms":
            return cmd_crypto_algorithms(args)
        else:
            # Default to status if no subcommand
            args.pretty = True
            return cmd_crypto_status(args)
    elif args.command == "authz":
        if args.authz_command == "check":
            return cmd_authz_check(args)
        elif args.authz_command == "policy":
            return cmd_authz_policy(args)
        elif args.authz_command == "enforcement":
            return cmd_authz_enforcement(args)
        else:
            authz_parser = [a for a in parser._subparsers._actions
                          if isinstance(a, argparse._SubParsersAction)][0]
            authz_parser.choices["authz"].print_help()
            return EXIT_USAGE_ERROR
    elif args.command == "exec":
        if args.exec_command == "adapters":
            return cmd_exec_adapters(args)
        elif args.exec_command == "boundary":
            return cmd_exec_boundary(args)
        elif args.exec_command == "readiness":
            return cmd_exec_readiness(args)
        else:
            # Default to adapters if no subcommand
            args.pretty = True
            return cmd_exec_adapters(args)
    else:
        parser.print_help()
        return EXIT_USAGE_ERROR


if __name__ == "__main__":
    sys.exit(main())
