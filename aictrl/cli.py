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
    generate_keypair,
    derive_public_key,
    sign_file,
    verify_signature,
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
from .commands.demo import run_demo
from .phases import get_current_phase, get_enabled_capabilities
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
        "phase": get_current_phase(),
        "commit": get_git_commit(),
        # Build watermarking (non-secret, traceable metadata)
        "build_timestamp": __build_timestamp__ or datetime.now(timezone.utc).isoformat(),
        "build_id": __build_id__,
        "product": "AICtrl - Portable AI Control Plane",
        "enabled_capabilities": list(get_enabled_capabilities().keys()),
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

    Phase 10: Supports --source mock (default) or --source ima for real IMA.
    """
    pretty = getattr(args, "pretty", True)
    source = getattr(args, "source", "mock")

    try:
        # Import Phase 10 measure_boot function
        from .commands.boot import measure_boot

        result = measure_boot(source=source)
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
    Phase 10: Supports --policy for policy-based verification.
    """
    pretty = getattr(args, "pretty", True)
    policy_path = getattr(args, "policy", None)

    try:
        # If policy provided, use policy-based verification
        if policy_path:
            from .commands.boot import verify_boot_against_policy

            result = verify_boot_against_policy(
                log_path=args.log,
                policy_path=policy_path,
            )
            output_json(result, pretty=pretty)
            if result.get("valid"):
                return EXIT_SUCCESS
            return EXIT_FAILURE

        # Otherwise use hash-based verification
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

    Phase 11: Supports signed attestation with --key --dangerous.
    Default: unsigned attestation with warning.
    Attestation is NOT authentication. Attestation is NOT authorization.
    """
    pretty = getattr(args, "pretty", True)
    key_path = getattr(args, "key", None)
    dangerous = getattr(args, "dangerous", False)

    try:
        # If key provided, generate signed attestation
        if key_path:
            from .commands.attest import generate_signed_attestation

            result = generate_signed_attestation(
                context=getattr(args, "context", None),
                evidence_bundle_path=getattr(args, "evidence_bundle", None),
                key_path=key_path,
                dangerous=dangerous,
            )

            # Check for safety gate failure
            if result.get("success") is False:
                output_json(result, pretty=pretty)
                return result.get("exit_code", 2)
        else:
            # Generate unsigned attestation (default)
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
                "signed": result.get("attestation_statement", {}).get("signature", {}).get("signed", False),
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

    Phase 11: Supports signature verification with --pubkey.
    Verifies an attestation statement against current state and/or signature.
    """
    pretty = getattr(args, "pretty", True)
    pubkey_path = getattr(args, "pubkey", None)

    try:
        # If pubkey provided, verify signature
        if pubkey_path:
            from .commands.attest import verify_attestation_signature

            result = verify_attestation_signature(
                statement_path=args.statement,
                pubkey_path=pubkey_path,
            )
            output_json(result, pretty=pretty)
            if result.get("valid"):
                return EXIT_SUCCESS
            return EXIT_FAILURE

        # Default: verify state consistency
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

    Reports algorithm support information.
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


def cmd_crypto_keygen(args) -> int:
    """Handle crypto keygen command.

    Generates an Ed25519 keypair. Requires --dangerous flag.
    """
    pretty = getattr(args, "pretty", True)
    try:
        result = generate_keypair(
            output_path=args.out,
            dangerous=getattr(args, "dangerous", False),
            force=getattr(args, "force", False),
        )
        output_json(result, pretty=pretty)
        if result.get("success"):
            return EXIT_SUCCESS
        return result.get("exit_code", EXIT_FAILURE)
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_crypto_pubkey(args) -> int:
    """Handle crypto pubkey command.

    Derives public key from private key.
    """
    pretty = getattr(args, "pretty", True)
    try:
        result = derive_public_key(
            key_path=args.key,
            output_path=args.out,
        )
        output_json(result, pretty=pretty)
        if result.get("success"):
            return EXIT_SUCCESS
        return result.get("exit_code", EXIT_FAILURE)
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_crypto_sign(args) -> int:
    """Handle crypto sign command.

    Signs a file with Ed25519.
    """
    pretty = getattr(args, "pretty", True)
    try:
        result = sign_file(
            key_path=args.key,
            input_path=getattr(args, "input", None) or args.file,
            output_path=args.out,
        )
        output_json(result, pretty=pretty)
        if result.get("success"):
            return EXIT_SUCCESS
        return result.get("exit_code", EXIT_FAILURE)
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"error": str(e)}, pretty=pretty)
        return EXIT_FAILURE


def cmd_crypto_verify(args) -> int:
    """Handle crypto verify command.

    Verifies an Ed25519 signature.
    """
    pretty = getattr(args, "pretty", True)
    try:
        result = verify_signature(
            pubkey_path=args.pubkey,
            input_path=getattr(args, "input", None) or args.file,
            sig_path=args.sig,
        )
        output_json(result, pretty=pretty)
        return result.get("exit_code", EXIT_FAILURE)
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


def cmd_exec_propose(args) -> int:
    """Handle exec propose command.

    Phase 12 Part 1: Create execution proposal.
    This command:
    - Has NO side effects except writing to explicit --out path
    - Validates adapter against allowlist (default deny)
    - Requires --dangerous for dangerous adapters/actions
    - NEVER executes anything
    """
    from .commands.exec import create_proposal

    pretty = getattr(args, "pretty", True)

    # Parse inputs JSON if provided
    inputs = None
    if args.inputs:
        try:
            inputs = json.loads(args.inputs)
        except json.JSONDecodeError as e:
            output_json({
                "success": False,
                "error": f"Invalid JSON in --inputs: {e}",
                "hint": "Provide valid JSON object for --inputs",
                "exit_code": 1,
            }, pretty=pretty)
            return EXIT_FAILURE

    try:
        result = create_proposal(
            action=args.action,
            target=args.target,
            adapter=args.adapter,
            subject=getattr(args, "subject", None),
            inputs=inputs,
            dangerous=getattr(args, "dangerous", False),
            out_path=args.out,
            overwrite=getattr(args, "overwrite", False),
        )
        output_json(result, pretty=pretty)

        # Return appropriate exit code
        if result.get("success"):
            return EXIT_SUCCESS
        return result.get("exit_code", EXIT_FAILURE)

    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"success": False, "error": str(e), "exit_code": 1}, pretty=pretty)
        return EXIT_FAILURE


def cmd_exec_review(args) -> int:
    """Handle exec review command.

    Phase 12 Part 1: Review execution proposal (read-only).
    This command:
    - NEVER modifies the proposal file
    - Validates content hash for tamper detection
    - Returns structured summary
    """
    from .commands.exec import review_proposal

    pretty = getattr(args, "pretty", True)

    try:
        result = review_proposal(proposal_path=args.proposal)
        output_json(result, pretty=pretty)

        # Return appropriate exit code
        if result.get("success") and result.get("valid"):
            return EXIT_SUCCESS
        return result.get("exit_code", EXIT_FAILURE)

    except AICtrlError as e:
        output_json(e.to_dict(), pretty=pretty)
        return EXIT_FAILURE
    except Exception as e:
        output_json({"success": False, "error": str(e), "exit_code": 1}, pretty=pretty)
        return EXIT_FAILURE


def cmd_demo(args) -> int:
    """Handle demo command.

    Runs the AICtrl baseline as a polished, client-facing demonstration.
    This command is:
    - Read-only with respect to host safety (no privileged actions)
    - Deterministic and offline-safe
    - Produces ASCII-only output in reports
    """
    try:
        result = run_demo(
            output_dir=getattr(args, "out", None),
            quick=getattr(args, "quick", False),
            verbose=True,
        )

        if result.get("success"):
            return EXIT_SUCCESS
        else:
            if result.get("error"):
                print(f"Error: {result['error']}")
            return EXIT_FAILURE
    except AICtrlError as e:
        output_json(e.to_dict(), pretty=True)
        return EXIT_FAILURE
    except Exception as e:
        print(f"Error: {e}")
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

    # demo command
    demo_parser = subparsers.add_parser(
        "demo",
        help="Run baseline demo with artifacts and verification instructions",
    )
    demo_parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick mode: suppress verbose per-test output",
    )
    demo_parser.add_argument(
        "--out",
        type=str,
        default=None,
        help="Output directory for artifacts (default: baseline/results/demo_<timestamp>)",
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

    # boot command (Phase 10: real boot measurement support)
    boot_parser = subparsers.add_parser(
        "boot",
        help="Boot measurement (Phase 10: supports mock and real IMA sources)",
    )
    boot_subparsers = boot_parser.add_subparsers(dest="boot_command")

    boot_measure_parser = boot_subparsers.add_parser(
        "measure",
        help="Read boot measurements (Phase 10: supports mock and IMA sources)",
    )
    boot_measure_parser.add_argument(
        "--source",
        type=str,
        choices=["mock", "ima"],
        default="mock",
        help="Measurement source: mock (default) or ima (real IMA from kernel)",
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
        "--policy",
        type=str,
        default=None,
        help="Path to policy JSON file for policy-based verification (Phase 10)",
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
        help="Generate attestation statement (Phase 11: supports --key --dangerous for signing)",
    )
    attest_generate_parser.add_argument(
        "--context",
        type=str,
        choices=["aios-sandbox"],
        default="aios-sandbox",
        help="Execution context (only aios-sandbox supported)",
    )
    attest_generate_parser.add_argument(
        "--key",
        type=str,
        default=None,
        help="Path to private key for signed attestation (Phase 11)",
    )
    attest_generate_parser.add_argument(
        "--dangerous",
        action="store_true",
        default=False,
        help="Required for signed attestation - confirms understanding of implications",
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
        help="Verify attestation statement (Phase 11: --pubkey for signature verification)",
    )
    attest_verify_parser.add_argument(
        "--statement",
        type=str,
        required=True,
        help="Path to attestation statement JSON file",
    )
    attest_verify_parser.add_argument(
        "--pubkey",
        type=str,
        default=None,
        help="Path to public key for signature verification (Phase 11, no trust store)",
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

    # crypto command - Phase 9 MVP cryptographic operations
    crypto_parser = subparsers.add_parser(
        "crypto",
        help="Cryptographic operations (Phase 9: Ed25519 signing/verification)",
    )
    crypto_subparsers = crypto_parser.add_subparsers(dest="crypto_command")

    crypto_status_parser = crypto_subparsers.add_parser(
        "status",
        help="Report cryptographic configuration status",
    )
    crypto_status_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    crypto_readiness_parser = crypto_subparsers.add_parser(
        "readiness",
        help="Report cryptographic readiness assessment",
    )
    crypto_readiness_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    crypto_algorithms_parser = crypto_subparsers.add_parser(
        "algorithms",
        help="Report algorithm support information",
    )
    crypto_algorithms_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    # Phase 9: Ed25519 key generation
    crypto_keygen_parser = crypto_subparsers.add_parser(
        "keygen",
        help="Generate Ed25519 keypair (requires --dangerous)",
    )
    crypto_keygen_parser.add_argument(
        "--out",
        type=str,
        required=True,
        help="Output path for private key (PEM format)",
    )
    crypto_keygen_parser.add_argument(
        "--dangerous",
        action="store_true",
        help="Required safety gate for key generation",
    )
    crypto_keygen_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing file",
    )
    crypto_keygen_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    # Phase 9: Public key derivation
    crypto_pubkey_parser = crypto_subparsers.add_parser(
        "pubkey",
        help="Derive public key from private key",
    )
    crypto_pubkey_parser.add_argument(
        "--key",
        type=str,
        required=True,
        help="Path to private key (PEM format)",
    )
    crypto_pubkey_parser.add_argument(
        "--out",
        type=str,
        required=True,
        help="Output path for public key (PEM format)",
    )
    crypto_pubkey_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    # Phase 9: Ed25519 signing
    crypto_sign_parser = crypto_subparsers.add_parser(
        "sign",
        help="Sign a file with Ed25519",
    )
    crypto_sign_parser.add_argument(
        "--key",
        type=str,
        required=True,
        help="Path to private key (PEM format)",
    )
    crypto_sign_parser.add_argument(
        "--in",
        dest="file",
        type=str,
        required=True,
        help="Path to file to sign",
    )
    crypto_sign_parser.add_argument(
        "--out",
        type=str,
        required=True,
        help="Output path for signature (base64 encoded)",
    )
    crypto_sign_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    # Phase 9: Ed25519 verification
    crypto_verify_parser = crypto_subparsers.add_parser(
        "verify",
        help="Verify an Ed25519 signature",
    )
    crypto_verify_parser.add_argument(
        "--pubkey",
        type=str,
        required=True,
        help="Path to public key (PEM format)",
    )
    crypto_verify_parser.add_argument(
        "--in",
        dest="file",
        type=str,
        required=True,
        help="Path to file that was signed",
    )
    crypto_verify_parser.add_argument(
        "--sig",
        type=str,
        required=True,
        help="Path to signature file (base64 encoded)",
    )
    crypto_verify_parser.add_argument(
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

    # exec command (Phase 12: propose/review added, still NO execution)
    exec_parser = subparsers.add_parser(
        "exec",
        help="Execution proposal/review (Phase 12: NO execution, propose and review only)",
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

    # Phase 12 Part 1: propose and review (NO execution)
    exec_propose_parser = exec_subparsers.add_parser(
        "propose",
        help="Create execution proposal (Phase 12: NO side effects except --out file)",
    )
    exec_propose_parser.add_argument(
        "--action",
        type=str,
        required=True,
        help="Action verb (read, write, execute, etc.)",
    )
    exec_propose_parser.add_argument(
        "--target",
        type=str,
        required=True,
        help="Target resource path or identifier",
    )
    exec_propose_parser.add_argument(
        "--adapter",
        type=str,
        required=True,
        help="Adapter name (noop, file-read, file-write, shell-readonly, shell-execute)",
    )
    exec_propose_parser.add_argument(
        "--subject",
        type=str,
        default=None,
        help="Optional subject identifier",
    )
    exec_propose_parser.add_argument(
        "--inputs",
        type=str,
        default=None,
        help="JSON object with adapter-specific inputs",
    )
    exec_propose_parser.add_argument(
        "--out",
        type=str,
        required=True,
        help="Output path for proposal JSON (required)",
    )
    exec_propose_parser.add_argument(
        "--overwrite",
        action="store_true",
        default=False,
        help="Overwrite existing output file",
    )
    exec_propose_parser.add_argument(
        "--dangerous",
        action="store_true",
        default=False,
        help="Required for dangerous adapters/actions",
    )
    exec_propose_parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output",
    )

    exec_review_parser = exec_subparsers.add_parser(
        "review",
        help="Review execution proposal (Phase 12: read-only, validates hash)",
    )
    exec_review_parser.add_argument(
        "--proposal",
        type=str,
        required=True,
        help="Path to proposal JSON file",
    )
    exec_review_parser.add_argument(
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
    elif args.command == "demo":
        return cmd_demo(args)
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
        elif args.crypto_command == "keygen":
            return cmd_crypto_keygen(args)
        elif args.crypto_command == "pubkey":
            return cmd_crypto_pubkey(args)
        elif args.crypto_command == "sign":
            return cmd_crypto_sign(args)
        elif args.crypto_command == "verify":
            return cmd_crypto_verify(args)
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
        elif args.exec_command == "propose":
            return cmd_exec_propose(args)
        elif args.exec_command == "review":
            return cmd_exec_review(args)
        else:
            # Default to adapters if no subcommand
            args.pretty = True
            return cmd_exec_adapters(args)
    else:
        parser.print_help()
        return EXIT_USAGE_ERROR


if __name__ == "__main__":
    sys.exit(main())
