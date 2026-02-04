"""aictrl attest command - attestation statement generation and verification.

Phase 11: Signed attestation support added.
- Unsigned attestation (default): simulation only, emits warning
- Signed attestation: requires --key and --dangerous flags
- Signature verification: requires explicit --pubkey (no trust store)

IMPORTANT:
- Signed attestation only. No enforcement.
- Attestation is NOT authentication (does not prove identity)
- Attestation is NOT authorization (does not grant permissions)
- Key usage requires explicit --dangerous flag

See docs/security/ATTESTATION_MODEL.md for semantics.
"""

import hashlib
import json
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..util.errors import AICtrlError
from ..util.invariants import (
    ExecutionContext,
    get_context_name,
    run_all_invariant_checks,
)
from .. import __version__


# Error codes for attestation commands
ATTEST_CONTEXT_ERROR = "AICTRL-8001"
ATTEST_GENERATION_ERROR = "AICTRL-8002"
ATTEST_VERIFICATION_ERROR = "AICTRL-8003"
ATTEST_STATEMENT_PARSE_ERROR = "AICTRL-8004"
ATTEST_IDENTITY_MISMATCH = "AICTRL-8005"
# Phase 11 error codes
ATTEST_SIGN_ERROR = "AICTRL-8010"
ATTEST_DANGEROUS_REQUIRED = "AICTRL-8011"
ATTEST_SIG_VERIFY_ERROR = "AICTRL-8012"
ATTEST_SIG_INVALID = "AICTRL-8013"


# Required notices for unsigned attestation statements
UNSIGNED_NOTICES = [
    {
        "type": "warning",
        "severity": "critical",
        "message": "WARNING: This attestation is UNSIGNED - not cryptographically signed",
    },
    {
        "type": "disclaimer",
        "severity": "critical",
        "message": "Attestation is NOT authentication - does not prove identity to external parties",
    },
    {
        "type": "disclaimer",
        "severity": "critical",
        "message": "Attestation is NOT authorization - does not grant permissions",
    },
    {
        "type": "info",
        "severity": "normal",
        "message": "Use --key and --dangerous to generate signed attestation",
    },
]

# Notices for signed attestation statements
SIGNED_NOTICES = [
    {
        "type": "info",
        "severity": "normal",
        "message": "This attestation is cryptographically signed with Ed25519",
    },
    {
        "type": "disclaimer",
        "severity": "critical",
        "message": "Attestation is NOT authentication - does not prove identity to external parties",
    },
    {
        "type": "disclaimer",
        "severity": "critical",
        "message": "Attestation is NOT authorization - does not grant permissions",
    },
    {
        "type": "disclaimer",
        "severity": "critical",
        "message": "Signed attestation only. No enforcement in this phase.",
    },
]

# Backwards compatibility alias
REQUIRED_NOTICES = UNSIGNED_NOTICES


def calculate_sha256(content: bytes) -> str:
    """Calculate SHA-256 hash of content.

    Args:
        content: Bytes to hash

    Returns:
        Hex-encoded lowercase SHA-256 hash
    """
    return hashlib.sha256(content).hexdigest()


def generate_timestamp() -> str:
    """Generate ISO 8601 timestamp with timezone."""
    return datetime.now(timezone.utc).isoformat()


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


def get_boot_measurements() -> dict[str, Any]:
    """Get current boot measurements from Phase 6.

    Returns:
        Boot measurement data including identity hash and measurements
    """
    from .boot import simulate_boot_measurements

    try:
        result = simulate_boot_measurements(context="aios-sandbox")
        return {
            "boot_identity_hash": result["measurement_log"]["combined_hash"],
            "measurement_count": len(result["measurement_log"]["measurements"]),
            "measurements": [
                {
                    "id": m["id"],
                    "name": m["name"],
                    "hash": m["hash"],
                    "algorithm": m["algorithm"],
                }
                for m in result["measurement_log"]["measurements"]
            ],
        }
    except Exception as e:
        raise AICtrlError(
            ATTEST_GENERATION_ERROR,
            "Failed to get boot measurements",
            cause=str(e),
            remediation=["Ensure sandbox is initialized", "Run from repository root"],
        )


def get_invariant_results(context: ExecutionContext) -> dict[str, Any]:
    """Get current invariant check results from Phase 4.

    Args:
        context: Execution context to check

    Returns:
        Invariant results including summary and hash
    """
    try:
        results = run_all_invariant_checks(context)

        # Compute hash of results for binding
        results_json = json.dumps(results, sort_keys=True)
        results_hash = calculate_sha256(results_json.encode("utf-8"))

        # Extract summary from nested structure
        summary = results.get("summary", {})

        return {
            "summary": {
                "passed": summary.get("passed", 0),
                "failed": summary.get("failed", 0),
                "skipped": summary.get("skipped", 0),
                "warned": summary.get("warned", 0),
                "overall_status": results.get("overall_status", "unknown"),
            },
            "context_checked": get_context_name(context),
            "results_hash": results_hash,
        }
    except Exception as e:
        raise AICtrlError(
            ATTEST_GENERATION_ERROR,
            "Failed to get invariant results",
            cause=str(e),
            remediation=["Check invariant configuration"],
        )


def compute_attestation_identity(
    boot_identity: str,
    invariant_hash: str,
    context: str,
) -> str:
    """Compute attestation identity from components.

    The attestation identity is:
        SHA-256(boot_identity + invariant_hash + context)

    Args:
        boot_identity: Boot identity hash
        invariant_hash: Hash of invariant results
        context: Execution context string

    Returns:
        Attestation identity hash
    """
    combined = boot_identity + invariant_hash + context
    return calculate_sha256(combined.encode("utf-8"))


def generate_attestation_statement(
    context: Optional[str] = None,
    evidence_bundle_path: Optional[str] = None,
) -> dict[str, Any]:
    """Generate an attestation statement.

    This is SIMULATION ONLY - no real cryptographic signing.

    Args:
        context: Execution context override (must be aios-sandbox)
        evidence_bundle_path: Optional path to evidence bundle to bind

    Returns:
        Attestation statement dictionary

    Raises:
        AICtrlError: If context is not sandbox or generation fails
    """
    # Validate context - only sandbox allowed for simulation
    if context and context != "aios-sandbox":
        raise AICtrlError(
            ATTEST_CONTEXT_ERROR,
            "Attestation generation only valid in sandbox context",
            cause=f"Requested context '{context}' is not 'aios-sandbox'",
            remediation=[
                "Use --context aios-sandbox",
                "Attestation is simulation only",
            ],
        )

    # Use sandbox context
    exec_context = ExecutionContext.AIOS_SANDBOX

    # Generate statement ID and timestamp
    statement_id = str(uuid.uuid4())
    generated_at = generate_timestamp()

    # Get boot measurements (Phase 6 binding)
    boot_claims = get_boot_measurements()

    # Get invariant results (Phase 4 binding)
    invariant_claims = get_invariant_results(exec_context)

    # Get system info
    system_claims = {
        "hostname": socket.gethostname(),
        "bbail_version": __version__,
        "bbail_commit": get_git_commit(),
    }

    # Build claims section
    claims = {
        "boot": boot_claims,
        "invariants": invariant_claims,
        "system": system_claims,
    }

    # Build bindings section
    bindings = {
        "boot_measurement_log": {
            "bound": True,
            "source": "bbail boot measure",
            "combined_hash": boot_claims["boot_identity_hash"],
        },
        "invariant_check": {
            "bound": True,
            "source": "bbail doctor",
            "results_hash": invariant_claims["results_hash"],
        },
        "evidence_bundle": {
            "bound": False,
            "bundle_id": None,
            "manifest_hash": None,
        },
    }

    # Bind evidence bundle if provided (Phase 5 binding)
    if evidence_bundle_path:
        bundle_path = Path(evidence_bundle_path)
        manifest_path = bundle_path / "manifest.json"
        if manifest_path.exists():
            with open(manifest_path, "r") as f:
                manifest = json.load(f)
            manifest_hash = calculate_sha256(
                json.dumps(manifest, sort_keys=True).encode("utf-8")
            )
            bindings["evidence_bundle"] = {
                "bound": True,
                "bundle_id": manifest.get("bundle_id"),
                "manifest_hash": manifest_hash,
            }

    # Compute attestation identity
    attestation_id = compute_attestation_identity(
        boot_claims["boot_identity_hash"],
        invariant_claims["results_hash"],
        "aios-sandbox",
    )

    # Build identity section
    identity = {
        "attestation_id": attestation_id,
        "algorithm": "SHA-256",
        "derivation": "boot_identity || invariant_hash || context",
        "components": {
            "boot_identity": boot_claims["boot_identity_hash"],
            "invariant_hash": invariant_claims["results_hash"],
            "context": "aios-sandbox",
        },
    }

    # Build signature placeholder (NOT IMPLEMENTED)
    signature_placeholder = {
        "signed": False,
        "algorithm": "none",
        "value": None,
        "signer": None,
        "note": "Signature not implemented - logical attestation only",
    }

    # Build complete statement
    statement = {
        "attestation_statement": {
            "version": "1.0",
            "statement_id": statement_id,
            "generated_at": generated_at,
            "context": "aios-sandbox",
            "claims": claims,
            "bindings": bindings,
            "identity": identity,
            "signature_placeholder": signature_placeholder,
            "notices": REQUIRED_NOTICES,
        }
    }

    return statement


def verify_attestation_statement(
    statement_path: str,
    allow_stale: bool = False,
) -> dict[str, Any]:
    """Verify an attestation statement.

    This verifies:
    1. Statement structure is valid
    2. Attestation identity is correctly derived
    3. Claims match current state (if not allowing stale)

    Args:
        statement_path: Path to attestation statement JSON
        allow_stale: If True, allow statements that don't match current state

    Returns:
        Verification result dictionary

    Raises:
        AICtrlError: If statement cannot be parsed or verified
    """
    # Load statement
    statement_file = Path(statement_path)
    if not statement_file.exists():
        raise AICtrlError(
            ATTEST_STATEMENT_PARSE_ERROR,
            f"Statement file not found: {statement_path}",
            cause="File does not exist",
            remediation=["Check the file path"],
        )

    try:
        with open(statement_file, "r") as f:
            statement = json.load(f)
    except json.JSONDecodeError as e:
        raise AICtrlError(
            ATTEST_STATEMENT_PARSE_ERROR,
            "Invalid JSON in statement file",
            cause=str(e),
            remediation=["Check the statement file format"],
        )

    # Extract statement content
    if "attestation_statement" not in statement:
        raise AICtrlError(
            ATTEST_STATEMENT_PARSE_ERROR,
            "Missing attestation_statement key",
            cause="Top-level key not found",
            remediation=["Ensure statement follows schema"],
        )

    stmt = statement["attestation_statement"]

    # Structural validation
    required_fields = [
        "version", "statement_id", "generated_at", "context",
        "claims", "bindings", "identity", "signature_placeholder", "notices"
    ]
    missing_fields = [f for f in required_fields if f not in stmt]
    if missing_fields:
        raise AICtrlError(
            ATTEST_STATEMENT_PARSE_ERROR,
            f"Missing required fields: {missing_fields}",
            cause="Statement incomplete",
            remediation=["Ensure statement follows schema"],
        )

    # Check version
    if stmt["version"] != "1.0":
        raise AICtrlError(
            ATTEST_VERIFICATION_ERROR,
            f"Unsupported schema version: {stmt['version']}",
            cause="Unknown version",
            remediation=["Use schema version 1.0"],
        )

    # Verify identity derivation
    identity = stmt["identity"]
    components = identity.get("components", {})

    computed_identity = compute_attestation_identity(
        components.get("boot_identity", ""),
        components.get("invariant_hash", ""),
        components.get("context", ""),
    )

    identity_valid = computed_identity == identity.get("attestation_id")
    if not identity_valid:
        raise AICtrlError(
            ATTEST_IDENTITY_MISMATCH,
            "Attestation identity does not match computed value",
            cause="Identity derivation mismatch",
            remediation=["Statement may be tampered or corrupted"],
        )

    # Get current state for comparison
    discrepancies = []
    current_boot = None
    current_invariants = None

    try:
        current_boot = get_boot_measurements()
    except Exception:
        discrepancies.append({
            "category": "high",
            "claim": "claims.boot",
            "message": "Could not get current boot measurements",
            "attested_value": stmt["claims"]["boot"]["boot_identity_hash"],
            "current_value": None,
        })

    try:
        exec_context = ExecutionContext.AIOS_SANDBOX
        current_invariants = get_invariant_results(exec_context)
    except Exception:
        discrepancies.append({
            "category": "high",
            "claim": "claims.invariants",
            "message": "Could not get current invariant results",
            "attested_value": stmt["claims"]["invariants"]["results_hash"],
            "current_value": None,
        })

    # Compare boot identity
    boot_matches = False
    if current_boot:
        attested_boot = stmt["claims"]["boot"]["boot_identity_hash"]
        current_boot_hash = current_boot["boot_identity_hash"]
        boot_matches = attested_boot == current_boot_hash

        if not boot_matches:
            discrepancies.append({
                "category": "critical",
                "claim": "claims.boot.boot_identity_hash",
                "message": "Boot identity changed",
                "attested_value": attested_boot,
                "current_value": current_boot_hash,
            })

    # Compare invariant results
    invariants_match = False
    if current_invariants:
        attested_inv = stmt["claims"]["invariants"]["results_hash"]
        current_inv_hash = current_invariants["results_hash"]
        invariants_match = attested_inv == current_inv_hash

        if not invariants_match:
            discrepancies.append({
                "category": "critical",
                "claim": "claims.invariants.results_hash",
                "message": "Invariant results changed",
                "attested_value": attested_inv,
                "current_value": current_inv_hash,
            })

    # Determine trust level
    if identity_valid and boot_matches and invariants_match:
        trust_level = "VERIFIED"
    elif identity_valid and (boot_matches or invariants_match):
        trust_level = "PARTIAL"
    elif identity_valid:
        trust_level = "STALE"
    else:
        trust_level = "INVALID"

    # Count discrepancies by category
    critical_count = len([d for d in discrepancies if d["category"] == "critical"])
    high_count = len([d for d in discrepancies if d["category"] == "high"])

    # Determine overall validity
    reflects_current = boot_matches and invariants_match
    valid = identity_valid and (reflects_current or allow_stale)

    return {
        "valid": valid,
        "statement_id": stmt["statement_id"],
        "generated_at": stmt["generated_at"],
        "checked_at": generate_timestamp(),
        "trust_level": trust_level,
        "identity_valid": identity_valid,
        "boot_claims_valid": boot_matches,
        "invariant_claims_valid": invariants_match,
        "reflects_current_state": reflects_current,
        "discrepancies": discrepancies,
        "discrepancy_count": len(discrepancies),
        "critical_count": critical_count,
        "high_count": high_count,
        "policy": {
            "allow_stale": allow_stale,
        },
    }


def compare_attestation_statements(
    statement1_path: str,
    statement2_path: str,
) -> dict[str, Any]:
    """Compare two attestation statements.

    Useful for drift detection between attestations.

    Args:
        statement1_path: Path to first statement
        statement2_path: Path to second statement

    Returns:
        Comparison result dictionary
    """
    # Load both statements
    def load_statement(path: str) -> dict:
        with open(path, "r") as f:
            data = json.load(f)
        return data.get("attestation_statement", {})

    stmt1 = load_statement(statement1_path)
    stmt2 = load_statement(statement2_path)

    # Compare key values
    boot1 = stmt1.get("claims", {}).get("boot", {}).get("boot_identity_hash")
    boot2 = stmt2.get("claims", {}).get("boot", {}).get("boot_identity_hash")

    inv1 = stmt1.get("claims", {}).get("invariants", {}).get("results_hash")
    inv2 = stmt2.get("claims", {}).get("invariants", {}).get("results_hash")

    id1 = stmt1.get("identity", {}).get("attestation_id")
    id2 = stmt2.get("identity", {}).get("attestation_id")

    differences = []

    if boot1 != boot2:
        differences.append({
            "field": "boot_identity",
            "statement1": boot1,
            "statement2": boot2,
        })

    if inv1 != inv2:
        differences.append({
            "field": "invariant_hash",
            "statement1": inv1,
            "statement2": inv2,
        })

    if id1 != id2:
        differences.append({
            "field": "attestation_id",
            "statement1": id1,
            "statement2": id2,
        })

    return {
        "identical": len(differences) == 0,
        "statement1_id": stmt1.get("statement_id"),
        "statement2_id": stmt2.get("statement_id"),
        "statement1_generated": stmt1.get("generated_at"),
        "statement2_generated": stmt2.get("generated_at"),
        "differences": differences,
        "difference_count": len(differences),
    }


# ============================================================================
# Phase 11: Signed Attestation Functions
# ============================================================================

# Dangerous warning for signed attestation
SIGNED_ATTEST_WARNING = """
================================================================================
                         SIGNED ATTESTATION WARNING
================================================================================

You are generating a SIGNED attestation statement.

This operation:
- Uses your private key to sign the attestation
- Creates a cryptographic binding to the attestation content
- Can be verified by anyone with your public key

This does NOT:
- Enforce any policy or authorization
- Grant any permissions
- Authenticate identity to external parties
- Substitute for proper security controls

The --dangerous flag confirms you understand these implications.

================================================================================
"""


def get_key_fingerprint(pubkey_pem: bytes) -> str:
    """Calculate fingerprint of a public key.

    Args:
        pubkey_pem: Public key in PEM format

    Returns:
        SHA-256 fingerprint (first 16 hex chars)
    """
    return calculate_sha256(pubkey_pem)[:16]


def generate_signed_attestation(
    context: Optional[str] = None,
    evidence_bundle_path: Optional[str] = None,
    key_path: Optional[str] = None,
    dangerous: bool = False,
) -> dict[str, Any]:
    """Generate a signed attestation statement.

    Phase 11: Requires --key and --dangerous flags.

    Args:
        context: Execution context override (must be aios-sandbox)
        evidence_bundle_path: Optional path to evidence bundle to bind
        key_path: Path to private key for signing
        dangerous: Must be True to proceed (safety gate)

    Returns:
        Signed attestation statement dictionary

    Raises:
        AICtrlError: If dangerous not set or signing fails
    """
    # Safety gate: require --dangerous for signed attestation
    if not dangerous:
        return {
            "success": False,
            "error": "Signed attestation requires --dangerous flag",
            "error_code": ATTEST_DANGEROUS_REQUIRED,
            "remediation": [
                "Add --dangerous flag to confirm you understand the implications",
                "Use 'aictrl attest generate --key <path> --dangerous'",
            ],
            "exit_code": 2,
        }

    # Validate key path
    if not key_path:
        raise AICtrlError(
            ATTEST_SIGN_ERROR,
            "Private key path required for signed attestation",
            cause="--key argument not provided",
            remediation=["Provide --key <path> to private key"],
        )

    key_file = Path(key_path)
    if not key_file.exists():
        raise AICtrlError(
            ATTEST_SIGN_ERROR,
            f"Private key not found: {key_path}",
            cause="File does not exist",
            remediation=["Check the key path", "Use 'aictrl crypto keygen --dangerous' to generate a key"],
        )

    # Check for cryptography library
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        raise AICtrlError(
            ATTEST_SIGN_ERROR,
            "cryptography library not available",
            cause="Required dependency not installed",
            remediation=["Install: pip install cryptography"],
        )

    # Load private key
    try:
        with open(key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise AICtrlError(
                ATTEST_SIGN_ERROR,
                "Key is not an Ed25519 private key",
                cause="Wrong key type",
                remediation=["Use an Ed25519 key generated with 'aictrl crypto keygen --dangerous'"],
            )
    except Exception as e:
        raise AICtrlError(
            ATTEST_SIGN_ERROR,
            "Failed to load private key",
            cause=str(e),
            remediation=["Check key file format (PEM PKCS8)"],
        )

    # Get public key for fingerprint
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_fingerprint = get_key_fingerprint(public_pem)

    # Generate base attestation statement
    base_statement = generate_attestation_statement(
        context=context,
        evidence_bundle_path=evidence_bundle_path,
    )

    stmt = base_statement["attestation_statement"]

    # Update notices for signed attestation
    stmt["notices"] = SIGNED_NOTICES

    # Create content to sign (canonical JSON of claims + identity)
    sign_content = {
        "claims": stmt["claims"],
        "identity": stmt["identity"],
        "bindings": stmt["bindings"],
        "statement_id": stmt["statement_id"],
        "generated_at": stmt["generated_at"],
    }
    content_json = json.dumps(sign_content, sort_keys=True, separators=(",", ":"))
    content_bytes = content_json.encode("utf-8")
    content_hash = calculate_sha256(content_bytes)

    # Sign the content
    try:
        import base64
        signature_bytes = private_key.sign(content_bytes)
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")
    except Exception as e:
        raise AICtrlError(
            ATTEST_SIGN_ERROR,
            "Failed to sign attestation",
            cause=str(e),
            remediation=["Check key file integrity"],
        )

    # Build signature section
    stmt["signature"] = {
        "signed": True,
        "algorithm": "Ed25519",
        "content_hash": content_hash,
        "value": signature_b64,
        "key_fingerprint": key_fingerprint,
        "note": "Signed attestation only. No enforcement.",
    }

    # Remove old placeholder
    if "signature_placeholder" in stmt:
        del stmt["signature_placeholder"]

    return {
        "attestation_statement": stmt,
        "warning_displayed": SIGNED_ATTEST_WARNING,
    }


def verify_attestation_signature(
    statement_path: str,
    pubkey_path: str,
) -> dict[str, Any]:
    """Verify the cryptographic signature on an attestation statement.

    Phase 11: Requires explicit --pubkey (no trust store).

    Args:
        statement_path: Path to attestation statement JSON
        pubkey_path: Path to public key for verification

    Returns:
        Verification result dictionary

    Raises:
        AICtrlError: If verification fails
    """
    # Validate file paths
    statement_file = Path(statement_path)
    pubkey_file = Path(pubkey_path)

    if not statement_file.exists():
        raise AICtrlError(
            ATTEST_SIG_VERIFY_ERROR,
            f"Statement file not found: {statement_path}",
            cause="File does not exist",
            remediation=["Check the file path"],
        )

    if not pubkey_file.exists():
        raise AICtrlError(
            ATTEST_SIG_VERIFY_ERROR,
            f"Public key not found: {pubkey_path}",
            cause="File does not exist",
            remediation=["Check the public key path"],
        )

    # Check for cryptography library
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        from cryptography.exceptions import InvalidSignature
        import base64
    except ImportError:
        raise AICtrlError(
            ATTEST_SIG_VERIFY_ERROR,
            "cryptography library not available",
            cause="Required dependency not installed",
            remediation=["Install: pip install cryptography"],
        )

    # Load statement
    try:
        with open(statement_file, "r") as f:
            statement = json.load(f)
    except json.JSONDecodeError as e:
        raise AICtrlError(
            ATTEST_SIG_VERIFY_ERROR,
            "Invalid JSON in statement file",
            cause=str(e),
            remediation=["Check the statement file format"],
        )

    stmt = statement.get("attestation_statement", {})

    # Check if statement is signed
    signature_info = stmt.get("signature", {})
    if not signature_info.get("signed"):
        return {
            "valid": False,
            "error": "Statement is not signed",
            "statement_id": stmt.get("statement_id"),
            "checked_at": generate_timestamp(),
            "note": "Use --key and --dangerous to generate signed attestation",
        }

    # Load public key
    try:
        with open(pubkey_file, "rb") as f:
            pubkey_pem = f.read()
            public_key = serialization.load_pem_public_key(pubkey_pem)
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise AICtrlError(
                ATTEST_SIG_VERIFY_ERROR,
                "Key is not an Ed25519 public key",
                cause="Wrong key type",
                remediation=["Use the public key corresponding to the signing key"],
            )
    except Exception as e:
        raise AICtrlError(
            ATTEST_SIG_VERIFY_ERROR,
            "Failed to load public key",
            cause=str(e),
            remediation=["Check public key file format"],
        )

    # Verify key fingerprint matches
    provided_fingerprint = get_key_fingerprint(pubkey_pem)
    statement_fingerprint = signature_info.get("key_fingerprint", "")

    if provided_fingerprint != statement_fingerprint:
        return {
            "valid": False,
            "error": "Key fingerprint mismatch",
            "statement_id": stmt.get("statement_id"),
            "checked_at": generate_timestamp(),
            "provided_fingerprint": provided_fingerprint,
            "expected_fingerprint": statement_fingerprint,
            "note": "The provided public key does not match the signing key",
        }

    # Reconstruct content that was signed
    sign_content = {
        "claims": stmt.get("claims", {}),
        "identity": stmt.get("identity", {}),
        "bindings": stmt.get("bindings", {}),
        "statement_id": stmt.get("statement_id"),
        "generated_at": stmt.get("generated_at"),
    }
    content_json = json.dumps(sign_content, sort_keys=True, separators=(",", ":"))
    content_bytes = content_json.encode("utf-8")

    # Verify content hash
    computed_hash = calculate_sha256(content_bytes)
    stored_hash = signature_info.get("content_hash", "")

    if computed_hash != stored_hash:
        return {
            "valid": False,
            "error": "Content hash mismatch - statement may be tampered",
            "statement_id": stmt.get("statement_id"),
            "checked_at": generate_timestamp(),
            "computed_hash": computed_hash,
            "stored_hash": stored_hash,
        }

    # Verify signature
    try:
        signature_b64 = signature_info.get("value", "")
        signature_bytes = base64.b64decode(signature_b64)
        public_key.verify(signature_bytes, content_bytes)
    except InvalidSignature:
        return {
            "valid": False,
            "error": "Signature verification failed",
            "statement_id": stmt.get("statement_id"),
            "checked_at": generate_timestamp(),
            "algorithm": signature_info.get("algorithm"),
            "key_fingerprint": provided_fingerprint,
            "note": "Signature does not match content - statement may be tampered",
        }
    except Exception as e:
        raise AICtrlError(
            ATTEST_SIG_VERIFY_ERROR,
            "Signature verification error",
            cause=str(e),
            remediation=["Check signature format"],
        )

    # Success
    return {
        "valid": True,
        "statement_id": stmt.get("statement_id"),
        "generated_at": stmt.get("generated_at"),
        "checked_at": generate_timestamp(),
        "algorithm": signature_info.get("algorithm"),
        "key_fingerprint": provided_fingerprint,
        "content_hash": computed_hash,
        "signature_verified": True,
        "note": "Signed attestation only. No enforcement.",
    }
