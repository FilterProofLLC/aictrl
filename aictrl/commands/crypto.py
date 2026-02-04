"""AICtrl crypto command - cryptographic operations.

Phase 9: MVP cryptographic operations for evidence bundles.

This module provides:
- Ed25519 key generation (requires --dangerous flag)
- Ed25519 signing of files
- Ed25519 signature verification
- Public key derivation from private key

All operations are deterministic and offline.
"""

import base64
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..phases import (
    get_current_phase,
    is_capability_enabled,
    require_capability,
    EXIT_NOT_IMPLEMENTED,
)

# Crypto readiness status constants
STATUS_NOT_CONFIGURED = "not_configured"
STATUS_CONFIGURED = "configured"
STATUS_DEGRADED = "degraded"

# Post-quantum readiness posture
PQ_MONITORING = "monitoring"

# Algorithm identifier
ALGORITHM_ED25519 = "ed25519"


def generate_timestamp() -> str:
    """Generate ISO 8601 timestamp with timezone."""
    return datetime.now(timezone.utc).isoformat()


def _check_cryptography_available() -> tuple[bool, str]:
    """Check if cryptography library is available."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        return True, ""
    except ImportError:
        return False, "cryptography library not installed. Run: pip install cryptography"


def get_crypto_status() -> dict[str, Any]:
    """Get current cryptographic configuration status.

    Returns:
        Crypto status dictionary
    """
    phase = get_current_phase()
    crypto_available, crypto_error = _check_cryptography_available()

    # Determine signing status based on phase and library availability
    if phase >= 9 and crypto_available:
        signing_status = {
            "enabled": True,
            "algorithm": ALGORITHM_ED25519,
            "key_provisioned": False,  # User must provision their own key
            "note": "Ed25519 signing available. Use 'aictrl crypto keygen --dangerous' to generate keys.",
        }
        verification_status = {
            "enabled": True,
            "algorithm": ALGORITHM_ED25519,
            "note": "Ed25519 verification available.",
        }
    else:
        signing_status = {
            "enabled": False,
            "algorithm": None,
            "key_provisioned": False,
            "reason": crypto_error if not crypto_available else "Not implemented - design phase only",
        }
        verification_status = {
            "enabled": False,
            "trusted_keys": [],
            "reason": crypto_error if not crypto_available else "Not implemented - design phase only",
        }

    return {
        "status": STATUS_CONFIGURED if (phase >= 9 and crypto_available) else STATUS_NOT_CONFIGURED,
        "checked_at": generate_timestamp(),
        "phase": f"Phase {phase}",
        "crypto_library_available": crypto_available,
        "configuration": {
            "signing": signing_status,
            "verification": verification_status,
            "encryption": {
                "enabled": False,
                "algorithm": None,
                "reason": "Not implemented - future phase",
            },
            "hashing": {
                "enabled": True,
                "algorithm": "SHA-256",
                "note": "Used for integrity checks",
            },
        },
        "keys": {
            "attestation": {
                "status": "not_provisioned",
                "type": ALGORITHM_ED25519 if phase >= 9 else None,
                "note": "User must provision keys with 'aictrl crypto keygen --dangerous'",
            },
            "artifact_signing": {
                "status": "not_provisioned",
                "type": ALGORITHM_ED25519 if phase >= 9 else None,
                "note": "User must provision keys with 'aictrl crypto keygen --dangerous'",
            },
        },
        "hardware": {
            "tpm_available": False,
            "hsm_available": False,
            "note": "Hardware security modules not integrated (future phase)",
        },
    }


def get_crypto_readiness() -> dict[str, Any]:
    """Get cryptographic readiness assessment.

    Returns:
        Crypto readiness assessment dictionary
    """
    phase = get_current_phase()
    crypto_available, _ = _check_cryptography_available()

    if phase >= 9 and crypto_available:
        impl_status = "available"
        impl_blockers = []
    else:
        impl_status = "not_started"
        impl_blockers = [
            "Cryptography library required",
            "Phase 9+ required",
        ]

    return {
        "readiness_level": "operational" if (phase >= 9 and crypto_available) else "design_complete",
        "checked_at": generate_timestamp(),
        "phase": f"Phase {phase}",
        "assessment": {
            "architecture": {
                "status": "documented",
                "document": "docs/security/CRYPTO_ARCHITECTURE.md",
            },
            "key_management": {
                "status": "policy_defined",
                "document": "docs/security/KEY_MANAGEMENT_POLICY.md",
            },
            "implementation": {
                "status": impl_status,
                "blockers": impl_blockers,
            },
        },
        "post_quantum": {
            "posture": PQ_MONITORING,
            "description": "Monitoring post-quantum cryptography standards",
        },
    }


def get_crypto_algorithms() -> dict[str, Any]:
    """Get information about algorithm support.

    Returns:
        Algorithm information dictionary
    """
    phase = get_current_phase()
    crypto_available, _ = _check_cryptography_available()

    signing_implemented = [ALGORITHM_ED25519] if (phase >= 9 and crypto_available) else []

    return {
        "checked_at": generate_timestamp(),
        "phase": f"Phase {phase}",
        "categories": {
            "hashing": {
                "implemented": ["SHA-256"],
                "planned": ["SHA-3", "BLAKE3"],
                "deprecated": ["SHA-1", "MD5"],
            },
            "signing": {
                "implemented": signing_implemented,
                "planned": ["ECDSA P-256", "RSA-PSS"],
                "post_quantum_candidates": ["ML-DSA (Dilithium)"],
            },
            "encryption": {
                "implemented": [],
                "planned": ["AES-256-GCM", "ChaCha20-Poly1305"],
            },
        },
        "agility": {
            "principle": "Algorithms selected via configuration, not code",
            "versioning": "All artifacts include algorithm identifier",
        },
    }


# =============================================================================
# Phase 9 MVP Crypto Operations
# =============================================================================

DANGEROUS_WARNING = """
================================================================================
                              *** WARNING ***
================================================================================

You are about to generate a cryptographic private key.

This operation:
  - Creates a private key file that MUST be kept secure
  - Cannot be undone - if the key is lost, data signed with it cannot be verified
  - Should only be done on a trusted, secure system

The private key will be written with permissions 0600 (owner read/write only).

NEVER:
  - Share the private key
  - Commit the private key to version control
  - Store the private key on untrusted systems
  - Use this key for production without proper key management procedures

================================================================================
"""


def generate_keypair(
    output_path: str,
    dangerous: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    """Generate an Ed25519 keypair.

    Args:
        output_path: Path to write the private key (PEM format).
        dangerous: Must be True to proceed (safety gate).
        force: If True, overwrite existing file.

    Returns:
        Result dictionary with success status and paths.
    """
    # Check capability
    enabled, error_msg = require_capability("crypto_keygen")
    if not enabled:
        return {
            "success": False,
            "error": error_msg,
            "exit_code": EXIT_NOT_IMPLEMENTED,
        }

    # Require --dangerous flag
    if not dangerous:
        return {
            "success": False,
            "error": "Key generation requires --dangerous flag",
            "hint": "This is a safety gate. Use 'aictrl crypto keygen --out <path> --dangerous' to proceed.",
            "exit_code": 2,
        }

    # Check cryptography library
    crypto_available, crypto_error = _check_cryptography_available()
    if not crypto_available:
        return {
            "success": False,
            "error": crypto_error,
            "exit_code": 1,
        }

    # Check if file exists
    path = Path(output_path)
    if path.exists() and not force:
        return {
            "success": False,
            "error": f"File already exists: {output_path}",
            "hint": "Use --force to overwrite.",
            "exit_code": 1,
        }

    # Print warning to stderr
    sys.stderr.write(DANGEROUS_WARNING)
    sys.stderr.flush()

    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization

        # Generate keypair
        private_key = ed25519.Ed25519PrivateKey.generate()

        # Serialize private key to PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Create parent directories if needed
        path.parent.mkdir(parents=True, exist_ok=True)

        # Write with secure permissions (0600)
        # First create with restrictive umask, then write
        old_umask = os.umask(0o177)
        try:
            with open(path, "wb") as f:
                f.write(private_pem)
            # Ensure permissions are correct
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        finally:
            os.umask(old_umask)

        # Derive public key path
        pub_path = Path(str(output_path) + ".pub")

        # Serialize public key
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Write public key (can be world-readable)
        with open(pub_path, "wb") as f:
            f.write(public_pem)

        return {
            "success": True,
            "algorithm": ALGORITHM_ED25519,
            "private_key_path": str(path),
            "public_key_path": str(pub_path),
            "private_key_permissions": "0600",
            "format": "PEM (PKCS8)",
            "warning": "Keep the private key secure. Never share or commit to version control.",
        }

    except Exception as e:
        return {
            "success": False,
            "error": f"Key generation failed: {e}",
            "exit_code": 1,
        }


def derive_public_key(
    key_path: str,
    output_path: str,
) -> dict[str, Any]:
    """Derive public key from private key.

    Args:
        key_path: Path to private key (PEM format).
        output_path: Path to write public key (PEM format).

    Returns:
        Result dictionary with success status.
    """
    # Check capability
    enabled, error_msg = require_capability("crypto_pubkey")
    if not enabled:
        return {
            "success": False,
            "error": error_msg,
            "exit_code": EXIT_NOT_IMPLEMENTED,
        }

    # Check cryptography library
    crypto_available, crypto_error = _check_cryptography_available()
    if not crypto_available:
        return {
            "success": False,
            "error": crypto_error,
            "exit_code": 1,
        }

    # Check key file exists
    key_file = Path(key_path)
    if not key_file.exists():
        return {
            "success": False,
            "error": f"Private key file not found: {key_path}",
            "exit_code": 1,
        }

    try:
        from cryptography.hazmat.primitives import serialization

        # Read private key
        with open(key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )

        # Get public key
        public_key = private_key.public_key()

        # Serialize
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Write
        out_path = Path(output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(public_pem)

        return {
            "success": True,
            "algorithm": ALGORITHM_ED25519,
            "public_key_path": str(out_path),
            "format": "PEM",
        }

    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to derive public key: {e}",
            "exit_code": 1,
        }


def sign_file(
    key_path: str,
    input_path: str,
    output_path: str,
) -> dict[str, Any]:
    """Sign a file with Ed25519.

    Args:
        key_path: Path to private key (PEM format).
        input_path: Path to file to sign.
        output_path: Path to write signature (base64 encoded).

    Returns:
        Result dictionary with signature info.
    """
    # Check capability
    enabled, error_msg = require_capability("crypto_sign")
    if not enabled:
        return {
            "success": False,
            "error": error_msg,
            "exit_code": EXIT_NOT_IMPLEMENTED,
        }

    # Check cryptography library
    crypto_available, crypto_error = _check_cryptography_available()
    if not crypto_available:
        return {
            "success": False,
            "error": crypto_error,
            "exit_code": 1,
        }

    # Check files exist
    key_file = Path(key_path)
    if not key_file.exists():
        return {
            "success": False,
            "error": f"Private key file not found: {key_path}",
            "exit_code": 1,
        }

    input_file = Path(input_path)
    if not input_file.exists():
        return {
            "success": False,
            "error": f"Input file not found: {input_path}",
            "exit_code": 1,
        }

    try:
        from cryptography.hazmat.primitives import serialization

        # Read private key
        with open(key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )

        # Read input file
        with open(input_file, "rb") as f:
            data = f.read()

        # Sign
        signature = private_key.sign(data)

        # Encode signature as base64
        sig_b64 = base64.b64encode(signature).decode("ascii")

        # Write signature
        out_path = Path(output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            f.write(sig_b64)

        return {
            "success": True,
            "algorithm": ALGORITHM_ED25519,
            "input": str(input_path),
            "signature": str(output_path),
            "bytes": len(signature),
            "encoding": "base64",
        }

    except Exception as e:
        return {
            "success": False,
            "error": f"Signing failed: {e}",
            "exit_code": 1,
        }


def verify_signature(
    pubkey_path: str,
    input_path: str,
    sig_path: str,
) -> dict[str, Any]:
    """Verify an Ed25519 signature.

    Args:
        pubkey_path: Path to public key (PEM format).
        input_path: Path to file that was signed.
        sig_path: Path to signature file (base64 encoded).

    Returns:
        Result dictionary with verification status.
    """
    # Check capability
    enabled, error_msg = require_capability("crypto_verify")
    if not enabled:
        return {
            "valid": False,
            "error": error_msg,
            "exit_code": EXIT_NOT_IMPLEMENTED,
        }

    # Check cryptography library
    crypto_available, crypto_error = _check_cryptography_available()
    if not crypto_available:
        return {
            "valid": False,
            "error": crypto_error,
            "exit_code": 2,
        }

    # Check files exist
    pubkey_file = Path(pubkey_path)
    if not pubkey_file.exists():
        return {
            "valid": False,
            "error": f"Public key file not found: {pubkey_path}",
            "exit_code": 2,
        }

    input_file = Path(input_path)
    if not input_file.exists():
        return {
            "valid": False,
            "error": f"Input file not found: {input_path}",
            "exit_code": 2,
        }

    sig_file = Path(sig_path)
    if not sig_file.exists():
        return {
            "valid": False,
            "error": f"Signature file not found: {sig_path}",
            "exit_code": 2,
        }

    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.exceptions import InvalidSignature

        # Read public key
        with open(pubkey_file, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        # Read input file
        with open(input_file, "rb") as f:
            data = f.read()

        # Read signature (base64 encoded)
        with open(sig_file, "r") as f:
            sig_b64 = f.read().strip()
        signature = base64.b64decode(sig_b64)

        # Verify
        try:
            public_key.verify(signature, data)
            return {
                "valid": True,
                "algorithm": ALGORITHM_ED25519,
                "input": str(input_path),
                "sig": str(sig_path),
                "exit_code": 0,
            }
        except InvalidSignature:
            return {
                "valid": False,
                "algorithm": ALGORITHM_ED25519,
                "input": str(input_path),
                "sig": str(sig_path),
                "reason": "Signature does not match",
                "exit_code": 1,
            }

    except Exception as e:
        return {
            "valid": False,
            "error": f"Verification failed: {e}",
            "exit_code": 2,
        }
