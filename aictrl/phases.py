"""AICtrl Phase and Capability Management.

This module provides the authoritative definition of phases and capabilities.
All commands that need phase-gating should consult this module.

Phases are integers >= 8. Capabilities are derived from the current phase.
"""

from typing import Any

# Current phase of AICtrl
# Phase 8: Design complete, no crypto ops
# Phase 9: MVP crypto (Ed25519 signing/verification)
# Phase 10: Real boot measurement (read-only TPM/IMA)
# Phase 11: Signed attestation only. No enforcement.
# Phase 12: Controlled execution proposal/review (no execution)
# Phase 13+: Future (exec run, authz enforcement)
CURRENT_PHASE = 12

# Capability definitions: each capability is enabled at a specific phase
# Format: capability_name -> (min_phase, description)
CAPABILITY_DEFINITIONS = {
    # Phase 8 capabilities (design complete)
    "crypto_status_reporting": (8, "Report crypto configuration status"),
    "crypto_readiness_reporting": (8, "Report crypto readiness assessment"),
    "authz_policy_evaluation": (8, "Evaluate authorization policy"),
    "exec_inspection": (8, "Inspect execution adapters/boundaries"),
    "boot_simulation": (8, "Simulate boot measurements"),
    "attest_simulation": (8, "Simulate attestation statements"),

    # Phase 9 capabilities (MVP crypto)
    "crypto_keygen": (9, "Generate Ed25519 keypairs (requires --dangerous)"),
    "crypto_sign": (9, "Sign files with Ed25519"),
    "crypto_verify": (9, "Verify Ed25519 signatures"),
    "crypto_pubkey": (9, "Derive public key from private key"),

    # Phase 10 capabilities (real boot measurement)
    "boot_real_measurement": (10, "Read real boot measurements (IMA)"),
    "boot_policy_verify": (10, "Verify boot log against policy"),

    # Phase 11 capabilities (signed attestation)
    "attest_signed": (11, "Generate signed attestation statements (requires --dangerous)"),
    "attest_verify_signature": (11, "Verify attestation signature with explicit pubkey"),

    # Phase 12 capabilities (exec propose/review - no execution)
    "exec_propose": (12, "Create execution proposals (no side effects)"),
    "exec_review": (12, "Review execution proposals (read-only)"),

    # Phase 13+ capabilities (future)
    "exec_run": (13, "Execute approved proposals with human gate"),
    "authz_enforceable": (14, "Enforceable authorization with policy signatures"),
}


def get_current_phase() -> int:
    """Return the current AICtrl phase."""
    return CURRENT_PHASE


def is_capability_enabled(capability: str) -> bool:
    """Check if a capability is enabled in the current phase.

    Args:
        capability: The capability name to check.

    Returns:
        True if the capability is enabled, False otherwise.
    """
    if capability not in CAPABILITY_DEFINITIONS:
        return False
    min_phase, _ = CAPABILITY_DEFINITIONS[capability]
    return CURRENT_PHASE >= min_phase


def get_enabled_capabilities() -> dict[str, str]:
    """Get all capabilities enabled in the current phase.

    Returns:
        Dictionary mapping capability name to description.
    """
    result = {}
    for cap, (min_phase, desc) in CAPABILITY_DEFINITIONS.items():
        if CURRENT_PHASE >= min_phase:
            result[cap] = desc
    return result


def get_disabled_capabilities() -> dict[str, dict[str, Any]]:
    """Get all capabilities NOT enabled in the current phase.

    Returns:
        Dictionary mapping capability name to info dict with
        description and required phase.
    """
    result = {}
    for cap, (min_phase, desc) in CAPABILITY_DEFINITIONS.items():
        if CURRENT_PHASE < min_phase:
            result[cap] = {
                "description": desc,
                "available_in_phase": min_phase,
            }
    return result


def get_phase_info() -> dict[str, Any]:
    """Get complete phase information for status/version output.

    Returns:
        Dictionary with current_phase and enabled_capabilities.
    """
    return {
        "current_phase": CURRENT_PHASE,
        "enabled_capabilities": get_enabled_capabilities(),
        "disabled_capabilities": get_disabled_capabilities(),
    }


def require_capability(capability: str) -> tuple[bool, str]:
    """Check if capability is enabled and return error message if not.

    Args:
        capability: The capability name to require.

    Returns:
        Tuple of (is_enabled, error_message).
        If enabled, error_message is empty.
        If not enabled, error_message contains the NOT IMPLEMENTED message.
    """
    if capability not in CAPABILITY_DEFINITIONS:
        return False, f"NOT IMPLEMENTED: Unknown capability '{capability}'"

    min_phase, desc = CAPABILITY_DEFINITIONS[capability]
    if CURRENT_PHASE >= min_phase:
        return True, ""

    return False, (
        f"NOT IMPLEMENTED: {desc} (phase {CURRENT_PHASE})\n"
        f"Available in phase {min_phase}+"
    )


# Exit code for "not implemented" (distinct from success=0 and failure=1)
EXIT_NOT_IMPLEMENTED = 2
