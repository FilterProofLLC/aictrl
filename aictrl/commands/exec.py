"""Execution adapter and boundary inspection commands.

CRITICAL: These commands are INSPECTION ONLY (Phase 8-11).
Phase 12 adds propose/review but still NO execution.

- NEVER execute anything
- NEVER touch the OS
- NEVER call subprocesses
- NEVER perform real execution
- propose writes ONLY to explicit --out path
- review is strictly read-only

Phase 12 Part 1: Proposal and Review ONLY.
All AI-generated inputs are treated as untrusted.
Default deny for unknown adapters/actions.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# Error codes for exec commands (Phase 12)
EXEC_PROPOSAL_ERROR = "AICTRL-9001"
EXEC_REVIEW_ERROR = "AICTRL-9002"
EXEC_DANGEROUS_REQUIRED = "AICTRL-9003"
EXEC_ADAPTER_DENIED = "AICTRL-9004"
EXEC_FILE_EXISTS = "AICTRL-9005"
EXEC_HASH_MISMATCH = "AICTRL-9006"
EXEC_INVALID_PROPOSAL = "AICTRL-9007"


# Adapter allowlist for Phase 12 Part 1
# These adapters are recognized but NOT executed
ALLOWED_ADAPTERS = {
    "noop": {
        "description": "No-operation adapter for testing",
        "dangerous": False,
    },
    "file-read": {
        "description": "Read file contents (read-only)",
        "dangerous": False,
    },
    "file-write": {
        "description": "Write file contents",
        "dangerous": True,
    },
    "shell-readonly": {
        "description": "Run shell command (read-only inspection)",
        "dangerous": False,
    },
    "shell-execute": {
        "description": "Run shell command with mutations",
        "dangerous": True,
    },
}

# Actions that require dangerous flag
DANGEROUS_ACTIONS = {"write", "execute", "delete", "modify", "signal"}


def get_adapters_info() -> dict[str, Any]:
    """Get execution adapter information.

    INSPECTION ONLY - reports adapter type definitions from documentation.
    This function:
    - NEVER executes anything
    - NEVER calls subprocesses
    - NEVER touches the OS
    - Only returns documentation-derived data
    """
    return {
        "simulation": True,
        "adapters": [
            {
                "type": "human_operator",
                "status": "conceptual",
                "description": "Human directly executing commands",
                "controller": "human",
                "trust_level": "highest",
                "implemented": False,
                "can_execute": True,
                "requires_acknowledgement": True,
            },
            {
                "type": "ci",
                "status": "conceptual",
                "description": "CI/CD pipeline execution (human-configured)",
                "controller": "ci_system",
                "trust_level": "scoped",
                "implemented": False,
                "can_execute": True,
                "requires_acknowledgement": True,
                "scope_constrained": True,
            },
            {
                "type": "external",
                "status": "future",
                "description": "External system adapter (design placeholder)",
                "controller": "external_operator",
                "trust_level": "external",
                "implemented": False,
                "can_execute": False,
                "requires_acknowledgement": True,
            },
        ],
        "ai_adapter_allowed": False,
        "ai_prohibition": {
            "reason": "AI can NEVER serve as an execution adapter",
            "invariant_violations": [
                "INV-004: AI never executes in production",
                "INV-005: Human approval required for privileged operations",
                "INV-007: AI cannot approve its own suggestions",
            ],
            "no_exceptions": True,
        },
        "note": "Inspection only - no adapter operations performed",
    }


def get_boundary_info() -> dict[str, Any]:
    """Get execution boundary information.

    INSPECTION ONLY - reports boundary definitions from documentation.
    This function:
    - NEVER executes anything
    - NEVER calls subprocesses
    - NEVER touches the OS
    - Only returns documentation-derived data
    """
    return {
        "simulation": True,
        "boundaries": {
            "simulation_barrier": {
                "description": "One-way boundary between AIOS simulation and real execution",
                "properties": {
                    "one_way": True,
                    "permanent": True,
                    "human_gated": True,
                    "evidence_generating": True,
                    "non_automatable": True,
                },
                "crossable_by": ["human_operator"],
                "requires": [
                    "authorization_decision",
                    "invariant_snapshot",
                    "boot_identity",
                    "request_document",
                    "risk_assessment",
                    "human_acknowledgement",
                ],
            },
            "aios_responsibilities": [
                "policy_evaluation",
                "evidence_generation",
                "request_formulation",
                "risk_identification",
                "documentation",
                "audit_trail",
            ],
            "aios_non_responsibilities": [
                "actual_execution",
                "execution_outcomes",
                "system_state_changes",
                "recovery_from_failures",
                "adapter_behavior",
                "credential_security",
            ],
            "operator_responsibilities": [
                "execution_decision",
                "actual_execution",
                "result_reporting",
                "backup_and_recovery",
                "incident_response",
            ],
        },
        "trust_propagation": "none",
        "trust_stops_at": [
            "execution_request_document",
            "adapter_interface",
        ],
        "ai_can_cross": False,
        "note": "Inspection only - no boundary operations performed",
    }


def get_readiness_info(request_id: str | None = None) -> dict[str, Any]:
    """Get execution readiness information.

    INSPECTION ONLY - reports readiness status from simulated state.
    This function:
    - NEVER executes anything
    - NEVER calls subprocesses
    - NEVER touches the OS
    - Only returns documentation-derived data
    """
    return {
        "simulation": True,
        "request_id": request_id or "none",
        "readiness": {
            "authorization": {
                "status": "not_evaluated",
                "required": True,
                "note": "Simulation only - no real authorization",
            },
            "invariants": {
                "status": "not_checked",
                "required": True,
                "note": "Simulation only - no real invariant check",
            },
            "boot_identity": {
                "status": "not_bound",
                "required": True,
                "note": "Simulation only - no real boot identity",
            },
            "acknowledgement": {
                "level_required": 3,
                "status": "not_acknowledged",
                "required": True,
                "note": "Human acknowledgement required before boundary crossing",
            },
            "evidence": {
                "status": "not_generated",
                "required": True,
                "note": "Would be generated on request creation",
            },
        },
        "ready_for_crossing": False,
        "blockers": [
            "Authorization not evaluated",
            "Invariants not checked",
            "Boot identity not bound",
            "Acknowledgement not received",
            "Evidence not generated",
        ],
        "irreversibility": {
            "assessment": "unknown",
            "acknowledgement_level": "undetermined",
            "note": "Irreversibility assessed on actual request",
        },
        "note": "Inspection only - no readiness operations performed",
    }


# ============================================================================
# Phase 12 Part 1: Proposal and Review Functions
# ============================================================================

def generate_timestamp() -> str:
    """Generate ISO 8601 timestamp with timezone."""
    return datetime.now(timezone.utc).isoformat()


def canonicalize_json(obj: dict) -> str:
    """Convert dict to canonical JSON string for hashing.

    Args:
        obj: Dictionary to canonicalize

    Returns:
        Canonical JSON string (sorted keys, no extra whitespace)
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def compute_content_hash(content: dict) -> str:
    """Compute SHA-256 hash of canonical JSON content.

    Args:
        content: Dictionary to hash

    Returns:
        Hex-encoded SHA-256 hash
    """
    canonical = canonicalize_json(content)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def is_dangerous_request(adapter: str, action: str) -> bool:
    """Check if a request requires the dangerous flag.

    Args:
        adapter: Adapter name
        action: Action verb

    Returns:
        True if dangerous flag is required
    """
    # Check if adapter is marked dangerous
    if adapter in ALLOWED_ADAPTERS:
        if ALLOWED_ADAPTERS[adapter].get("dangerous", False):
            return True

    # Check if action is in dangerous list
    if action.lower() in DANGEROUS_ACTIONS:
        return True

    return False


def validate_adapter(adapter: str) -> tuple[bool, str]:
    """Validate adapter is in allowlist.

    Args:
        adapter: Adapter name to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if adapter not in ALLOWED_ADAPTERS:
        return False, f"Adapter '{adapter}' not in allowlist. Allowed: {list(ALLOWED_ADAPTERS.keys())}"
    return True, ""


def create_proposal(
    action: str,
    target: str,
    adapter: str,
    subject: Optional[str] = None,
    inputs: Optional[dict] = None,
    dangerous: bool = False,
    out_path: Optional[str] = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Create an execution proposal.

    This function has NO side effects except writing to the explicit out_path.

    Args:
        action: Action verb (read, write, execute, etc.)
        target: Target resource path or identifier
        adapter: Adapter name from allowlist
        subject: Optional subject identifier
        inputs: Optional adapter-specific inputs
        dangerous: Whether dangerous flag was provided
        out_path: Path to write proposal (required)
        overwrite: Whether to overwrite existing file

    Returns:
        Result dictionary with success status and proposal or error
    """
    # Validate adapter is in allowlist (default deny)
    valid, error = validate_adapter(adapter)
    if not valid:
        return {
            "success": False,
            "error": error,
            "error_code": EXEC_ADAPTER_DENIED,
            "hint": "Use an adapter from the allowlist",
            "exit_code": 2,
        }

    # Check if dangerous flag is required
    if is_dangerous_request(adapter, action) and not dangerous:
        return {
            "success": False,
            "error": "Dangerous operation requires --dangerous flag",
            "error_code": EXEC_DANGEROUS_REQUIRED,
            "hint": f"Adapter '{adapter}' with action '{action}' requires --dangerous",
            "exit_code": 2,
        }

    # Validate output path
    if not out_path:
        return {
            "success": False,
            "error": "Output path required (--out)",
            "error_code": EXEC_PROPOSAL_ERROR,
            "hint": "Specify --out <path> for proposal output",
            "exit_code": 2,
        }

    out_file = Path(out_path)
    if out_file.exists() and not overwrite:
        return {
            "success": False,
            "error": f"Output file exists: {out_path}",
            "error_code": EXEC_FILE_EXISTS,
            "hint": "Use --overwrite to replace existing file",
            "exit_code": 2,
        }

    # Build proposal content (without hash - hash is computed over this)
    proposal_id = str(uuid.uuid4())
    created_at = generate_timestamp()

    proposal_content = {
        "action": action,
        "target": target,
        "adapter": adapter,
        "subject": subject or "",
        "inputs": inputs or {},
        "created_at": created_at,
    }

    # Compute content hash
    content_hash = compute_content_hash(proposal_content)

    # Build complete proposal
    proposal = {
        "schema_version": "1.0",
        "proposal_id": proposal_id,
        "created_at": created_at,
        "phase": 12,
        "status": "proposed",
        "content_hash": content_hash,
        "dangerous_requested": dangerous,
        "policy_decision_id": None,
        "request": {
            "action": action,
            "target": target,
            "adapter": adapter,
            "subject": subject or "",
            "inputs": inputs or {},
        },
        "adapter_info": {
            "name": adapter,
            "description": ALLOWED_ADAPTERS[adapter]["description"],
            "dangerous": ALLOWED_ADAPTERS[adapter]["dangerous"],
        },
    }

    # Write proposal to file
    try:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w") as f:
            json.dump(proposal, f, indent=2, sort_keys=True)
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to write proposal: {e}",
            "error_code": EXEC_PROPOSAL_ERROR,
            "hint": "Check output path permissions",
            "exit_code": 1,
        }

    return {
        "success": True,
        "proposal_id": proposal_id,
        "content_hash": content_hash,
        "output_path": str(out_file),
        "status": "proposed",
        "dangerous_requested": dangerous,
        "adapter": adapter,
        "action": action,
    }


def review_proposal(proposal_path: str) -> dict[str, Any]:
    """Review an execution proposal (read-only).

    This function NEVER modifies the proposal file.

    Args:
        proposal_path: Path to proposal JSON file

    Returns:
        Result dictionary with validation status and summary
    """
    prop_file = Path(proposal_path)

    # Check file exists
    if not prop_file.exists():
        return {
            "success": False,
            "valid": False,
            "error": f"Proposal file not found: {proposal_path}",
            "error_code": EXEC_REVIEW_ERROR,
            "hint": "Check the proposal file path",
            "exit_code": 1,
        }

    # Load proposal
    try:
        with open(prop_file, "r") as f:
            proposal = json.load(f)
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "valid": False,
            "error": f"Invalid JSON in proposal: {e}",
            "error_code": EXEC_INVALID_PROPOSAL,
            "hint": "Proposal file must be valid JSON",
            "exit_code": 1,
        }

    # Validate required fields
    required_fields = [
        "schema_version", "proposal_id", "created_at", "phase",
        "status", "content_hash", "request"
    ]
    missing = [f for f in required_fields if f not in proposal]
    if missing:
        return {
            "success": False,
            "valid": False,
            "error": f"Missing required fields: {missing}",
            "error_code": EXEC_INVALID_PROPOSAL,
            "hint": "Proposal may be corrupted or from incompatible version",
            "exit_code": 1,
        }

    # Validate request structure
    request = proposal.get("request", {})
    request_fields = ["action", "target", "adapter"]
    missing_req = [f for f in request_fields if f not in request]
    if missing_req:
        return {
            "success": False,
            "valid": False,
            "error": f"Missing request fields: {missing_req}",
            "error_code": EXEC_INVALID_PROPOSAL,
            "hint": "Proposal request section is incomplete",
            "exit_code": 1,
        }

    # Recompute content hash to verify integrity
    proposal_content = {
        "action": request.get("action", ""),
        "target": request.get("target", ""),
        "adapter": request.get("adapter", ""),
        "subject": request.get("subject", ""),
        "inputs": request.get("inputs", {}),
        "created_at": proposal.get("created_at", ""),
    }
    computed_hash = compute_content_hash(proposal_content)
    stored_hash = proposal.get("content_hash", "")

    if computed_hash != stored_hash:
        return {
            "success": False,
            "valid": False,
            "error": "Content hash mismatch - proposal may be tampered",
            "error_code": EXEC_HASH_MISMATCH,
            "hint": "Proposal content does not match stored hash",
            "computed_hash": computed_hash,
            "stored_hash": stored_hash,
            "exit_code": 2,
        }

    # Build review summary
    timestamp = generate_timestamp()

    return {
        "success": True,
        "valid": True,
        "reviewed_at": timestamp,
        "proposal_id": proposal.get("proposal_id"),
        "content_hash": stored_hash,
        "hash_verified": True,
        "status": proposal.get("status"),
        "phase": proposal.get("phase"),
        "dangerous_requested": proposal.get("dangerous_requested", False),
        "request_summary": {
            "action": request.get("action"),
            "target": request.get("target"),
            "adapter": request.get("adapter"),
            "subject": request.get("subject", ""),
        },
        "adapter_info": proposal.get("adapter_info", {}),
        "created_at": proposal.get("created_at"),
        "human_summary": (
            f"Proposal {proposal.get('proposal_id')}: "
            f"{request.get('action')} on {request.get('target')} "
            f"via {request.get('adapter')} adapter"
        ),
    }


def get_allowed_adapters() -> dict[str, Any]:
    """Get list of allowed adapters for Phase 12.

    Returns:
        Dictionary of adapter info
    """
    return {
        "adapters": ALLOWED_ADAPTERS,
        "count": len(ALLOWED_ADAPTERS),
        "dangerous_adapters": [
            k for k, v in ALLOWED_ADAPTERS.items() if v.get("dangerous")
        ],
        "safe_adapters": [
            k for k, v in ALLOWED_ADAPTERS.items() if not v.get("dangerous")
        ],
    }
