"""Execution adapter and boundary inspection commands.

Phase 8-11: Inspection only.
Phase 12 Part 1: Proposal and Review (no execution).
Phase 12 Part 2: Approval and Controlled Execution.

CRITICAL SAFETY INVARIANTS:
- No execution without prior approval artifact
- Approval MUST bind to proposal_id and content_hash
- Hash re-verified at execution time
- Dangerous adapters require --dangerous at BOTH propose AND run
- Default-deny adapter allowlist applies at all stages
- No implicit execution paths
- No shell execution unless adapter explicitly allows
- No writes outside explicit targets
- All failures return deterministic exit codes (2 for policy denial)
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

# Phase 12 Part 2 error codes
EXEC_APPROVAL_ERROR = "AICTRL-9010"
EXEC_INVALID_APPROVAL = "AICTRL-9011"
EXEC_APPROVAL_MISMATCH = "AICTRL-9012"
EXEC_NO_APPROVAL = "AICTRL-9013"
EXEC_RUN_ERROR = "AICTRL-9014"
EXEC_REVIEW_REQUIRED = "AICTRL-9015"
EXEC_ADAPTER_EXECUTION_ERROR = "AICTRL-9016"


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


# ============================================================================
# Phase 12 Part 2: Approval and Controlled Execution Functions
# ============================================================================

def approve_proposal(
    proposal_path: str,
    approved_by: str,
    out_path: Optional[str] = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Approve an execution proposal.

    Creates an approval artifact that binds to the proposal's ID and content hash.
    This function has NO side effects except writing to the explicit out_path.
    This function does NOT execute anything.

    Args:
        proposal_path: Path to proposal JSON file
        approved_by: Identity of the approver (user-provided string)
        out_path: Path to write approval (required)
        overwrite: Whether to overwrite existing file

    Returns:
        Result dictionary with success status and approval or error
    """
    # Validate output path first (fail fast)
    if not out_path:
        return {
            "success": False,
            "error": "Output path required (--out)",
            "error_code": EXEC_APPROVAL_ERROR,
            "hint": "Specify --out <path> for approval output",
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

    # Validate approved_by
    if not approved_by or not approved_by.strip():
        return {
            "success": False,
            "error": "Approver identity required (--approved-by)",
            "error_code": EXEC_APPROVAL_ERROR,
            "hint": "Specify --approved-by <identity>",
            "exit_code": 2,
        }

    # First, review the proposal to validate it
    review_result = review_proposal(proposal_path)

    if not review_result.get("success"):
        # Propagate review error
        return {
            "success": False,
            "error": f"Proposal review failed: {review_result.get('error', 'unknown')}",
            "error_code": review_result.get("error_code", EXEC_APPROVAL_ERROR),
            "hint": review_result.get("hint", "Fix proposal before approval"),
            "exit_code": review_result.get("exit_code", 2),
        }

    # Extract validated data from review
    proposal_id = review_result.get("proposal_id")
    content_hash = review_result.get("content_hash")

    if not proposal_id or not content_hash:
        return {
            "success": False,
            "error": "Proposal missing required fields (proposal_id, content_hash)",
            "error_code": EXEC_INVALID_PROPOSAL,
            "hint": "Proposal may be corrupted",
            "exit_code": 2,
        }

    # Generate approval
    approval_id = str(uuid.uuid4())
    approved_at = generate_timestamp()

    approval = {
        "schema_version": "1.0",
        "approval_id": approval_id,
        "approved_at": approved_at,
        "approved_by": approved_by.strip(),
        "phase": 12,
        "status": "approved",
        # CRITICAL: Bind to proposal identity and content hash
        "proposal_id": proposal_id,
        "content_hash": content_hash,
        # Store proposal path for reference (not used for validation)
        "proposal_path": str(Path(proposal_path).resolve()),
        # Store request summary for audit trail
        "request_summary": review_result.get("request_summary", {}),
        "dangerous_requested": review_result.get("dangerous_requested", False),
    }

    # Write approval to file
    try:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w") as f:
            json.dump(approval, f, indent=2, sort_keys=True)
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to write approval: {e}",
            "error_code": EXEC_APPROVAL_ERROR,
            "hint": "Check output path permissions",
            "exit_code": 1,
        }

    return {
        "success": True,
        "approval_id": approval_id,
        "proposal_id": proposal_id,
        "content_hash": content_hash,
        "approved_by": approved_by.strip(),
        "approved_at": approved_at,
        "output_path": str(out_file),
        "status": "approved",
    }


def _load_and_validate_approval(approval_path: str) -> tuple[Optional[dict], Optional[dict]]:
    """Load and validate an approval file.

    Args:
        approval_path: Path to approval JSON file

    Returns:
        Tuple of (approval_dict, error_dict). If error, approval is None.
    """
    approval_file = Path(approval_path)

    if not approval_file.exists():
        return None, {
            "success": False,
            "error": f"Approval file not found: {approval_path}",
            "error_code": EXEC_NO_APPROVAL,
            "hint": "Run 'exec approve' first to create approval",
            "exit_code": 2,
        }

    try:
        with open(approval_file, "r") as f:
            approval = json.load(f)
    except json.JSONDecodeError as e:
        return None, {
            "success": False,
            "error": f"Invalid JSON in approval: {e}",
            "error_code": EXEC_INVALID_APPROVAL,
            "hint": "Approval file must be valid JSON",
            "exit_code": 1,
        }

    # Validate required fields
    required_fields = [
        "schema_version", "approval_id", "approved_at", "approved_by",
        "proposal_id", "content_hash", "status"
    ]
    missing = [f for f in required_fields if f not in approval]
    if missing:
        return None, {
            "success": False,
            "error": f"Missing required approval fields: {missing}",
            "error_code": EXEC_INVALID_APPROVAL,
            "hint": "Approval may be corrupted or from incompatible version",
            "exit_code": 1,
        }

    # Validate status
    if approval.get("status") != "approved":
        return None, {
            "success": False,
            "error": f"Approval status is '{approval.get('status')}', expected 'approved'",
            "error_code": EXEC_INVALID_APPROVAL,
            "hint": "Only approved proposals can be executed",
            "exit_code": 2,
        }

    return approval, None


def _execute_adapter(
    adapter: str,
    action: str,
    target: str,
    inputs: dict,
    dangerous: bool,
) -> dict[str, Any]:
    """Execute the adapter logic.

    CRITICAL: This is the ONLY function that performs actual execution.
    All safety checks MUST be completed before calling this function.

    Args:
        adapter: Adapter name (must be in allowlist)
        action: Action verb
        target: Target resource
        inputs: Adapter-specific inputs
        dangerous: Whether dangerous flag was provided

    Returns:
        Execution result dictionary
    """
    executed_at = generate_timestamp()

    # ADAPTER: noop - No operation, always succeeds
    if adapter == "noop":
        return {
            "success": True,
            "adapter": adapter,
            "action": action,
            "target": target,
            "executed_at": executed_at,
            "result": {
                "operation": "noop",
                "message": "No-operation adapter executed successfully",
            },
        }

    # ADAPTER: file-read - Read file contents
    if adapter == "file-read":
        target_path = Path(target)
        if not target_path.exists():
            return {
                "success": False,
                "adapter": adapter,
                "action": action,
                "target": target,
                "executed_at": executed_at,
                "error": f"Target file not found: {target}",
                "error_code": EXEC_ADAPTER_EXECUTION_ERROR,
                "exit_code": 1,
            }
        if not target_path.is_file():
            return {
                "success": False,
                "adapter": adapter,
                "action": action,
                "target": target,
                "executed_at": executed_at,
                "error": f"Target is not a file: {target}",
                "error_code": EXEC_ADAPTER_EXECUTION_ERROR,
                "exit_code": 1,
            }
        try:
            content = target_path.read_text()
            return {
                "success": True,
                "adapter": adapter,
                "action": action,
                "target": target,
                "executed_at": executed_at,
                "result": {
                    "operation": "file-read",
                    "bytes_read": len(content),
                    "content": content,
                },
            }
        except Exception as e:
            return {
                "success": False,
                "adapter": adapter,
                "action": action,
                "target": target,
                "executed_at": executed_at,
                "error": f"Failed to read file: {e}",
                "error_code": EXEC_ADAPTER_EXECUTION_ERROR,
                "exit_code": 1,
            }

    # ADAPTER: file-write - Write file contents (DANGEROUS)
    if adapter == "file-write":
        # Double-check dangerous flag (defense in depth)
        if not dangerous:
            return {
                "success": False,
                "adapter": adapter,
                "action": action,
                "target": target,
                "executed_at": executed_at,
                "error": "file-write requires --dangerous flag",
                "error_code": EXEC_DANGEROUS_REQUIRED,
                "exit_code": 2,
            }
        content = inputs.get("content", "")
        target_path = Path(target)
        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text(content)
            return {
                "success": True,
                "adapter": adapter,
                "action": action,
                "target": target,
                "executed_at": executed_at,
                "result": {
                    "operation": "file-write",
                    "bytes_written": len(content),
                    "path": str(target_path.resolve()),
                },
            }
        except Exception as e:
            return {
                "success": False,
                "adapter": adapter,
                "action": action,
                "target": target,
                "executed_at": executed_at,
                "error": f"Failed to write file: {e}",
                "error_code": EXEC_ADAPTER_EXECUTION_ERROR,
                "exit_code": 1,
            }

    # ADAPTER: shell-readonly - Read-only shell command
    if adapter == "shell-readonly":
        import subprocess
        try:
            # Run with shell=False for safety, capture output
            result = subprocess.run(
                target.split(),
                capture_output=True,
                text=True,
                timeout=30,
            )
            return {
                "success": True,
                "adapter": adapter,
                "action": action,
                "target": target,
                "executed_at": executed_at,
                "result": {
                    "operation": "shell-readonly",
                    "exit_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                },
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "adapter": adapter,
                "action": action,
                "target": target,
                "executed_at": executed_at,
                "error": "Shell command timed out (30s limit)",
                "error_code": EXEC_ADAPTER_EXECUTION_ERROR,
                "exit_code": 1,
            }
        except Exception as e:
            return {
                "success": False,
                "adapter": adapter,
                "action": action,
                "target": target,
                "executed_at": executed_at,
                "error": f"Shell command failed: {e}",
                "error_code": EXEC_ADAPTER_EXECUTION_ERROR,
                "exit_code": 1,
            }

    # ADAPTER: shell-execute - Shell command with mutations (DANGEROUS)
    if adapter == "shell-execute":
        # Double-check dangerous flag (defense in depth)
        if not dangerous:
            return {
                "success": False,
                "adapter": adapter,
                "action": action,
                "target": target,
                "executed_at": executed_at,
                "error": "shell-execute requires --dangerous flag",
                "error_code": EXEC_DANGEROUS_REQUIRED,
                "exit_code": 2,
            }
        import subprocess
        try:
            # Run with shell=False for safety, capture output
            result = subprocess.run(
                target.split(),
                capture_output=True,
                text=True,
                timeout=30,
            )
            return {
                "success": True,
                "adapter": adapter,
                "action": action,
                "target": target,
                "executed_at": executed_at,
                "result": {
                    "operation": "shell-execute",
                    "exit_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                },
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "adapter": adapter,
                "action": action,
                "target": target,
                "executed_at": executed_at,
                "error": "Shell command timed out (30s limit)",
                "error_code": EXEC_ADAPTER_EXECUTION_ERROR,
                "exit_code": 1,
            }
        except Exception as e:
            return {
                "success": False,
                "adapter": adapter,
                "action": action,
                "target": target,
                "executed_at": executed_at,
                "error": f"Shell command failed: {e}",
                "error_code": EXEC_ADAPTER_EXECUTION_ERROR,
                "exit_code": 1,
            }

    # Unknown adapter - should never reach here due to allowlist check
    return {
        "success": False,
        "adapter": adapter,
        "action": action,
        "target": target,
        "executed_at": executed_at,
        "error": f"Unknown adapter: {adapter}",
        "error_code": EXEC_ADAPTER_DENIED,
        "exit_code": 2,
    }


def run_proposal(
    proposal_path: str,
    approval_path: str,
    dangerous: bool = False,
) -> dict[str, Any]:
    """Execute an approved proposal.

    CRITICAL SAFETY CHECKS (in order):
    1. Load and validate approval file
    2. Load and validate proposal file
    3. Re-verify content hash matches approval
    4. Validate adapter is in allowlist
    5. Validate dangerous flag if required
    6. Only then execute

    Args:
        proposal_path: Path to proposal JSON file
        approval_path: Path to approval JSON file
        dangerous: Whether dangerous flag was provided at run time

    Returns:
        Execution result dictionary
    """
    # STEP 1: Load and validate approval
    approval, error = _load_and_validate_approval(approval_path)
    if error:
        return error

    # STEP 2: Review proposal (validates structure and hash)
    review_result = review_proposal(proposal_path)
    if not review_result.get("success"):
        return {
            "success": False,
            "error": f"Proposal validation failed: {review_result.get('error', 'unknown')}",
            "error_code": review_result.get("error_code", EXEC_RUN_ERROR),
            "hint": review_result.get("hint", "Proposal may be tampered or invalid"),
            "exit_code": review_result.get("exit_code", 2),
        }

    # STEP 3: Verify approval binds to this proposal
    proposal_id = review_result.get("proposal_id")
    content_hash = review_result.get("content_hash")

    if approval.get("proposal_id") != proposal_id:
        return {
            "success": False,
            "error": "Approval proposal_id does not match proposal",
            "error_code": EXEC_APPROVAL_MISMATCH,
            "hint": "Approval was created for a different proposal",
            "approval_proposal_id": approval.get("proposal_id"),
            "actual_proposal_id": proposal_id,
            "exit_code": 2,
        }

    # CRITICAL: Re-verify content hash matches approval
    if approval.get("content_hash") != content_hash:
        return {
            "success": False,
            "error": "Proposal content_hash does not match approval",
            "error_code": EXEC_HASH_MISMATCH,
            "hint": "Proposal was modified after approval",
            "approval_hash": approval.get("content_hash"),
            "actual_hash": content_hash,
            "exit_code": 2,
        }

    # STEP 4: Extract request details
    request_summary = review_result.get("request_summary", {})
    adapter = request_summary.get("adapter")
    action = request_summary.get("action")
    target = request_summary.get("target")

    # Load full proposal to get inputs
    prop_file = Path(proposal_path)
    with open(prop_file, "r") as f:
        proposal = json.load(f)
    inputs = proposal.get("request", {}).get("inputs", {})

    # STEP 5: Validate adapter in allowlist (defense in depth)
    valid, error_msg = validate_adapter(adapter)
    if not valid:
        return {
            "success": False,
            "error": error_msg,
            "error_code": EXEC_ADAPTER_DENIED,
            "hint": "Adapter not in allowlist",
            "exit_code": 2,
        }

    # STEP 6: Validate dangerous flag at run time
    dangerous_in_proposal = review_result.get("dangerous_requested", False)

    if is_dangerous_request(adapter, action):
        # Dangerous flag required at BOTH propose AND run
        if not dangerous_in_proposal:
            return {
                "success": False,
                "error": "Dangerous operation was not flagged at propose time",
                "error_code": EXEC_DANGEROUS_REQUIRED,
                "hint": "Re-create proposal with --dangerous flag",
                "exit_code": 2,
            }
        if not dangerous:
            return {
                "success": False,
                "error": "Dangerous operation requires --dangerous flag at run time",
                "error_code": EXEC_DANGEROUS_REQUIRED,
                "hint": "Add --dangerous flag to exec run command",
                "exit_code": 2,
            }

    # STEP 7: Execute the adapter (ONLY place execution happens)
    exec_result = _execute_adapter(
        adapter=adapter,
        action=action,
        target=target,
        inputs=inputs,
        dangerous=dangerous,
    )

    # Enrich result with execution context
    exec_result["proposal_id"] = proposal_id
    exec_result["approval_id"] = approval.get("approval_id")
    exec_result["content_hash"] = content_hash
    exec_result["approved_by"] = approval.get("approved_by")
    exec_result["approved_at"] = approval.get("approved_at")

    return exec_result
