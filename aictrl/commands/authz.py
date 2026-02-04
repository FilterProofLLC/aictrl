"""aictrl authz command - authorization policy evaluation.

This module provides DETERMINISTIC AUTHORIZATION EVALUATION for AICtrl.

CRITICAL: This module does NOT:
- Implement authentication (no identity verification)
- Manage users, roles, or accounts
- Handle credentials or tokens
- Make network calls
- Perform cryptographic operations

Authorization determines: "Is this action allowed in this context?"

See docs/security/AUTHORIZATION_MODEL.md for semantics.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from .. import __version__
from ..util.invariants import (
    ExecutionContext,
    get_context_name,
    detect_execution_context,
)


# Error codes for authorization commands
AUTHZ_INVALID_SUBJECT = "AICTRL-9001"
AUTHZ_INVALID_ACTION = "AICTRL-9002"
AUTHZ_INVALID_CONTEXT = "AICTRL-9003"
AUTHZ_POLICY_ERROR = "AICTRL-9004"
AUTHZ_EVALUATION_ERROR = "AICTRL-9005"

# Subject types
SUBJECT_SYSTEM = "system"
SUBJECT_HUMAN_OPERATOR = "human_operator"
SUBJECT_TOOLING = "tooling"

VALID_SUBJECTS = [SUBJECT_SYSTEM, SUBJECT_HUMAN_OPERATOR, SUBJECT_TOOLING]

# Action types
ACTION_READ = "read"
ACTION_WRITE = "write"
ACTION_MEASURE = "measure"
ACTION_EXPORT = "export"
ACTION_SIMULATE = "simulate"

VALID_ACTIONS = [ACTION_READ, ACTION_WRITE, ACTION_MEASURE, ACTION_EXPORT, ACTION_SIMULATE]

# Decision types
DECISION_ALLOW = "ALLOW"
DECISION_DENY = "DENY"
DECISION_PROPOSAL = "PROPOSAL"

# Context types
VALID_CONTEXTS = ["aios-base", "aios-dev", "aios-ci", "aios-sandbox"]

# Required notices for all authorization decisions
REQUIRED_NOTICES = [
    {
        "type": "disclaimer",
        "severity": "critical",
        "message": "Authorization is NOT authentication - does not verify identity",
    },
    {
        "type": "disclaimer",
        "severity": "normal",
        "message": "Authorization decisions are deterministic and auditable",
    },
    {
        "type": "info",
        "severity": "normal",
        "message": "See docs/security/AUTHORIZATION_MODEL.md for semantics",
    },
]


def generate_timestamp() -> str:
    """Generate ISO 8601 timestamp with timezone."""
    return datetime.now(timezone.utc).isoformat()


def generate_evidence_id() -> str:
    """Generate unique evidence identifier."""
    return str(uuid.uuid4())


# Built-in policy rules
# These are the default policies - no external policy loading
BUILTIN_RULES = {
    "aios-sandbox": [
        {
            "id": "SANDBOX-001",
            "name": "allow-system-all",
            "priority": 100,
            "subject": {"type": SUBJECT_SYSTEM},
            "action": {"type": "*"},
            "effect": DECISION_ALLOW,
            "reason": "System operations allowed in sandbox",
        },
        {
            "id": "SANDBOX-002",
            "name": "allow-human-all",
            "priority": 100,
            "subject": {"type": SUBJECT_HUMAN_OPERATOR},
            "action": {"type": "*"},
            "effect": DECISION_ALLOW,
            "reason": "Human operators can perform all sandbox actions",
        },
        {
            "id": "SANDBOX-003",
            "name": "allow-tooling-read",
            "priority": 100,
            "subject": {"type": SUBJECT_TOOLING},
            "action": {"type": ACTION_READ},
            "effect": DECISION_ALLOW,
            "reason": "Tooling can read in sandbox",
        },
        {
            "id": "SANDBOX-004",
            "name": "allow-tooling-measure",
            "priority": 100,
            "subject": {"type": SUBJECT_TOOLING},
            "action": {"type": ACTION_MEASURE},
            "effect": DECISION_ALLOW,
            "reason": "Tooling can measure in sandbox",
        },
        {
            "id": "SANDBOX-005",
            "name": "allow-tooling-export",
            "priority": 100,
            "subject": {"type": SUBJECT_TOOLING},
            "action": {"type": ACTION_EXPORT},
            "effect": DECISION_ALLOW,
            "reason": "Tooling can export evidence in sandbox",
        },
        {
            "id": "SANDBOX-006",
            "name": "allow-tooling-simulate",
            "priority": 100,
            "subject": {"type": SUBJECT_TOOLING},
            "action": {"type": ACTION_SIMULATE},
            "effect": DECISION_ALLOW,
            "reason": "Tooling can simulate in sandbox",
        },
        {
            "id": "SANDBOX-007",
            "name": "tooling-write-proposal",
            "priority": 100,
            "subject": {"type": SUBJECT_TOOLING},
            "action": {"type": ACTION_WRITE},
            "effect": DECISION_PROPOSAL,
            "reason": "Tooling write requires human approval",
        },
    ],
    "aios-dev": [
        {
            "id": "DEV-001",
            "name": "allow-system-read",
            "priority": 100,
            "subject": {"type": SUBJECT_SYSTEM},
            "action": {"type": ACTION_READ},
            "effect": DECISION_ALLOW,
            "reason": "System can read in dev",
        },
        {
            "id": "DEV-002",
            "name": "allow-system-measure",
            "priority": 100,
            "subject": {"type": SUBJECT_SYSTEM},
            "action": {"type": ACTION_MEASURE},
            "effect": DECISION_ALLOW,
            "reason": "System can measure in dev",
        },
        {
            "id": "DEV-003",
            "name": "allow-human-all",
            "priority": 100,
            "subject": {"type": SUBJECT_HUMAN_OPERATOR},
            "action": {"type": "*"},
            "effect": DECISION_ALLOW,
            "reason": "Human operators have full dev access",
        },
        {
            "id": "DEV-004",
            "name": "allow-tooling-read",
            "priority": 100,
            "subject": {"type": SUBJECT_TOOLING},
            "action": {"type": ACTION_READ},
            "effect": DECISION_ALLOW,
            "reason": "Tooling can read in dev",
        },
        {
            "id": "DEV-005",
            "name": "allow-tooling-measure",
            "priority": 100,
            "subject": {"type": SUBJECT_TOOLING},
            "action": {"type": ACTION_MEASURE},
            "effect": DECISION_ALLOW,
            "reason": "Tooling can measure in dev",
        },
        {
            "id": "DEV-006",
            "name": "allow-tooling-export",
            "priority": 100,
            "subject": {"type": SUBJECT_TOOLING},
            "action": {"type": ACTION_EXPORT},
            "effect": DECISION_ALLOW,
            "reason": "Tooling can export in dev",
        },
        {
            "id": "DEV-007",
            "name": "tooling-write-proposal",
            "priority": 100,
            "subject": {"type": SUBJECT_TOOLING},
            "action": {"type": ACTION_WRITE},
            "effect": DECISION_PROPOSAL,
            "reason": "Tooling write requires human approval",
        },
        {
            "id": "DEV-008",
            "name": "deny-system-write",
            "priority": 50,
            "subject": {"type": SUBJECT_SYSTEM},
            "action": {"type": ACTION_WRITE},
            "effect": DECISION_DENY,
            "reason": "System cannot write in dev (human authority required)",
        },
    ],
    "aios-ci": [
        {
            "id": "CI-001",
            "name": "allow-system-read",
            "priority": 100,
            "subject": {"type": SUBJECT_SYSTEM},
            "action": {"type": ACTION_READ},
            "effect": DECISION_ALLOW,
            "reason": "System can read in CI",
        },
        {
            "id": "CI-002",
            "name": "allow-system-measure",
            "priority": 100,
            "subject": {"type": SUBJECT_SYSTEM},
            "action": {"type": ACTION_MEASURE},
            "effect": DECISION_ALLOW,
            "reason": "System can measure in CI",
        },
        {
            "id": "CI-003",
            "name": "allow-tooling-read",
            "priority": 100,
            "subject": {"type": SUBJECT_TOOLING},
            "action": {"type": ACTION_READ},
            "effect": DECISION_ALLOW,
            "reason": "Tooling can read in CI",
        },
        {
            "id": "CI-004",
            "name": "allow-tooling-measure",
            "priority": 100,
            "subject": {"type": SUBJECT_TOOLING},
            "action": {"type": ACTION_MEASURE},
            "effect": DECISION_ALLOW,
            "reason": "Tooling can measure in CI",
        },
        {
            "id": "CI-005",
            "name": "allow-tooling-export",
            "priority": 100,
            "subject": {"type": SUBJECT_TOOLING},
            "action": {"type": ACTION_EXPORT},
            "effect": DECISION_ALLOW,
            "reason": "Tooling can export in CI",
        },
        {
            "id": "CI-006",
            "name": "deny-all-write",
            "priority": 50,
            "subject": {"type": "*"},
            "action": {"type": ACTION_WRITE},
            "effect": DECISION_DENY,
            "reason": "CI is ephemeral - no persistent writes",
        },
    ],
    "aios-base": [
        {
            "id": "BASE-001",
            "name": "allow-system-read",
            "priority": 100,
            "subject": {"type": SUBJECT_SYSTEM},
            "action": {"type": ACTION_READ},
            "effect": DECISION_ALLOW,
            "reason": "System can read in production",
        },
        {
            "id": "BASE-002",
            "name": "allow-system-measure",
            "priority": 100,
            "subject": {"type": SUBJECT_SYSTEM},
            "action": {"type": ACTION_MEASURE},
            "effect": DECISION_ALLOW,
            "reason": "System can measure in production",
        },
        {
            "id": "BASE-003",
            "name": "allow-human-read",
            "priority": 100,
            "subject": {"type": SUBJECT_HUMAN_OPERATOR},
            "action": {"type": ACTION_READ},
            "effect": DECISION_ALLOW,
            "reason": "Human operators can read in production",
        },
        {
            "id": "BASE-004",
            "name": "allow-human-measure",
            "priority": 100,
            "subject": {"type": SUBJECT_HUMAN_OPERATOR},
            "action": {"type": ACTION_MEASURE},
            "effect": DECISION_ALLOW,
            "reason": "Human operators can measure in production",
        },
        {
            "id": "BASE-005",
            "name": "human-write-limited",
            "priority": 100,
            "subject": {"type": SUBJECT_HUMAN_OPERATOR},
            "action": {"type": ACTION_WRITE},
            "effect": DECISION_PROPOSAL,
            "reason": "Production writes require explicit justification",
        },
        {
            "id": "BASE-006",
            "name": "deny-tooling-all",
            "priority": 50,
            "subject": {"type": SUBJECT_TOOLING},
            "action": {"type": "*"},
            "effect": DECISION_DENY,
            "reason": "Tooling not installed in production",
        },
    ],
}


def validate_subject(subject: str) -> bool:
    """Validate subject type.

    Args:
        subject: Subject type to validate

    Returns:
        True if valid, False otherwise
    """
    return subject in VALID_SUBJECTS


def validate_action(action: str) -> bool:
    """Validate action type.

    Args:
        action: Action type to validate

    Returns:
        True if valid, False otherwise
    """
    return action in VALID_ACTIONS


def validate_context(context: str) -> bool:
    """Validate execution context.

    Args:
        context: Context to validate

    Returns:
        True if valid, False otherwise
    """
    return context in VALID_CONTEXTS


def matches_subject(rule_subject: dict, request_subject: str) -> bool:
    """Check if rule subject matches request subject.

    Args:
        rule_subject: Subject specification from rule
        request_subject: Subject from request

    Returns:
        True if matches
    """
    rule_type = rule_subject.get("type", "*")
    if rule_type == "*":
        return True
    return rule_type == request_subject


def matches_action(rule_action: dict, request_action: str) -> bool:
    """Check if rule action matches request action.

    Args:
        rule_action: Action specification from rule
        request_action: Action from request

    Returns:
        True if matches
    """
    rule_type = rule_action.get("type", "*")
    if rule_type == "*":
        return True
    return rule_type == request_action


def evaluate_policy(
    subject: str,
    action: str,
    context: str,
    target: Optional[str] = None,
) -> dict[str, Any]:
    """Evaluate authorization policy for a request.

    This is the core policy evaluation function. It is DETERMINISTIC:
    same inputs always produce the same output.

    Args:
        subject: Subject type (system, human_operator, tooling)
        action: Action type (read, write, measure, export, simulate)
        context: Execution context (aios-base, aios-dev, aios-ci, aios-sandbox)
        target: Optional action target (path, resource, etc.)

    Returns:
        Authorization decision with evidence
    """
    evidence_id = generate_evidence_id()
    timestamp = generate_timestamp()

    # Validate inputs
    if not validate_subject(subject):
        return {
            "decision": DECISION_DENY,
            "evidence_id": evidence_id,
            "timestamp": timestamp,
            "subject": {"type": subject, "valid": False},
            "action": {"type": action, "target": target},
            "context": context,
            "policy": {"rule_matched": None, "rule_source": "validation"},
            "reason": f"Invalid subject type: {subject}",
            "error": {"code": AUTHZ_INVALID_SUBJECT, "message": f"Subject must be one of: {VALID_SUBJECTS}"},
        }

    if not validate_action(action):
        return {
            "decision": DECISION_DENY,
            "evidence_id": evidence_id,
            "timestamp": timestamp,
            "subject": {"type": subject, "valid": True},
            "action": {"type": action, "target": target, "valid": False},
            "context": context,
            "policy": {"rule_matched": None, "rule_source": "validation"},
            "reason": f"Invalid action type: {action}",
            "error": {"code": AUTHZ_INVALID_ACTION, "message": f"Action must be one of: {VALID_ACTIONS}"},
        }

    if not validate_context(context):
        return {
            "decision": DECISION_DENY,
            "evidence_id": evidence_id,
            "timestamp": timestamp,
            "subject": {"type": subject, "valid": True},
            "action": {"type": action, "target": target, "valid": True},
            "context": context,
            "policy": {"rule_matched": None, "rule_source": "validation"},
            "reason": f"Invalid context: {context}",
            "error": {"code": AUTHZ_INVALID_CONTEXT, "message": f"Context must be one of: {VALID_CONTEXTS}"},
        }

    # Get rules for context
    rules = BUILTIN_RULES.get(context, [])

    # Sort by priority (lower = higher priority)
    sorted_rules = sorted(rules, key=lambda r: r.get("priority", 999))

    # Evaluate rules
    matched_rule = None
    for rule in sorted_rules:
        if matches_subject(rule.get("subject", {}), subject):
            if matches_action(rule.get("action", {}), action):
                matched_rule = rule
                break

    # Determine decision
    if matched_rule:
        decision = matched_rule.get("effect", DECISION_DENY)
        reason = matched_rule.get("reason", "Rule matched")
        rule_id = matched_rule.get("id", "unknown")
        rule_name = matched_rule.get("name", "unknown")
    else:
        # Default deny
        decision = DECISION_DENY
        reason = "No matching rule - default deny"
        rule_id = None
        rule_name = None

    return {
        "decision": decision,
        "evidence_id": evidence_id,
        "timestamp": timestamp,
        "subject": {"type": subject, "valid": True},
        "action": {"type": action, "target": target, "valid": True},
        "context": context,
        "policy": {
            "rule_matched": rule_id,
            "rule_name": rule_name,
            "rule_source": "builtin",
            "rules_evaluated": len(sorted_rules),
        },
        "reason": reason,
    }


def check_authorization(
    subject: str,
    action: str,
    context: Optional[str] = None,
    target: Optional[str] = None,
) -> dict[str, Any]:
    """Check authorization for an action.

    This is the main entry point for authorization checks.
    It is DETERMINISTIC and produces AUDITABLE evidence.

    Args:
        subject: Subject type (system, human_operator, tooling)
        action: Action type (read, write, measure, export, simulate)
        context: Execution context (auto-detected if not provided)
        target: Optional action target

    Returns:
        Authorization check result with evidence
    """
    # Auto-detect context if not provided
    if context is None:
        detected = detect_execution_context()
        context = get_context_name(detected)

    # Evaluate policy
    result = evaluate_policy(subject, action, context, target)

    # Add metadata
    result["bbail_version"] = __version__
    result["notices"] = REQUIRED_NOTICES.copy()

    return {
        "authorization_check": result,
    }


def get_policy_summary(context: Optional[str] = None) -> dict[str, Any]:
    """Get summary of authorization policy for a context.

    Args:
        context: Execution context (auto-detected if not provided)

    Returns:
        Policy summary
    """
    # Auto-detect context if not provided
    if context is None:
        detected = detect_execution_context()
        context = get_context_name(detected)

    if context not in VALID_CONTEXTS:
        return {
            "error": {"code": AUTHZ_INVALID_CONTEXT, "message": f"Invalid context: {context}"},
        }

    rules = BUILTIN_RULES.get(context, [])

    # Summarize rules
    allow_rules = [r for r in rules if r.get("effect") == DECISION_ALLOW]
    deny_rules = [r for r in rules if r.get("effect") == DECISION_DENY]
    proposal_rules = [r for r in rules if r.get("effect") == DECISION_PROPOSAL]

    return {
        "policy_summary": {
            "context": context,
            "checked_at": generate_timestamp(),
            "default": "deny",
            "rule_counts": {
                "total": len(rules),
                "allow": len(allow_rules),
                "deny": len(deny_rules),
                "proposal": len(proposal_rules),
            },
            "rules": [
                {
                    "id": r.get("id"),
                    "name": r.get("name"),
                    "subject": r.get("subject", {}).get("type"),
                    "action": r.get("action", {}).get("type"),
                    "effect": r.get("effect"),
                }
                for r in sorted(rules, key=lambda r: r.get("priority", 999))
            ],
            "notices": [
                {
                    "type": "info",
                    "message": "Policy is deny-by-default",
                },
                {
                    "type": "info",
                    "message": "Rules are evaluated in priority order",
                },
                {
                    "type": "info",
                    "message": "See docs/security/POLICY_LANGUAGE.md for syntax",
                },
            ],
        }
    }


def get_enforcement_points() -> dict[str, Any]:
    """Get summary of enforcement points.

    Returns:
        Enforcement points summary
    """
    enforcement_points = [
        {"id": "EP-001", "name": "cli_entry", "category": "CLI", "action": "invoke"},
        {"id": "EP-002", "name": "command_dispatch", "category": "CLI", "action": "varies"},
        {"id": "EP-010", "name": "bbail_status", "category": "Command", "action": "read"},
        {"id": "EP-011", "name": "bbail_doctor", "category": "Command", "action": "measure"},
        {"id": "EP-020", "name": "evidence_export", "category": "Evidence", "action": "export"},
        {"id": "EP-030", "name": "boot_measure", "category": "Boot", "action": "simulate"},
        {"id": "EP-040", "name": "attest_generate", "category": "Attestation", "action": "export"},
        {"id": "EP-050", "name": "sandbox_status", "category": "Sandbox", "action": "read"},
        {"id": "EP-051", "name": "sandbox_start", "category": "Sandbox", "action": "simulate"},
        {"id": "EP-060", "name": "authz_check", "category": "Authorization", "action": "read"},
        {"id": "EP-070", "name": "pr_create", "category": "PR", "action": "write"},
    ]

    return {
        "enforcement_points": {
            "checked_at": generate_timestamp(),
            "count": len(enforcement_points),
            "points": enforcement_points,
            "notices": [
                {
                    "type": "info",
                    "message": "See docs/security/POLICY_ENFORCEMENT_POINTS.md for details",
                },
            ],
        }
    }
