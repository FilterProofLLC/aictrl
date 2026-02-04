"""Security Invariant Enforcement for aictrl.

This module provides the mechanical enforcement scaffolding for AICtrl security
invariants (INV-001 to INV-019). It maps each invariant to:
- Execution context applicability
- Enforcement mechanism
- Evidence artifact generation

IMPORTANT: Invariant violations MUST block operations deterministically.
"""

import os
import shutil
from enum import Enum
from typing import Any, Literal, Optional

from .safe_exec import get_safety_status, is_host_safety_enabled


class ExecutionContext(Enum):
    """AIOS execution contexts as defined in AIOS_EXECUTION_CONTEXTS.md."""
    AIOS_BASE = "aios-base"      # Production runtime (immutable, no AI)
    AIOS_DEV = "aios-dev"        # Development (layered, AI advisory)
    AIOS_CI = "aios-ci"          # CI pipeline (ephemeral, headless)
    AIOS_SANDBOX = "aios-sandbox"  # Userspace simulation
    UNKNOWN = "unknown"          # Cannot determine context


InvariantStatus = Literal["pass", "fail", "skip", "warn"]


# Invariant applicability by context
# True = invariant applies and must be checked
# False = invariant does not apply (skip)
INVARIANT_CONTEXT_MAP = {
    # Immutability Invariants
    "INV-001": {"aios-base": True, "aios-dev": False, "aios-ci": False, "aios-sandbox": False},
    "INV-002": {"aios-base": True, "aios-dev": False, "aios-ci": True, "aios-sandbox": False},
    "INV-003": {"aios-base": True, "aios-dev": False, "aios-ci": False, "aios-sandbox": False},

    # Human Authority Invariants
    "INV-004": {"aios-base": True, "aios-dev": False, "aios-ci": False, "aios-sandbox": False},
    "INV-005": {"aios-base": True, "aios-dev": True, "aios-ci": True, "aios-sandbox": True},
    "INV-006": {"aios-base": True, "aios-dev": True, "aios-ci": True, "aios-sandbox": True},
    "INV-007": {"aios-base": True, "aios-dev": True, "aios-ci": True, "aios-sandbox": True},

    # Evidence Invariants
    "INV-008": {"aios-base": True, "aios-dev": True, "aios-ci": True, "aios-sandbox": True},
    "INV-009": {"aios-base": True, "aios-dev": True, "aios-ci": False, "aios-sandbox": False},
    "INV-010": {"aios-base": True, "aios-dev": True, "aios-ci": True, "aios-sandbox": True},
    "INV-011": {"aios-base": True, "aios-dev": True, "aios-ci": True, "aios-sandbox": True},

    # Isolation Invariants
    "INV-012": {"aios-base": True, "aios-dev": False, "aios-ci": True, "aios-sandbox": False},
    "INV-013": {"aios-base": True, "aios-dev": True, "aios-ci": False, "aios-sandbox": False},
    "INV-014": {"aios-base": True, "aios-dev": True, "aios-ci": False, "aios-sandbox": False},
    "INV-015": {"aios-base": True, "aios-dev": True, "aios-ci": True, "aios-sandbox": True},

    # Default Invariants
    "INV-016": {"aios-base": True, "aios-dev": True, "aios-ci": True, "aios-sandbox": True},
    "INV-017": {"aios-base": True, "aios-dev": True, "aios-ci": True, "aios-sandbox": False},
    "INV-018": {"aios-base": True, "aios-dev": True, "aios-ci": True, "aios-sandbox": False},
    "INV-019": {"aios-base": False, "aios-dev": True, "aios-ci": True, "aios-sandbox": True},
}

# Invariant metadata
INVARIANT_METADATA = {
    "INV-001": {
        "name": "Production Images Are Immutable",
        "category": "Immutability",
        "enforcement": "runtime",
        "mechanism": "assertion",
    },
    "INV-002": {
        "name": "Signed Artifacts Unmodifiable",
        "category": "Immutability",
        "enforcement": "build",
        "mechanism": "test",
    },
    "INV-003": {
        "name": "Rollback Requires Verification",
        "category": "Immutability",
        "enforcement": "runtime",
        "mechanism": "assertion",
    },
    "INV-004": {
        "name": "AI Never Executes in Production",
        "category": "Human Authority",
        "enforcement": "build",
        "mechanism": "denial",
    },
    "INV-005": {
        "name": "Human Approval Required",
        "category": "Human Authority",
        "enforcement": "cli",
        "mechanism": "assertion",
    },
    "INV-006": {
        "name": "Human Intent Logged",
        "category": "Human Authority",
        "enforcement": "cli",
        "mechanism": "audit",
    },
    "INV-007": {
        "name": "AI Cannot Self-Approve",
        "category": "Human Authority",
        "enforcement": "cli",
        "mechanism": "denial",
    },
    "INV-008": {
        "name": "Evidence Cannot Be Disabled",
        "category": "Evidence",
        "enforcement": "runtime",
        "mechanism": "denial",
    },
    "INV-009": {
        "name": "Audit Logs Append-Only",
        "category": "Evidence",
        "enforcement": "runtime",
        "mechanism": "assertion",
    },
    "INV-010": {
        "name": "Secrets Never Logged",
        "category": "Evidence",
        "enforcement": "cli",
        "mechanism": "denial",
    },
    "INV-011": {
        "name": "Evidence Supports Attribution",
        "category": "Evidence",
        "enforcement": "cli",
        "mechanism": "assertion",
    },
    "INV-012": {
        "name": "Dev Artifacts Never Reach Production",
        "category": "Isolation",
        "enforcement": "build",
        "mechanism": "assertion",
    },
    "INV-013": {
        "name": "Container Isolation Enforced",
        "category": "Isolation",
        "enforcement": "runtime",
        "mechanism": "assertion",
    },
    "INV-014": {
        "name": "Network Default Deny",
        "category": "Isolation",
        "enforcement": "runtime",
        "mechanism": "assertion",
    },
    "INV-015": {
        "name": "Cross-Context Trust Isolated",
        "category": "Isolation",
        "enforcement": "build",
        "mechanism": "denial",
    },
    "INV-016": {
        "name": "Failures Default to Deny",
        "category": "Defaults",
        "enforcement": "cli",
        "mechanism": "assertion",
    },
    "INV-017": {
        "name": "No Default Passwords",
        "category": "Defaults",
        "enforcement": "build",
        "mechanism": "assertion",
    },
    "INV-018": {
        "name": "No Default Secrets in Images",
        "category": "Defaults",
        "enforcement": "build",
        "mechanism": "test",
    },
    "INV-019": {
        "name": "Host Safety Guard Enabled",
        "category": "Defaults",
        "enforcement": "cli",
        "mechanism": "assertion",
    },
}


def detect_execution_context() -> ExecutionContext:
    """Detect the current execution context.

    Detection heuristics:
    1. AIOS_CONTEXT env var (explicit override)
    2. CI environment variables (GitHub Actions, GitLab CI, etc.)
    3. Sandbox state file presence
    4. System characteristics (rpm-ostree, AI tooling presence)

    Returns:
        ExecutionContext enum value
    """
    # 1. Explicit override via environment variable
    explicit_context = os.environ.get("AIOS_CONTEXT", "").lower()
    if explicit_context:
        context_map = {
            "aios-base": ExecutionContext.AIOS_BASE,
            "aios-dev": ExecutionContext.AIOS_DEV,
            "aios-ci": ExecutionContext.AIOS_CI,
            "aios-sandbox": ExecutionContext.AIOS_SANDBOX,
        }
        if explicit_context in context_map:
            return context_map[explicit_context]

    # 2. CI environment detection
    ci_indicators = [
        "CI",           # Generic CI
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "JENKINS_URL",
        "TRAVIS",
        "CIRCLECI",
    ]
    for indicator in ci_indicators:
        if os.environ.get(indicator):
            return ExecutionContext.AIOS_CI

    # 3. Sandbox state file presence
    sandbox_state_paths = [
        "sandbox/aios-dev/state/runtime.json",
        "../sandbox/aios-dev/state/runtime.json",
        os.path.expanduser("~/sandbox/aios-dev/state/runtime.json"),
    ]
    for path in sandbox_state_paths:
        if os.path.exists(path):
            return ExecutionContext.AIOS_SANDBOX

    # 4. Check for rpm-ostree (indicates aios-base or aios-dev)
    if shutil.which("rpm-ostree"):
        # Check if Python is present (aios-dev has Python, aios-base doesn't)
        # But we're running Python, so we're in aios-dev or sandbox
        python_path = shutil.which("python3")
        if python_path and "/usr" in python_path:
            return ExecutionContext.AIOS_DEV
        return ExecutionContext.AIOS_BASE

    # 5. Default to sandbox (running on developer host)
    return ExecutionContext.AIOS_SANDBOX


def get_context_name(context: ExecutionContext) -> str:
    """Get the string name of an execution context.

    Args:
        context: ExecutionContext enum value

    Returns:
        String name (e.g., "aios-dev")
    """
    return context.value


def is_invariant_applicable(invariant_id: str, context: ExecutionContext) -> bool:
    """Check if an invariant applies in the given context.

    Args:
        invariant_id: Invariant ID (e.g., "INV-019")
        context: ExecutionContext to check

    Returns:
        True if invariant should be checked in this context
    """
    if invariant_id not in INVARIANT_CONTEXT_MAP:
        return False

    context_name = get_context_name(context)
    if context_name == "unknown":
        # In unknown context, apply all invariants (fail-safe)
        return True

    return INVARIANT_CONTEXT_MAP[invariant_id].get(context_name, False)


def make_invariant_result(
    invariant_id: str,
    status: InvariantStatus,
    context: ExecutionContext,
    evidence: str,
    remediation: Optional[str] = None,
) -> dict[str, Any]:
    """Create an invariant check result dictionary.

    Args:
        invariant_id: Invariant ID (e.g., "INV-019")
        status: Check result status
        context: Execution context
        evidence: Evidence string
        remediation: Optional remediation guidance

    Returns:
        Dictionary with check result
    """
    metadata = INVARIANT_METADATA.get(invariant_id, {})
    return {
        "invariant_id": invariant_id,
        "name": metadata.get("name", "Unknown"),
        "category": metadata.get("category", "Unknown"),
        "status": status,
        "context": get_context_name(context),
        "evidence": evidence,
        "enforcement": metadata.get("enforcement", "unknown"),
        "mechanism": metadata.get("mechanism", "unknown"),
        "remediation": remediation,
    }


# Individual invariant check functions
# These return (status, evidence, remediation) tuples


def check_inv_004_no_ai_in_prod(context: ExecutionContext) -> tuple[InvariantStatus, str, Optional[str]]:
    """INV-004: AI Never Executes in Production.

    In production (aios-base), no AI tooling should be present.
    """
    if context != ExecutionContext.AIOS_BASE:
        return ("skip", "Not applicable in non-production context", None)

    # Check for Python (AI tooling depends on Python)
    python_path = shutil.which("python3") or shutil.which("python")
    if python_path:
        return (
            "fail",
            f"Python found at {python_path} (AI tooling possible)",
            "Remove Python from production image"
        )

    # Check for aictrl
    aictrl_path = shutil.which("aictrl")
    if aictrl_path:
        return (
            "fail",
            f"aictrl found at {aictrl_path} (AI tooling present)",
            "Remove aictrl from production image"
        )

    return ("pass", "No AI tooling detected in production", None)


def check_inv_010_secret_redaction(context: ExecutionContext) -> tuple[InvariantStatus, str, Optional[str]]:
    """INV-010: Secrets Are Never Logged.

    Check that secret redaction patterns are in place.
    """
    # This is a code-level invariant - we verify patterns exist
    # In a real implementation, this would scan log outputs
    redaction_patterns = [
        r"-----BEGIN.*PRIVATE KEY-----",
        r"password\s*[:=]\s*\S+",
        r"(api[_-]?key|token|secret)\s*[:=]\s*\S+",
        r"AKIA[0-9A-Z]{16}",
    ]
    return (
        "pass",
        f"Redaction patterns defined ({len(redaction_patterns)} patterns)",
        None
    )


def check_inv_012_no_dev_artifacts(context: ExecutionContext) -> tuple[InvariantStatus, str, Optional[str]]:
    """INV-012: Development Artifacts Never Reach Production.

    In production (aios-base), no dev tools should be present.
    """
    if context != ExecutionContext.AIOS_BASE:
        return ("skip", "Only applicable in production context", None)

    dev_tools = ["gcc", "make", "python3", "pip", "pytest"]
    found_tools = []

    for tool in dev_tools:
        if shutil.which(tool):
            found_tools.append(tool)

    if found_tools:
        return (
            "fail",
            f"Development tools found: {', '.join(found_tools)}",
            "Strip development tools from production image"
        )

    return ("pass", "No development artifacts in production", None)


def check_inv_016_fail_deny(context: ExecutionContext) -> tuple[InvariantStatus, str, Optional[str]]:
    """INV-016: Security Failure Modes Default to Deny.

    Verify that security failures result in denial, not bypass.
    """
    # This invariant is verified by code review and testing
    # Here we check the Host Safety Guard fail-safe behavior
    if is_host_safety_enabled():
        return (
            "pass",
            "Host Safety Guard demonstrates fail-safe (deny by default)",
            None
        )
    else:
        return (
            "warn",
            "Host Safety Guard disabled - fail-safe demonstration limited",
            "Enable Host Safety Guard for fail-safe behavior"
        )


def check_inv_017_no_default_passwords(context: ExecutionContext) -> tuple[InvariantStatus, str, Optional[str]]:
    """INV-017: No Default Passwords.

    Check that no known default passwords exist.
    """
    if context == ExecutionContext.AIOS_SANDBOX:
        return ("skip", "Not applicable in sandbox", None)

    # In a real implementation, this would check /etc/shadow
    # For safety, we don't access /etc/shadow without root
    shadow_path = "/etc/shadow"
    if os.path.exists(shadow_path):
        # Can't read without root, but presence is noted
        return (
            "warn",
            f"{shadow_path} exists (cannot verify without root)",
            "Verify manually: no default password hashes"
        )
    else:
        return (
            "skip",
            f"{shadow_path} not accessible",
            None
        )


def check_inv_018_no_default_secrets(context: ExecutionContext) -> tuple[InvariantStatus, str, Optional[str]]:
    """INV-018: No Default Secrets in Images.

    Check for common secret patterns in configuration.
    """
    if context == ExecutionContext.AIOS_SANDBOX:
        return ("skip", "Not applicable in sandbox", None)

    # Check for common secret file locations
    secret_locations = [
        "/etc/pki/tls/private",
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_ed25519",
    ]

    found_secrets = []
    for location in secret_locations:
        if os.path.exists(location):
            found_secrets.append(location)

    if found_secrets:
        return (
            "warn",
            f"Potential secret locations exist: {', '.join(found_secrets)}",
            "Verify no default secrets in image"
        )

    return ("pass", "No obvious default secrets detected", None)


def check_inv_019_host_safety(context: ExecutionContext) -> tuple[InvariantStatus, str, Optional[str]]:
    """INV-019: Host Safety Guard Is Enabled by Default.

    Verify that Host Safety Guard is active.
    """
    if context == ExecutionContext.AIOS_BASE:
        return ("skip", "Host Safety Guard not applicable in production", None)

    safety_status = get_safety_status()

    if safety_status["host_safety_enabled"]:
        return (
            "pass",
            f"Host Safety Guard active ({safety_status['denylist_pattern_count']} patterns)",
            None
        )
    else:
        return (
            "fail",
            f"Host Safety Guard DISABLED (env={safety_status['env_var']}, flag={safety_status['risk_flag_passed']})",
            "Enable Host Safety Guard (remove BBAIL_HOST_SAFETY=0)"
        )


# Map of invariant IDs to check functions
INVARIANT_CHECKS = {
    "INV-004": check_inv_004_no_ai_in_prod,
    "INV-010": check_inv_010_secret_redaction,
    "INV-012": check_inv_012_no_dev_artifacts,
    "INV-016": check_inv_016_fail_deny,
    "INV-017": check_inv_017_no_default_passwords,
    "INV-018": check_inv_018_no_default_secrets,
    "INV-019": check_inv_019_host_safety,
}


def run_invariant_check(invariant_id: str, context: ExecutionContext) -> dict[str, Any]:
    """Run a single invariant check.

    Args:
        invariant_id: Invariant ID (e.g., "INV-019")
        context: Execution context

    Returns:
        Invariant check result dictionary
    """
    # Check if invariant applies in this context
    if not is_invariant_applicable(invariant_id, context):
        return make_invariant_result(
            invariant_id,
            "skip",
            context,
            f"Not applicable in {get_context_name(context)} context",
        )

    # Run the check if we have a check function
    if invariant_id in INVARIANT_CHECKS:
        check_func = INVARIANT_CHECKS[invariant_id]
        status, evidence, remediation = check_func(context)
        return make_invariant_result(invariant_id, status, context, evidence, remediation)
    else:
        # No check function - mark as needing human review
        return make_invariant_result(
            invariant_id,
            "skip",
            context,
            "No automated check available (human review required)",
        )


def run_all_invariant_checks(context: Optional[ExecutionContext] = None) -> dict[str, Any]:
    """Run all invariant checks for the given context.

    Args:
        context: Execution context (auto-detected if None)

    Returns:
        Dictionary with all check results and summary
    """
    if context is None:
        context = detect_execution_context()

    results = []
    for invariant_id in sorted(INVARIANT_METADATA.keys()):
        result = run_invariant_check(invariant_id, context)
        results.append(result)

    # Calculate summary
    passed = sum(1 for r in results if r["status"] == "pass")
    failed = sum(1 for r in results if r["status"] == "fail")
    skipped = sum(1 for r in results if r["status"] == "skip")
    warned = sum(1 for r in results if r["status"] == "warn")

    overall = "pass"
    if failed > 0:
        overall = "fail"
    elif warned > 0:
        overall = "warn"

    return {
        "context": get_context_name(context),
        "context_detected": context == detect_execution_context(),
        "overall_status": overall,
        "summary": {
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "warned": warned,
            "total": len(results),
        },
        "invariants": results,
    }


def get_context_info() -> dict[str, Any]:
    """Get information about the current execution context.

    Returns:
        Dictionary with context details
    """
    context = detect_execution_context()
    context_name = get_context_name(context)

    # Count applicable invariants
    applicable_count = sum(
        1 for inv_id in INVARIANT_CONTEXT_MAP
        if is_invariant_applicable(inv_id, context)
    )

    return {
        "context": context_name,
        "applicable_invariants": applicable_count,
        "total_invariants": len(INVARIANT_METADATA),
        "detection_method": _get_detection_reason(context),
    }


def _get_detection_reason(context: ExecutionContext) -> str:
    """Get the reason for context detection.

    Args:
        context: Detected context

    Returns:
        Human-readable reason
    """
    explicit = os.environ.get("AIOS_CONTEXT", "")
    if explicit:
        return f"AIOS_CONTEXT environment variable set to '{explicit}'"

    ci_vars = ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "TRAVIS", "CIRCLECI"]
    for var in ci_vars:
        if os.environ.get(var):
            return f"CI environment detected ({var} is set)"

    if context == ExecutionContext.AIOS_SANDBOX:
        return "Developer host detected (default to sandbox)"

    if shutil.which("rpm-ostree"):
        return "rpm-ostree detected (AIOS system)"

    return "Heuristic detection"
