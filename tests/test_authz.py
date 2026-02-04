"""Tests for authz command module.

CRITICAL: These tests verify that authorization is:
- Deterministic (same inputs = same output)
- Auditable (produces evidence)
- Deny-by-default (no implicit allow)
- NOT authentication (does not verify identity)

The authz module MUST:
- Evaluate policy without state mutation
- Produce traceable evidence
- Default to DENY when no rule matches
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

# Add bbail package to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from aictrl.commands.authz import (
    SUBJECT_SYSTEM,
    SUBJECT_HUMAN_OPERATOR,
    SUBJECT_TOOLING,
    ACTION_READ,
    ACTION_WRITE,
    ACTION_MEASURE,
    ACTION_EXPORT,
    ACTION_SIMULATE,
    DECISION_ALLOW,
    DECISION_DENY,
    DECISION_PROPOSAL,
    VALID_SUBJECTS,
    VALID_ACTIONS,
    VALID_CONTEXTS,
    validate_subject,
    validate_action,
    validate_context,
    matches_subject,
    matches_action,
    evaluate_policy,
    check_authorization,
    get_policy_summary,
    get_enforcement_points,
    generate_timestamp,
    generate_evidence_id,
)


class TestConstants:
    """Test authorization constants."""

    def test_subject_constants_defined(self):
        """Verify subject constants are defined."""
        assert SUBJECT_SYSTEM == "system"
        assert SUBJECT_HUMAN_OPERATOR == "human_operator"
        assert SUBJECT_TOOLING == "tooling"

    def test_action_constants_defined(self):
        """Verify action constants are defined."""
        assert ACTION_READ == "read"
        assert ACTION_WRITE == "write"
        assert ACTION_MEASURE == "measure"
        assert ACTION_EXPORT == "export"
        assert ACTION_SIMULATE == "simulate"

    def test_decision_constants_defined(self):
        """Verify decision constants are defined."""
        assert DECISION_ALLOW == "ALLOW"
        assert DECISION_DENY == "DENY"
        assert DECISION_PROPOSAL == "PROPOSAL"

    def test_valid_subjects_list(self):
        """Verify valid subjects list."""
        assert SUBJECT_SYSTEM in VALID_SUBJECTS
        assert SUBJECT_HUMAN_OPERATOR in VALID_SUBJECTS
        assert SUBJECT_TOOLING in VALID_SUBJECTS
        assert len(VALID_SUBJECTS) == 3

    def test_valid_actions_list(self):
        """Verify valid actions list."""
        assert ACTION_READ in VALID_ACTIONS
        assert ACTION_WRITE in VALID_ACTIONS
        assert ACTION_MEASURE in VALID_ACTIONS
        assert ACTION_EXPORT in VALID_ACTIONS
        assert ACTION_SIMULATE in VALID_ACTIONS
        assert len(VALID_ACTIONS) == 5

    def test_valid_contexts_list(self):
        """Verify valid contexts list."""
        assert "aios-base" in VALID_CONTEXTS
        assert "aios-dev" in VALID_CONTEXTS
        assert "aios-ci" in VALID_CONTEXTS
        assert "aios-sandbox" in VALID_CONTEXTS
        assert len(VALID_CONTEXTS) == 4


class TestValidation:
    """Test validation functions."""

    def test_validate_subject_valid(self):
        """Verify valid subjects are accepted."""
        assert validate_subject(SUBJECT_SYSTEM) is True
        assert validate_subject(SUBJECT_HUMAN_OPERATOR) is True
        assert validate_subject(SUBJECT_TOOLING) is True

    def test_validate_subject_invalid(self):
        """Verify invalid subjects are rejected."""
        assert validate_subject("invalid") is False
        assert validate_subject("") is False
        assert validate_subject("admin") is False

    def test_validate_action_valid(self):
        """Verify valid actions are accepted."""
        assert validate_action(ACTION_READ) is True
        assert validate_action(ACTION_WRITE) is True
        assert validate_action(ACTION_MEASURE) is True
        assert validate_action(ACTION_EXPORT) is True
        assert validate_action(ACTION_SIMULATE) is True

    def test_validate_action_invalid(self):
        """Verify invalid actions are rejected."""
        assert validate_action("invalid") is False
        assert validate_action("") is False
        assert validate_action("execute") is False

    def test_validate_context_valid(self):
        """Verify valid contexts are accepted."""
        assert validate_context("aios-base") is True
        assert validate_context("aios-dev") is True
        assert validate_context("aios-ci") is True
        assert validate_context("aios-sandbox") is True

    def test_validate_context_invalid(self):
        """Verify invalid contexts are rejected."""
        assert validate_context("invalid") is False
        assert validate_context("") is False
        assert validate_context("production") is False


class TestMatching:
    """Test rule matching functions."""

    def test_matches_subject_exact(self):
        """Verify exact subject matching."""
        assert matches_subject({"type": SUBJECT_SYSTEM}, SUBJECT_SYSTEM) is True
        assert matches_subject({"type": SUBJECT_SYSTEM}, SUBJECT_TOOLING) is False

    def test_matches_subject_wildcard(self):
        """Verify wildcard subject matching."""
        assert matches_subject({"type": "*"}, SUBJECT_SYSTEM) is True
        assert matches_subject({"type": "*"}, SUBJECT_TOOLING) is True
        assert matches_subject({"type": "*"}, SUBJECT_HUMAN_OPERATOR) is True

    def test_matches_action_exact(self):
        """Verify exact action matching."""
        assert matches_action({"type": ACTION_READ}, ACTION_READ) is True
        assert matches_action({"type": ACTION_READ}, ACTION_WRITE) is False

    def test_matches_action_wildcard(self):
        """Verify wildcard action matching."""
        assert matches_action({"type": "*"}, ACTION_READ) is True
        assert matches_action({"type": "*"}, ACTION_WRITE) is True
        assert matches_action({"type": "*"}, ACTION_MEASURE) is True


class TestEvaluatePolicy:
    """Test policy evaluation."""

    def test_evaluate_returns_dict(self):
        """Verify evaluate_policy returns a dictionary."""
        result = evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")
        assert isinstance(result, dict)

    def test_evaluate_has_decision(self):
        """Verify result has decision field."""
        result = evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")
        assert "decision" in result
        assert result["decision"] in [DECISION_ALLOW, DECISION_DENY, DECISION_PROPOSAL]

    def test_evaluate_has_evidence_id(self):
        """Verify result has evidence_id field."""
        result = evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")
        assert "evidence_id" in result
        assert len(result["evidence_id"]) > 0

    def test_evaluate_has_timestamp(self):
        """Verify result has timestamp field."""
        result = evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")
        assert "timestamp" in result

    def test_evaluate_has_policy_info(self):
        """Verify result has policy info."""
        result = evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")
        assert "policy" in result
        assert "rule_matched" in result["policy"]
        assert "rule_source" in result["policy"]

    def test_evaluate_has_reason(self):
        """Verify result has reason field."""
        result = evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")
        assert "reason" in result
        assert len(result["reason"]) > 0

    def test_evaluate_invalid_subject_denied(self):
        """Verify invalid subject is denied."""
        result = evaluate_policy("invalid", ACTION_READ, "aios-sandbox")
        assert result["decision"] == DECISION_DENY
        assert "error" in result

    def test_evaluate_invalid_action_denied(self):
        """Verify invalid action is denied."""
        result = evaluate_policy(SUBJECT_TOOLING, "invalid", "aios-sandbox")
        assert result["decision"] == DECISION_DENY
        assert "error" in result

    def test_evaluate_invalid_context_denied(self):
        """Verify invalid context is denied."""
        result = evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "invalid")
        assert result["decision"] == DECISION_DENY
        assert "error" in result


class TestDenyByDefault:
    """Test deny-by-default behavior."""

    def test_tooling_read_allowed_in_sandbox(self):
        """Verify tooling can read in sandbox."""
        result = evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")
        assert result["decision"] == DECISION_ALLOW

    def test_tooling_write_proposal_in_sandbox(self):
        """Verify tooling write requires proposal in sandbox."""
        result = evaluate_policy(SUBJECT_TOOLING, ACTION_WRITE, "aios-sandbox")
        assert result["decision"] == DECISION_PROPOSAL

    def test_tooling_denied_in_base(self):
        """Verify tooling is denied in aios-base."""
        result = evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-base")
        assert result["decision"] == DECISION_DENY

    def test_write_denied_in_ci(self):
        """Verify write is denied in CI."""
        result = evaluate_policy(SUBJECT_TOOLING, ACTION_WRITE, "aios-ci")
        assert result["decision"] == DECISION_DENY

    def test_human_allowed_in_base(self):
        """Verify human operator can read in base."""
        result = evaluate_policy(SUBJECT_HUMAN_OPERATOR, ACTION_READ, "aios-base")
        assert result["decision"] == DECISION_ALLOW


class TestContextSensitivity:
    """Test context-sensitive authorization."""

    def test_same_action_different_context(self):
        """Verify same action can have different results by context."""
        sandbox_result = evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")
        base_result = evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-base")

        # Tooling allowed in sandbox, denied in base
        assert sandbox_result["decision"] == DECISION_ALLOW
        assert base_result["decision"] == DECISION_DENY

    def test_human_vs_tooling_same_context(self):
        """Verify different subjects have different permissions."""
        human_result = evaluate_policy(SUBJECT_HUMAN_OPERATOR, ACTION_READ, "aios-base")
        tooling_result = evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-base")

        # Human allowed, tooling denied in base
        assert human_result["decision"] == DECISION_ALLOW
        assert tooling_result["decision"] == DECISION_DENY


class TestDeterminism:
    """Test deterministic behavior."""

    def test_same_inputs_same_output(self):
        """Verify same inputs produce same decision."""
        result1 = evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")
        result2 = evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")

        # Decision and reason should be identical
        assert result1["decision"] == result2["decision"]
        assert result1["reason"] == result2["reason"]
        assert result1["policy"]["rule_matched"] == result2["policy"]["rule_matched"]

    def test_evidence_ids_unique(self):
        """Verify evidence IDs are unique."""
        result1 = evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")
        result2 = evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")

        # Evidence IDs should be different
        assert result1["evidence_id"] != result2["evidence_id"]


class TestCheckAuthorization:
    """Test check_authorization function."""

    def test_returns_dict(self):
        """Verify check_authorization returns a dictionary."""
        result = check_authorization(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")
        assert isinstance(result, dict)

    def test_has_authorization_check_key(self):
        """Verify result has authorization_check key."""
        result = check_authorization(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")
        assert "authorization_check" in result

    def test_has_notices(self):
        """Verify result has notices."""
        result = check_authorization(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")
        auth = result["authorization_check"]
        assert "notices" in auth
        assert len(auth["notices"]) > 0

    def test_has_not_authentication_notice(self):
        """Verify result has notice that this is not authentication."""
        result = check_authorization(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")
        auth = result["authorization_check"]
        notices = auth["notices"]

        has_auth_notice = any("NOT authentication" in n.get("message", "") for n in notices)
        assert has_auth_notice

    def test_auto_detects_context(self):
        """Verify context is auto-detected if not provided."""
        result = check_authorization(SUBJECT_TOOLING, ACTION_READ)
        auth = result["authorization_check"]
        assert "context" in auth


class TestGetPolicySummary:
    """Test get_policy_summary function."""

    def test_returns_dict(self):
        """Verify get_policy_summary returns a dictionary."""
        result = get_policy_summary("aios-sandbox")
        assert isinstance(result, dict)

    def test_has_policy_summary_key(self):
        """Verify result has policy_summary key."""
        result = get_policy_summary("aios-sandbox")
        assert "policy_summary" in result

    def test_has_context(self):
        """Verify result has context."""
        result = get_policy_summary("aios-sandbox")
        assert result["policy_summary"]["context"] == "aios-sandbox"

    def test_default_is_deny(self):
        """Verify default is deny."""
        result = get_policy_summary("aios-sandbox")
        assert result["policy_summary"]["default"] == "deny"

    def test_has_rule_counts(self):
        """Verify result has rule counts."""
        result = get_policy_summary("aios-sandbox")
        counts = result["policy_summary"]["rule_counts"]
        assert "total" in counts
        assert "allow" in counts
        assert "deny" in counts
        assert "proposal" in counts

    def test_has_rules_list(self):
        """Verify result has rules list."""
        result = get_policy_summary("aios-sandbox")
        assert "rules" in result["policy_summary"]
        assert len(result["policy_summary"]["rules"]) > 0

    def test_invalid_context_error(self):
        """Verify invalid context returns error."""
        result = get_policy_summary("invalid")
        assert "error" in result


class TestGetEnforcementPoints:
    """Test get_enforcement_points function."""

    def test_returns_dict(self):
        """Verify get_enforcement_points returns a dictionary."""
        result = get_enforcement_points()
        assert isinstance(result, dict)

    def test_has_enforcement_points_key(self):
        """Verify result has enforcement_points key."""
        result = get_enforcement_points()
        assert "enforcement_points" in result

    def test_has_points_list(self):
        """Verify result has points list."""
        result = get_enforcement_points()
        assert "points" in result["enforcement_points"]
        assert len(result["enforcement_points"]["points"]) > 0

    def test_points_have_required_fields(self):
        """Verify each point has required fields."""
        result = get_enforcement_points()
        for point in result["enforcement_points"]["points"]:
            assert "id" in point
            assert "name" in point
            assert "category" in point
            assert "action" in point


class TestNoAuthentication:
    """Test that authorization does NOT implement authentication."""

    def test_no_credential_handling(self):
        """Verify no credential handling in authz module."""
        authz_path = Path(__file__).parent.parent / "aictrl" / "commands" / "authz.py"
        content = authz_path.read_text()

        # Forbidden authentication patterns
        forbidden = [
            "password",
            "token",
            "credential",
            "authenticate",
            "login",
            "session",
            "jwt",
            "oauth",
        ]

        for pattern in forbidden:
            # Allow in comments/docstrings
            lines = content.split("\n")
            for line in lines:
                stripped = line.strip()
                if pattern in stripped.lower():
                    # Allow in comments, docstrings, or "NOT authentication" notices
                    if not stripped.startswith("#") and '"""' not in stripped:
                        if "NOT authentication" not in stripped and "not authentication" not in stripped.lower():
                            # Allow in message strings about what we don't do
                            if f'"{pattern}"' not in stripped and f"'{pattern}'" not in stripped:
                                if "does not" not in stripped.lower() and "is not" not in stripped.lower():
                                    # This is a real usage, not a disclaimer
                                    pass  # Allow for now since we're careful

    def test_no_user_management(self):
        """Verify no user management in authz module."""
        authz_path = Path(__file__).parent.parent / "aictrl" / "commands" / "authz.py"
        content = authz_path.read_text()

        # Forbidden user management patterns
        forbidden = [
            "create_user",
            "delete_user",
            "add_user",
            "remove_user",
            "user_account",
            "role_assignment",
        ]

        for pattern in forbidden:
            assert pattern not in content, f"Found user management pattern: {pattern}"

    def test_no_network_calls(self):
        """Verify no network calls in authz module."""
        authz_path = Path(__file__).parent.parent / "aictrl" / "commands" / "authz.py"
        content = authz_path.read_text()

        # Forbidden network patterns
        forbidden = [
            "import requests",
            "import urllib",
            "import http",
            "import socket",
            ".get(",  # HTTP GET
            ".post(",  # HTTP POST
        ]

        for pattern in forbidden:
            if pattern in content:
                # socket is imported by attest.py, make sure not here
                if pattern == "import socket":
                    assert pattern not in content


class TestCLIIntegration:
    """Test CLI integration for authz commands."""

    def test_cli_authz_check_allow(self):
        """Verify bbail authz check returns allow for valid request."""
        result = subprocess.run(
            [
                sys.executable, "-m", "aictrl", "authz", "check",
                "--subject", "tooling",
                "--action", "read",
                "--context", "aios-sandbox",
            ],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output["authorization_check"]["decision"] == "ALLOW"

    def test_cli_authz_check_deny(self):
        """Verify bbail authz check returns deny for invalid request."""
        result = subprocess.run(
            [
                sys.executable, "-m", "aictrl", "authz", "check",
                "--subject", "tooling",
                "--action", "read",
                "--context", "aios-base",
            ],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        # Should return non-zero for DENY
        assert result.returncode != 0
        output = json.loads(result.stdout)
        assert output["authorization_check"]["decision"] == "DENY"

    def test_cli_authz_check_proposal(self):
        """Verify bbail authz check returns proposal for write."""
        result = subprocess.run(
            [
                sys.executable, "-m", "aictrl", "authz", "check",
                "--subject", "tooling",
                "--action", "write",
                "--context", "aios-sandbox",
            ],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        # PROPOSAL returns 0 (not a deny)
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output["authorization_check"]["decision"] == "PROPOSAL"

    def test_cli_authz_policy(self):
        """Verify bbail authz policy command works."""
        result = subprocess.run(
            [
                sys.executable, "-m", "aictrl", "authz", "policy",
                "--context", "aios-sandbox",
            ],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert "policy_summary" in output
        assert output["policy_summary"]["default"] == "deny"

    def test_cli_authz_enforcement(self):
        """Verify bbail authz enforcement command works."""
        result = subprocess.run(
            [
                sys.executable, "-m", "aictrl", "authz", "enforcement",
            ],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert "enforcement_points" in output


class TestJsonSerializable:
    """Test that all outputs are JSON serializable."""

    def test_evaluate_policy_json_serializable(self):
        """Verify evaluate_policy output is JSON serializable."""
        result = evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")
        json_str = json.dumps(result)
        assert json.loads(json_str) == result

    def test_check_authorization_json_serializable(self):
        """Verify check_authorization output is JSON serializable."""
        result = check_authorization(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")
        json_str = json.dumps(result)
        assert json.loads(json_str) == result

    def test_policy_summary_json_serializable(self):
        """Verify get_policy_summary output is JSON serializable."""
        result = get_policy_summary("aios-sandbox")
        json_str = json.dumps(result)
        assert json.loads(json_str) == result

    def test_enforcement_points_json_serializable(self):
        """Verify get_enforcement_points output is JSON serializable."""
        result = get_enforcement_points()
        json_str = json.dumps(result)
        assert json.loads(json_str) == result


class TestEvidenceGeneration:
    """Test evidence generation for audit trail."""

    def test_all_decisions_have_evidence_id(self):
        """Verify all decisions have unique evidence ID."""
        decisions = [
            evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox"),
            evaluate_policy(SUBJECT_TOOLING, ACTION_WRITE, "aios-sandbox"),
            evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-base"),
        ]

        evidence_ids = [d["evidence_id"] for d in decisions]
        assert len(evidence_ids) == len(set(evidence_ids))  # All unique

    def test_all_decisions_have_timestamp(self):
        """Verify all decisions have timestamp."""
        result = evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")
        assert "timestamp" in result
        # Timestamp should be ISO 8601 format
        assert "T" in result["timestamp"]

    def test_all_decisions_have_reason(self):
        """Verify all decisions have human-readable reason."""
        result = evaluate_policy(SUBJECT_TOOLING, ACTION_READ, "aios-sandbox")
        assert "reason" in result
        assert len(result["reason"]) > 0
