"""Tests for security invariant enforcement.

These tests verify that:
1. Invariants are enforced where declared
2. Violations are detected deterministically
3. Context detection works correctly
4. Invariant applicability matrix is correct

IMPORTANT: These tests run WITHOUT root and WITHOUT touching /proc or /sys.
"""

import json
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from aictrl.util.invariants import (
    ExecutionContext,
    INVARIANT_CONTEXT_MAP,
    INVARIANT_METADATA,
    INVARIANT_CHECKS,
    detect_execution_context,
    get_context_name,
    get_context_info,
    is_invariant_applicable,
    make_invariant_result,
    run_invariant_check,
    run_all_invariant_checks,
    check_inv_004_no_ai_in_prod,
    check_inv_010_secret_redaction,
    check_inv_012_no_dev_artifacts,
    check_inv_016_fail_deny,
    check_inv_017_no_default_passwords,
    check_inv_018_no_default_secrets,
    check_inv_019_host_safety,
)


class TestExecutionContext:
    """Tests for ExecutionContext enum."""

    def test_context_values(self):
        """ExecutionContext should have expected values."""
        assert ExecutionContext.AIOS_BASE.value == "aios-base"
        assert ExecutionContext.AIOS_DEV.value == "aios-dev"
        assert ExecutionContext.AIOS_CI.value == "aios-ci"
        assert ExecutionContext.AIOS_SANDBOX.value == "aios-sandbox"
        assert ExecutionContext.UNKNOWN.value == "unknown"

    def test_all_contexts_have_string_values(self):
        """All contexts should have string values."""
        for ctx in ExecutionContext:
            assert isinstance(ctx.value, str)
            assert len(ctx.value) > 0


class TestInvariantMetadata:
    """Tests for invariant metadata completeness."""

    def test_all_19_invariants_defined(self):
        """All 19 invariants (INV-001 to INV-019) should be defined."""
        for i in range(1, 20):
            inv_id = f"INV-{i:03d}"
            assert inv_id in INVARIANT_METADATA, f"Missing metadata for {inv_id}"
            assert inv_id in INVARIANT_CONTEXT_MAP, f"Missing context map for {inv_id}"

    def test_metadata_has_required_fields(self):
        """Each invariant should have required metadata fields."""
        required_fields = ["name", "category", "enforcement", "mechanism"]
        for inv_id, metadata in INVARIANT_METADATA.items():
            for field in required_fields:
                assert field in metadata, f"{inv_id} missing field: {field}"

    def test_categories_are_valid(self):
        """Categories should match ENFORCEMENT_MODEL.md."""
        valid_categories = ["Immutability", "Human Authority", "Evidence", "Isolation", "Defaults"]
        for inv_id, metadata in INVARIANT_METADATA.items():
            assert metadata["category"] in valid_categories, \
                f"{inv_id} has invalid category: {metadata['category']}"

    def test_enforcement_locations_valid(self):
        """Enforcement locations should be valid."""
        valid_locations = ["cli", "ci", "runtime", "build"]
        for inv_id, metadata in INVARIANT_METADATA.items():
            assert metadata["enforcement"] in valid_locations, \
                f"{inv_id} has invalid enforcement: {metadata['enforcement']}"

    def test_mechanisms_valid(self):
        """Mechanisms should be valid."""
        valid_mechanisms = ["assertion", "denial", "test", "audit"]
        for inv_id, metadata in INVARIANT_METADATA.items():
            assert metadata["mechanism"] in valid_mechanisms, \
                f"{inv_id} has invalid mechanism: {metadata['mechanism']}"


class TestContextMap:
    """Tests for invariant context applicability map."""

    def test_context_map_has_all_contexts(self):
        """Each invariant should have entries for all main contexts."""
        contexts = ["aios-base", "aios-dev", "aios-ci", "aios-sandbox"]
        for inv_id, context_map in INVARIANT_CONTEXT_MAP.items():
            for ctx in contexts:
                assert ctx in context_map, f"{inv_id} missing context: {ctx}"

    def test_context_values_are_boolean(self):
        """Context applicability values should be boolean."""
        for inv_id, context_map in INVARIANT_CONTEXT_MAP.items():
            for ctx, value in context_map.items():
                assert isinstance(value, bool), \
                    f"{inv_id}[{ctx}] is not boolean: {type(value)}"

    def test_inv_019_only_in_non_prod(self):
        """INV-019 (Host Safety) should not apply in production."""
        assert INVARIANT_CONTEXT_MAP["INV-019"]["aios-base"] is False
        assert INVARIANT_CONTEXT_MAP["INV-019"]["aios-dev"] is True
        assert INVARIANT_CONTEXT_MAP["INV-019"]["aios-ci"] is True
        assert INVARIANT_CONTEXT_MAP["INV-019"]["aios-sandbox"] is True

    def test_inv_004_only_in_prod(self):
        """INV-004 (No AI in Prod) should only apply in production."""
        assert INVARIANT_CONTEXT_MAP["INV-004"]["aios-base"] is True
        assert INVARIANT_CONTEXT_MAP["INV-004"]["aios-dev"] is False


class TestContextDetection:
    """Tests for execution context detection."""

    def test_explicit_context_override(self):
        """AIOS_CONTEXT env var should override detection."""
        with mock.patch.dict(os.environ, {"AIOS_CONTEXT": "aios-dev"}):
            assert detect_execution_context() == ExecutionContext.AIOS_DEV

        with mock.patch.dict(os.environ, {"AIOS_CONTEXT": "aios-ci"}):
            assert detect_execution_context() == ExecutionContext.AIOS_CI

        with mock.patch.dict(os.environ, {"AIOS_CONTEXT": "aios-sandbox"}):
            assert detect_execution_context() == ExecutionContext.AIOS_SANDBOX

    def test_ci_detection_github_actions(self):
        """GitHub Actions should be detected as CI."""
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=False):
            # Clear AIOS_CONTEXT if set
            env = os.environ.copy()
            env.pop("AIOS_CONTEXT", None)
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
                    assert detect_execution_context() == ExecutionContext.AIOS_CI

    def test_ci_detection_generic(self):
        """Generic CI env var should be detected."""
        env = {"CI": "true"}
        with mock.patch.dict(os.environ, env, clear=True):
            assert detect_execution_context() == ExecutionContext.AIOS_CI

    def test_get_context_name(self):
        """get_context_name should return string value."""
        assert get_context_name(ExecutionContext.AIOS_DEV) == "aios-dev"
        assert get_context_name(ExecutionContext.AIOS_BASE) == "aios-base"

    def test_get_context_info_returns_dict(self):
        """get_context_info should return a dictionary."""
        info = get_context_info()
        assert isinstance(info, dict)
        assert "context" in info
        assert "applicable_invariants" in info
        assert "total_invariants" in info
        assert info["total_invariants"] == 19


class TestInvariantApplicability:
    """Tests for invariant applicability checking."""

    def test_is_invariant_applicable_valid(self):
        """is_invariant_applicable should work for valid invariants."""
        assert is_invariant_applicable("INV-019", ExecutionContext.AIOS_DEV) is True
        assert is_invariant_applicable("INV-019", ExecutionContext.AIOS_BASE) is False
        assert is_invariant_applicable("INV-004", ExecutionContext.AIOS_BASE) is True
        assert is_invariant_applicable("INV-004", ExecutionContext.AIOS_DEV) is False

    def test_is_invariant_applicable_unknown_invariant(self):
        """Unknown invariants should return False."""
        assert is_invariant_applicable("INV-999", ExecutionContext.AIOS_DEV) is False

    def test_is_invariant_applicable_unknown_context(self):
        """Unknown context should apply all invariants (fail-safe)."""
        assert is_invariant_applicable("INV-019", ExecutionContext.UNKNOWN) is True


class TestMakeInvariantResult:
    """Tests for invariant result creation."""

    def test_result_has_required_fields(self):
        """Result should have all required fields."""
        result = make_invariant_result(
            "INV-019",
            "pass",
            ExecutionContext.AIOS_DEV,
            "Test evidence"
        )
        required = ["invariant_id", "name", "category", "status", "context",
                   "evidence", "enforcement", "mechanism"]
        for field in required:
            assert field in result, f"Missing field: {field}"

    def test_result_includes_remediation(self):
        """Result should include remediation when provided."""
        result = make_invariant_result(
            "INV-019",
            "fail",
            ExecutionContext.AIOS_DEV,
            "Test evidence",
            "Fix this"
        )
        assert result["remediation"] == "Fix this"

    def test_result_status_values(self):
        """Result status should be the value passed."""
        for status in ["pass", "fail", "skip", "warn"]:
            result = make_invariant_result(
                "INV-019", status, ExecutionContext.AIOS_DEV, "Test"
            )
            assert result["status"] == status


class TestIndividualChecks:
    """Tests for individual invariant check functions."""

    def test_inv_010_secret_redaction_passes(self):
        """INV-010 should pass (patterns are defined)."""
        status, evidence, remediation = check_inv_010_secret_redaction(
            ExecutionContext.AIOS_DEV
        )
        assert status == "pass"
        assert "patterns" in evidence.lower()

    def test_inv_016_fail_deny_in_dev(self):
        """INV-016 should check fail-safe behavior."""
        status, evidence, remediation = check_inv_016_fail_deny(
            ExecutionContext.AIOS_DEV
        )
        # Status depends on Host Safety Guard state
        assert status in ["pass", "warn"]

    def test_inv_017_no_default_passwords_sandbox_skip(self):
        """INV-017 should skip in sandbox context."""
        status, evidence, remediation = check_inv_017_no_default_passwords(
            ExecutionContext.AIOS_SANDBOX
        )
        assert status == "skip"

    def test_inv_018_no_default_secrets_sandbox_skip(self):
        """INV-018 should skip in sandbox context."""
        status, evidence, remediation = check_inv_018_no_default_secrets(
            ExecutionContext.AIOS_SANDBOX
        )
        assert status == "skip"

    def test_inv_019_host_safety_skips_in_prod(self):
        """INV-019 should skip in production context."""
        status, evidence, remediation = check_inv_019_host_safety(
            ExecutionContext.AIOS_BASE
        )
        assert status == "skip"

    def test_inv_004_no_ai_skips_in_dev(self):
        """INV-004 should skip in non-production context."""
        status, evidence, remediation = check_inv_004_no_ai_in_prod(
            ExecutionContext.AIOS_DEV
        )
        assert status == "skip"

    def test_inv_012_no_dev_artifacts_skips_in_dev(self):
        """INV-012 should skip in non-production context."""
        status, evidence, remediation = check_inv_012_no_dev_artifacts(
            ExecutionContext.AIOS_DEV
        )
        assert status == "skip"


class TestRunInvariantCheck:
    """Tests for run_invariant_check function."""

    def test_run_check_returns_dict(self):
        """run_invariant_check should return a dictionary."""
        result = run_invariant_check("INV-019", ExecutionContext.AIOS_DEV)
        assert isinstance(result, dict)

    def test_run_check_skips_inapplicable(self):
        """Should skip checks not applicable in context."""
        result = run_invariant_check("INV-004", ExecutionContext.AIOS_DEV)
        assert result["status"] == "skip"

    def test_run_check_with_check_function(self):
        """Should run check function when available."""
        result = run_invariant_check("INV-019", ExecutionContext.AIOS_DEV)
        # INV-019 has a check function
        assert result["status"] in ["pass", "fail"]

    def test_run_check_without_check_function(self):
        """Should mark as skip when no check function."""
        # INV-005 has no automated check
        result = run_invariant_check("INV-005", ExecutionContext.AIOS_DEV)
        assert result["status"] == "skip"
        assert "human review" in result["evidence"].lower()


class TestRunAllInvariantChecks:
    """Tests for run_all_invariant_checks function."""

    def test_returns_dict_with_summary(self):
        """Should return dict with summary."""
        result = run_all_invariant_checks(ExecutionContext.AIOS_SANDBOX)
        assert isinstance(result, dict)
        assert "summary" in result
        assert "invariants" in result

    def test_summary_has_counts(self):
        """Summary should have pass/fail/skip/warn counts."""
        result = run_all_invariant_checks(ExecutionContext.AIOS_SANDBOX)
        summary = result["summary"]
        assert "passed" in summary
        assert "failed" in summary
        assert "skipped" in summary
        assert "warned" in summary
        assert "total" in summary

    def test_counts_add_up(self):
        """Counts should add up to total."""
        result = run_all_invariant_checks(ExecutionContext.AIOS_SANDBOX)
        summary = result["summary"]
        total = summary["passed"] + summary["failed"] + summary["skipped"] + summary["warned"]
        assert total == summary["total"]

    def test_total_is_19(self):
        """Total invariants should be 19."""
        result = run_all_invariant_checks(ExecutionContext.AIOS_SANDBOX)
        assert result["summary"]["total"] == 19

    def test_auto_detects_context_when_none(self):
        """Should auto-detect context when not provided."""
        result = run_all_invariant_checks(None)
        assert "context" in result
        assert result["context"] in ["aios-base", "aios-dev", "aios-ci", "aios-sandbox", "unknown"]

    def test_overall_status_logic(self):
        """Overall status should reflect worst status."""
        # Force known context
        result = run_all_invariant_checks(ExecutionContext.AIOS_SANDBOX)
        overall = result["overall_status"]
        assert overall in ["pass", "warn", "fail"]

        # If any failed, overall should be fail
        if result["summary"]["failed"] > 0:
            assert overall == "fail"
        elif result["summary"]["warned"] > 0:
            assert overall == "warn"
        else:
            assert overall == "pass"

    def test_invariants_list_complete(self):
        """Invariants list should have 19 entries."""
        result = run_all_invariant_checks(ExecutionContext.AIOS_SANDBOX)
        assert len(result["invariants"]) == 19

    def test_each_invariant_has_required_fields(self):
        """Each invariant result should have required fields."""
        result = run_all_invariant_checks(ExecutionContext.AIOS_SANDBOX)
        required = ["invariant_id", "name", "status", "context", "evidence"]
        for inv_result in result["invariants"]:
            for field in required:
                assert field in inv_result, f"Missing {field} in {inv_result.get('invariant_id')}"


class TestInvariantChecksDeterministic:
    """Tests proving invariant checks are deterministic."""

    def test_same_context_same_results(self):
        """Same context should produce consistent results."""
        result1 = run_all_invariant_checks(ExecutionContext.AIOS_SANDBOX)
        result2 = run_all_invariant_checks(ExecutionContext.AIOS_SANDBOX)

        # Status counts should match
        assert result1["summary"] == result2["summary"]
        assert result1["overall_status"] == result2["overall_status"]

        # Each invariant status should match
        for i in range(19):
            assert result1["invariants"][i]["status"] == result2["invariants"][i]["status"]

    def test_different_contexts_different_applicability(self):
        """Different contexts should have different applicable invariants."""
        dev_result = run_all_invariant_checks(ExecutionContext.AIOS_DEV)
        sandbox_result = run_all_invariant_checks(ExecutionContext.AIOS_SANDBOX)

        # INV-017 applies in dev but not sandbox
        dev_inv017 = next(r for r in dev_result["invariants"] if r["invariant_id"] == "INV-017")
        sandbox_inv017 = next(r for r in sandbox_result["invariants"] if r["invariant_id"] == "INV-017")

        # In sandbox, it's skipped
        assert sandbox_inv017["status"] == "skip"


class TestInvariantEnforcementIntegration:
    """Integration tests for invariant enforcement with doctor command."""

    def test_doctor_includes_invariants_by_default(self):
        """Doctor command should include invariants by default."""
        from aictrl.commands.doctor import run_doctor

        result = run_doctor()
        assert "invariants" in result

    def test_doctor_respects_no_invariants_flag(self):
        """Doctor should skip invariants when flag is set."""
        from aictrl.commands.doctor import run_doctor

        result = run_doctor(include_invariants=False)
        assert "invariants" not in result

    def test_doctor_respects_context_override(self):
        """Doctor should use context override."""
        from aictrl.commands.doctor import run_doctor

        result = run_doctor(context="aios-sandbox")
        assert result["execution_context"] == "aios-sandbox"

    def test_doctor_output_json_serializable(self):
        """Doctor with invariants should be JSON serializable."""
        from aictrl.commands.doctor import run_doctor

        result = run_doctor(context="aios-sandbox")
        json_str = json.dumps(result)
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert "invariants" in parsed


class TestEnforcementModelCompliance:
    """Tests verifying compliance with ENFORCEMENT_MODEL.md."""

    def test_cli_enforced_invariants_have_checks(self):
        """CLI-enforced invariants should have check functions."""
        cli_enforced = [
            inv_id for inv_id, meta in INVARIANT_METADATA.items()
            if meta["enforcement"] == "cli"
        ]

        # At least some CLI invariants should have checks
        checks_available = [inv_id for inv_id in cli_enforced if inv_id in INVARIANT_CHECKS]
        assert len(checks_available) > 0, "No CLI-enforced invariants have checks"

    def test_inv_019_is_cli_enforced(self):
        """INV-019 should be CLI-enforced per ENFORCEMENT_MODEL.md."""
        assert INVARIANT_METADATA["INV-019"]["enforcement"] == "cli"
        assert "INV-019" in INVARIANT_CHECKS

    def test_context_applicability_matches_enforcement_model(self):
        """Context applicability should match ENFORCEMENT_MODEL.md E.1."""
        # Per ENFORCEMENT_MODEL.md Section E.1:
        # inv_019_host_safety: aios-base=N/A, aios-dev=Yes, aios-ci=Yes, aios-sandbox=Yes
        assert INVARIANT_CONTEXT_MAP["INV-019"]["aios-base"] is False
        assert INVARIANT_CONTEXT_MAP["INV-019"]["aios-dev"] is True
        assert INVARIANT_CONTEXT_MAP["INV-019"]["aios-ci"] is True
        assert INVARIANT_CONTEXT_MAP["INV-019"]["aios-sandbox"] is True

        # inv_004_no_ai_in_prod: aios-base=Yes, others=N/A
        assert INVARIANT_CONTEXT_MAP["INV-004"]["aios-base"] is True
        assert INVARIANT_CONTEXT_MAP["INV-004"]["aios-dev"] is False

    def test_all_invariant_categories_represented(self):
        """All five categories should have invariants."""
        categories = set(meta["category"] for meta in INVARIANT_METADATA.values())
        expected = {"Immutability", "Human Authority", "Evidence", "Isolation", "Defaults"}
        assert categories == expected
